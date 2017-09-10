package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/consul/tlsutil"
	"github.com/hashicorp/consul/types"
	discover "github.com/hashicorp/go-discover"
	"github.com/hashicorp/go-sockaddr/template"
	"github.com/hashicorp/hcl"
)

type Builder struct {
	// Flags contains the parsed command line arguments.
	Flags Flags

	// Default contains the default configuration. When set to nil , the
	// default configuration depends on the value of the Flags.DevMode
	// flag.
	Default *Config

	// Configs contains the user configuration fragments in the order to
	// be merged.
	Configs []Config

	// Warnings contains the warnigns encountered when
	// parsing the configuration.
	Warnings []string

	// err contains the first error that occurred during
	// building the runtime configuration.
	err error
}

// readFile parses a JSON or HCL config file and appends it to the list of
// config fragments.
func (b *Builder) readFile(name string) error {
	format := "json"
	if strings.HasSuffix(name, ".hcl") {
		format = "hcl"
	}
	data, err := ioutil.ReadFile(name)
	if err != nil {
		return fmt.Errorf("config: Error reading %s: %s", name, err)
	}
	if err := b.ReadBytes(data, format); err != nil {
		return fmt.Errorf("config: Error parsing %s: %s", name, err)
	}
	return nil
}

// ReadPath reads a single config file or all files in a directory (but
// not its sub-directories) and appends them to the list of config
// fragments. If path refers to a file then the format is assumed to be
// JSON unless the file has a '.hcl' suffix. If path refers to a
// directory then the format is determined by the suffix and only files
// with a '.json' or '.hcl' suffix are processed.
func (b *Builder) ReadPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("config: Error reading %s. %s", path, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("config: Error reading %s. %s", path, err)
	}

	if !fi.IsDir() {
		return b.readFile(fi.Name())
	}

	fis, err := f.Readdir(-1)
	if err != nil {
		return fmt.Errorf("config: Error reading %s. %s", path, err)
	}

	// sort files by name
	sort.Sort(byName(fis))

	for _, fi := range fis {
		// do not recurse into sub dirs
		if fi.IsDir() {
			continue
		}

		// skip files without json or hcl extension
		if !strings.HasSuffix(fi.Name(), ".json") && !strings.HasSuffix(fi.Name(), ".hcl") {
			continue
		}

		if err := b.readFile(fi.Name()); err != nil {
			return err
		}
	}
	return nil
}

type byName []os.FileInfo

func (a byName) Len() int           { return len(a) }
func (a byName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byName) Less(i, j int) bool { return a[i].Name() < a[j].Name() }

// ReadBytes parses config file data in either JSON or HCL format.
func (b *Builder) ReadBytes(data []byte, format string) error {
	var c Config
	switch format {
	case "json":
		if err := json.Unmarshal(data, &c); err != nil {
			return err
		}
	case "hcl":
		if err := hcl.Decode(&c, string(data)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid format: %s", format)
	}
	return b.AppendConfig(c)
}

// AppendConfig checks for non-recoverable errors and appends the
// configuration to the list of config fragments from which the runtime
// configuration is built.
func (b *Builder) AppendConfig(c Config) error {
	if err := b.ValidateConfig(c); err != nil {
		return err
	}
	b.Configs = append(b.Configs, c)
	return nil
}

// ValidateConfig checks the configuration for non-recoverable errors.
func (b *Builder) ValidateConfig(c Config) error {
	if b.intVal(c.Autopilot.MaxTrailingLogs) < 0 {
		return fmt.Errorf("autopilot.max_trailing_logs < 0")
	}

	_, err := tlsutil.ParseCiphers(b.stringVal(c.TLSCipherSuites))
	if err != nil {
		return fmt.Errorf("invalid tls cipher suites: %s", err)
	}

	return nil
}

// Build constructs the runtime configuration from the config fragments
// and the command line flags. The config fragments are processed in the
// order they were added with the flags being processed last to give
// precedence over the other fragments. If the error is nil then
// warnings can still contain deprecation or format warnigns that should
// be presented to the user.
func (b *Builder) Build() (rt RuntimeConfig, err error) {
	// ----------------------------------------------------------------
	// validate flags and config fragments
	//

	if err := b.ValidateConfig(b.Flags.Config); err != nil {
		return RuntimeConfig{}, err
	}
	if b.Default == nil {
		b.Default = &defaultConfig
		if b.boolVal(b.Flags.DevMode) {
			b.Default = &defaultDevConfig
		}
	}
	if err := b.ValidateConfig(*b.Default); err != nil {
		return RuntimeConfig{}, err
	}
	for _, c := range b.Configs {
		if err := b.ValidateConfig(c); err != nil {
			return RuntimeConfig{}, err
		}
	}

	// ----------------------------------------------------------------
	// deprecated flags
	//
	// needs to come before merging because of -dc flag
	//

	if b.Flags.DeprecatedAtlasInfrastructure != nil {
		b.warn(`'-atlas' is deprecated`)
	}
	if b.Flags.DeprecatedAtlasToken != nil {
		b.warn(`'-atlas-token' is deprecated`)
	}
	if b.Flags.DeprecatedAtlasJoin != nil {
		b.warn(`'-atlas-join' is deprecated`)
	}
	if b.Flags.DeprecatedAtlasEndpoint != nil {
		b.warn(`'-atlas-endpoint' is deprecated`)
	}
	if b.stringVal(b.Flags.DeprecatedDatacenter) != "" && b.stringVal(b.Flags.Config.Datacenter) == "" {
		b.warn(`'-dc' is deprecated. Use '-datacenter' instead`)
		b.Flags.Config.Datacenter = b.Flags.DeprecatedDatacenter
	}

	// ----------------------------------------------------------------
	// merge config fragments as follows
	//
	//   default, files in alphabetical order, flags
	//
	// Since the merge logic is to overwrite all fields with later
	// values except slices which are merged by appending later values
	// we need to merge all slice values defined in flags before we
	// merge the config files since the flag values for slices are
	// otherwise appended instead of prepended.

	flagSlices, flagValues := b.splitSlicesAndValues(b.Flags.Config)
	cfgs := []Config{*b.Default, flagSlices}
	cfgs = append(cfgs, b.Configs...)
	cfgs = append(cfgs, flagValues)
	c := Merge(cfgs)

	// ----------------------------------------------------------------
	// process/merge some complex values
	//

	var dnsRecursors []string
	if c.DNSRecursor != nil {
		dnsRecursors = append(dnsRecursors, b.stringVal(c.DNSRecursor))
	}
	dnsRecursors = append(dnsRecursors, c.DNSRecursors...)

	var dnsServiceTTL = map[string]time.Duration{}
	for k, v := range c.DNS.ServiceTTL {
		dnsServiceTTL[k] = b.durationVal(&v)
	}

	// we can ignore the error in ParseCiphers since ValidateConfig has checked this
	var tlsCipherSuites []uint16
	tlsCipherSuites, _ = tlsutil.ParseCiphers(b.stringVal(c.TLSCipherSuites))

	// ----------------------------------------------------------------
	// checks and services
	//

	var checks []*structs.CheckDefinition
	if c.Check != nil {
		checks = append(checks, b.checkVal(c.Check))
	}
	for _, check := range c.Checks {
		checks = append(checks, b.checkVal(&check))
	}

	var services []*structs.ServiceDefinition
	for _, service := range c.Services {
		services = append(services, b.serviceVal(&service))
	}
	if c.Service != nil {
		services = append(services, b.serviceVal(c.Service))
	}

	// ----------------------------------------------------------------
	// addresses
	//

	addrs := func(name string, addrs []string, overrideAddr *string, port int) []string {
		if port <= 0 {
			return nil
		}

		if b.stringVal(overrideAddr) != "" {
			addrs = b.ipTemplateVal(name, overrideAddr)
		}

		var a []string
		for _, addr := range addrs {
			switch {
			case b.isSocket(addr):
				a = append(a, addr)
			default:
				a = append(a, b.joinHostPort(addr, port))
			}
		}
		return a
	}

	var bindAddrs []string
	if c.BindAddr != nil {
		bindAddrs = b.ipTemplateVal("bind", c.BindAddr)
	}

	var clientAddrs []string
	if c.ClientAddr != nil {
		clientAddrs = b.ipTemplateVal("client", c.ClientAddr)
	}

	// todo(fs): take magic value for "disabled" into account, e.g. 0 or -1
	dnsPort := b.intVal(c.Ports.DNS)
	if dnsPort < 0 {
		dnsPort = 0
	}
	dnsAddrs := addrs("dns", clientAddrs, c.Addresses.DNS, dnsPort)

	httpPort := b.intVal(c.Ports.HTTP)
	if httpPort < 0 {
		httpPort = 0
	}
	httpAddrs := addrs("http", clientAddrs, c.Addresses.HTTP, httpPort)

	httpsPort := b.intVal(c.Ports.HTTPS)
	if httpsPort < 0 {
		httpsPort = 0
	}
	httpsAddrs := addrs("https", clientAddrs, c.Addresses.HTTPS, httpsPort)

	advertiseAddrLAN := b.singleIPTemplateVal("advertise lan", c.AdvertiseAddrLAN)
	advertiseAddrWAN := b.singleIPTemplateVal("advertise wan", c.AdvertiseAddrWAN)
	serfAdvertiseAddrLAN := b.singleIPTemplateVal("serf advertise lan", c.AdvertiseAddrs.SerfLAN)
	serfAdvertiseAddrWAN := b.singleIPTemplateVal("serf advertise wan", c.AdvertiseAddrs.SerfWAN)
	serfBindAddrLAN := b.singleIPTemplateVal("serf bind lan", c.SerfBindAddrLAN)
	serfBindAddrWAN := b.singleIPTemplateVal("serf bind wan", c.SerfBindAddrWAN)

	// ----------------------------------------------------------------
	// deprecated fields
	//

	httpResponseHeaders := c.HTTPConfig.ResponseHeaders
	if len(c.DeprecatedHTTPAPIResponseHeaders) > 0 {
		b.deprecate("http_api_response_headers", "http_config.response_headers", "")
		if httpResponseHeaders == nil {
			httpResponseHeaders = map[string]string{}
		}
		for k, v := range c.DeprecatedHTTPAPIResponseHeaders {
			httpResponseHeaders[k] = v
		}
	}

	dogstatsdAddr := b.stringVal(c.Telemetry.DogstatsdAddr)
	if c.DeprecatedDogstatsdAddr != nil {
		b.deprecate("dogstatsd_addr", "telemetry.dogstatsd_addr", "")
		dogstatsdAddr = b.stringVal(c.DeprecatedDogstatsdAddr)
	}

	dogstatsdTags := c.Telemetry.DogstatsdTags
	if len(c.DeprecatedDogstatsdTags) > 0 {
		b.deprecate("dogstatsd_tags", "telemetry.dogstatsd_tags", "")
		dogstatsdTags = append(c.DeprecatedDogstatsdTags, dogstatsdTags...)
	}

	statsdAddr := b.stringVal(c.Telemetry.StatsdAddr)
	if c.DeprecatedStatsdAddr != nil {
		b.deprecate("statsd_addr", "telemetry.statsd_addr", "")
		statsdAddr = b.stringVal(c.DeprecatedStatsdAddr)
	}

	statsiteAddr := b.stringVal(c.Telemetry.StatsiteAddr)
	if c.DeprecatedStatsiteAddr != nil {
		b.deprecate("statsite_addr", "telemetry.statsite_addr", "")
		statsiteAddr = b.stringVal(c.DeprecatedStatsiteAddr)
	}

	statsitePrefix := b.stringVal(c.Telemetry.StatsitePrefix)
	if c.DeprecatedStatsitePrefix != nil {
		b.deprecate("statsite_prefix", "telemetry.statsite_prefix", "")
		statsitePrefix = b.stringVal(c.DeprecatedStatsitePrefix)
	}

	// patch deprecated retry-join-{gce,azure,ec2)-* parameters
	// into -retry-join and issue warning.
	if !reflect.DeepEqual(c.DeprecatedRetryJoinEC2, RetryJoinEC2{}) {
		m := discover.Config{
			"provider":          "aws",
			"region":            b.stringVal(c.DeprecatedRetryJoinEC2.Region),
			"tag_key":           b.stringVal(c.DeprecatedRetryJoinEC2.TagKey),
			"tag_value":         b.stringVal(c.DeprecatedRetryJoinEC2.TagValue),
			"access_key_id":     b.stringVal(c.DeprecatedRetryJoinEC2.AccessKeyID),
			"secret_access_key": b.stringVal(c.DeprecatedRetryJoinEC2.SecretAccessKey),
		}
		c.RetryJoinLAN = append(c.RetryJoinLAN, m.String())
		c.DeprecatedRetryJoinEC2 = RetryJoinEC2{}

		// redact m before output
		if m["access_key_id"] != "" {
			m["access_key_id"] = "hidden"
		}
		if m["secret_access_key"] != "" {
			m["secret_access_key"] = "hidden"
		}

		b.warn("config: retry_join_ec2 is deprecated. Please add %q to retry_join.", m)
	}

	if !reflect.DeepEqual(c.DeprecatedRetryJoinAzure, RetryJoinAzure{}) {
		m := discover.Config{
			"provider":          "azure",
			"tag_name":          b.stringVal(c.DeprecatedRetryJoinAzure.TagName),
			"tag_value":         b.stringVal(c.DeprecatedRetryJoinAzure.TagValue),
			"subscription_id":   b.stringVal(c.DeprecatedRetryJoinAzure.SubscriptionID),
			"tenant_id":         b.stringVal(c.DeprecatedRetryJoinAzure.TenantID),
			"client_id":         b.stringVal(c.DeprecatedRetryJoinAzure.ClientID),
			"secret_access_key": b.stringVal(c.DeprecatedRetryJoinAzure.SecretAccessKey),
		}
		c.RetryJoinLAN = append(c.RetryJoinLAN, m.String())
		c.DeprecatedRetryJoinAzure = RetryJoinAzure{}

		// redact m before output
		if m["subscription_id"] != "" {
			m["subscription_id"] = "hidden"
		}
		if m["tenant_id"] != "" {
			m["tenant_id"] = "hidden"
		}
		if m["client_id"] != "" {
			m["client_id"] = "hidden"
		}
		if m["secret_access_key"] != "" {
			m["secret_access_key"] = "hidden"
		}

		b.warn("config: retry_join_azure is deprecated. Please add %q to retry_join.", m)
	}

	if !reflect.DeepEqual(c.DeprecatedRetryJoinGCE, RetryJoinGCE{}) {
		m := discover.Config{
			"provider":         "gce",
			"project_name":     b.stringVal(c.DeprecatedRetryJoinGCE.ProjectName),
			"zone_pattern":     b.stringVal(c.DeprecatedRetryJoinGCE.ZonePattern),
			"tag_value":        b.stringVal(c.DeprecatedRetryJoinGCE.TagValue),
			"credentials_file": b.stringVal(c.DeprecatedRetryJoinGCE.CredentialsFile),
		}
		c.RetryJoinLAN = append(c.RetryJoinLAN, m.String())
		c.DeprecatedRetryJoinGCE = RetryJoinGCE{}

		// redact m before output
		if m["credentials_file"] != "" {
			m["credentials_file"] = "hidden"
		}

		b.warn("config: retry_join_gce is deprecated. Please add %q to retry_join.", m)
	}

	// missing complex stuff
	if c.Watches != nil {
		panic("add me")
	}

	// ----------------------------------------------------------------
	// build runtime config
	//
	rt = RuntimeConfig{
		// ACL
		ACLAgentMasterToken:  b.stringVal(c.ACLAgentMasterToken),
		ACLAgentToken:        b.stringVal(c.ACLAgentToken),
		ACLDatacenter:        b.stringVal(c.ACLDatacenter),
		ACLDefaultPolicy:     b.stringVal(c.ACLDefaultPolicy),
		ACLDownPolicy:        b.stringVal(c.ACLDownPolicy),
		ACLEnforceVersion8:   b.boolVal(c.ACLEnforceVersion8),
		ACLMasterToken:       b.stringVal(c.ACLMasterToken),
		ACLReplicationToken:  b.stringVal(c.ACLReplicationToken),
		ACLTTL:               b.durationVal(c.ACLTTL),
		ACLToken:             b.stringVal(c.ACLToken),
		EnableACLReplication: b.boolVal(c.EnableACLReplication),

		// Autopilot
		AutopilotCleanupDeadServers:      b.boolVal(c.Autopilot.CleanupDeadServers),
		AutopilotDisableUpgradeMigration: b.boolVal(c.Autopilot.DisableUpgradeMigration),
		AutopilotLastContactThreshold:    b.durationVal(c.Autopilot.LastContactThreshold),
		AutopilotMaxTrailingLogs:         uint64(b.intVal(c.Autopilot.MaxTrailingLogs)),
		AutopilotRedundancyZoneTag:       b.stringVal(c.Autopilot.RedundancyZoneTag),
		AutopilotServerStabilizationTime: b.durationVal(c.Autopilot.ServerStabilizationTime),
		AutopilotUpgradeVersionTag:       b.stringVal(c.Autopilot.UpgradeVersionTag),

		// DNS
		DNSAddrs:              dnsAddrs,
		DNSAllowStale:         b.boolVal(c.DNS.AllowStale),
		DNSDisableCompression: b.boolVal(c.DNS.DisableCompression),
		DNSDomain:             b.stringVal(c.DNSDomain),
		DNSEnableTruncate:     b.boolVal(c.DNS.EnableTruncate),
		DNSMaxStale:           b.durationVal(c.DNS.MaxStale),
		DNSNodeTTL:            b.durationVal(c.DNS.NodeTTL),
		DNSOnlyPassing:        b.boolVal(c.DNS.OnlyPassing),
		DNSPort:               dnsPort,
		DNSRecursorTimeout:    b.durationVal(c.DNS.RecursorTimeout),
		DNSRecursors:          dnsRecursors,
		DNSServiceTTL:         dnsServiceTTL,
		DNSUDPAnswerLimit:     b.intVal(c.DNS.UDPAnswerLimit),

		// HTTP
		HTTPPort:            httpPort,
		HTTPSPort:           httpsPort,
		HTTPAddrs:           httpAddrs,
		HTTPSAddrs:          httpsAddrs,
		HTTPBlockEndpoints:  c.HTTPConfig.BlockEndpoints,
		HTTPResponseHeaders: httpResponseHeaders,

		// Performance
		PerformanceRaftMultiplier: b.intVal(c.Performance.RaftMultiplier),

		// Telemetry
		TelemetryCirconusAPIApp:                     b.stringVal(c.Telemetry.CirconusAPIApp),
		TelemetryCirconusAPIToken:                   b.stringVal(c.Telemetry.CirconusAPIToken),
		TelemetryCirconusAPIURL:                     b.stringVal(c.Telemetry.CirconusAPIURL),
		TelemetryCirconusBrokerID:                   b.stringVal(c.Telemetry.CirconusBrokerID),
		TelemetryCirconusBrokerSelectTag:            b.stringVal(c.Telemetry.CirconusBrokerSelectTag),
		TelemetryCirconusCheckDisplayName:           b.stringVal(c.Telemetry.CirconusCheckDisplayName),
		TelemetryCirconusCheckForceMetricActivation: b.stringVal(c.Telemetry.CirconusCheckForceMetricActivation),
		TelemetryCirconusCheckID:                    b.stringVal(c.Telemetry.CirconusCheckID),
		TelemetryCirconusCheckInstanceID:            b.stringVal(c.Telemetry.CirconusCheckInstanceID),
		TelemetryCirconusCheckSearchTag:             b.stringVal(c.Telemetry.CirconusCheckSearchTag),
		TelemetryCirconusCheckTags:                  b.stringVal(c.Telemetry.CirconusCheckTags),
		TelemetryCirconusSubmissionInterval:         b.stringVal(c.Telemetry.CirconusSubmissionInterval),
		TelemetryCirconusSubmissionURL:              b.stringVal(c.Telemetry.CirconusSubmissionURL),
		TelemetryDisableHostname:                    b.boolVal(c.Telemetry.DisableHostname),
		TelemetryDogstatsdAddr:                      dogstatsdAddr,
		TelemetryDogstatsdTags:                      dogstatsdTags,
		TelemetryFilterDefault:                      b.boolVal(c.Telemetry.FilterDefault),
		TelemetryPrefixFilter:                       c.Telemetry.PrefixFilter,
		TelemetryStatsdAddr:                         statsdAddr,
		TelemetryStatsiteAddr:                       statsiteAddr,
		TelemetryStatsitePrefix:                     statsitePrefix,

		// Agent
		AdvertiseAddrLAN:            advertiseAddrLAN,
		AdvertiseAddrWAN:            advertiseAddrWAN,
		BindAddrs:                   bindAddrs,
		Bootstrap:                   b.boolVal(c.Bootstrap),
		BootstrapExpect:             b.intVal(c.BootstrapExpect),
		CAFile:                      b.stringVal(c.CAFile),
		CAPath:                      b.stringVal(c.CAPath),
		CertFile:                    b.stringVal(c.CertFile),
		CheckUpdateInterval:         b.durationVal(c.CheckUpdateInterval),
		Checks:                      checks,
		ClientAddrs:                 clientAddrs,
		DataDir:                     b.stringVal(c.DataDir),
		Datacenter:                  b.stringVal(c.Datacenter),
		DevMode:                     b.boolVal(b.Flags.DevMode),
		DisableAnonymousSignature:   b.boolVal(c.DisableAnonymousSignature),
		DisableCoordinates:          b.boolVal(c.DisableCoordinates),
		DisableHostNodeID:           b.boolVal(c.DisableHostNodeID),
		DisableKeyringFile:          b.boolVal(c.DisableKeyringFile),
		DisableRemoteExec:           b.boolVal(c.DisableRemoteExec),
		DisableUpdateCheck:          b.boolVal(c.DisableUpdateCheck),
		EnableDebug:                 b.boolVal(c.EnableDebug),
		EnableScriptChecks:          b.boolVal(c.EnableScriptChecks),
		EnableSyslog:                b.boolVal(c.EnableSyslog),
		EnableUI:                    b.boolVal(c.EnableUI),
		EncryptKey:                  b.stringVal(c.EncryptKey),
		EncryptVerifyIncoming:       b.boolVal(c.EncryptVerifyIncoming),
		EncryptVerifyOutgoing:       b.boolVal(c.EncryptVerifyOutgoing),
		KeyFile:                     b.stringVal(c.KeyFile),
		LeaveOnTerm:                 b.boolVal(c.LeaveOnTerm),
		LogLevel:                    b.stringVal(c.LogLevel),
		NodeID:                      b.stringVal(c.NodeID),
		NodeMeta:                    c.NodeMeta,
		NodeName:                    b.stringVal(c.NodeName),
		NonVotingServer:             b.boolVal(c.NonVotingServer),
		PidFile:                     b.stringVal(c.PidFile),
		RPCProtocol:                 b.intVal(c.RPCProtocol),
		RaftProtocol:                b.intVal(c.RaftProtocol),
		ReconnectTimeoutLAN:         b.durationVal(c.ReconnectTimeoutLAN),
		ReconnectTimeoutWAN:         b.durationVal(c.ReconnectTimeoutWAN),
		RejoinAfterLeave:            b.boolVal(c.RejoinAfterLeave),
		RetryJoinIntervalLAN:        b.durationVal(c.RetryJoinIntervalLAN),
		RetryJoinIntervalWAN:        b.durationVal(c.RetryJoinIntervalWAN),
		RetryJoinLAN:                c.RetryJoinLAN,
		RetryJoinMaxAttemptsLAN:     b.intVal(c.RetryJoinMaxAttemptsLAN),
		RetryJoinMaxAttemptsWAN:     b.intVal(c.RetryJoinMaxAttemptsWAN),
		RetryJoinWAN:                c.RetryJoinWAN,
		SerfAdvertiseAddrLAN:        serfAdvertiseAddrLAN,
		SerfAdvertiseAddrWAN:        serfAdvertiseAddrWAN,
		SerfBindAddrLAN:             serfBindAddrLAN,
		SerfBindAddrWAN:             serfBindAddrWAN,
		ServerMode:                  b.boolVal(c.ServerMode),
		ServerName:                  b.stringVal(c.ServerName),
		Services:                    services,
		SessionTTLMin:               b.durationVal(c.SessionTTLMin),
		SkipLeaveOnInt:              b.boolVal(c.SkipLeaveOnInt),
		StartJoinAddrsLAN:           c.StartJoinAddrsLAN,
		StartJoinAddrsWAN:           c.StartJoinAddrsWAN,
		SyslogFacility:              b.stringVal(c.SyslogFacility),
		TLSCipherSuites:             tlsCipherSuites,
		TLSMinVersion:               b.stringVal(c.TLSMinVersion),
		TLSPreferServerCipherSuites: b.boolVal(c.TLSPreferServerCipherSuites),
		TaggedAddresses:             c.TaggedAddresses,
		TranslateWANAddrs:           b.boolVal(c.TranslateWANAddrs),
		UIDir:                       b.stringVal(c.UIDir),
		UnixSocketGroup:             b.stringVal(c.UnixSocket.Group),
		UnixSocketMode:              b.stringVal(c.UnixSocket.Mode),
		UnixSocketUser:              b.stringVal(c.UnixSocket.User),
		VerifyIncoming:              b.boolVal(c.VerifyIncoming),
		VerifyIncomingHTTPS:         b.boolVal(c.VerifyIncomingHTTPS),
		VerifyIncomingRPC:           b.boolVal(c.VerifyIncomingRPC),
		VerifyOutgoing:              b.boolVal(c.VerifyOutgoing),
		VerifyServerHostname:        b.boolVal(c.VerifyServerHostname),
	}

	return rt, b.err
}

// splitSlicesAndValues moves all slice values defined in c to 'slices'
// and all other values to 'values'.
func (b *Builder) splitSlicesAndValues(c Config) (slices, values Config) {
	v, t := reflect.ValueOf(c), reflect.TypeOf(c)
	rs, rv := reflect.New(t), reflect.New(t)

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Type.Kind() == reflect.Slice {
			rs.Elem().Field(i).Set(v.Field(i))
		} else {
			rv.Elem().Field(i).Set(v.Field(i))
		}
	}
	return rs.Elem().Interface().(Config), rv.Elem().Interface().(Config)
}

func (b *Builder) deprecate(oldname, newname, where string) {
	if where != "" {
		where = " " + where
	}
	b.warn("config: %q is deprecated%s. Please use %q instead.", oldname, where, newname)
}

func (b *Builder) warn(msg string, args ...interface{}) {
	b.Warnings = append(b.Warnings, fmt.Sprintf(msg, args...))
}

func (b *Builder) checkVal(v *CheckDefinition) *structs.CheckDefinition {
	if b.err != nil || v == nil {
		return nil
	}

	id := types.CheckID(b.stringVal(v.ID))
	if v.CheckID != nil {
		id = types.CheckID(b.stringVal(v.CheckID))
	}

	serviceID := v.ServiceID
	if v.AliasServiceID != nil {
		b.deprecate("serviceid", "service_id", "in check definitions")
		serviceID = v.AliasServiceID
	}

	dockerContainerID := v.DockerContainerID
	if v.AliasDockerContainerID != nil {
		b.deprecate("dockercontainerid", "docker_container_id", "in check definitions")
		dockerContainerID = v.AliasDockerContainerID
	}

	tlsSkipVerify := v.TLSSkipVerify
	if v.AliasTLSSkipVerify != nil {
		b.deprecate("tlsskipverify", "tls_skip_verify", "in check definitions")
		tlsSkipVerify = v.AliasTLSSkipVerify
	}

	deregisterCriticalServiceAfter := v.DeregisterCriticalServiceAfter
	if v.AliasDeregisterCriticalServiceAfter != nil {
		b.deprecate("deregistercriticalserviceafter", "deregister_critical_service_after", "in check definitions")
		deregisterCriticalServiceAfter = v.AliasDeregisterCriticalServiceAfter
	}

	return &structs.CheckDefinition{
		ID:                id,
		Name:              b.stringVal(v.Name),
		Notes:             b.stringVal(v.Notes),
		ServiceID:         b.stringVal(serviceID),
		Token:             b.stringVal(v.Token),
		Status:            b.stringVal(v.Status),
		Script:            b.stringVal(v.Script),
		HTTP:              b.stringVal(v.HTTP),
		Header:            v.Header,
		Method:            b.stringVal(v.Method),
		TCP:               b.stringVal(v.TCP),
		Interval:          b.durationVal(v.Interval),
		DockerContainerID: b.stringVal(dockerContainerID),
		Shell:             b.stringVal(v.Shell),
		TLSSkipVerify:     b.boolVal(tlsSkipVerify),
		Timeout:           b.durationVal(v.Timeout),
		TTL:               b.durationVal(v.TTL),
		DeregisterCriticalServiceAfter: b.durationVal(deregisterCriticalServiceAfter),
	}
}

func (b *Builder) serviceVal(v *ServiceDefinition) *structs.ServiceDefinition {
	if b.err != nil || v == nil {
		return nil
	}

	var check structs.CheckType
	if v.Check != nil {
		check = *b.checkVal(v.Check).CheckType()
	}

	var checks structs.CheckTypes
	for _, check := range v.Checks {
		checks = append(checks, b.checkVal(&check).CheckType())
	}

	return &structs.ServiceDefinition{
		ID:                b.stringVal(v.ID),
		Name:              b.stringVal(v.Name),
		Tags:              v.Tags,
		Address:           b.stringVal(v.Address),
		Port:              b.intVal(v.Port),
		Token:             b.stringVal(v.Token),
		EnableTagOverride: b.boolVal(v.EnableTagOverride),
		Check:             check,
		Checks:            checks,
	}
}

func (b *Builder) boolVal(v *bool) bool {
	if b.err != nil || v == nil {
		return false
	}
	return *v
}

func (b *Builder) durationVal(v *string) (d time.Duration) {
	if b.err != nil || v == nil {
		return 0
	}
	d, b.err = time.ParseDuration(*v)
	return
}

func (b *Builder) intVal(v *int) int {
	if b.err != nil || v == nil {
		return 0
	}
	return *v
}

func (b *Builder) uint64Val(v *uint64) uint64 {
	if b.err != nil || v == nil {
		return 0
	}
	return *v
}

func (b *Builder) stringVal(v *string) string {
	if b.err != nil || v == nil {
		return ""
	}
	return *v
}

func (b *Builder) singleIPTemplateVal(name string, v *string) string {
	s := b.ipTemplateVal(name, v)
	if b.err != nil || len(s) == 0 {
		return ""
	}
	if len(s) != 1 {
		b.err = fmt.Errorf("%s: multiple addresses configured: %v", name, s)
		return ""
	}
	return s[0]
}

func (b *Builder) ipTemplateVal(name string, v *string) []string {
	if b.err != nil || v == nil {
		return nil
	}

	s := b.stringVal(v)
	if s == "" {
		return []string{"0.0.0.0"}
	}

	out, err := template.Parse(s)
	if err != nil {
		b.err = fmt.Errorf("%s: unable to parse address template %q: %v", name, s, err)
		return nil
	}
	return strings.Fields(out)
}

func (b *Builder) joinHostPort(host string, port int) string {
	if host == "0.0.0.0" {
		host = ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func (b *Builder) isSocket(s string) bool {
	return strings.HasPrefix(s, "unix://")
}
