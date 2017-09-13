package config

import (
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/consul/agent/consul"
	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/consul/ipaddr"
	"github.com/hashicorp/consul/tlsutil"
	"github.com/hashicorp/consul/types"
	discover "github.com/hashicorp/go-discover"
	"github.com/hashicorp/go-sockaddr/template"
	"golang.org/x/time/rate"
)

// todo(fs): port SetupTaggedAndAdvertiseAddrs
// todo(fs): port existing validation from command/agent.go
// todo(fs): support dev config
// todo(fs): validate node_meta data
// todo(fs): add new limit and segments
// todo(fs): add tests for errors
// todo(fs): check ip addrs are valid
// todo(fs): check sockets not allowed for advertise and serf bind addrs
// todo(fs): port VerifyUniqueListeners

// Builder constructs a valid runtime configuration from multiple
// configuration fragments.
//
// To build the runtime configuration first call Build() which merges
// the fragments in a pre-defined order, converts the data types and
// structures into their final form and performs the syntactic
// validation.
//
// The fragments are merged in the following order:
//
//  * default configuration
//  * config files in alphabetical order
//  * command line arguments
//
// The config fragments are merged sequentially and later values
// overwrite previously set values. Slice values are merged by
// concatenating the two slices.
//
// Then call Validate() to perform the semantic validation to ensure
// that the configuration is ready to be used.
//
// Splitting the construction into two phases greatly simplifies testing
// since not all pre-conditions have to be satisfied when performing
// syntactical tests.
type Builder struct {
	// Flags contains the parsed command line arguments.
	Flags Flags

	// Default contains the default configuration. When set to nil , the
	// default configuration depends on the value of the Flags.DevMode
	// flag.
	Default *Config

	// DefaultRuntime contains the default configuration of the non-user
	// configurable values.
	DefaultRuntime RuntimeConfig

	// Revision contains the git commit hash.
	Revision string

	// Version contains the version number.
	Version string

	// VersionPrerelease contains the version suffix.
	VersionPrerelease string

	// Configs contains the user configuration fragments in the order to
	// be merged.
	Configs []Config

	// Warnings contains the warnigns encountered when
	// parsing the configuration.
	Warnings []string

	// Hostname returns the hostname of the machine. If nil, os.Hostname
	// is called.
	Hostname func() (string, error)

	// PrivateIPv4 will return the private IPv4 address found.
	// If there are multiple private IPv4 addresses an error is returned.
	PrivateIPv4 func() (*net.IPAddr, error)

	// PublicIPv6 will return the public IPv6 address found.
	// If there are multiple public IPv6 addresses an error is returned.
	PublicIPv6 func() (*net.IPAddr, error)

	// err contains the first error that occurred during
	// building the runtime configuration.
	err error
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

// readFile parses a JSON or HCL config file and appends it to the list of
// config fragments.
func (b *Builder) readFile(name string) error {
	c, err := ParseFile(name)
	if err != nil {
		return fmt.Errorf("config: Error parsing %s: %s", name, err)
	}
	b.Configs = append(b.Configs, c)
	return nil
}

type byName []os.FileInfo

func (a byName) Len() int           { return len(a) }
func (a byName) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byName) Less(i, j int) bool { return a[i].Name() < a[j].Name() }

func (b *Builder) BuildAndValidate() (RuntimeConfig, error) {
	rt, err := b.Build()
	if err != nil {
		return RuntimeConfig{}, err
	}
	if err := b.Validate(rt); err != nil {
		return RuntimeConfig{}, err
	}
	return rt, nil
}

// Build constructs the runtime configuration from the config fragments
// and the command line flags. The config fragments are processed in the
// order they were added with the flags being processed last to give
// precedence over the other fragments. If the error is nil then
// warnings can still contain deprecation or format warnigns that should
// be presented to the user.
func (b *Builder) Build() (rt RuntimeConfig, err error) {
	b.err = nil
	b.Warnings = nil

	// ----------------------------------------------------------------
	// deprecated flags
	//
	// needs to come before merging because of -dc flag
	//

	if b.Flags.DeprecatedAtlasInfrastructure != nil {
		b.warn(`==> DEPRECATION: "-atlas" is deprecated. Please remove it from your configuration`)
	}
	if b.Flags.DeprecatedAtlasToken != nil {
		b.warn(`==> DEPRECATION: "-atlas-token" is deprecated. Please remove it from your configuration`)
	}
	if b.Flags.DeprecatedAtlasJoin != nil {
		b.warn(`==> DEPRECATION: "-atlas-join" is deprecated. Please remove it from your configuration`)
	}
	if b.Flags.DeprecatedAtlasEndpoint != nil {
		b.warn(`==> DEPRECATION: "-atlas-endpoint" is deprecated. Please remove it from your configuration`)
	}
	if b.stringVal(b.Flags.DeprecatedDatacenter) != "" && b.stringVal(b.Flags.Config.Datacenter) == "" {
		b.warn(`==> DEPRECATION: "-dc" is deprecated. Use "-datacenter" instead`)
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

	var cfgs []Config
	if b.Default != nil {
		cfgs = append(cfgs, *b.Default)
	}

	flagSlices, flagValues := b.splitSlicesAndValues(b.Flags.Config)
	cfgs = append(cfgs, flagSlices)
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

	leaveOnTerm := !b.boolVal(c.ServerMode)
	if c.LeaveOnTerm != nil {
		leaveOnTerm = b.boolVal(c.LeaveOnTerm)
	}

	skipLeaveOnInt := b.boolVal(c.ServerMode)
	if c.SkipLeaveOnInt != nil {
		skipLeaveOnInt = b.boolVal(c.SkipLeaveOnInt)
	}

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

	dnsPort := b.portVal(c.Ports.DNS)
	httpPort := b.portVal(c.Ports.HTTP)
	httpsPort := b.portVal(c.Ports.HTTPS)
	serverPort := b.portVal(c.Ports.Server)
	serfPortLAN := b.portVal(c.Ports.SerfLAN)
	serfPortWAN := b.portVal(c.Ports.SerfWAN)

	// we need to treat the bindAddr special since
	// we need to know whether the expanded value is
	// 0.0.0.0 or [::] since in these cases the
	// advertise addresses are chosen differently.
	privateIPv4 := b.PrivateIPv4
	if privateIPv4 == nil {
		privateIPv4 = func() (*net.IPAddr, error) {
			ip, err := consul.GetPrivateIP()
			if err != nil {
				return nil, err
			}
			return &net.IPAddr{IP: ip}, nil
		}
	}

	publicIPv6 := b.PublicIPv6
	if publicIPv6 == nil {
		publicIPv6 = func() (*net.IPAddr, error) {
			ip, err := consul.GetPublicIPv6()
			if err != nil {
				return nil, err
			}
			return &net.IPAddr{IP: ip}, nil
		}
	}

	// first derive the advertise address from the configured
	// or expanded bind address
	var bindAddr *net.IPAddr
	var derivedAdvertiseAddr string
	switch {
	case ipaddr.IsAnyV4(b.stringVal(c.BindAddr)):
		bindAddr = b.expandFirstIP("bind_addr", c.BindAddr)
		derivedAdvertiseAddr = "0.0.0.0"

	case ipaddr.IsAnyV6(b.stringVal(c.BindAddr)):
		bindAddr = b.expandFirstIP("bind_addr", c.BindAddr)
		derivedAdvertiseAddr = "[::]"

	default:
		bindAddr = b.expandFirstIP("bind_addr", c.BindAddr)
		if b.err != nil {
			return RuntimeConfig{}, b.err
		}
		switch {
		case ipaddr.IsAnyV4(bindAddr):
			derivedAdvertiseAddr = "0.0.0.0"
		case ipaddr.IsAnyV6(bindAddr):
			derivedAdvertiseAddr = "[::]"
		}
	}

	// determine the actual advertise address
	var advertiseAddr *net.IPAddr
	switch {
	case ipaddr.IsAnyV4(derivedAdvertiseAddr):
		advertiseAddr, err = privateIPv4()

	case ipaddr.IsAnyV6(derivedAdvertiseAddr):
		advertiseAddr, err = publicIPv6()

	default:
		advertiseAddr = bindAddr
	}
	if err != nil {
		// show "bind_addr" as the root cause of the error since we
		// cannot derive a proper advertise address from the configured
		// bind address. Hence, the bind address configuration is the
		// main issue.
		return RuntimeConfig{}, fmt.Errorf("bind_addr: %s", err)
	}

	serfBindAddrLAN := b.makeTCPAddr(b.expandFirstIP("serf_lan", c.SerfBindAddrLAN), advertiseAddr, serfPortLAN)
	serfBindAddrWAN := b.makeTCPAddr(b.expandFirstIP("serf_wan", c.SerfBindAddrWAN), advertiseAddr, serfPortWAN)
	// serverBindAddr := b.makeTCPAddr(bindAddr, nil, serverPort)
	advertiseAddrLAN := b.makeTCPAddr(b.expandFirstIP("advertise_addr", c.AdvertiseAddrLAN), advertiseAddr, serverPort)
	advertiseAddrWAN := b.makeTCPAddr(b.expandFirstIP("advertise_addr_wan", c.AdvertiseAddrWAN), advertiseAddrLAN, serverPort)
	serfAdvertiseAddrLAN := b.makeTCPAddr(b.expandFirstIP("advertise_addresses.serf_lan", c.AdvertiseAddrs.SerfLAN), advertiseAddr, serfPortLAN)
	serfAdvertiseAddrWAN := b.makeTCPAddr(b.expandFirstIP("advertise_addresses.serf_wan", c.AdvertiseAddrs.SerfWAN), advertiseAddr, serfPortWAN)
	serverAdvertiseAddr := b.makeTCPAddr(b.expandFirstIP("advertise_addresses.rpc", c.AdvertiseAddrs.RPC), advertiseAddr, serverPort)

	clientAddrs := b.expandIPs("client_addr", c.ClientAddr)
	dnsAddrs := b.makeAddrs(b.expandAddrs("addresses.dns", c.Addresses.DNS), clientAddrs, dnsPort)
	httpAddrs := b.makeAddrs(b.expandAddrs("addresses.http", c.Addresses.HTTP), clientAddrs, httpPort)
	httpsAddrs := b.makeAddrs(b.expandAddrs("addresses.https", c.Addresses.HTTPS), clientAddrs, httpsPort)

	// segments
	var segments []structs.NetworkSegment
	for _, s := range c.Segments {
		segments = append(segments, structs.NetworkSegment{
			Name:        b.stringVal(s.Name),
			Bind:        b.stringVal(s.Bind),
			Port:        b.intVal(s.Port),
			RPCListener: b.boolVal(s.RPCListener),
			Advertise:   b.stringVal(s.Advertise),
		})
	}

	// ----------------------------------------------------------------
	// deprecated fields
	//

	if c.Addresses.DeprecatedRPC != nil {
		b.warn(`==> DEPRECATION: "addresses.rpc" is deprecated and is no longer used. Please remove it from your configuration.`)
	}
	if c.Ports.DeprecatedRPC != nil {
		b.warn(`==> DEPRECATION: "ports.rpc" is deprecated and is no longer used. Please remove it from your configuration.`)
	}
	if c.DeprecatedAtlasInfrastructure != nil {
		b.warn(`==> DEPRECATION: "atlas_infrastructure" is deprecated and is no longer used. Please remove it from your configuration.`)
	}
	if c.DeprecatedAtlasToken != nil {
		b.warn(`==> DEPRECATION: "atlas_token" is deprecated and is no longer used. Please remove it from your configuration.`)
	}
	if c.DeprecatedAtlasACLToken != nil {
		b.warn(`==> DEPRECATION: "atlas_acl_token" is deprecated and is no longer used. Please remove it from your configuration.`)
	}
	if c.DeprecatedAtlasJoin != nil {
		b.warn(`==> DEPRECATION: "atlas_join" is deprecated and is no longer used. Please remove it from your configuration.`)
	}
	if c.DeprecatedAtlasEndpoint != nil {
		b.warn(`==> DEPRECATION: "atlas_endpoint" is deprecated and is no longer used. Please remove it from your configuration.`)
	}

	httpResponseHeaders := c.HTTPConfig.ResponseHeaders
	if len(c.DeprecatedHTTPAPIResponseHeaders) > 0 {
		b.warn(`==> DEPRECATION: "http_api_response_headers" is deprecated. Please use "http_config.response_headers" instead.`)
		if httpResponseHeaders == nil {
			httpResponseHeaders = map[string]string{}
		}
		for k, v := range c.DeprecatedHTTPAPIResponseHeaders {
			httpResponseHeaders[k] = v
		}
	}

	dogstatsdAddr := b.stringVal(c.Telemetry.DogstatsdAddr)
	if c.DeprecatedDogstatsdAddr != nil {
		b.warn(`==> DEPRECATION: "dogstatsd_addr" is deprecated. Please use "telemetry.dogstatsd_addr" instead.`)
		dogstatsdAddr = b.stringVal(c.DeprecatedDogstatsdAddr)
	}

	dogstatsdTags := c.Telemetry.DogstatsdTags
	if len(c.DeprecatedDogstatsdTags) > 0 {
		b.warn(`==> DEPRECATION: "dogstatsd_tags" is deprecated. Please use "telemetry.dogstatsd_tags" instead.`)
		dogstatsdTags = append(c.DeprecatedDogstatsdTags, dogstatsdTags...)
	}

	statsdAddr := b.stringVal(c.Telemetry.StatsdAddr)
	if c.DeprecatedStatsdAddr != nil {
		b.warn(`==> DEPRECATION: "statsd_addr" is deprecated. Please use "telemetry.statsd_addr" instead.`)
		statsdAddr = b.stringVal(c.DeprecatedStatsdAddr)
	}

	statsiteAddr := b.stringVal(c.Telemetry.StatsiteAddr)
	if c.DeprecatedStatsiteAddr != nil {
		b.warn(`==> DEPRECATION: "statsite_addr" is deprecated. Please use "telemetry.statsite_addr" instead.`)
		statsiteAddr = b.stringVal(c.DeprecatedStatsiteAddr)
	}

	statsitePrefix := b.stringVal(c.Telemetry.StatsitePrefix)
	if c.DeprecatedStatsitePrefix != nil {
		b.warn(`==> DEPRECATION: "statsite_prefix" is deprecated. Please use "telemetry.statsite_prefix" instead.`)
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

		b.warn(`==> DEPRECATION: "retry_join_ec2" is deprecated. Please add %q to "retry_join".`, m)
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

		b.warn(`==> DEPRECATION: "retry_join_azure" is deprecated. Please add %q to "retry_join".`, m)
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

		b.warn(`==> DEPRECATION: "retry_join_gce" is deprecated. Please add %q to "retry_join".`, m)
	}

	// Compile all the watches
	// var watchPlans []*watch.Plan
	// for _, params := range c.Watches {
	// 	// Parse the watches, excluding the handler
	// 	wp, err := watch.ParseExempt(params, []string{"handler"})
	// 	if err != nil {
	// 		b.err = fmt.Errorf("Failed to parse watch (%#v): %v", params, err)
	// 		panic(b.err)
	// 	}

	// 	// Get the handler
	// 	h := wp.Exempt["handler"]
	// 	if _, ok := h.(string); h == nil || !ok {
	// 		b.err = fmt.Errorf("Watch handler must be a string")
	// 		panic(b.err)
	// 	}

	// 	// Store the watch plan
	// 	watchPlans = append(watchPlans, wp)
	// }

	// ----------------------------------------------------------------
	// build runtime config
	//
	rt = RuntimeConfig{
		// non-user configurable values
		ACLDisabledTTL:             b.DefaultRuntime.ACLDisabledTTL,
		AEInterval:                 b.DefaultRuntime.AEInterval,
		CheckDeregisterIntervalMin: b.DefaultRuntime.CheckDeregisterIntervalMin,
		CheckReapInterval:          b.DefaultRuntime.CheckReapInterval,
		SyncCoordinateIntervalMin:  b.DefaultRuntime.SyncCoordinateIntervalMin,
		SyncCoordinateRateTarget:   b.DefaultRuntime.SyncCoordinateRateTarget,

		Revision:          b.Revision,
		Version:           b.Version,
		VersionPrerelease: b.VersionPrerelease,

		// ACL
		ACLAgentMasterToken:  b.stringVal(c.ACLAgentMasterToken),
		ACLAgentToken:        b.stringVal(c.ACLAgentToken),
		ACLDatacenter:        strings.ToLower(b.stringVal(c.ACLDatacenter)),
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
		AutopilotMaxTrailingLogs:         b.int64Val(c.Autopilot.MaxTrailingLogs),
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
		BindAddr:                    bindAddr,
		Bootstrap:                   b.boolVal(c.Bootstrap),
		BootstrapExpect:             b.intVal(c.BootstrapExpect),
		CAFile:                      b.stringVal(c.CAFile),
		CAPath:                      b.stringVal(c.CAPath),
		CertFile:                    b.stringVal(c.CertFile),
		CheckUpdateInterval:         b.durationVal(c.CheckUpdateInterval),
		Checks:                      checks,
		ClientAddrs:                 clientAddrs,
		DataDir:                     b.stringVal(c.DataDir),
		Datacenter:                  strings.ToLower(b.stringVal(c.Datacenter)),
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
		LeaveOnTerm:                 leaveOnTerm,
		LogLevel:                    b.stringVal(c.LogLevel),
		NodeID:                      b.stringVal(c.NodeID),
		NodeMeta:                    c.NodeMeta,
		NodeName:                    b.nodeName(c.NodeName),
		NonVotingServer:             b.boolVal(c.NonVotingServer),
		PidFile:                     b.stringVal(c.PidFile),
		RPCAdvertiseAddr:            serverAdvertiseAddr,
		RPCProtocol:                 b.intVal(c.RPCProtocol),
		RPCRateLimit:                rate.Limit(b.float64Val(c.Limits.RPCRate)),
		RPCMaxBurst:                 b.intVal(c.Limits.RPCMaxBurst),
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
		SegmentName:                 b.stringVal(c.SegmentName),
		Segments:                    segments,
		SerfAdvertiseAddrLAN:        serfAdvertiseAddrLAN,
		SerfAdvertiseAddrWAN:        serfAdvertiseAddrWAN,
		SerfBindAddrLAN:             serfBindAddrLAN,
		SerfBindAddrWAN:             serfBindAddrWAN,
		ServerMode:                  b.boolVal(c.ServerMode),
		ServerName:                  b.stringVal(c.ServerName),
		Services:                    services,
		SessionTTLMin:               b.durationVal(c.SessionTTLMin),
		SkipLeaveOnInt:              skipLeaveOnInt,
		StartJoinAddrsLAN:           c.StartJoinAddrsLAN,
		StartJoinAddrsWAN:           c.StartJoinAddrsWAN,
		SyslogFacility:              b.stringVal(c.SyslogFacility),
		TLSCipherSuites:             b.tlsCipherSuites(c.TLSCipherSuites),
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
		Watches:                     c.Watches,
	}

	if rt.BootstrapExpect == 1 {
		rt.Bootstrap = true
		rt.BootstrapExpect = 0
		b.warn(`BootstrapExpect is set to 1; this is the same as Bootstrap mode.`)
	}

	return rt, b.err
}

// Validate performs semantical validation of the runtime configuration.
func (b *Builder) Validate(rt RuntimeConfig) error {
	if rt.AutopilotMaxTrailingLogs < 0 {
		return fmt.Errorf("autopilot.max_trailing_logs < 0")
	}

	// validDatacenter is used to validate a datacenter
	var validDatacenter = regexp.MustCompile("^[a-z0-9_-]+$")

	if !validDatacenter.MatchString(rt.Datacenter) {
		return fmt.Errorf("Datacenter must be alpha-numeric with underscores and hyphens only")
	}

	if rt.ACLDatacenter != "" && !validDatacenter.MatchString(rt.ACLDatacenter) {
		return fmt.Errorf("ACL datacenter must be alpha-numeric with underscores and hyphens only")
	}

	if rt.Bootstrap && !rt.ServerMode {
		return fmt.Errorf("Bootstrap mode requires Server mode")
	}

	if rt.BootstrapExpect < 0 {
		return fmt.Errorf("BootstrapExpect cannot be negative")
	}

	if rt.BootstrapExpect > 0 && !rt.ServerMode {
		return fmt.Errorf("BootstrapExpect mode requires Server mode")
	}

	if rt.BootstrapExpect > 0 && rt.DevMode {
		return fmt.Errorf("BootstrapExpect mode cannot be enabled in dev mode")
	}

	if rt.BootstrapExpect > 0 && rt.Bootstrap {
		return fmt.Errorf("BootstrapExpect mode and Bootstrap mode are mutually exclusive")
	}

	if rt.BootstrapExpect > 1 {
		b.warn("BootstrapExpect mode enabled, expecting %d servers", rt.BootstrapExpect)
	}
	if rt.BootstrapExpect == 2 {
		b.warn(`A cluster with 2 servers will provide no failure tolerance.  See https://www.consul.io/docs/internals/consensus.html#deployment-table`)
	}

	if rt.BootstrapExpect > 2 && rt.BootstrapExpect%2 == 0 {
		b.warn(`A cluster with an even number of servers does not achieve optimum fault tolerance.  See https://www.consul.io/docs/internals/consensus.html#deployment-table`)
	}

	if rt.Bootstrap {
		b.warn(`Bootstrap mode enabled! Do not enable unless necessary`)
	}

	if rt.EnableUI && rt.UIDir != "" {
		return fmt.Errorf(
			"Both the ui and ui-dir flags were specified, please provide only one.\n" +
				"If trying to use your own web UI resources, use the ui-dir flag.\n" +
				"If using Consul version 0.7.0 or later, the web UI is included in the binary so use ui to enable it")
	}

	if ipaddr.IsAny(rt.AdvertiseAddrLAN) {
		return fmt.Errorf("Advertise address cannot be 0.0.0.0, :: or [::]")
	}

	if ipaddr.IsAny(rt.AdvertiseAddrWAN) {
		return fmt.Errorf("Advertise WAN address cannot be 0.0.0.0, :: or [::]")
	}

	if ipaddr.IsAny(rt.RPCAdvertiseAddr) {
		return fmt.Errorf("RPC Advertise address cannot be 0.0.0.0, :: or [::]")
	}

	if ipaddr.IsAny(rt.SerfAdvertiseAddrLAN) {
		return fmt.Errorf("Serf Advertise LAN address cannot be 0.0.0.0, :: or [::]")
	}

	if ipaddr.IsAny(rt.SerfAdvertiseAddrWAN) {
		return fmt.Errorf("Serf Advertise WAN address cannot be 0.0.0.0, :: or [::]")
	}

	if rt.DNSUDPAnswerLimit <= 0 {
		return fmt.Errorf("dns_config.udp_answer_limit must be > 0")
	}

	if rt.NodeName == "" {
		return fmt.Errorf("Node name cannot be empty")
	}

	if err := structs.ValidateMetadata(rt.NodeMeta, false); err != nil {
		return fmt.Errorf("Failed to parse node metadata: %v", err)
	}

	// make sure listener addresses are unique
	// todo(fs): check serf and rpc advertise/bind addresses for uniqueness as well
	usage := map[string]string{}
	uniqueAddr := func(name string, addr net.Addr) error {
		key := addr.String()
		if other, inuse := usage[key]; inuse {
			return fmt.Errorf("%s address %s already configured for %s", name, key, other)
		}
		usage[key] = name
		return nil
	}
	uniqueAddrs := func(name string, addrs []net.Addr) error {
		for _, a := range addrs {
			if err := uniqueAddr(name, a); err != nil {
				return err
			}
		}
		return nil
	}

	if err := uniqueAddrs("DNS", rt.DNSAddrs); err != nil {
		return err
	}
	if err := uniqueAddrs("HTTP", rt.HTTPAddrs); err != nil {
		return err
	}
	if err := uniqueAddrs("HTTPS", rt.HTTPSAddrs); err != nil {
		return err
	}
	if err := uniqueAddr("RPC Advertise", rt.RPCAdvertiseAddr); err != nil {
		return err
	}
	if err := uniqueAddr("Serf Advertise LAN", rt.SerfAdvertiseAddrLAN); err != nil {
		return err
	}
	if err := uniqueAddr("Serf Advertise WAN", rt.SerfAdvertiseAddrWAN); err != nil {
		return err
	}

	if rt.ServerMode && rt.SegmentName != "" {
		return fmt.Errorf("Segment option can only be set on clients")
	}

	if !rt.ServerMode && len(rt.Segments) > 0 {
		return fmt.Errorf("Segments can only be configured on servers")
	}

	return nil
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
		b.warn(`==> DEPRECATION: "serviceid" is deprecated in check definitions. Please use "service_id" instead.`)
		serviceID = v.AliasServiceID
	}

	dockerContainerID := v.DockerContainerID
	if v.AliasDockerContainerID != nil {
		b.warn(`==> DEPRECATION: "dockercontainerid" is deprecated in check definitions. Please use "docker_container_id" instead.`)
		dockerContainerID = v.AliasDockerContainerID
	}

	tlsSkipVerify := v.TLSSkipVerify
	if v.AliasTLSSkipVerify != nil {
		b.warn(`==> DEPRECATION: "tlsskipverify" is deprecated in check definitions. Please use "tls_skip_verify" instead.`)
		tlsSkipVerify = v.AliasTLSSkipVerify
	}

	deregisterCriticalServiceAfter := v.DeregisterCriticalServiceAfter
	if v.AliasDeregisterCriticalServiceAfter != nil {
		b.warn(`==> DEPRECATION: "deregistercriticalserviceafter" is deprecated in check definitions. Please use "deregister_critical_service_after" instead.`)
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

	var checks structs.CheckTypes
	for _, check := range v.Checks {
		checks = append(checks, b.checkVal(&check).CheckType())
	}
	if v.Check != nil {
		checks = append(checks, b.checkVal(v.Check).CheckType())
	}

	return &structs.ServiceDefinition{
		ID:                b.stringVal(v.ID),
		Name:              b.stringVal(v.Name),
		Tags:              v.Tags,
		Address:           b.stringVal(v.Address),
		Port:              b.intVal(v.Port),
		Token:             b.stringVal(v.Token),
		EnableTagOverride: b.boolVal(v.EnableTagOverride),
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

func (b *Builder) portVal(v *int) int {
	if b.err != nil || v == nil || *v <= 0 || *v > 65535 {
		return -1
	}
	return *v
}

func (b *Builder) int64Val(v *int64) int64 {
	if b.err != nil || v == nil {
		return 0
	}
	return int64(*v)
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

func (b *Builder) float64Val(v *float64) float64 {
	if b.err != nil || v == nil {
		return 0
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

func (b *Builder) tlsCipherSuites(v *string) []uint16 {
	if b.err != nil || v == nil {
		return nil
	}

	var a []uint16
	a, err := tlsutil.ParseCiphers(*v)
	if err != nil {
		b.err = fmt.Errorf("invalid tls cipher suites: %s", err)
	}
	return a
}

func (b *Builder) nodeName(v *string) string {
	if b.err != nil {
		return ""
	}

	nodeName := b.stringVal(v)
	if nodeName == "" {
		fn := b.Hostname
		if fn == nil {
			fn = os.Hostname
		}
		name, err := fn()
		if err != nil {
			b.err = fmt.Errorf("Error determining node name: %s", err)
			return ""
		}
		nodeName = name
	}
	return strings.TrimSpace(nodeName)
}

// expandAddrs expands the go-sockaddr template in s and returns the
// result as a list of *net.IPAddr and *net.UnixAddr.
func (b *Builder) expandAddrs(name string, s *string) []net.Addr {
	if b.err != nil || s == nil {
		return nil
	}

	x, err := template.Parse(*s)
	if err != nil {
		b.err = fmt.Errorf("%s: error parsing %q: %s", name, s, err)
		return nil
	}

	var addrs []net.Addr
	for _, a := range strings.Fields(x) {
		switch {
		case strings.HasPrefix(a, "unix://"):
			addrs = append(addrs, &net.UnixAddr{Name: a[len("unix://"):], Net: "unix"})
		default:
			// net.ParseIP does not like '[::]'
			ip := net.ParseIP(a)
			if a == "[::]" {
				ip = net.ParseIP("::")
			}
			if ip == nil {
				b.err = fmt.Errorf("%s: invalid ip address: %s", name, a)
				return nil
			}
			addrs = append(addrs, &net.IPAddr{IP: ip})
		}
	}

	return addrs
}

// expandIPs expands the go-sockaddr template in s and returns a list of
// *net.IPAddr. If one of the expanded addresses is a unix socket
// address an error is set and nil is returned.
func (b *Builder) expandIPs(name string, s *string) []*net.IPAddr {
	if b.err != nil || s == nil {
		return nil
	}

	addrs := b.expandAddrs(name, s)
	var x []*net.IPAddr
	for _, addr := range addrs {
		switch a := addr.(type) {
		case *net.IPAddr:
			x = append(x, a)
		case *net.UnixAddr:
			b.err = fmt.Errorf("%s: cannot use a unix socket: %s", name, a)
			return nil
		default:
			b.err = fmt.Errorf("%s: invalid address type %T", a)
			return nil
		}
	}
	return x
}

// expandFirstAddr expands the go-sockaddr template in s and returns the
// first address which is either a *net.IPAddr or a *net.UnixAddr. If
// the template expands to multiple addresses and error is set and nil
// is returned.
func (b *Builder) expandFirstAddr(name string, s *string) net.Addr {
	if b.err != nil || s == nil {
		return nil
	}

	addrs := b.expandAddrs(name, s)
	if len(addrs) == 0 {
		return nil
	}
	if len(addrs) > 1 {
		var x []string
		for _, a := range addrs {
			x = append(x, a.String())
		}
		b.err = fmt.Errorf("%s: multiple addresses found: %s", name, strings.Join(x, " "))
		return nil
	}
	return addrs[0]
}

// expandFirstIP exapnds the go-sockaddr template in s and returns the
// first address if it is not a unix socket address. If the template
// expands to multiple addresses and error is set and nil is returned.
func (b *Builder) expandFirstIP(name string, s *string) *net.IPAddr {
	if b.err != nil || s == nil {
		return nil
	}

	addr := b.expandFirstAddr(name, s)
	if addr == nil {
		return nil
	}
	switch a := addr.(type) {
	case *net.IPAddr:
		return a
	case *net.UnixAddr:
		b.err = fmt.Errorf("%s: cannot use a unix socket: %s", name, addr)
		return nil
	default:
		b.err = fmt.Errorf("%s: invalid address type %T", a)
		return nil
	}
}

func (b *Builder) makeTCPAddr(pri *net.IPAddr, sec net.Addr, port int) *net.TCPAddr {
	if pri == nil && sec == nil || port <= 0 {
		return nil
	}
	addr := pri
	if addr == nil {
		switch a := sec.(type) {
		case *net.IPAddr:
			addr = a
		case *net.TCPAddr:
			addr = &net.IPAddr{IP: a.IP}
		default:
			panic(fmt.Sprintf("makeTCPAddr requires a net.IPAddr or a net.TCPAddr. Got %T", a))
		}
	}
	return &net.TCPAddr{IP: addr.IP, Port: port}
}

// makeAddr creates an *net.TCPAddr or a *net.UnixAddr from either the
// primary or secondary address and the given port. If the port is <= 0
// then the address is considered to be disabled and nil is returned.
func (b *Builder) makeAddr(pri, sec net.Addr, port int) net.Addr {
	if pri == nil && sec == nil || port <= 0 {
		return nil
	}
	addr := pri
	if addr == nil {
		addr = sec
	}
	switch a := addr.(type) {
	case *net.IPAddr:
		return &net.TCPAddr{IP: a.IP, Port: port}
	case *net.UnixAddr:
		return a
	default:
		panic(fmt.Sprintf("invalid address type %T", a))
	}
}

// makeAddrs creates a list of *net.TCPAddr or *net.UnixAddr entries
// from either the primary or secondary addresses and the given port.
// If the port is <= 0 then the address is considered to be disabled
// and nil is returned.
func (b *Builder) makeAddrs(pri []net.Addr, sec []*net.IPAddr, port int) []net.Addr {
	if len(pri) == 0 && len(sec) == 0 || port <= 0 {
		return nil
	}
	addrs := pri
	if len(addrs) == 0 {
		addrs = []net.Addr{}
		for _, a := range sec {
			addrs = append(addrs, a)
		}
	}
	var x []net.Addr
	for _, a := range addrs {
		x = append(x, b.makeAddr(a, nil, port))
	}
	return x
}

// isUnixAddr returns true when the given address is a unix socket address type.
func (b *Builder) isUnixAddr(a net.Addr) bool {
	_, ok := a.(*net.UnixAddr)
	return a != nil && ok
}
