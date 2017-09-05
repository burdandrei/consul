package config

// Config defines the format of a configuration file in either JSON or HCL
// format.
//
// It must contain only pointer values, slices and maps to support
// standardized merging of multiple Config structs into one.
//
// Since this is the format which users use to specify their configuration
// it should be treated as an external API which cannot be changed and
// refactored at will since this will break existing setups.
type Config struct {
	// todo(fs): where is this set/used?
	// todo(fs): these are values in the default config which are not configurable.
	// ACLDisabledTTL             *time.Duration       `json:"-" hcl:"-"`
	// AEInterval                 *time.Duration       `json:"-" hcl:"-"`
	// CheckDeregisterIntervalMin *time.Duration       `json:"-" hcl:"-"`
	// CheckReapInterval          *time.Duration       `json:"-" hcl:"-"`

	Addresses        Addresses            `json:"addresses" hcl:"addresses"`
	AdvertiseAddrLAN *string              `json:"advertise_addr" hcl:"advertise_addr"`
	AdvertiseAddrWAN *string              `json:"advertise_addr_wan" hcl:"advertise_addr_wan"`
	AdvertiseAddrs   AdvertiseAddrsConfig `json:"advertise_addrs" hcl:"advertise_addrs"`
	Ports            Ports                `json:"ports" hcl:"ports"`
	SerfBindAddrLAN  *string              `json:"serf_lan" hcl:"serf_lan"`
	SerfBindAddrWAN  *string              `json:"serf_wan" hcl:"serf_wan"`

	ACLAgentMasterToken         *string             `json:"acl_agent_master_token" hcl:"acl_agent_master_token"`
	ACLAgentToken               *string             `json:"acl_agent_token" hcl:"acl_agent_token"`
	ACLDatacenter               *string             `json:"acl_datacenter" hcl:"acl_datacenter"`
	ACLDefaultPolicy            *string             `json:"acl_default_policy" hcl:"acl_default_policy"`
	ACLDownPolicy               *string             `json:"acl_down_policy" hcl:"acl_down_policy"`
	ACLEnforceVersion8          *bool               `json:"acl_enforce_version_8" hcl:"acl_enforce_version_8"`
	ACLMasterToken              *string             `json:"acl_master_token" hcl:"acl_master_token"`
	ACLReplicationToken         *string             `json:"acl_replication_token" hcl:"acl_replication_token"`
	ACLTTL                      *string             `json:"acl_ttl" hcl:"acl_ttl"`
	ACLToken                    *string             `json:"acl_token" hcl:"acl_token"`
	Autopilot                   Autopilot           `json:"autopilot" hcl:"autopilot"`
	BindAddr                    *string             `json:"bind_addr" hcl:"bind_addr"`
	Bootstrap                   *bool               `json:"bootstrap" hcl:"bootstrap"`
	BootstrapExpect             *int                `json:"bootstrap_expect" hcl:"bootstrap_expect"`
	CAFile                      *string             `json:"ca_file" hcl:"ca_file"`
	CAPath                      *string             `json:"ca_path" hcl:"ca_path"`
	CertFile                    *string             `json:"cert_file" hcl:"cert_file"`
	CheckUpdateInterval         *string             `json:"check_update_interval" hcl:"check_update_interval"`
	Check                       *CheckDefinition    `json:"check" hcl:"check"` // needs to be a pointer to avoid partial merges
	Checks                      []CheckDefinition   `json:"checks" hcl:"checks"`
	ClientAddr                  *string             `json:"client_addr" hcl:"client_addr"`
	DNS                         DNS                 `json:"dns_config" hcl:"dns_config"`
	DNSDomain                   *string             `json:"domain" hcl:"domain"`
	DNSRecursor                 *string             `json:"recursor" hcl:"recursor"`
	DNSRecursors                []string            `json:"recursors" hcl:"recursors"`
	DataDir                     *string             `json:"data_dir" hcl:"data_dir"`
	Datacenter                  *string             `json:"datacenter" hcl:"datacenter"`
	DisableAnonymousSignature   *bool               `json:"disable_anonymous_signature" hcl:"disable_anonymous_signature"`
	DisableCoordinates          *bool               `json:"disable_coordinates" hcl:"disable_coordinates"`
	DisableHostNodeID           *bool               `json:"disable_host_node_id" hcl:"disable_host_node_id"`
	DisableKeyringFile          *bool               `json:"disable_keyring_file" hcl:"disable_keyring_file"`
	DisableRemoteExec           *bool               `json:"disable_remote_exec" hcl:"disable_remote_exec"`
	DisableUpdateCheck          *bool               `json:"disable_update_check" hcl:"disable_update_check"`
	EnableACLReplication        *bool               `json:"enable_acl_replication" hcl:"enable_acl_replication"`
	EnableDebug                 *bool               `json:"enable_debug" hcl:"enable_debug"`
	EnableScriptChecks          *bool               `json:"enable_script_checks" hcl:"enable_script_checks"`
	EnableSyslog                *bool               `json:"enable_syslog" hcl:"enable_syslog"`
	EnableUI                    *bool               `json:"enable_ui" hcl:"enable_ui"`
	EncryptKey                  *string             `json:"encrypt" hcl:"encrypt"`
	EncryptVerifyIncoming       *bool               `json:"encrypt_verify_incoming" hcl:"encrypt_verify_incoming"`
	EncryptVerifyOutgoing       *bool               `json:"encrypt_verify_outgoing" hcl:"encrypt_verify_outgoing"`
	HTTPConfig                  HTTPConfig          `json:"http_config" hcl:"http_config"`
	KeyFile                     *string             `json:"key_file" hcl:"key_file"`
	LeaveOnTerm                 *bool               `json:"leave_on_terminate" hcl:"leave_on_terminate"`
	LogLevel                    *string             `json:"log_level" hcl:"log_level"`
	NodeID                      *string             `json:"node_id" hcl:"node_id"`
	NodeMeta                    map[string]string   `json:"node_meta" hcl:"node_meta"`
	NodeName                    *string             `json:"node_name" hcl:"node_name"`
	NonVotingServer             *bool               `json:"non_voting_server" hcl:"non_voting_server"`
	Performance                 Performance         `json:"performance" hcl:"performance"`
	PidFile                     *string             `json:"pid_file" hcl:"pid_file"`
	RPCProtocol                 *int                `json:"protocol" hcl:"protocol"`
	RaftProtocol                *int                `json:"raft_protocol" hcl:"raft_protocol"`
	ReconnectTimeoutLAN         *string             `json:"reconnect_timeout" hcl:"reconnect_timeout"`
	ReconnectTimeoutWAN         *string             `json:"reconnect_timeout_wan" hcl:"reconnect_timeout_wan"`
	RejoinAfterLeave            *bool               `json:"rejoin_after_leave" hcl:"rejoin_after_leave"`
	RetryJoinIntervalLAN        *string             `json:"retry_interval" hcl:"retry_interval"`
	RetryJoinIntervalWAN        *string             `json:"retry_interval_wan" hcl:"retry_interval_wan"`
	RetryJoinLAN                []string            `json:"retry_join" hcl:"retry_join"`
	RetryJoinMaxAttemptsLAN     *int                `json:"retry_max" hcl:"retry_max"`
	RetryJoinMaxAttemptsWAN     *int                `json:"retry_max_wan" hcl:"retry_max_wan"`
	RetryJoinWAN                []string            `json:"retry_join_wan" hcl:"retry_join_wan"`
	ServerMode                  *bool               `json:"server" hcl:"server"`
	ServerName                  *string             `json:"server_name" hcl:"server_name"`
	Service                     *ServiceDefinition  `json:"service" hcl:"service"`
	Services                    []ServiceDefinition `json:"services" hcl:"services"`
	SessionTTLMin               *string             `json:"session_ttl_min" hcl:"session_ttl_min"`
	SkipLeaveOnInt              *bool               `json:"skip_leave_on_interrupt" hcl:"skip_leave_on_interrupt"`
	StartJoinAddrsLAN           []string            `json:"start_join" hcl:"start_join"`
	StartJoinAddrsWAN           []string            `json:"start_join_wan" hcl:"start_join_wan"`
	SyslogFacility              *string             `json:"syslog_facility" hcl:"syslog_facility"`
	TLSCipherSuites             *string             `json:"tls_cipher_suites" hcl:"tls_cipher_suites"`
	TLSMinVersion               *string             `json:"tls_min_version" hcl:"tls_min_version"`
	TLSPreferServerCipherSuites *bool               `json:"tls_prefer_server_cipher_suites" hcl:"tls_prefer_server_cipher_suites"`
	TaggedAddresses             map[string]string   `json:"tagged_addresses" hcl:"tagged_addresses"`
	Telemetry                   Telemetry           `json:"telemetry" hcl:"telemetry"`
	TranslateWANAddrs           *bool               `json:"translate_wan_addrs" hcl:"translate_wan_addrs"`
	UIDir                       *string             `json:"ui_dir" hcl:"ui_dir"`
	UnixSocket                  UnixSocket          `json:"unix_sockets" hcl:"unix_sockets"`
	VerifyIncoming              *bool               `json:"verify_incoming" hcl:"verify_incoming"`
	VerifyIncomingHTTPS         *bool               `json:"verify_incoming_https" hcl:"verify_incoming_https"`
	VerifyIncomingRPC           *bool               `json:"verify_incoming_rpc" hcl:"verify_incoming_rpc"`
	VerifyOutgoing              *bool               `json:"verify_outgoing" hcl:"verify_outgoing"`
	VerifyServerHostname        *bool               `json:"verify_server_hostname" hcl:"verify_server_hostname"`

	// tests are done until here
	Watches []map[string]interface{} `json:"watches" hcl:"watches"`

	DeprecatedDogstatsdAddr          *string           `json:"dogstatsd_addr" hcl:"dogstatsd_addr"`
	DeprecatedDogstatsdTags          []string          `json:"dogstatsd_tags" hcl:"dogstatsd_tags"`
	DeprecatedHTTPAPIResponseHeaders map[string]string `json:"http_api_response_headers" hcl:"http_api_response_headers"`
	DeprecatedRetryJoinAzure         RetryJoinAzure    `json:"retry_join_azure" hcl:"retry_join_azure"`
	DeprecatedRetryJoinEC2           RetryJoinEC2      `json:"retry_join_ec2" hcl:"retry_join_ec2"`
	DeprecatedRetryJoinGCE           RetryJoinGCE      `json:"retry_join_gce" hcl:"retry_join_gce"`
	DeprecatedStatsdAddr             *string           `json:"statsd_addr" hcl:"statsd_addr"`
	DeprecatedStatsiteAddr           *string           `json:"statsite_addr" hcl:"statsite_addr"`
	DeprecatedStatsitePrefix         *string           `json:"statsite_prefix" hcl:"statsite_prefix"`
}

type Addresses struct {
	DNS   *string `json:"dns" hcl:"dns"`
	HTTP  *string `json:"http" hcl:"http"`
	HTTPS *string `json:"https" hcl:"https"`
	RPC   *string `json:"rpc" hcl:"rpc"`
}

type AdvertiseAddrsConfig struct {
	RPC     *string `json:"rpc" hcl:"rpc"`
	SerfLAN *string `json:"serf_lan" hcl:"serf_lan"`
	SerfWAN *string `json:"serf_wan" hcl:"serf_wan"`
}

type Autopilot struct {
	CleanupDeadServers      *bool   `json:"cleanup_dead_servers" hcl:"cleanup_dead_servers"`
	DisableUpgradeMigration *bool   `json:"disable_upgrade_migration" hcl:"disable_upgrade_migration"`
	LastContactThreshold    *string `json:"last_contact_threshold" hcl:"last_contact_threshold"`
	// todo(fs): do we need uint64 here? If yes, then I need to write a special parser b/c of JSON limit of 2^53-1 for ints
	MaxTrailingLogs         *int    `json:"max_trailing_logs" hcl:"max_trailing_logs"`
	RedundancyZoneTag       *string `json:"redundancy_zone_tag" hcl:"redundancy_zone_tag"`
	ServerStabilizationTime *string `json:"server_stabilization_time" hcl:"server_stabilization_time"`
	UpgradeVersionTag       *string `json:"upgrade_version_tag" hcl:"upgrade_version_tag"`
}

type ServiceDefinition struct {
	ID                *string           `json:"id" hcl:"id"`
	Name              *string           `json:"name" hcl:"name"`
	Tags              []string          `json:"tags" hcl:"tags"`
	Address           *string           `json:"address" hcl:"address"`
	Port              *int              `json:"port" hcl:"port"`
	Check             *CheckDefinition  `json:"check" hcl:"check"`
	Checks            []CheckDefinition `json:"checks" hcl:"checks"`
	Token             *string           `json:"token" hcl:"token"`
	EnableTagOverride *bool             `json:"enable_tag_override" hcl:"enable_tag_override"`
}

type CheckDefinition struct {
	ID                             *string             `json:"id" hcl:"id"`
	CheckID                        *string             `json:"check_id" hcl:"check_id"`
	Name                           *string             `json:"name" hcl:"name"`
	Notes                          *string             `json:"notes" hcl:"notes"`
	ServiceID                      *string             `json:"service_id" hcl:"service_id"`
	Token                          *string             `json:"token" hcl:"token"`
	Status                         *string             `json:"status" hcl:"status"`
	Script                         *string             `json:"script" hcl:"script"`
	HTTP                           *string             `json:"http" hcl:"http"`
	Header                         map[string][]string `json:"header" hcl:"header"`
	Method                         *string             `json:"method" hcl:"method"`
	TCP                            *string             `json:"tcp" hcl:"tcp"`
	Interval                       *string             `json:"interval" hcl:"interval"`
	DockerContainerID              *string             `json:"docker_container_id" hcl:"docker_container_id"`
	Shell                          *string             `json:"shell" hcl:"shell"`
	TLSSkipVerify                  *bool               `json:"tls_skip_verify" hcl:"tls_skip_verify"`
	Timeout                        *string             `json:"timeout" hcl:"timeout"`
	TTL                            *string             `json:"ttl" hcl:"ttl"`
	DeregisterCriticalServiceAfter *string             `json:"deregister_critical_service_after" hcl:"deregister_critical_service_after"`

	// alias fields with different names
	AliasDeregisterCriticalServiceAfter *string `json:"deregistercriticalserviceafter" hcl:"deregistercriticalserviceafter"`
	AliasDockerContainerID              *string `json:"dockercontainerid" hcl:"dockercontainerid"`
	AliasServiceID                      *string `json:"serviceid" hcl:"serviceid"`
	AliasTLSSkipVerify                  *bool   `json:"tlsskipverify" hcl:"tlsskipverify"`
}

type DNS struct {
	AllowStale         *bool             `json:"allow_stale" hcl:"allow_stale"`
	DisableCompression *bool             `json:"disable_compression" hcl:"disable_compression"`
	EnableTruncate     *bool             `json:"enable_truncate" hcl:"enable_truncate"`
	MaxStale           *string           `json:"max_stale" hcl:"max_stale"`
	NodeTTL            *string           `json:"node_ttl" hcl:"node_ttl"`
	OnlyPassing        *bool             `json:"only_passing" hcl:"only_passing"`
	RecursorTimeout    *string           `json:"recursor_timeout" hcl:"recursor_timeout"`
	ServiceTTL         map[string]string `json:"service_ttl" hcl:"service_ttl"`
	UDPAnswerLimit     *int              `json:"udp_answer_limit" hcl:"udp_answer_limit"`
}

type HTTPConfig struct {
	BlockEndpoints  []string          `json:"block_endpoints" hcl:"block_endpoints"`
	ResponseHeaders map[string]string `json:"response_headers" hcl:"response_headers"`
}

type Performance struct {
	RaftMultiplier *int `json:"raft_multiplier" hcl:"raft_multiplier"` // todo(fs): validate as uint
}

type Telemetry struct {
	CirconusAPIApp                     *string  `json:"circonus_api_app" hcl:"circonus_api_app"`
	CirconusAPIToken                   *string  `json:"circonus_api_token" json:"-" hcl:"circonus_api_token" json:"-"`
	CirconusAPIURL                     *string  `json:"circonus_api_url" hcl:"circonus_api_url"`
	CirconusBrokerID                   *string  `json:"circonus_broker_id" hcl:"circonus_broker_id"`
	CirconusBrokerSelectTag            *string  `json:"circonus_broker_select_tag" hcl:"circonus_broker_select_tag"`
	CirconusCheckDisplayName           *string  `json:"circonus_check_display_name" hcl:"circonus_check_display_name"`
	CirconusCheckForceMetricActivation *string  `json:"circonus_check_force_metric_activation" hcl:"circonus_check_force_metric_activation"`
	CirconusCheckID                    *string  `json:"circonus_check_id" hcl:"circonus_check_id"`
	CirconusCheckInstanceID            *string  `json:"circonus_check_instance_id" hcl:"circonus_check_instance_id"`
	CirconusCheckSearchTag             *string  `json:"circonus_check_search_tag" hcl:"circonus_check_search_tag"`
	CirconusCheckTags                  *string  `json:"circonus_check_tags" hcl:"circonus_check_tags"`
	CirconusSubmissionInterval         *string  `json:"circonus_submission_interval" hcl:"circonus_submission_interval"`
	CirconusSubmissionURL              *string  `json:"circonus_submission_url" hcl:"circonus_submission_url"`
	DisableHostname                    *bool    `json:"disable_hostname" hcl:"disable_hostname"`
	DogstatsdAddr                      *string  `json:"dogstatsd_addr" hcl:"dogstatsd_addr"`
	DogstatsdTags                      []string `json:"dogstatsd_tags" hcl:"dogstatsd_tags"`
	FilterDefault                      *bool    `json:"filter_default" hcl:"filter_default"`
	PrefixFilter                       []string `json:"prefix_filter" hcl:"prefix_filter"`
	StatsdAddr                         *string  `json:"statsd_address" hcl:"statsd_address"`
	StatsiteAddr                       *string  `json:"statsite_address" hcl:"statsite_address"`
	StatsitePrefix                     *string  `json:"statsite_prefix" hcl:"statsite_prefix"`
}

type Ports struct {
	DNS     *int `json:"dns" hcl:"dns"`
	HTTP    *int `json:"http" hcl:"http"`
	HTTPS   *int `json:"https" hcl:"https"`
	SerfLAN *int `json:"serf_lan" hcl:"serf_lan"`
	SerfWAN *int `json:"serf_wan" hcl:"serf_wan"`
	Server  *int `json:"server" hcl:"server"`

	DeprecatedRPC *int `json:"rpc" hcl:"rpc"`
}

type RetryJoinAzure struct {
	TagName         *string `json:"tag_name" hcl:"tag_name"`
	TagValue        *string `json:"tag_value" hcl:"tag_value"`
	SubscriptionID  *string `json:"subscription_id" hcl:"subscription_id"`
	TenantID        *string `json:"tenant_id" hcl:"tenant_id"`
	ClientID        *string `json:"client_id" hcl:"client_id"`
	SecretAccessKey *string `json:"secret_access_key" hcl:"secret_access_key"`
}

type RetryJoinEC2 struct {
	Region          *string `json:"region" hcl:"region"`
	TagKey          *string `json:"tag_key" hcl:"tag_key"`
	TagValue        *string `json:"tag_value" hcl:"tag_value"`
	AccessKeyID     *string `json:"access_key_id" hcl:"access_key_id"`
	SecretAccessKey *string `json:"secret_access_key" hcl:"secret_access_key"`
}

type RetryJoinGCE struct {
	ProjectName     *string `json:"project_name" hcl:"project_name"`
	ZonePattern     *string `json:"zone_pattern" hcl:"zone_pattern"`
	TagValue        *string `json:"tag_value" hcl:"tag_value"`
	CredentialsFile *string `json:"credentials_file" hcl:"credentials_file"`
}

type UnixSocket struct {
	User  *string `json:"user" hcl:"user"`
	Group *string `json:"group" hcl:"group"`
	Mode  *string `json:"mode" hcl:"mode"`
}
