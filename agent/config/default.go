package config

import (
	"time"

	"github.com/hashicorp/consul/agent/consul"
)

func pBool(v bool) *bool                { return &v }
func pInt(v int) *int                   { return &v }
func pString(v string) *string          { return &v }
func pDuration(v time.Duration) *string { s := v.String(); return &s }

// defaultConfig is the default configuration file.
var defaultConfig = Config{
	Bootstrap:       pBool(false),
	BootstrapExpect: pInt(0),
	ServerMode:      pBool(false),
	Datacenter:      pString("dc1"),
	DNSDomain:       pString("consul."),
	LogLevel:        pString("INFO"),
	ClientAddr:      pString("127.0.0.1"),
	BindAddr:        pString("0.0.0.0"),
	Ports: Ports{
		DNS:     pInt(8600),
		HTTP:    pInt(8500),
		HTTPS:   pInt(-1),
		SerfLAN: pInt(8301),
		SerfWAN: pInt(8302),
		Server:  pInt(8300),
	},
	DNS: DNS{
		AllowStale:      pBool(true),
		UDPAnswerLimit:  pInt(3),
		MaxStale:        pDuration(10 * 365 * 24 * time.Hour),
		RecursorTimeout: pDuration(2 * time.Second),
	},
	Telemetry: Telemetry{
		StatsitePrefix: pString("consul"),
		FilterDefault:  pBool(true),
	},
	SyslogFacility:      pString("LOCAL0"),
	RPCProtocol:         pInt(consul.ProtocolVersion2Compatible),
	CheckUpdateInterval: pDuration(5 * time.Minute),
	DisableCoordinates:  pBool(false),

	ACLTTL:               pDuration(30 * time.Second),
	ACLDownPolicy:        pString("extend-cache"),
	ACLDefaultPolicy:     pString("allow"),
	ACLEnforceVersion8:   pBool(true),
	DisableRemoteExec:    pBool(true),
	RetryJoinIntervalLAN: pDuration(30 * time.Second),
	RetryJoinIntervalWAN: pDuration(30 * time.Second),

	TLSMinVersion: pString("tls10"),

	EncryptVerifyIncoming: pBool(true),
	EncryptVerifyOutgoing: pBool(true),

	DisableHostNodeID: pBool(true),
	// 		Limits: Limits{
	// 			RPCRate:     rate.Inf,
	// 			RPCMaxBurst: 1000,
	// 		},

}

// defaultRuntimeConfig contains the default values of the runtime configuration
// which cannot be configured through the config file.
var defaultRuntimeConfig = RuntimeConfig{
	ACLDisabledTTL:             120 * time.Second,
	CheckDeregisterIntervalMin: 1 * time.Minute,
	CheckReapInterval:          30 * time.Second,
	AEInterval:                 1 * time.Minute,

	// SyncCoordinateRateTarget is set based on the rate that we want
	// the server to handle as an aggregate across the entire cluster.
	// If you update this, you'll need to adjust CoordinateUpdate* in
	// the server-side config accordingly.
	SyncCoordinateRateTarget:  64.0, // updates / second
	SyncCoordinateIntervalMin: 15 * time.Second,
}
