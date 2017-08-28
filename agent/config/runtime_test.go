package config

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/consul/agent/structs"
	"github.com/pascaldekloe/goe/verify"
)

// TestConfigFlagsAndEdgecases tests the command line flags and
// edgecases for the config parsing. It provides a test structure which
// checks for warnings on deprecated fields and flags.  These tests
// should check one option at a time if possible and should use generic
// values, e.g. 'a' or 1 instead of 'servicex' or 3306.

func TestConfigFlagsAndEdgecases(t *testing.T) {
	tests := []struct {
		desc             string
		json, hcl, flags []string
		rt               RuntimeConfig
		warns            []string
		err              error
	}{
		// cmd line flags
		{
			desc:  "-bind",
			flags: []string{`-bind`, `1.2.3.4`},
			rt:    RuntimeConfig{BindAddrs: []string{"1.2.3.4"}},
		},
		{
			desc:  "-bootstrap",
			flags: []string{`-bootstrap`},
			rt:    RuntimeConfig{Bootstrap: true},
		},
		{
			desc:  "-bootstrap-expect",
			flags: []string{`-bootstrap-expect`, `1`},
			rt:    RuntimeConfig{BootstrapExpect: 1},
		},
		{
			desc:  "-client",
			flags: []string{`-client`, `1.2.3.4`},
			rt:    RuntimeConfig{ClientAddr: "1.2.3.4"},
		},
		{
			desc:  "-data-dir",
			flags: []string{`-data-dir`, `a`},
			rt:    RuntimeConfig{DataDir: "a"},
		},
		{
			desc:  "-datacenter",
			flags: []string{`-datacenter`, `a`},
			rt:    RuntimeConfig{Datacenter: "a"},
		},
		{
			desc:  "-dev",
			flags: []string{`-dev`},
			rt:    RuntimeConfig{DevMode: true},
		},
		{
			desc:  "-disable-host-node-id",
			flags: []string{`-disable-host-node-id`},
			rt:    RuntimeConfig{DisableHostNodeID: true},
		},
		{
			desc:  "-disable-keyring-file",
			flags: []string{`-disable-keyring-file`},
			rt:    RuntimeConfig{DisableKeyringFile: true},
		},
		{
			desc:  "-dns-port",
			flags: []string{`-dns-port`, `123`, `-bind`, `0.0.0.0`},
			rt: RuntimeConfig{
				BindAddrs:   []string{"0.0.0.0"},
				DNSPort:     123,
				DNSAddrsUDP: []string{":123"},
				DNSAddrsTCP: []string{":123"},
			},
		},
		{
			desc:  "-domain",
			flags: []string{`-domain`, `a`},
			rt:    RuntimeConfig{DNSDomain: "a"},
		},
		{
			desc:  "-enable-script-checks",
			flags: []string{`-enable-script-checks`},
			rt:    RuntimeConfig{EnableScriptChecks: true},
		},
		{ // todo(fs): shouldn't this be '-encrypt-key'?
			desc:  "-encrypt",
			flags: []string{`-encrypt`, `a`},
			rt:    RuntimeConfig{EncryptKey: "a"},
		},
		{
			desc:  "-http-port",
			flags: []string{`-http-port`, `123`, `-bind`, `0.0.0.0`},
			rt: RuntimeConfig{
				BindAddrs: []string{"0.0.0.0"},
				HTTPPort:  123,
				HTTPAddrs: []string{":123"},
			},
		},
		{
			desc:  "-join",
			flags: []string{`-join`, `a`, `-join`, `b`},
			rt:    RuntimeConfig{StartJoinAddrsLAN: []string{"a", "b"}},
		},
		{
			desc:  "-join-wan",
			flags: []string{`-join-wan`, `a`, `-join-wan`, `b`},
			rt:    RuntimeConfig{StartJoinAddrsWAN: []string{"a", "b"}},
		},
		{
			desc:  "-log-level",
			flags: []string{`-log-level`, `a`},
			rt:    RuntimeConfig{LogLevel: "a"},
		},
		{ // todo(fs): shouldn't this be '-node-name'?
			desc:  "-node",
			flags: []string{`-node`, `a`},
			rt:    RuntimeConfig{NodeName: "a"},
		},
		{
			desc:  "-node-id",
			flags: []string{`-node-id`, `a`},
			rt:    RuntimeConfig{NodeID: "a"},
		},
		{
			desc:  "-node-meta",
			flags: []string{`-node-meta`, `a:b`, `-node-meta`, `c:d`},
			rt:    RuntimeConfig{NodeMeta: map[string]string{"a": "b", "c": "d"}},
		},
		{
			desc:  "-non-voting-server",
			flags: []string{`-non-voting-server`},
			rt:    RuntimeConfig{NonVotingServer: true},
		},
		{
			desc:  "-pid-file",
			flags: []string{`-pid-file`, `a`},
			rt:    RuntimeConfig{PidFile: "a"},
		},
		{
			desc:  "-protocol",
			flags: []string{`-protocol`, `1`},
			rt:    RuntimeConfig{RPCProtocol: 1},
		},
		{
			desc:  "-raft-protocol",
			flags: []string{`-raft-protocol`, `1`},
			rt:    RuntimeConfig{RaftProtocol: 1},
		},
		{
			desc:  "-recursor",
			flags: []string{`-recursor`, `a`, `-recursor`, `b`},
			rt:    RuntimeConfig{DNSRecursors: []string{"a", "b"}},
		},
		{
			desc:  "-rejoin",
			flags: []string{`-rejoin`},
			rt:    RuntimeConfig{RejoinAfterLeave: true},
		},
		{
			desc:  "-retry-interval",
			flags: []string{`-retry-interval`, `5s`},
			rt:    RuntimeConfig{RetryJoinIntervalLAN: 5 * time.Second},
		},
		{
			desc:  "-retry-interval-wan",
			flags: []string{`-retry-interval-wan`, `5s`},
			rt:    RuntimeConfig{RetryJoinIntervalWAN: 5 * time.Second},
		},
		{
			desc:  "-retry-join",
			flags: []string{`-retry-join`, `a`, `-retry-join`, `b`},
			rt:    RuntimeConfig{RetryJoinLAN: []string{"a", "b"}},
		},
		{
			desc:  "-retry-join-wan",
			flags: []string{`-retry-join-wan`, `a`, `-retry-join-wan`, `b`},
			rt:    RuntimeConfig{RetryJoinWAN: []string{"a", "b"}},
		},
		{
			desc:  "-retry-max",
			flags: []string{`-retry-max`, `1`},
			rt:    RuntimeConfig{RetryJoinMaxAttemptsLAN: 1},
		},
		{
			desc:  "-retry-max-wan",
			flags: []string{`-retry-max-wan`, `1`},
			rt:    RuntimeConfig{RetryJoinMaxAttemptsWAN: 1},
		},
		{
			desc:  "-server",
			flags: []string{`-server`},
			rt:    RuntimeConfig{ServerMode: true},
		},
		{
			desc:  "-syslog",
			flags: []string{`-syslog`},
			rt:    RuntimeConfig{EnableSyslog: true},
		},
		{
			desc:  "-ui",
			flags: []string{`-ui`},
			rt:    RuntimeConfig{EnableUI: true},
		},
		{
			desc:  "-ui-dir",
			flags: []string{`-ui-dir`, `a`},
			rt:    RuntimeConfig{UIDir: "a"},
		},
		/*
			add(&f.Config.AdvertiseAddrLAN, "advertise", "Sets the advertise address to use.")
			add(&f.Config.AdvertiseAddrWAN, "advertise-wan", "Sets address to advertise on WAN instead of -advertise address.")
			add(&f.Config.SerfBindAddrLAN, "serf-lan-bind", "Address to bind Serf LAN listeners to.")
			add(&f.Config.SerfBindAddrWAN, "serf-wan-bind", "Address to bind Serf WAN listeners to.")
		*/

		// deprecated flags
		{
			desc:  "-atlas",
			flags: []string{`-atlas`, `a`},
			rt:    RuntimeConfig{},
			warns: []string{`'-atlas' is deprecated`},
		},
		{
			desc:  "-atlas-join",
			flags: []string{`-atlas-join`},
			rt:    RuntimeConfig{},
			warns: []string{`'-atlas-join' is deprecated`},
		},
		{
			desc:  "-atlas-endpoint",
			flags: []string{`-atlas-endpoint`, `a`},
			rt:    RuntimeConfig{},
			warns: []string{`'-atlas-endpoint' is deprecated`},
		},
		{
			desc:  "-atlas-token",
			flags: []string{`-atlas-token`, `a`},
			rt:    RuntimeConfig{},
			warns: []string{`'-atlas-token' is deprecated`},
		},
		{
			desc:  "-dc",
			flags: []string{`-dc`, `a`},
			rt:    RuntimeConfig{Datacenter: "a"},
			warns: []string{`'-dc' is deprecated. Use '-datacenter' instead`},
		},

		// deprecated fields
		{
			desc:  "check.service_id alias",
			json:  []string{`{"check":{ "service_id":"d", "serviceid":"dd" }}`},
			hcl:   []string{`check = { service_id="d" serviceid="dd" }`},
			rt:    RuntimeConfig{Checks: []*structs.CheckDefinition{{ServiceID: "dd"}}},
			warns: []string{`config: "serviceid" is deprecated in check definitions. Please use "service_id" instead.`},
		},
		{
			desc:  "check.docker_container_id alias",
			json:  []string{`{"check":{ "docker_container_id":"k", "dockercontainerid":"kk" }}`},
			hcl:   []string{`check = { docker_container_id="k" dockercontainerid="kk" }`},
			rt:    RuntimeConfig{Checks: []*structs.CheckDefinition{{DockerContainerID: "kk"}}},
			warns: []string{`config: "dockercontainerid" is deprecated in check definitions. Please use "docker_container_id" instead.`},
		},
		{
			desc:  "check.tls_skip_verify alias",
			json:  []string{`{"check":{ "tls_skip_verify":true, "tlsskipverify":false }}`},
			hcl:   []string{`check = { tls_skip_verify=true tlsskipverify=false }`},
			rt:    RuntimeConfig{Checks: []*structs.CheckDefinition{{TLSSkipVerify: false}}},
			warns: []string{`config: "tlsskipverify" is deprecated in check definitions. Please use "tls_skip_verify" instead.`},
		},
		{
			desc:  "check.deregister_critical_service_after alias",
			json:  []string{`{"check":{ "deregister_critical_service_after":"5s", "deregistercriticalserviceafter": "10s" }}`},
			hcl:   []string{`check = { deregister_critical_service_after="5s" deregistercriticalserviceafter="10s"}`},
			rt:    RuntimeConfig{Checks: []*structs.CheckDefinition{{DeregisterCriticalServiceAfter: 10 * time.Second}}},
			warns: []string{`config: "deregistercriticalserviceafter" is deprecated in check definitions. Please use "deregister_critical_service_after" instead.`},
		},
		{
			desc:  "telemetry.dogstatsd_addr alias",
			json:  []string{`{"dogstatsd_addr":"a", "telemetry":{"dogstatsd_addr": "b"}}`},
			hcl:   []string{`dogstatsd_addr = "a" telemetry = { dogstatsd_addr = "b"}`},
			rt:    RuntimeConfig{TelemetryDogstatsdAddr: "a"},
			warns: []string{`config: "dogstatsd_addr" is deprecated. Please use "telemetry.dogstatsd_addr" instead.`},
		},
		{
			desc:  "telemetry.dogstatsd_tags alias",
			json:  []string{`{"dogstatsd_tags":["a", "b"], "telemetry": { "dogstatsd_tags": ["c", "d"]}}`},
			hcl:   []string{`dogstatsd_tags = ["a", "b"] telemetry = { dogstatsd_tags = ["c", "d"] }`},
			rt:    RuntimeConfig{TelemetryDogstatsdTags: []string{"a", "b", "c", "d"}},
			warns: []string{`config: "dogstatsd_tags" is deprecated. Please use "telemetry.dogstatsd_tags" instead.`},
		},
		{
			desc:  "telemetry.statsd_addr alias",
			json:  []string{`{"statsd_addr":"a", "telemetry":{"statsd_addr": "b"}}`},
			hcl:   []string{`statsd_addr = "a" telemetry = { statsd_addr = "b" }`},
			rt:    RuntimeConfig{TelemetryStatsdAddr: "a"},
			warns: []string{`config: "statsd_addr" is deprecated. Please use "telemetry.statsd_addr" instead.`},
		},
		{
			desc:  "telemetry.statsite_addr alias",
			json:  []string{`{"statsite_addr":"a", "telemetry":{ "statsite_addr": "b" }}`},
			hcl:   []string{`statsite_addr = "a" telemetry = { statsite_addr = "b"}`},
			rt:    RuntimeConfig{TelemetryStatsiteAddr: "a"},
			warns: []string{`config: "statsite_addr" is deprecated. Please use "telemetry.statsite_addr" instead.`},
		},
		{
			desc:  "telemetry.statsite_prefix alias",
			json:  []string{`{"statsite_prefix":"a", "telemetry":{ "statsite_prefix": "b" }}`},
			hcl:   []string{`statsite_prefix = "a" telemetry = { statsite_prefix = "b" }`},
			rt:    RuntimeConfig{TelemetryStatsitePrefix: "a"},
			warns: []string{`config: "statsite_prefix" is deprecated. Please use "telemetry.statsite_prefix" instead.`},
		},

		// ports and addresses
		{
			desc: "ports == 0",
			json: []string{`{ "bind_addr":"0.0.0.0", "ports":{} }`},
			hcl:  []string{` bind_addr = "0.0.0.0" ports {}`},
			rt: RuntimeConfig{
				BindAddrs: []string{"0.0.0.0"},
			},
		},
		{
			desc: "ports < 0",
			json: []string{`{ "bind_addr":"0.0.0.0", "ports":{ "dns":-1, "http":-2, "https":-3 } }`},
			hcl:  []string{` bind_addr = "0.0.0.0" ports { dns = -1 http = -2 https = -3 }`},
			rt: RuntimeConfig{
				BindAddrs: []string{"0.0.0.0"},
			},
		},

		// precedence rules
		{
			desc: "precedence: merge order",
			json: []string{
				`{
					"bootstrap":true,
					"bootstrap_expect": 1,
					"datacenter":"a",
					"start_join":["a", "b"],
					"node_meta": {"a":"b"}
				}`,
				`{
					"bootstrap":false,
					"bootstrap_expect": 2,
					"datacenter":"b",
					"start_join":["c", "d"],
					"node_meta": {"c":"d"}
				}`,
			},
			hcl: []string{
				`
				bootstrap = true
				bootstrap_expect = 1
				datacenter = "a"
				start_join = ["a", "b"]
				node_meta = { "a" = "b" }
				`,
				`
				bootstrap = false
				bootstrap_expect = 2
				datacenter = "b"
				start_join = ["c", "d"]
				node_meta = { "c" = "d" }
				`,
			},
			rt: RuntimeConfig{
				Bootstrap:         false,
				BootstrapExpect:   2,
				Datacenter:        "b",
				StartJoinAddrsLAN: []string{"a", "b", "c", "d"},
				NodeMeta:          map[string]string{"c": "d"},
			},
		},
		{
			desc: "precedence: flag before file",
			json: []string{
				`{
					"bootstrap":true,
					"bootstrap_expect": 1,
					"datacenter":"a",
					"recursors":["a", "b"],
					"start_join":["a", "b"],
					"node_meta": {"a":"b"}
				}`,
			},
			hcl: []string{
				`
				bootstrap = true
				bootstrap_expect = 1
				datacenter = "a"
				recursors = ["a", "b"]
				start_join = ["a", "b"]
				node_meta = { "a" = "b" }
				`,
			},
			flags: []string{
				`-bootstrap=false`,
				`-bootstrap-expect=2`,
				`-datacenter=b`,
				`-join`, `c`, `-join`, `d`,
				`-node-meta`, `c:d`,
				`-recursor`, `c`, `-recursor`, `d`,
			},
			rt: RuntimeConfig{
				Bootstrap:         false,
				BootstrapExpect:   2,
				Datacenter:        "b",
				StartJoinAddrsLAN: []string{"c", "d", "a", "b"},
				NodeMeta:          map[string]string{"c": "d"},
				DNSRecursors:      []string{"c", "d", "a", "b"},
			},
		},
	}

	for _, tt := range tests {
		for _, format := range []string{"json", "hcl"} {
			if len(tt.json) != len(tt.hcl) {
				t.Fatal("JSON and HCL test case out of sync")
			}

			srcs := tt.json
			if format == "hcl" {
				srcs = tt.hcl
			}

			// ugly hack to skip second run for flag-only tests
			if len(srcs) == 0 && format == "hcl" {
				continue
			}

			var desc []string
			if len(srcs) > 0 {
				desc = append(desc, format)
			}
			if tt.desc != "" {
				desc = append(desc, tt.desc)
			}

			t.Run(strings.Join(desc, ":"), func(t *testing.T) {
				// add flags
				flags, err := ParseFlags(tt.flags)
				if err != nil {
					t.Fatalf("ParseFlags failed: %s", err)
				}

				b, err := NewBuilder(flags, Config{})
				if err != nil {
					t.Fatalf("NewBuilder failed: %s", err)
				}
				for _, src := range srcs {
					if err := b.ReadBytes([]byte(src), format); err != nil {
						t.Fatalf("ReadBytes failed for %q: %s", src, err)
					}
				}
				rt, warnings, err := b.Build()

				if !verify.Values(t, "", rt, tt.rt) {
					t.FailNow()
				}

				if !verify.Values(t, "warnings", warnings, tt.warns) {
					t.FailNow()
				}
			})
		}
	}
}

// TestFullConfig tests the conversion from a fully populated JSON or
// HCL config file to a RuntimeConfig structure. All fields must be set
// to a unique non-zero value.
//
// To aid populating the fields the following bash functions can be used
// to generate random strings and ints:
//
//   random-int() { echo $RANDOM }
//   random-string() { base64 /dev/urandom | tr -d '/+' | fold -w ${1:-32} | head -n 1 }
//
// To generate a random string of length 8 run the following command in
// a terminal:
//
//   random-string 8
//
func TestFullConfig(t *testing.T) {
	flagSrc := []string{"-dev"}
	src := map[string]string{
		"json": `{
			"acl_agent_master_token": "furuQD0b",
			"acl_agent_token": "cOshLOQ2",
			"acl_datacenter": "M3uRCk3Z",
			"acl_default_policy": "ArK3WIfE",
			"acl_down_policy": "vZXMfMP0",
			"acl_enforce_version_8": true,
			"acl_master_token": "C1Q1oIwh",
			"acl_replication_token": "LMmgy5dO",
			"acl_token": "O1El0wan",
			"acl_ttl": "18060s",
			"autopilot": {
				"cleanup_dead_servers": true,
				"disable_upgrade_migration": true,
				"last_contact_threshold": "12705s",
				"max_trailing_logs": 17849,
				"redundancy_zone_tag": "3IsufDJf",
				"server_stabilization_time": "23057s",
				"upgrade_version_tag": "W9pDwFAL"
			},
			"bind_addr": "6rFPKyh6",
			"bootstrap": true,
			"bootstrap_expect": 28094,
			"ca_file": "erA7T0PM",
			"ca_path": "mQEN1Mfp",
			"cert_file": "7s4QAzDk",
			"check": {
				"id": "fZaCAXww",
				"name": "OOM2eo0f",
				"notes": "zXzXI9Gt",
				"service_id": "L8G0QNmR",
				"token": "oo4BCTgJ",
				"status": "qLykAl5u",
				"script": "dhGfIF8n",
				"http": "29B93haH",
				"header": {
					"hBq0zn1q": [ "2a9o9ZKP", "vKwA5lR6" ],
					"f3r6xFtM": [ "RyuIdDWv", "QbxEcIUM" ]
				},
				"method": "Dou0nGT5",
				"tcp": "JY6fTTcw",
				"interval": "18714s",
				"docker_container_id": "qF66POS9",
				"shell": "sOnDy228",
				"tls_skip_verify": true,
				"timeout": "5954s",
				"ttl": "30044s",
				"deregister_critical_service_after": "13209s"
			},
			"checks": [
				{
					"id": "uAjE6m9Z",
					"name": "QsZRGpYr",
					"notes": "VJ7Sk4BY",
					"service_id": "lSulPcyz",
					"token": "toO59sh8",
					"status": "9RlWsXMV",
					"script": "8qbd8tWw",
					"http": "dohLcyQ2",
					"header": {
						"hBq0zn1q": [ "1sDbEqYG", "lJGASsWK" ],
						"f3r6xFtM": [ "LMccm3Qe", "k5H5RggQ" ]
					},
					"method": "aldrIQ4l",
					"tcp": "RJQND605",
					"interval": "22164s",
					"docker_container_id": "ipgdFtjd",
					"shell": "qAeOYy0M",
					"tls_skip_verify": true,
					"timeout": "1813s",
					"ttl": "21743s",
					"deregister_critical_service_after": "14232s"
				},
				{
					"id": "Cqq95BhP",
					"name": "3qXpkS0i",
					"notes": "sb5qLTex",
					"service_id": "CmUUcRna",
					"token": "a3nQzHuy",
					"status": "irj26nf3",
					"script": "FJsI1oXt",
					"http": "yzhgsQ7Y",
					"header": {
						"zcqwA8dO": [ "qb1zx0DL", "sXCxPFsD" ],
						"qxvdnSE9": [ "6wBPUYdF", "YYh8wtSZ" ]
					},
					"method": "gLrztrNw",
					"tcp": "4jG5casb",
					"interval": "28767s",
					"docker_container_id": "THW6u7rL",
					"shell": "C1Zt3Zwh",
					"tls_skip_verify": true,
					"timeout": "18506s",
					"ttl": "31006s",
					"deregister_critical_service_after": "2366s"
				}
			],
			"check_update_interval": "16507s",
			"client_addr": "e15dFavQ",
			"data_dir": "oTOOIoV9",
			"datacenter": "rzo029wG",
			"disable_anonymous_signature": true,
			"disable_coordinates": true,
			"disable_host_node_id": true,
			"disable_keyring_file": true,
			"disable_remote_exec": true,
			"disable_update_check": true,
			"domain": "7W1xXSqd",
			"dns_config": {
				"allow_stale": true,
				"disable_compression": true,
				"enable_truncate": true,
				"max_stale": "29685s",
				"node_ttl": "7084s",
				"only_passing": true,
				"recursor_timeout": "4427s",
				"service_ttl": {
					"*": "32030s"
				},
				"udp_answer_limit": 29909
			},
			"enable_acl_replication": true,
			"enable_debug": true,
			"enable_script_checks": true,
			"enable_syslog": true,
			"enable_ui": true,
			"encrypt": "A4wELWqH",
			"encrypt_verify_incoming": true,
			"encrypt_verify_outgoing": true,
			"http_config": {
				"block_endpoints": [ "RBvAFcGD", "fWOWFznh" ],
				"response_headers": {
					"M6TKa9NP": "xjuxjOzQ",
					"JRCrHZed": "rl0mTx81"
				}
			},
			"key_file": "IEkkwgIA",
			"leave_on_terminate": true,
			"log_level": "k1zo9Spt",
			"node_id": "AsUIlw99",
			"node_meta": {
				"5mgGQMBk": "mJLtVMSG",
				"A7ynFMJB": "0Nx6RGab"
			},
			"node_name": "otlLxGaI",
			"non_voting_server": true,
			"performance": {
				"raft_multiplier": 22057
			},
			"pid_file": "43xN80Km",
			"ports": {
				"dns": 7001,
				"http": 7999,
				"https": 15127
			},
			"protocol": 30793,
			"raft_protocol": 19016,
			"reconnect_timeout": "23739s",
			"reconnect_timeout_wan": "26694s",
			"recursor": "EZX7MOYF",
			"recursors": [ "FtFhoUHl", "UYkwck1k" ],
			"rejoin_after_leave": true,
			"retry_interval": "8067s",
			"retry_interval_wan": "28866s",
			"retry_join": [ "pbsSFY7U", "l0qLtWij" ],
			"retry_join_wan": [ "PFsR02Ye", "rJdQIhER" ],
			"retry_max": 913,
			"retry_max_wan": 23160,
			"server": true,
			"server_name": "Oerr9n1G",
			"session_ttl_min": "26627s",
			"skip_leave_on_interrupt": true,
			"start_join": [ "LR3hGDoG", "MwVpZ4Up" ],
			"start_join_wan": [ "EbFSc3nA", "kwXTh623" ],
			"syslog_facility": "hHv79Uia",
			"tagged_addresses": {
				"7MYgHrYH": "dALJAhLD",
				"h6DdBy6K": "ebrr9zZ8"
			},
			"telemetry": {
				"circonus_api_app": "p4QOTe9j",
				"circonus_api_token": "E3j35V23",
				"circonus_api_url": "mEMjHpGg",
				"circonus_broker_id": "BHlxUhed",
				"circonus_broker_select_tag": "13xy1gHm",
				"circonus_check_display_name": "DRSlQR6n",
				"circonus_check_force_metric_activation": "Ua5FGVYf",
				"circonus_check_id": "kGorutad",
				"circonus_check_instance_id": "rwoOL6R4",
				"circonus_check_search_tag": "ovT4hT4f",
				"circonus_check_tags": "prvO4uBl",
				"circonus_submission_interval": "DolzaflP",
				"circonus_submission_url": "gTcbS93G",
				"disable_hostname": true,
				"dogstatsd_addr": "0wSndumK",
				"dogstatsd_tags": [ "3N81zSUB","Xtj8AnXZ" ],
				"filter_default": true,
				"prefix_filter": [ "oJotS8XJ","cazlEhGn" ],
				"statsd_address": "drce87cy",
				"statsite_address": "HpFwKB8R",
				"statsite_prefix": "ftO6DySn"
			},
			"tls_cipher_suites": "TLS_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA",
			"tls_min_version": "pAOWafkR",
			"tls_prefer_server_cipher_suites": true,
			"translate_wan_addrs": true,
			"ui_dir": "11IFzAUn",
			"unix_sockets": {
				"group": "8pFodrV8",
				"mode": "E8sAwOv4",
				"user": "E0nB1DwA"
			},
			"verify_incoming": true,
			"verify_incoming_https": true,
			"verify_incoming_rpc": true,
			"verify_outgoing": true,
			"verify_server_hostname": true
		}`,
		"hcl": `
			acl_agent_master_token = "furuQD0b"
			acl_agent_token = "cOshLOQ2"
			acl_datacenter = "M3uRCk3Z"
			acl_default_policy = "ArK3WIfE"
			acl_down_policy = "vZXMfMP0"
			acl_enforce_version_8 = true
			acl_master_token = "C1Q1oIwh"
			acl_replication_token = "LMmgy5dO"
			acl_token = "O1El0wan"
			acl_ttl = "18060s"
			autopilot = {
				cleanup_dead_servers = true
				disable_upgrade_migration = true
				last_contact_threshold = "12705s"
				max_trailing_logs = 17849
				redundancy_zone_tag = "3IsufDJf"
				server_stabilization_time = "23057s"
				upgrade_version_tag = "W9pDwFAL"
			}
			bind_addr = "6rFPKyh6"
			bootstrap = true
			bootstrap_expect = 28094
			ca_file = "erA7T0PM"
			ca_path = "mQEN1Mfp"
			cert_file = "7s4QAzDk"
			check = {
				id = "fZaCAXww"
				name = "OOM2eo0f"
				notes = "zXzXI9Gt"
				service_id = "L8G0QNmR"
				token = "oo4BCTgJ"
				status = "qLykAl5u"
				script = "dhGfIF8n"
				http = "29B93haH"
				header = {
					hBq0zn1q = [ "2a9o9ZKP", "vKwA5lR6" ]
					f3r6xFtM = [ "RyuIdDWv", "QbxEcIUM" ]
				}
				method = "Dou0nGT5"
				tcp = "JY6fTTcw"
				interval = "18714s"
				docker_container_id = "qF66POS9"
				shell = "sOnDy228"
				tls_skip_verify = true
				timeout = "5954s"
				ttl = "30044s"
				deregister_critical_service_after = "13209s"
			},
			checks = [
				{
					id = "uAjE6m9Z"
					name = "QsZRGpYr"
					notes = "VJ7Sk4BY"
					service_id = "lSulPcyz"
					token = "toO59sh8"
					status = "9RlWsXMV"
					script = "8qbd8tWw"
					http = "dohLcyQ2"
					header = {
						"hBq0zn1q" = [ "1sDbEqYG", "lJGASsWK" ]
						"f3r6xFtM" = [ "LMccm3Qe", "k5H5RggQ" ]
					}
					method = "aldrIQ4l"
					tcp = "RJQND605"
					interval = "22164s"
					docker_container_id = "ipgdFtjd"
					shell = "qAeOYy0M"
					tls_skip_verify = true
					timeout = "1813s"
					ttl = "21743s"
					deregister_critical_service_after = "14232s"
				},
				{
					id = "Cqq95BhP"
					name = "3qXpkS0i"
					notes = "sb5qLTex"
					service_id = "CmUUcRna"
					token = "a3nQzHuy"
					status = "irj26nf3"
					script = "FJsI1oXt"
					http = "yzhgsQ7Y"
					header = {
						"zcqwA8dO" = [ "qb1zx0DL", "sXCxPFsD" ]
						"qxvdnSE9" = [ "6wBPUYdF", "YYh8wtSZ" ]
					}
					method = "gLrztrNw"
					tcp = "4jG5casb"
					interval = "28767s"
					docker_container_id = "THW6u7rL"
					shell = "C1Zt3Zwh"
					tls_skip_verify = true
					timeout = "18506s"
					ttl = "31006s"
					deregister_critical_service_after = "2366s"
				}
			]
			check_update_interval = "16507s"
			client_addr = "e15dFavQ"
			data_dir = "oTOOIoV9"
			datacenter = "rzo029wG"
			disable_anonymous_signature = true
			disable_coordinates = true
			disable_host_node_id = true
			disable_keyring_file = true
			disable_remote_exec = true
			disable_update_check = true
			domain = "7W1xXSqd"
			dns_config {
				allow_stale = true
				disable_compression = true
				enable_truncate = true
				max_stale = "29685s"
				node_ttl = "7084s"
				only_passing = true
				recursor_timeout = "4427s"
				service_ttl = {
					"*" = "32030s"
				}
				udp_answer_limit = 29909
			}
			enable_acl_replication = true
			enable_debug = true
			enable_script_checks = true
			enable_syslog = true
			enable_ui = true
			encrypt = "A4wELWqH"
			encrypt_verify_incoming = true
			encrypt_verify_outgoing = true
			http_config {
				block_endpoints = [ "RBvAFcGD", "fWOWFznh" ]
				response_headers = {
					"M6TKa9NP" = "xjuxjOzQ"
					"JRCrHZed" = "rl0mTx81"
				}
			}
			key_file = "IEkkwgIA"
			leave_on_terminate = true
			log_level = "k1zo9Spt"
			node_id = "AsUIlw99"
			node_meta {
				"5mgGQMBk" = "mJLtVMSG"
				"A7ynFMJB" = "0Nx6RGab"
			}
			node_name = "otlLxGaI"
			non_voting_server = true
			performance {
				raft_multiplier = 22057
			}
			pid_file = "43xN80Km"
			ports {
				dns = 7001,
				http = 7999,
				https = 15127
			}
			protocol = 30793
			raft_protocol = 19016
			reconnect_timeout = "23739s"
			reconnect_timeout_wan = "26694s"
			recursor = "EZX7MOYF"
			recursors = [ "FtFhoUHl", "UYkwck1k" ]
			rejoin_after_leave = true
			retry_interval = "8067s"
			retry_interval_wan = "28866s"
			retry_join = [ "pbsSFY7U", "l0qLtWij" ]
			retry_join_wan = [ "PFsR02Ye", "rJdQIhER" ]
			retry_max = 913
			retry_max_wan = 23160
			server = true
			server_name = "Oerr9n1G"
			session_ttl_min = "26627s"
			skip_leave_on_interrupt = true
			start_join = [ "LR3hGDoG", "MwVpZ4Up" ]
			start_join_wan = [ "EbFSc3nA", "kwXTh623" ]
			syslog_facility = "hHv79Uia"
			tagged_addresses = {
				"7MYgHrYH" = "dALJAhLD"
				"h6DdBy6K" = "ebrr9zZ8"
			}
			telemetry {
				circonus_api_app = "p4QOTe9j"
				circonus_api_token = "E3j35V23"
				circonus_api_url = "mEMjHpGg"
				circonus_broker_id = "BHlxUhed"
				circonus_broker_select_tag = "13xy1gHm"
				circonus_check_display_name = "DRSlQR6n"
				circonus_check_force_metric_activation = "Ua5FGVYf"
				circonus_check_id = "kGorutad"
				circonus_check_instance_id = "rwoOL6R4"
				circonus_check_search_tag = "ovT4hT4f"
				circonus_check_tags = "prvO4uBl"
				circonus_submission_interval = "DolzaflP"
				circonus_submission_url = "gTcbS93G"
				disable_hostname = true
				dogstatsd_addr = "0wSndumK"
				dogstatsd_tags = [ "3N81zSUB","Xtj8AnXZ" ]
				filter_default = true
				prefix_filter = [ "oJotS8XJ","cazlEhGn" ]
				statsd_address = "drce87cy"
				statsite_address = "HpFwKB8R"
				statsite_prefix = "ftO6DySn"
			}
			tls_cipher_suites = "TLS_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA"
			tls_min_version = "pAOWafkR"
			tls_prefer_server_cipher_suites = true
			translate_wan_addrs = true
			ui_dir = "11IFzAUn"
			unix_sockets = {
				group = "8pFodrV8"
				mode = "E8sAwOv4"
				user = "E0nB1DwA"
			}
			verify_incoming = true
			verify_incoming_https = true
			verify_incoming_rpc = true
			verify_outgoing = true
			verify_server_hostname = true
		`}

	want := RuntimeConfig{
		ACLAgentMasterToken:              "furuQD0b",
		ACLAgentToken:                    "cOshLOQ2",
		ACLDatacenter:                    "M3uRCk3Z",
		ACLDefaultPolicy:                 "ArK3WIfE",
		ACLDownPolicy:                    "vZXMfMP0",
		ACLEnforceVersion8:               true,
		ACLMasterToken:                   "C1Q1oIwh",
		ACLReplicationToken:              "LMmgy5dO",
		ACLTTL:                           18060 * time.Second,
		ACLToken:                         "O1El0wan",
		AutopilotCleanupDeadServers:      true,
		AutopilotDisableUpgradeMigration: true,
		AutopilotLastContactThreshold:    12705 * time.Second,
		AutopilotMaxTrailingLogs:         17849,
		AutopilotRedundancyZoneTag:       "3IsufDJf",
		AutopilotServerStabilizationTime: 23057 * time.Second,
		AutopilotUpgradeVersionTag:       "W9pDwFAL",
		BindAddrs:                        []string{"6rFPKyh6"},
		Bootstrap:                        true,
		BootstrapExpect:                  28094,
		CAFile:                           "erA7T0PM",
		CAPath:                           "mQEN1Mfp",
		CertFile:                         "7s4QAzDk",
		Checks: []*structs.CheckDefinition{
			&structs.CheckDefinition{
				ID:        "fZaCAXww",
				Name:      "OOM2eo0f",
				Notes:     "zXzXI9Gt",
				ServiceID: "L8G0QNmR",
				Token:     "oo4BCTgJ",
				Status:    "qLykAl5u",
				Script:    "dhGfIF8n",
				HTTP:      "29B93haH",
				Header: map[string][]string{
					"hBq0zn1q": {"2a9o9ZKP", "vKwA5lR6"},
					"f3r6xFtM": {"RyuIdDWv", "QbxEcIUM"},
				},
				Method:            "Dou0nGT5",
				TCP:               "JY6fTTcw",
				Interval:          18714 * time.Second,
				DockerContainerID: "qF66POS9",
				Shell:             "sOnDy228",
				TLSSkipVerify:     true,
				Timeout:           5954 * time.Second,
				TTL:               30044 * time.Second,
				DeregisterCriticalServiceAfter: 13209 * time.Second,
			},
			&structs.CheckDefinition{
				ID:        "uAjE6m9Z",
				Name:      "QsZRGpYr",
				Notes:     "VJ7Sk4BY",
				ServiceID: "lSulPcyz",
				Token:     "toO59sh8",
				Status:    "9RlWsXMV",
				Script:    "8qbd8tWw",
				HTTP:      "dohLcyQ2",
				Header: map[string][]string{
					"hBq0zn1q": []string{"1sDbEqYG", "lJGASsWK"},
					"f3r6xFtM": []string{"LMccm3Qe", "k5H5RggQ"},
				},
				Method:            "aldrIQ4l",
				TCP:               "RJQND605",
				Interval:          22164 * time.Second,
				DockerContainerID: "ipgdFtjd",
				Shell:             "qAeOYy0M",
				TLSSkipVerify:     true,
				Timeout:           1813 * time.Second,
				TTL:               21743 * time.Second,
				DeregisterCriticalServiceAfter: 14232 * time.Second,
			},
			&structs.CheckDefinition{
				ID:        "Cqq95BhP",
				Name:      "3qXpkS0i",
				Notes:     "sb5qLTex",
				ServiceID: "CmUUcRna",
				Token:     "a3nQzHuy",
				Status:    "irj26nf3",
				Script:    "FJsI1oXt",
				HTTP:      "yzhgsQ7Y",
				Header: map[string][]string{
					"zcqwA8dO": []string{"qb1zx0DL", "sXCxPFsD"},
					"qxvdnSE9": []string{"6wBPUYdF", "YYh8wtSZ"},
				},
				Method:            "gLrztrNw",
				TCP:               "4jG5casb",
				Interval:          28767 * time.Second,
				DockerContainerID: "THW6u7rL",
				Shell:             "C1Zt3Zwh",
				TLSSkipVerify:     true,
				Timeout:           18506 * time.Second,
				TTL:               31006 * time.Second,
				DeregisterCriticalServiceAfter: 2366 * time.Second,
			},
		},
		CheckUpdateInterval:                         16507 * time.Second,
		ClientAddr:                                  "e15dFavQ",
		DNSAddrsTCP:                                 []string{"6rFPKyh6:7001"},
		DNSAddrsUDP:                                 []string{"6rFPKyh6:7001"},
		DNSAllowStale:                               true,
		DNSDisableCompression:                       true,
		DNSDomain:                                   "7W1xXSqd",
		DNSEnableTruncate:                           true,
		DNSMaxStale:                                 29685 * time.Second,
		DNSNodeTTL:                                  7084 * time.Second,
		DNSOnlyPassing:                              true,
		DNSPort:                                     7001,
		DNSRecursorTimeout:                          4427 * time.Second,
		DNSRecursors:                                []string{"EZX7MOYF", "FtFhoUHl", "UYkwck1k"},
		DNSServiceTTL:                               map[string]time.Duration{"*": 32030 * time.Second},
		DNSUDPAnswerLimit:                           29909,
		DataDir:                                     "oTOOIoV9",
		Datacenter:                                  "rzo029wG",
		DevMode:                                     true,
		DisableAnonymousSignature:                   true,
		DisableCoordinates:                          true,
		DisableHostNodeID:                           true,
		DisableKeyringFile:                          true,
		DisableRemoteExec:                           true,
		DisableUpdateCheck:                          true,
		EnableACLReplication:                        true,
		EnableDebug:                                 true,
		EnableScriptChecks:                          true,
		EnableSyslog:                                true,
		EnableUI:                                    true,
		EncryptKey:                                  "A4wELWqH",
		EncryptVerifyIncoming:                       true,
		EncryptVerifyOutgoing:                       true,
		HTTPAddrs:                                   []string{"6rFPKyh6:7999"},
		HTTPBlockEndpoints:                          []string{"RBvAFcGD", "fWOWFznh"},
		HTTPPort:                                    7999,
		HTTPResponseHeaders:                         map[string]string{"M6TKa9NP": "xjuxjOzQ", "JRCrHZed": "rl0mTx81"},
		HTTPSAddrs:                                  []string{"6rFPKyh6:15127"},
		HTTPSPort:                                   15127,
		KeyFile:                                     "IEkkwgIA",
		LeaveOnTerm:                                 true,
		LogLevel:                                    "k1zo9Spt",
		NodeID:                                      "AsUIlw99",
		NodeMeta:                                    map[string]string{"5mgGQMBk": "mJLtVMSG", "A7ynFMJB": "0Nx6RGab"},
		NodeName:                                    "otlLxGaI",
		NonVotingServer:                             true,
		PerformanceRaftMultiplier:                   22057,
		PidFile:                                     "43xN80Km",
		RPCProtocol:                                 30793,
		RaftProtocol:                                19016,
		ReconnectTimeoutLAN:                         23739 * time.Second,
		ReconnectTimeoutWAN:                         26694 * time.Second,
		RejoinAfterLeave:                            true,
		RetryJoinIntervalLAN:                        8067 * time.Second,
		RetryJoinIntervalWAN:                        28866 * time.Second,
		RetryJoinLAN:                                []string{"pbsSFY7U", "l0qLtWij"},
		RetryJoinMaxAttemptsLAN:                     913,
		RetryJoinMaxAttemptsWAN:                     23160,
		RetryJoinWAN:                                []string{"PFsR02Ye", "rJdQIhER"},
		ServerMode:                                  true,
		ServerName:                                  "Oerr9n1G",
		SessionTTLMin:                               26627 * time.Second,
		SkipLeaveOnInt:                              true,
		StartJoinAddrsLAN:                           []string{"LR3hGDoG", "MwVpZ4Up"},
		StartJoinAddrsWAN:                           []string{"EbFSc3nA", "kwXTh623"},
		SyslogFacility:                              "hHv79Uia",
		TelemetryCirconusAPIApp:                     "p4QOTe9j",
		TelemetryCirconusAPIToken:                   "E3j35V23",
		TelemetryCirconusAPIURL:                     "mEMjHpGg",
		TelemetryCirconusBrokerID:                   "BHlxUhed",
		TelemetryCirconusBrokerSelectTag:            "13xy1gHm",
		TelemetryCirconusCheckDisplayName:           "DRSlQR6n",
		TelemetryCirconusCheckForceMetricActivation: "Ua5FGVYf",
		TelemetryCirconusCheckID:                    "kGorutad",
		TelemetryCirconusCheckInstanceID:            "rwoOL6R4",
		TelemetryCirconusCheckSearchTag:             "ovT4hT4f",
		TelemetryCirconusCheckTags:                  "prvO4uBl",
		TelemetryCirconusSubmissionInterval:         "DolzaflP",
		TelemetryCirconusSubmissionURL:              "gTcbS93G",
		TelemetryDisableHostname:                    true,
		TelemetryDogstatsdAddr:                      "0wSndumK",
		TelemetryDogstatsdTags:                      []string{"3N81zSUB", "Xtj8AnXZ"},
		TelemetryFilterDefault:                      true,
		TelemetryPrefixFilter:                       []string{"oJotS8XJ", "cazlEhGn"},
		TelemetryStatsdAddr:                         "drce87cy",
		TelemetryStatsiteAddr:                       "HpFwKB8R",
		TelemetryStatsitePrefix:                     "ftO6DySn",
		TLSCipherSuites:                             []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
		TLSMinVersion:                               "pAOWafkR",
		TLSPreferServerCipherSuites:                 true,
		TaggedAddresses:                             map[string]string{"7MYgHrYH": "dALJAhLD", "h6DdBy6K": "ebrr9zZ8"},
		TranslateWANAddrs:                           true,
		UIDir:                                       "11IFzAUn",
		UnixSocketUser:                              "E0nB1DwA",
		UnixSocketGroup:                             "8pFodrV8",
		UnixSocketMode:                              "E8sAwOv4",
		VerifyIncoming:                              true,
		VerifyIncomingHTTPS:                         true,
		VerifyIncomingRPC:                           true,
		VerifyOutgoing:                              true,
		VerifyServerHostname:                        true,
	}

	// ensure that all fields are set to unique non-zero values
	// if err := nonZero("RuntimeConfig", nil, want); err != nil {
	// 	t.Fatal(err)
	// }

	for format, s := range src {
		t.Run(format, func(t *testing.T) {
			var flags Flags
			fs := flag.NewFlagSet("", flag.ContinueOnError)
			AddFlags(fs, &flags)
			if err := fs.Parse(flagSrc); err != nil {
				t.Fatalf("ParseFlags: %s", err)
			}

			// ensure that all fields are set to unique non-zero values
			// if err := nonZero("Config", nil, cfg); err != nil {
			// 	t.Fatal(err)
			// }

			b, err := NewBuilder(flags, Config{})
			if err != nil {
				t.Fatalf("NewBuilder: %s", err)
			}
			if err := b.ReadBytes([]byte(s), format); err != nil {
				t.Fatalf("ReadBytes: %s", err)
			}
			rt, warnings, err := b.Build()
			if len(warnings) > 0 {
				t.Fatal("got %d warnings want 0: %v", len(warnings), warnings)
			}
			if !verify.Values(t, "", rt, want) {
				t.FailNow()
			}
		})
	}
}

// nonZero verifies recursively that all fields are set to unique,
// non-zero and non-nil values.
//
// struct: check all fields recursively
// slice: check len > 0 and all values recursively
// ptr: check not nil
// bool: check not zero (cannot check uniqueness)
// string, int, uint: check not zero and unique
// other: error
func nonZero(name string, uniq map[interface{}]string, v interface{}) error {
	if v == nil {
		return fmt.Errorf("%q is nil", name)
	}

	if uniq == nil {
		uniq = map[interface{}]string{}
	}

	isUnique := func(v interface{}) error {
		if other := uniq[v]; other != "" {
			return fmt.Errorf("%q and %q use vaule %q", name, other, v)
		}
		uniq[v] = name
		return nil
	}

	val, typ := reflect.ValueOf(v), reflect.TypeOf(v)
	// fmt.Printf("%s: %T\n", name, v)
	switch typ.Kind() {
	case reflect.Struct:
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			fieldname := fmt.Sprintf("%s.%s", name, f.Name)
			err := nonZero(fieldname, uniq, val.Field(i).Interface())
			if err != nil {
				return err
			}
		}

	case reflect.Slice:
		if val.Len() == 0 {
			return fmt.Errorf("%q is empty slice", name)
		}
		for i := 0; i < val.Len(); i++ {
			elemname := fmt.Sprintf("%s[%d]", name, i)
			err := nonZero(elemname, uniq, val.Index(i).Interface())
			if err != nil {
				return err
			}
		}

	case reflect.Map:
		if val.Len() == 0 {
			return fmt.Errorf("%q is empty map", name)
		}
		for _, key := range val.MapKeys() {
			keyname := fmt.Sprintf("%s[%s]", name, key.String())
			if err := nonZero(keyname, uniq, key.Interface()); err != nil {
				return fmt.Errorf("%q has zero value map key", name)
			}
			if err := nonZero(keyname, uniq, val.MapIndex(key).Interface()); err != nil {
				return err
			}
		}

	case reflect.Bool:
		if val.Bool() != true {
			return fmt.Errorf("%q is zero value", name)
		}
		// do not test bool for uniqueness since there are only two values

	case reflect.String:
		if val.Len() == 0 {
			return fmt.Errorf("%q is zero value", name)
		}
		return isUnique(v)

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if val.Int() == 0 {
			return fmt.Errorf("%q is zero value", name)
		}
		return isUnique(v)

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if val.Uint() == 0 {
			return fmt.Errorf("%q is zero value", name)
		}
		return isUnique(v)

	case reflect.Float32, reflect.Float64:
		if val.Float() == 0 {
			return fmt.Errorf("%q is zero value", name)
		}
		return isUnique(v)

	case reflect.Ptr:
		if val.IsNil() {
			return fmt.Errorf("%q is nil", name)
		}
		return nonZero("*"+name, uniq, val.Elem().Interface())

	default:
		return fmt.Errorf("%T is not supported", v)
	}
	return nil
}

func TestNonZero(t *testing.T) {
	var empty string

	tests := []struct {
		desc string
		v    interface{}
		err  error
	}{
		{"nil", nil, errors.New(`"x" is nil`)},
		{"zero bool", false, errors.New(`"x" is zero value`)},
		{"zero string", "", errors.New(`"x" is zero value`)},
		{"zero int", int(0), errors.New(`"x" is zero value`)},
		{"zero int8", int8(0), errors.New(`"x" is zero value`)},
		{"zero int16", int16(0), errors.New(`"x" is zero value`)},
		{"zero int32", int32(0), errors.New(`"x" is zero value`)},
		{"zero int64", int64(0), errors.New(`"x" is zero value`)},
		{"zero uint", uint(0), errors.New(`"x" is zero value`)},
		{"zero uint8", uint8(0), errors.New(`"x" is zero value`)},
		{"zero uint16", uint16(0), errors.New(`"x" is zero value`)},
		{"zero uint32", uint32(0), errors.New(`"x" is zero value`)},
		{"zero uint64", uint64(0), errors.New(`"x" is zero value`)},
		{"zero float32", float32(0), errors.New(`"x" is zero value`)},
		{"zero float64", float64(0), errors.New(`"x" is zero value`)},
		{"ptr to zero value", &empty, errors.New(`"*x" is zero value`)},
		{"empty slice", []string{}, errors.New(`"x" is empty slice`)},
		{"slice with zero value", []string{""}, errors.New(`"x[0]" is zero value`)},
		{"empty map", map[string]string{}, errors.New(`"x" is empty map`)},
		{"map with zero value key", map[string]string{"": "y"}, errors.New(`"x" has zero value map key`)},
		{"map with zero value elem", map[string]string{"y": ""}, errors.New(`"x[y]" is zero value`)},
		{"struct with nil field", struct{ Y *int }{}, errors.New(`"x.Y" is nil`)},
		{"struct with zero value field", struct{ Y string }{}, errors.New(`"x.Y" is zero value`)},
		{"struct with empty array", struct{ Y []string }{}, errors.New(`"x.Y" is empty slice`)},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			if got, want := nonZero("x", nil, tt.v), tt.err; !reflect.DeepEqual(got, want) {
				t.Fatalf("got error %v want %v", got, want)
			}
		})
	}
}
