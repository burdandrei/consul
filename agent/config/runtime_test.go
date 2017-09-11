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
	randomString := func(n int) string {
		s := ""
		for ; n > 0; n-- {
			s += "x"
		}
		return s
	}

	metaPairs := func(n int, format string) string {
		var s []string
		for i := 0; i < n; i++ {
			switch format {
			case "json":
				s = append(s, fmt.Sprintf(`"%d":"%d"`, i, i))
			case "hcl":
				s = append(s, fmt.Sprintf(`"%d"="%d"`, i, i))
			default:
				panic("invalid format: " + format)
			}
		}
		switch format {
		case "json":
			return strings.Join(s, ",")
		case "hcl":
			return strings.Join(s, " ")
		default:
			panic("invalid format: " + format)
		}
	}

	tests := []struct {
		desc     string
		flags    []string
		json     []string
		hcl      []string
		patch    func(rt *RuntimeConfig)
		err      error
		warns    []string
		hostname func() (string, error)
	}{
		// ------------------------------------------------------------
		// cmd line flags
		//

		{
			desc:  "-advertise",
			flags: []string{`-advertise`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.AdvertiseAddrLAN = "a"
			},
		},
		{
			desc:  "-advertise-wan",
			flags: []string{`-advertise-wan`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.AdvertiseAddrWAN = "a"
			},
		},
		{
			desc:  "-bind",
			flags: []string{`-bind`, `1.2.3.4`},
			patch: func(rt *RuntimeConfig) {
				rt.BindAddrs = []string{"1.2.3.4"}
			},
		},
		{
			desc:  "-bootstrap",
			flags: []string{`-bootstrap`, `-server`},
			patch: func(rt *RuntimeConfig) {
				rt.Bootstrap = true
				rt.ServerMode = true
				rt.LeaveOnTerm = false
				rt.SkipLeaveOnInt = true
			},
			warns: []string{"Bootstrap mode enabled! Do not enable unless necessary"},
		},
		{
			desc:  "-bootstrap-expect",
			flags: []string{`-bootstrap-expect`, `3`, `-server`},
			patch: func(rt *RuntimeConfig) {
				rt.BootstrapExpect = 3
				rt.ServerMode = true
				rt.LeaveOnTerm = false
				rt.SkipLeaveOnInt = true
			},
			warns: []string{"BootstrapExpect mode enabled, expecting 3 servers"},
		},
		{
			desc:  "-client",
			flags: []string{`-client`, `1.2.3.4`},
			patch: func(rt *RuntimeConfig) {
				rt.ClientAddrs = []string{"1.2.3.4"}
				rt.DNSAddrs = []string{"1.2.3.4:8600"}
				rt.HTTPAddrs = []string{"1.2.3.4:8500"}
			},
		},
		{
			desc:  "-data-dir",
			flags: []string{`-data-dir`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.DataDir = "a"
			},
		},
		{
			desc:  "-datacenter",
			flags: []string{`-datacenter`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.Datacenter = "a"
			},
		},
		{
			desc:  "-dev",
			flags: []string{`-dev`},
			patch: func(rt *RuntimeConfig) {
				rt.DevMode = true
			},
		},
		{
			desc:  "-disable-host-node-id",
			flags: []string{`-disable-host-node-id`},
			patch: func(rt *RuntimeConfig) {
				rt.DisableHostNodeID = true
			},
		},
		{
			desc:  "-disable-keyring-file",
			flags: []string{`-disable-keyring-file`},
			patch: func(rt *RuntimeConfig) {
				rt.DisableKeyringFile = true
			},
		},
		{
			desc:  "-dns-port",
			flags: []string{`-dns-port`, `123`},
			patch: func(rt *RuntimeConfig) {
				rt.DNSPort = 123
				rt.DNSAddrs = []string{"127.0.0.1:123"}
			},
		},
		{
			desc:  "-domain",
			flags: []string{`-domain`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.DNSDomain = "a"
			},
		},
		{
			desc:  "-enable-script-checks",
			flags: []string{`-enable-script-checks`},
			patch: func(rt *RuntimeConfig) {
				rt.EnableScriptChecks = true
			},
		},
		{ // todo(fs): shouldn't this be '-encrypt-key'?
			desc:  "-encrypt",
			flags: []string{`-encrypt`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.EncryptKey = "a"
			},
		},
		{
			desc:  "-http-port",
			flags: []string{`-http-port`, `123`},
			patch: func(rt *RuntimeConfig) {
				rt.HTTPPort = 123
				rt.HTTPAddrs = []string{"127.0.0.1:123"}
			},
		},
		{
			desc:  "-join",
			flags: []string{`-join`, `a`, `-join`, `b`},
			patch: func(rt *RuntimeConfig) {
				rt.StartJoinAddrsLAN = []string{"a", "b"}
			},
		},
		{
			desc:  "-join-wan",
			flags: []string{`-join-wan`, `a`, `-join-wan`, `b`},
			patch: func(rt *RuntimeConfig) {
				rt.StartJoinAddrsWAN = []string{"a", "b"}
			},
		},
		{
			desc:  "-log-level",
			flags: []string{`-log-level`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.LogLevel = "a"
			},
		},
		{ // todo(fs): shouldn't this be '-node-name'?
			desc:  "-node",
			flags: []string{`-node`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.NodeName = "a"
			},
		},
		{
			desc:  "-node-id",
			flags: []string{`-node-id`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.NodeID = "a"
			},
		},
		{
			desc:  "-node-meta",
			flags: []string{`-node-meta`, `a:b`, `-node-meta`, `c:d`},
			patch: func(rt *RuntimeConfig) {
				rt.NodeMeta = map[string]string{"a": "b", "c": "d"}
			},
		},
		{
			desc:  "-non-voting-server",
			flags: []string{`-non-voting-server`},
			patch: func(rt *RuntimeConfig) {
				rt.NonVotingServer = true
			},
		},
		{
			desc:  "-pid-file",
			flags: []string{`-pid-file`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.PidFile = "a"
			},
		},
		{
			desc:  "-protocol",
			flags: []string{`-protocol`, `1`},
			patch: func(rt *RuntimeConfig) {
				rt.RPCProtocol = 1
			},
		},
		{
			desc:  "-raft-protocol",
			flags: []string{`-raft-protocol`, `1`},
			patch: func(rt *RuntimeConfig) {
				rt.RaftProtocol = 1
			},
		},
		{
			desc:  "-recursor",
			flags: []string{`-recursor`, `a`, `-recursor`, `b`},
			patch: func(rt *RuntimeConfig) {
				rt.DNSRecursors = []string{"a", "b"}
			},
		},
		{
			desc:  "-rejoin",
			flags: []string{`-rejoin`},
			patch: func(rt *RuntimeConfig) {
				rt.RejoinAfterLeave = true
			},
		},
		{
			desc:  "-retry-interval",
			flags: []string{`-retry-interval`, `5s`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinIntervalLAN = 5 * time.Second
			},
		},
		{
			desc:  "-retry-interval-wan",
			flags: []string{`-retry-interval-wan`, `5s`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinIntervalWAN = 5 * time.Second
			},
		},
		{
			desc:  "-retry-join",
			flags: []string{`-retry-join`, `a`, `-retry-join`, `b`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinLAN = []string{"a", "b"}
			},
		},
		{
			desc:  "-retry-join-wan",
			flags: []string{`-retry-join-wan`, `a`, `-retry-join-wan`, `b`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinWAN = []string{"a", "b"}
			},
		},
		{
			desc:  "-retry-max",
			flags: []string{`-retry-max`, `1`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinMaxAttemptsLAN = 1
			},
		},
		{
			desc:  "-retry-max-wan",
			flags: []string{`-retry-max-wan`, `1`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinMaxAttemptsWAN = 1
			},
		},
		{
			desc:  "-serf-lan-bind",
			flags: []string{`-serf-lan-bind`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.SerfBindAddrLAN = "a"
			},
		},
		{
			desc:  "-serf-wan-bind",
			flags: []string{`-serf-wan-bind`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.SerfBindAddrWAN = "a"
			},
		},
		{
			desc:  "-server",
			flags: []string{`-server`},
			patch: func(rt *RuntimeConfig) {
				rt.ServerMode = true
				rt.LeaveOnTerm = false
				rt.SkipLeaveOnInt = true
			},
		},
		{
			desc:  "-syslog",
			flags: []string{`-syslog`},
			patch: func(rt *RuntimeConfig) {
				rt.EnableSyslog = true
			},
		},
		{
			desc:  "-ui",
			flags: []string{`-ui`},
			patch: func(rt *RuntimeConfig) {
				rt.EnableUI = true
			},
		},
		{
			desc:  "-ui-dir",
			flags: []string{`-ui-dir`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.UIDir = "a"
			},
		},

		// ------------------------------------------------------------
		// deprecated flags
		//

		{
			desc:  "-atlas",
			flags: []string{`-atlas`, `a`},
			warns: []string{`'-atlas' is deprecated`},
		},
		{
			desc:  "-atlas-join",
			flags: []string{`-atlas-join`},
			warns: []string{`'-atlas-join' is deprecated`},
		},
		{
			desc:  "-atlas-endpoint",
			flags: []string{`-atlas-endpoint`, `a`},
			warns: []string{`'-atlas-endpoint' is deprecated`},
		},
		{
			desc:  "-atlas-token",
			flags: []string{`-atlas-token`, `a`},
			warns: []string{`'-atlas-token' is deprecated`},
		},
		{
			desc:  "-dc",
			flags: []string{`-dc`, `a`},
			warns: []string{`'-dc' is deprecated. Use '-datacenter' instead`},
			patch: func(rt *RuntimeConfig) {
				rt.Datacenter = "a"
			},
		},
		{
			desc:  "-retry-join-azure-tag-name",
			flags: []string{`-retry-join-azure-tag-name`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinLAN = []string{"provider=azure tag_name=a"}
			},
			warns: []string{`config: retry_join_azure is deprecated. Please add "provider=azure tag_name=a" to retry_join.`},
		},
		{
			desc:  "-retry-join-azure-tag-value",
			flags: []string{`-retry-join-azure-tag-value`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinLAN = []string{"provider=azure tag_value=a"}
			},
			warns: []string{`config: retry_join_azure is deprecated. Please add "provider=azure tag_value=a" to retry_join.`},
		},
		{
			desc:  "-retry-join-ec2-region",
			flags: []string{`-retry-join-ec2-region`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinLAN = []string{"provider=aws region=a"}
			},
			warns: []string{`config: retry_join_ec2 is deprecated. Please add "provider=aws region=a" to retry_join.`},
		},
		{
			desc:  "-retry-join-ec2-tag-key",
			flags: []string{`-retry-join-ec2-tag-key`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinLAN = []string{"provider=aws tag_key=a"}
			},
			warns: []string{`config: retry_join_ec2 is deprecated. Please add "provider=aws tag_key=a" to retry_join.`},
		},
		{
			desc:  "-retry-join-ec2-tag-value",
			flags: []string{`-retry-join-ec2-tag-value`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinLAN = []string{"provider=aws tag_value=a"}
			},
			warns: []string{`config: retry_join_ec2 is deprecated. Please add "provider=aws tag_value=a" to retry_join.`},
		},
		{
			desc:  "-retry-join-gce-credentials-file",
			flags: []string{`-retry-join-gce-credentials-file`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinLAN = []string{"provider=gce credentials_file=a"}
			},
			warns: []string{`config: retry_join_gce is deprecated. Please add "provider=gce credentials_file=hidden" to retry_join.`},
		},
		{
			desc:  "-retry-join-gce-project-name",
			flags: []string{`-retry-join-gce-project-name`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinLAN = []string{"provider=gce project_name=a"}
			},
			warns: []string{`config: retry_join_gce is deprecated. Please add "provider=gce project_name=a" to retry_join.`},
		},
		{
			desc:  "-retry-join-gce-tag-value",
			flags: []string{`-retry-join-gce-tag-value`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinLAN = []string{"provider=gce tag_value=a"}
			},
			warns: []string{`config: retry_join_gce is deprecated. Please add "provider=gce tag_value=a" to retry_join.`},
		},
		{
			desc:  "-retry-join-gce-zone-pattern",
			flags: []string{`-retry-join-gce-zone-pattern`, `a`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinLAN = []string{"provider=gce zone_pattern=a"}
			},
			warns: []string{`config: retry_join_gce is deprecated. Please add "provider=gce zone_pattern=a" to retry_join.`},
		},

		// ------------------------------------------------------------
		// deprecated fields
		//

		{
			desc: "check.service_id alias",
			json: []string{`{"check":{ "service_id":"d", "serviceid":"dd" }}`},
			hcl:  []string{`check = { service_id="d" serviceid="dd" }`},
			patch: func(rt *RuntimeConfig) {
				rt.Checks = []*structs.CheckDefinition{{ServiceID: "dd"}}
			},
			warns: []string{`config: "serviceid" is deprecated in check definitions. Please use "service_id" instead.`},
		},
		{
			desc: "check.docker_container_id alias",
			json: []string{`{"check":{ "docker_container_id":"k", "dockercontainerid":"kk" }}`},
			hcl:  []string{`check = { docker_container_id="k" dockercontainerid="kk" }`},
			patch: func(rt *RuntimeConfig) {
				rt.Checks = []*structs.CheckDefinition{{DockerContainerID: "kk"}}
			},
			warns: []string{`config: "dockercontainerid" is deprecated in check definitions. Please use "docker_container_id" instead.`},
		},
		{
			desc: "check.tls_skip_verify alias",
			json: []string{`{"check":{ "tls_skip_verify":true, "tlsskipverify":false }}`},
			hcl:  []string{`check = { tls_skip_verify=true tlsskipverify=false }`},
			patch: func(rt *RuntimeConfig) {
				rt.Checks = []*structs.CheckDefinition{{TLSSkipVerify: false}}
			},
			warns: []string{`config: "tlsskipverify" is deprecated in check definitions. Please use "tls_skip_verify" instead.`},
		},
		{
			desc: "check.deregister_critical_service_after alias",
			json: []string{`{"check":{ "deregister_critical_service_after":"5s", "deregistercriticalserviceafter": "10s" }}`},
			hcl:  []string{`check = { deregister_critical_service_after="5s" deregistercriticalserviceafter="10s"}`},
			patch: func(rt *RuntimeConfig) {
				rt.Checks = []*structs.CheckDefinition{{DeregisterCriticalServiceAfter: 10 * time.Second}}
			},
			warns: []string{`config: "deregistercriticalserviceafter" is deprecated in check definitions. Please use "deregister_critical_service_after" instead.`},
		},
		{
			desc: "http_api_response_headers",
			json: []string{`{"http_api_response_headers":{"a":"b","c":"d"}}`},
			hcl:  []string{`http_api_response_headers = {"a"="b" "c"="d"}`},
			patch: func(rt *RuntimeConfig) {
				rt.HTTPResponseHeaders = map[string]string{"a": "b", "c": "d"}
			},
			warns: []string{`config: "http_api_response_headers" is deprecated. Please use "http_config.response_headers" instead.`},
		},
		{
			desc: "retry_join_azure",
			json: []string{`{
					"retry_join_azure":{
						"tag_name": "a",
						"tag_value": "b",
						"subscription_id": "c",
						"tenant_id": "d",
						"client_id": "e",
						"secret_access_key": "f"
					}
				}`},
			hcl: []string{`
					retry_join_azure = {
						tag_name = "a"
						tag_value = "b"
						subscription_id = "c"
						tenant_id = "d"
						client_id = "e"
						secret_access_key = "f"
					}
				`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinLAN = []string{"provider=azure client_id=e secret_access_key=f subscription_id=c tag_name=a tag_value=b tenant_id=d"}
			},
			warns: []string{`config: retry_join_azure is deprecated. Please add "provider=azure client_id=hidden secret_access_key=hidden subscription_id=hidden tag_name=a tag_value=b tenant_id=hidden" to retry_join.`},
		},
		{
			desc: "retry_join_ec2",
			json: []string{`{
					"retry_join_ec2":{
						"tag_key": "a",
						"tag_value": "b",
						"region": "c",
						"access_key_id": "d",
						"secret_access_key": "e"
					}
				}`},
			hcl: []string{`
					retry_join_ec2 = {
						tag_key = "a"
						tag_value = "b"
						region = "c"
						access_key_id = "d"
						secret_access_key = "e"
					}
				`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinLAN = []string{"provider=aws access_key_id=d region=c secret_access_key=e tag_key=a tag_value=b"}
			},
			warns: []string{`config: retry_join_ec2 is deprecated. Please add "provider=aws access_key_id=hidden region=c secret_access_key=hidden tag_key=a tag_value=b" to retry_join.`},
		},
		{
			desc: "retry_join_gce",
			json: []string{`{
					"retry_join_gce":{
						"project_name": "a",
						"zone_pattern": "b",
						"tag_value": "c",
						"credentials_file": "d"
					}
				}`},
			hcl: []string{`
					retry_join_gce = {
						project_name = "a"
						zone_pattern = "b"
						tag_value = "c"
						credentials_file = "d"
					}
				`},
			patch: func(rt *RuntimeConfig) {
				rt.RetryJoinLAN = []string{"provider=gce credentials_file=d project_name=a tag_value=c zone_pattern=b"}
			},
			warns: []string{`config: retry_join_gce is deprecated. Please add "provider=gce credentials_file=hidden project_name=a tag_value=c zone_pattern=b" to retry_join.`},
		},

		{
			desc:  "telemetry.dogstatsd_addr alias",
			json:  []string{`{"dogstatsd_addr":"a", "telemetry":{"dogstatsd_addr": "b"}}`},
			hcl:   []string{`dogstatsd_addr = "a" telemetry = { dogstatsd_addr = "b"}`},
			warns: []string{`config: "dogstatsd_addr" is deprecated. Please use "telemetry.dogstatsd_addr" instead.`},
			patch: func(rt *RuntimeConfig) {
				rt.TelemetryDogstatsdAddr = "a"
			},
		},
		{
			desc:  "telemetry.dogstatsd_tags alias",
			json:  []string{`{"dogstatsd_tags":["a", "b"], "telemetry": { "dogstatsd_tags": ["c", "d"]}}`},
			hcl:   []string{`dogstatsd_tags = ["a", "b"] telemetry = { dogstatsd_tags = ["c", "d"] }`},
			warns: []string{`config: "dogstatsd_tags" is deprecated. Please use "telemetry.dogstatsd_tags" instead.`},
			patch: func(rt *RuntimeConfig) {
				rt.TelemetryDogstatsdTags = []string{"a", "b", "c", "d"}
			},
		},
		{
			desc:  "telemetry.statsd_addr alias",
			json:  []string{`{"statsd_addr":"a", "telemetry":{"statsd_addr": "b"}}`},
			hcl:   []string{`statsd_addr = "a" telemetry = { statsd_addr = "b" }`},
			warns: []string{`config: "statsd_addr" is deprecated. Please use "telemetry.statsd_addr" instead.`},
			patch: func(rt *RuntimeConfig) {
				rt.TelemetryStatsdAddr = "a"
			},
		},
		{
			desc:  "telemetry.statsite_addr alias",
			json:  []string{`{"statsite_addr":"a", "telemetry":{ "statsite_addr": "b" }}`},
			hcl:   []string{`statsite_addr = "a" telemetry = { statsite_addr = "b"}`},
			warns: []string{`config: "statsite_addr" is deprecated. Please use "telemetry.statsite_addr" instead.`},
			patch: func(rt *RuntimeConfig) {
				rt.TelemetryStatsiteAddr = "a"
			},
		},
		{
			desc:  "telemetry.statsite_prefix alias",
			json:  []string{`{"statsite_prefix":"a", "telemetry":{ "statsite_prefix": "b" }}`},
			hcl:   []string{`statsite_prefix = "a" telemetry = { statsite_prefix = "b" }`},
			warns: []string{`config: "statsite_prefix" is deprecated. Please use "telemetry.statsite_prefix" instead.`},
			patch: func(rt *RuntimeConfig) {
				rt.TelemetryStatsitePrefix = "a"
			},
		},

		// ------------------------------------------------------------
		// ports and addresses
		//

		{
			desc: "client addr and ports == 0",
			json: []string{`{
					"client_addr":"0.0.0.0",
					"ports":{}
				}`},
			hcl: []string{`
					client_addr = "0.0.0.0"
					ports {}
				`},
			patch: func(rt *RuntimeConfig) {
				rt.ClientAddrs = []string{"0.0.0.0"}
				rt.DNSAddrs = []string{":8600"}
				rt.HTTPAddrs = []string{":8500"}
			},
		},
		{
			desc: "client addr and ports < 0",
			json: []string{`{
					"client_addr":"0.0.0.0",
					"ports": { "dns":-1, "http":-2, "https":-3 }
				}`},
			hcl: []string{`
					client_addr = "0.0.0.0"
					ports { dns = -1 http = -2 https = -3 }
				`},
			patch: func(rt *RuntimeConfig) {
				rt.ClientAddrs = []string{"0.0.0.0"}
				rt.DNSPort = 0
				rt.DNSAddrs = []string{}
				rt.HTTPPort = 0
				rt.HTTPAddrs = []string{}
			},
		},
		{
			desc: "client addr and ports < 0",
			json: []string{`{
					"client_addr":"0.0.0.0",
					"ports": { "dns":-1, "http":-2, "https":-3 }
				}`},
			hcl: []string{`
					client_addr = "0.0.0.0"
					ports { dns = -1 http = -2 https = -3 }
				`},
			patch: func(rt *RuntimeConfig) {
				rt.ClientAddrs = []string{"0.0.0.0"}
				rt.DNSPort = 0
				rt.DNSAddrs = []string{}
				rt.HTTPPort = 0
				rt.HTTPAddrs = []string{}
			},
		},
		{
			desc: "client addr and ports > 0",
			json: []string{`{
					"client_addr":"0.0.0.0",
					"ports":{ "dns": 1, "http": 2, "https": 3 }
				}`},
			hcl: []string{`
					client_addr = "0.0.0.0"
					ports { dns = 1 http = 2 https = 3 }
				`},
			patch: func(rt *RuntimeConfig) {
				rt.ClientAddrs = []string{"0.0.0.0"}
				rt.DNSPort = 1
				rt.DNSAddrs = []string{":1"}
				rt.HTTPPort = 2
				rt.HTTPAddrs = []string{":2"}
				rt.HTTPSPort = 3
				rt.HTTPSAddrs = []string{":3"}
			},
		},

		{
			desc: "client addr, addresses and ports == 0",
			json: []string{`{
					"client_addr":"0.0.0.0",
					"addresses": { "dns": "1.1.1.1", "http": "2.2.2.2", "https": "3.3.3.3" },
					"ports":{}
				}`},
			hcl: []string{`
					client_addr = "0.0.0.0"
					addresses = { dns = "1.1.1.1" http = "2.2.2.2" https = "3.3.3.3" }
					ports {}
				`},
			patch: func(rt *RuntimeConfig) {
				rt.ClientAddrs = []string{"0.0.0.0"}
				rt.DNSAddrs = []string{"1.1.1.1:8600"}
				rt.HTTPAddrs = []string{"2.2.2.2:8500"}
			},
		},
		{
			desc: "client addr, addresses and ports < 0",
			json: []string{`{
					"client_addr":"0.0.0.0",
					"addresses": { "dns": "1.1.1.1", "http": "2.2.2.2", "https": "3.3.3.3" },
					"ports": { "dns":-1, "http":-2, "https":-3 }
				}`},
			hcl: []string{`
					client_addr = "0.0.0.0"
					addresses = { dns = "1.1.1.1" http = "2.2.2.2" https = "3.3.3.3" }
					ports { dns = -1 http = -2 https = -3 }
				`},
			patch: func(rt *RuntimeConfig) {
				rt.ClientAddrs = []string{"0.0.0.0"}
				rt.DNSPort = 0
				rt.DNSAddrs = []string{}
				rt.HTTPPort = 0
				rt.HTTPAddrs = []string{}
			},
		},
		{
			desc: "client addr, addresses and ports",
			json: []string{`{
					"client_addr": "0.0.0.0",
					"addresses": { "dns": "1.1.1.1", "http": "2.2.2.2", "https": "3.3.3.3" },
					"ports":{ "dns":1, "http":2, "https":3 }
				}`},
			hcl: []string{`
					client_addr = "0.0.0.0"
					addresses = { dns = "1.1.1.1" http = "2.2.2.2" https = "3.3.3.3" }
					ports { dns = 1 http = 2 https = 3 }
				`},
			patch: func(rt *RuntimeConfig) {
				rt.ClientAddrs = []string{"0.0.0.0"}
				rt.DNSPort = 1
				rt.DNSAddrs = []string{"1.1.1.1:1"}
				rt.HTTPPort = 2
				rt.HTTPAddrs = []string{"2.2.2.2:2"}
				rt.HTTPSPort = 3
				rt.HTTPSAddrs = []string{"3.3.3.3:3"}
			},
		},
		{
			desc: "client template and ports",
			json: []string{`{
					"client_addr": "{{ printf \"1.2.3.4 2001:db8::1\" }}",
					"ports":{ "dns":1, "http":2, "https":3 }
				}`},
			hcl: []string{`
					client_addr = "{{ printf \"1.2.3.4 2001:db8::1\" }}"
					ports { dns = 1 http = 2 https = 3 }
				`},
			patch: func(rt *RuntimeConfig) {
				rt.ClientAddrs = []string{"1.2.3.4", "2001:db8::1"}
				rt.DNSPort = 1
				rt.DNSAddrs = []string{"1.2.3.4:1", "[2001:db8::1]:1"}
				rt.HTTPPort = 2
				rt.HTTPAddrs = []string{"1.2.3.4:2", "[2001:db8::1]:2"}
				rt.HTTPSPort = 3
				rt.HTTPSAddrs = []string{"1.2.3.4:3", "[2001:db8::1]:3"}
			},
		},
		{
			desc: "client, address template and ports",
			json: []string{`{
					"client_addr": "{{ printf \"1.2.3.4 unix://foo 2001:db8::1\" }}",
					"addresses": {
						"dns": "{{ printf \"1.1.1.1 unix://dns 2001:db8::10 \" }}",
						"http": "{{ printf \"2.2.2.2 unix://http 2001:db8::20 \" }}",
						"https": "{{ printf \"3.3.3.3 unix://https 2001:db8::30 \" }}"
					},
					"ports":{ "dns":1, "http":2, "https":3 }
				}`},
			hcl: []string{`
					client_addr = "{{ printf \"1.2.3.4 unix://foo 2001:db8::1\" }}"
					addresses = {
						dns = "{{ printf \"1.1.1.1 unix://dns 2001:db8::10 \" }}"
						http = "{{ printf \"2.2.2.2 unix://http 2001:db8::20 \" }}"
						https = "{{ printf \"3.3.3.3 unix://https 2001:db8::30 \" }}"
					}
					ports { dns = 1 http = 2 https = 3 }
				`},
			patch: func(rt *RuntimeConfig) {
				rt.ClientAddrs = []string{"1.2.3.4", "unix://foo", "2001:db8::1"}
				rt.DNSPort = 1
				rt.DNSAddrs = []string{"1.1.1.1:1", "unix://dns", "[2001:db8::10]:1"}
				rt.HTTPPort = 2
				rt.HTTPAddrs = []string{"2.2.2.2:2", "unix://http", "[2001:db8::20]:2"}
				rt.HTTPSPort = 3
				rt.HTTPSAddrs = []string{"3.3.3.3:3", "unix://https", "[2001:db8::30]:3"}
			},
		},
		{
			desc: "advertise address lan template",
			json: []string{`{ "advertise_addr": "{{ printf \"1.2.3.4\" }}" }`},
			hcl:  []string{`advertise_addr = "{{ printf \"1.2.3.4\" }}"`},
			patch: func(rt *RuntimeConfig) {
				rt.AdvertiseAddrLAN = "1.2.3.4"
			},
		},
		{
			desc: "advertise address wan template",
			json: []string{`{ "advertise_addr_wan": "{{ printf \"1.2.3.4\" }}" }`},
			hcl:  []string{`advertise_addr_wan = "{{ printf \"1.2.3.4\" }}"`},
			patch: func(rt *RuntimeConfig) {
				rt.AdvertiseAddrWAN = "1.2.3.4"
			},
		},
		{
			desc: "serf advertise address lan template",
			json: []string{`{ "advertise_addrs": { "serf_lan": "{{ printf \"1.2.3.4\" }}" } }`},
			hcl:  []string{`advertise_addrs = { serf_lan = "{{ printf \"1.2.3.4\" }}" }`},
			patch: func(rt *RuntimeConfig) {
				rt.SerfAdvertiseAddrLAN = "1.2.3.4"
			},
		},
		{
			desc: "serf advertise address wan template",
			json: []string{`{ "advertise_addrs": { "serf_wan": "{{ printf \"1.2.3.4\" }}" } }`},
			hcl:  []string{`advertise_addrs = { serf_wan = "{{ printf \"1.2.3.4\" }}" }`},
			patch: func(rt *RuntimeConfig) {
				rt.SerfAdvertiseAddrWAN = "1.2.3.4"
			},
		},
		{
			desc: "serf bind address lan template",
			json: []string{`{ "serf_lan": "{{ printf \"1.2.3.4\" }}" }`},
			hcl:  []string{`serf_lan = "{{ printf \"1.2.3.4\" }}"`},
			patch: func(rt *RuntimeConfig) {
				rt.SerfBindAddrLAN = "1.2.3.4"
			},
		},
		{
			desc: "serf bind address wan template",
			json: []string{`{ "serf_wan": "{{ printf \"1.2.3.4\" }}" }`},
			hcl:  []string{`serf_wan = "{{ printf \"1.2.3.4\" }}"`},
			patch: func(rt *RuntimeConfig) {
				rt.SerfBindAddrWAN = "1.2.3.4"
			},
		},

		// ------------------------------------------------------------
		// precedence rules
		//

		{
			desc: "precedence: merge order",
			json: []string{
				`{
						"bootstrap": true,
						"bootstrap_expect": 1,
						"datacenter": "a",
						"start_join": ["a", "b"],
						"node_meta": {"a":"b"}
					}`,
				`{
						"bootstrap": false,
						"bootstrap_expect": 0,
						"datacenter":"b",
						"start_join": ["c", "d"],
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
					bootstrap_expect = 0
					datacenter = "b"
					start_join = ["c", "d"]
					node_meta = { "c" = "d" }
					`,
			},
			patch: func(rt *RuntimeConfig) {
				rt.Bootstrap = false
				rt.BootstrapExpect = 0
				rt.Datacenter = "b"
				rt.StartJoinAddrsLAN = []string{"a", "b", "c", "d"}
				rt.NodeMeta = map[string]string{"c": "d"}
			},
		},
		{
			desc: "precedence: flag before file",
			json: []string{
				`{
						"advertise_addr": "a",
						"advertise_addr_wan": "a",
						"bootstrap":true,
						"bootstrap_expect": 1,
						"datacenter":"a",
						"node_meta": {"a":"b"},
						"recursors":["a", "b"],
						"serf_lan": "a",
						"serf_wan": "a",
						"start_join":["a", "b"]
					}`,
			},
			hcl: []string{
				`
					advertise_addr = "a"
					advertise_addr_wan = "a"
					bootstrap = true
					bootstrap_expect = 1
					datacenter = "a"
					node_meta = { "a" = "b" }
					recursors = ["a", "b"]
					serf_lan = "a"
					serf_wan = "a"
					start_join = ["a", "b"]
					`,
			},
			flags: []string{
				`-advertise`, `b`,
				`-advertise-wan`, `b`,
				`-bootstrap=false`,
				`-bootstrap-expect=0`,
				`-datacenter=b`,
				`-join`, `c`, `-join`, `d`,
				`-node-meta`, `c:d`,
				`-recursor`, `c`, `-recursor`, `d`,
				`-serf-lan-bind`, `b`,
				`-serf-wan-bind`, `b`,
			},
			patch: func(rt *RuntimeConfig) {
				rt.AdvertiseAddrLAN = "b"
				rt.AdvertiseAddrWAN = "b"
				rt.Datacenter = "b"
				rt.DNSRecursors = []string{"c", "d", "a", "b"}
				rt.NodeMeta = map[string]string{"c": "d"}
				rt.SerfBindAddrLAN = "b"
				rt.SerfBindAddrWAN = "b"
				rt.StartJoinAddrsLAN = []string{"c", "d", "a", "b"}
			},
		},

		// ------------------------------------------------------------
		// validations
		//

		{
			desc: "datacenter is lower-cased",
			json: []string{`{ "datacenter": "A" }`},
			hcl:  []string{`datacenter = "A"`},
			patch: func(rt *RuntimeConfig) {
				rt.Datacenter = "a"
			},
		},
		{
			desc: "acl_datacenter is lower-cased",
			json: []string{`{ "acl_datacenter": "A" }`},
			hcl:  []string{`acl_datacenter = "A"`},
			patch: func(rt *RuntimeConfig) {
				rt.ACLDatacenter = "a"
			},
		},
		{
			desc: "datacenter invalid",
			json: []string{`{ "datacenter": "%" }`},
			hcl:  []string{`datacenter = "%"`},
			err:  errors.New("Datacenter must be alpha-numeric with underscores and hyphens only"),
		},
		{
			desc:  "acl_datacenter invalid",
			flags: []string{`-datacenter=a`},
			json:  []string{`{ "acl_datacenter": "%" }`},
			hcl:   []string{`acl_datacenter = "%"`},
			err:   errors.New("ACL datacenter must be alpha-numeric with underscores and hyphens only"),
		},
		{
			desc:  "autopilot.max_trailing_logs invalid",
			flags: []string{`-datacenter=a`},
			json:  []string{`{ "autopilot": { "max_trailing_logs": -1 } }`},
			hcl:   []string{`autopilot = { max_trailing_logs = -1 }`},
			err:   errors.New("autopilot.max_trailing_logs < 0"),
		},
		{
			desc:  "bootstrap without server",
			flags: []string{`-datacenter=a`},
			json:  []string{`{ "bootstrap": true }`},
			hcl:   []string{`bootstrap = true`},
			err:   errors.New("Bootstrap mode requires Server mode"),
		},
		{
			desc:  "bootstrap-expect without server",
			flags: []string{`-datacenter=a`},
			json:  []string{`{ "bootstrap_expect": 3 }`},
			hcl:   []string{`bootstrap_expect = 3`},
			err:   errors.New("BootstrapExpect mode requires Server mode"),
		},
		{
			desc:  "bootstrap-expect invalid",
			flags: []string{`-datacenter=a`},
			json:  []string{`{ "bootstrap_expect": -1 }`},
			hcl:   []string{`bootstrap_expect = -1`},
			err:   errors.New("BootstrapExpect cannot be negative"),
		},
		{
			desc:  "bootstrap-expect and dev mode",
			flags: []string{`-datacenter=a`, `-dev`},
			json:  []string{`{ "bootstrap_expect": 3, "server": true }`},
			hcl:   []string{`bootstrap_expect = 3 server = true`},
			err:   errors.New("BootstrapExpect mode cannot be enabled in dev mode"),
		},
		{
			desc:  "bootstrap-expect and boostrap",
			flags: []string{`-datacenter=a`},
			json:  []string{`{ "bootstrap": true, "bootstrap_expect": 3, "server": true }`},
			hcl:   []string{`bootstrap = true bootstrap_expect = 3 server = true`},
			err:   errors.New("BootstrapExpect mode and Bootstrap mode are mutually exclusive"),
		},
		{
			desc:  "enable_ui and ui_dir",
			flags: []string{`-datacenter=a`},
			json:  []string{`{ "enable_ui": true, "ui_dir": "a" }`},
			hcl:   []string{`enable_ui = true ui_dir = "a"`},
			err: errors.New("Both the ui and ui-dir flags were specified, please provide only one.\n" +
				"If trying to use your own web UI resources, use the ui-dir flag.\n" +
				"If using Consul version 0.7.0 or later, the web UI is included in the binary so use ui to enable it"),
		},
		{
			desc:  "advertise_addr ipv4 any",
			flags: []string{`-datacenter=a`},
			json:  []string{`{ "advertise_addr": "0.0.0.0" }`},
			hcl:   []string{`advertise_addr = "0.0.0.0"`},
			err:   errors.New("Advertise address cannot be 0.0.0.0"),
		},
		{
			desc:  "advertise_addr ipv6 any",
			flags: []string{`-datacenter=a`},
			json:  []string{`{ "advertise_addr": "::" }`},
			hcl:   []string{`advertise_addr = "::"`},
			err:   errors.New("Advertise address cannot be ::"),
		},
		{
			desc:  "advertise_addr ipv6 any brackets",
			flags: []string{`-datacenter=a`},
			json:  []string{`{ "advertise_addr": "[::]" }`},
			hcl:   []string{`advertise_addr = "[::]"`},
			err:   errors.New("Advertise address cannot be [::]"),
		},
		{
			desc:  "advertise_addr_wan ipv4 any",
			flags: []string{`-datacenter=a`},
			json:  []string{`{ "advertise_addr_wan": "0.0.0.0" }`},
			hcl:   []string{`advertise_addr_wan = "0.0.0.0"`},
			err:   errors.New("Advertise WAN address cannot be 0.0.0.0"),
		},
		{
			desc:  "advertise_addr_wan ipv6 any",
			flags: []string{`-datacenter=a`},
			json:  []string{`{ "advertise_addr_wan": "::" }`},
			hcl:   []string{`advertise_addr_wan = "::"`},
			err:   errors.New("Advertise WAN address cannot be ::"),
		},
		{
			desc:  "advertise_addr_wan ipv6 any brackets",
			flags: []string{`-datacenter=a`},
			json:  []string{`{ "advertise_addr_wan": "[::]" }`},
			hcl:   []string{`advertise_addr_wan = "[::]"`},
			err:   errors.New("Advertise WAN address cannot be [::]"),
		},
		{
			desc:  "dns_config.udp_answer_limit invalid",
			flags: []string{`-datacenter=a`},
			json:  []string{`{ "dns_config": { "udp_answer_limit": 0 } }`},
			hcl:   []string{`dns_config = { udp_answer_limit = 0 }`},
			err:   errors.New("dns_config.udp_answer_limit must be > 0"),
		},
		{
			desc:  "dns_config.udp_answer_limit invalid",
			flags: []string{`-datacenter=a`},
			json:  []string{`{ "dns_config": { "udp_answer_limit": 0 } }`},
			hcl:   []string{`dns_config = { udp_answer_limit = 0 }`},
			err:   errors.New("dns_config.udp_answer_limit must be > 0"),
		},
		{
			desc:     "node_name invalid",
			flags:    []string{`-datacenter=a`},
			hostname: func() (string, error) { return "", nil },
			err:      errors.New("Node name cannot be empty"),
		},
		{
			desc:  "node_meta key too long",
			flags: []string{`-datacenter=a`},
			json: []string{
				`{ "dns_config": { "udp_answer_limit": 1 } }`,
				`{ "node_meta": { "` + randomString(130) + `": "a" } }`,
			},
			hcl: []string{
				`dns_config = { udp_answer_limit = 1 }`,
				`node_meta = { "` + randomString(130) + `" = "a" }`,
			},
			err: errors.New("Failed to parse node metadata: Couldn't load metadata pair ('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'a'): Key is too long (limit: 128 characters)"),
		},
		{
			desc:  "node_meta value too long",
			flags: []string{`-datacenter=a`},
			json: []string{
				`{ "dns_config": { "udp_answer_limit": 1 } }`,
				`{ "node_meta": { "a": "` + randomString(520) + `" } }`,
			},
			hcl: []string{
				`dns_config = { udp_answer_limit = 1 }`,
				`node_meta = { "a" = "` + randomString(520) + `" }`,
			},
			err: errors.New("Failed to parse node metadata: Couldn't load metadata pair ('a', 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'): Value is too long (limit: 512 characters)"),
		},
		{
			desc:  "node_meta too many keys",
			flags: []string{`-datacenter=a`},
			json: []string{
				`{ "dns_config": { "udp_answer_limit": 1 } }`,
				`{ "node_meta": {` + metaPairs(70, "json") + `} }`,
			},
			hcl: []string{
				`dns_config = { udp_answer_limit = 1 }`,
				`node_meta = {` + metaPairs(70, "hcl") + ` }`,
			},
			err: errors.New("Failed to parse node metadata: Node metadata cannot contain more than 64 key/value pairs"),
		},
		{
			desc:  "unique listeners dns vs http",
			flags: []string{`-datacenter=a`},
			json: []string{`{
					"client_addr": "1.2.3.4",
					"ports": { "dns": 1000, "http": 1000 },
					"dns_config": { "udp_answer_limit": 1 }
				}`},
			hcl: []string{`
					client_addr = "1.2.3.4"
					ports = { dns = 1000 http = 1000 }
					dns_config = { udp_answer_limit = 1 }
				`},
			err: errors.New("HTTP address 1.2.3.4:1000 already configured for DNS"),
		},
		{
			desc:  "unique listeners dns vs https",
			flags: []string{`-datacenter=a`},
			json: []string{`{
					"client_addr": "1.2.3.4",
					"ports": { "dns": 1000, "https": 1000 },
					"dns_config": { "udp_answer_limit": 1 }
				}`},
			hcl: []string{`
					client_addr = "1.2.3.4"
					ports = { dns = 1000 https = 1000 }
					dns_config = { udp_answer_limit = 1 }
				`},
			err: errors.New("HTTPS address 1.2.3.4:1000 already configured for DNS"),
		},
		{
			desc:  "unique listeners http vs https",
			flags: []string{`-datacenter=a`},
			json: []string{`{
					"client_addr": "1.2.3.4",
					"ports": { "http": 1000, "https": 1000 },
					"dns_config": { "udp_answer_limit": 1 }
				}`},
			hcl: []string{`
					client_addr = "1.2.3.4"
					ports = { http = 1000 https = 1000 }
					dns_config = { udp_answer_limit = 1 }
				`},
			err: errors.New("HTTPS address 1.2.3.4:1000 already configured for HTTP"),
		},
	}

	for _, tt := range tests {
		for pass, format := range []string{"json", "hcl"} {
			// when we test only flags then there are no JSON or HCL
			// sources and we need to make only one pass over the
			// tests.
			flagsOnly := len(tt.json) == 0 && len(tt.hcl) == 0
			if flagsOnly && pass > 0 {
				continue
			}

			// json and hcl sources need to be in sync
			// to make sure we're generating the same config
			if len(tt.json) != len(tt.hcl) {
				t.Fatal("JSON and HCL test case out of sync")
			}

			// select the source
			srcs := tt.json
			if format == "hcl" {
				srcs = tt.hcl
			}

			// build the description
			var desc []string
			if !flagsOnly {
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

				// mock the hostname function unless a mock is provided
				hostnameFn := tt.hostname
				if hostnameFn == nil {
					hostnameFn = func() (string, error) { return "nodex", nil }
				}

				// create the builder with the flags
				b := &Builder{
					Flags:    flags,
					Default:  &defaultConfig,
					Hostname: hostnameFn,
				}
				if flags.DevMode != nil && *flags.DevMode {
					b.Default = &defaultDevConfig
				}

				// read the source fragements
				for _, src := range srcs {
					if err := b.ReadBytes([]byte(src), format); err != nil {
						t.Fatalf("ReadBytes failed for %q: %s", src, err)
					}
				}

				// build/merge the config fragments
				rt, err := b.BuildAndValidate()
				if got, want := err, tt.err; !reflect.DeepEqual(got, want) {
					t.Fatalf("got error %v want %v", got, want)
				}

				// check the warnings
				if !verify.Values(t, "warnings", b.Warnings, tt.warns) {
					t.FailNow()
				}

				// stop if we expected an error
				if tt.err != nil {
					return
				}

				// build the runtime config we expect
				// from the same default config and patch it
				x := &Builder{Default: b.Default, Hostname: b.Hostname}
				wantRT, err := x.Build()
				if err != nil {
					t.Fatalf("build default failed: %s", err)
				}
				if tt.patch != nil {
					tt.patch(&wantRT)
				}
				if err := x.Validate(wantRT); err != nil {
					t.Fatalf("validate default failed: %s", err)
				}
				if got, want := rt, wantRT; !verify.Values(t, "", got, want) {
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
	flagSrc := []string{}
	src := map[string]string{
		"json": `{
			"acl_agent_master_token": "furuQD0b",
			"acl_agent_token": "cOshLOQ2",
			"acl_datacenter": "m3urck3z",
			"acl_default_policy": "ArK3WIfE",
			"acl_down_policy": "vZXMfMP0",
			"acl_enforce_version_8": true,
			"acl_master_token": "C1Q1oIwh",
			"acl_replication_token": "LMmgy5dO",
			"acl_token": "O1El0wan",
			"acl_ttl": "18060s",
			"addresses": {
				"dns": "kEtdOtsn",
				"http": "uCOhLXzi",
				"https": "z4j7tmn2"
			},
			"advertise_addr": "zkCS5pci",
			"advertise_addr_wan": "587rk4R8",
			"advertise_addrs": {
				"serf_lan": "XPYfEKBY",
				"serf_wan": "53wnhkCC"
			},
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
			"bootstrap": false,
			"bootstrap_expect": 53,
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
						"ZBfTin3L": [ "1sDbEqYG", "lJGASsWK" ],
						"Ui0nU99X": [ "LMccm3Qe", "k5H5RggQ" ]
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
			"datacenter": "rzo029wg",
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
			"enable_ui": false,
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
			"serf_lan": "bdJGdMtR",
			"serf_wan": "rSfygrZH",
			"server": true,
			"server_name": "Oerr9n1G",
			"service": {
				"id": "dLOXpSCI",
				"name": "o1ynPkp0",
				"tags": ["nkwshvM5", "NTDWn3ek"],
				"address": "cOlSOhbp",
				"token": "msy7iWER",
				"port": 24237,
				"enable_tag_override": true,
				"check": {
					"check_id": "RMi85Dv8",
					"name": "iehanzuq",
					"status": "rCvn53TH",
					"notes": "fti5lfF3",
					"script": "rtj34nfd",
					"http": "dl3Fgme3",
					"header": {
						"rjm4DEd3": ["2m3m2Fls"],
						"l4HwQ112": ["fk56MNlo", "dhLK56aZ"]
					},
					"method": "9afLm3Mj",
					"tcp": "fjiLFqVd",
					"interval": "23926s",
					"docker_container_id": "dO5TtRHk",
					"shell": "e6q2ttES",
					"tls_skip_verify": true,
					"timeout": "38483s",
					"ttl": "10943s",
					"deregister_critical_service_after": "68787s"
				},
				"checks": [
					{
						"id": "Zv99e9Ka",
						"name": "sgV4F7Pk",
						"notes": "yP5nKbW0",
						"status": "7oLMEyfu",
						"script": "NlUQ3nTE",
						"http": "KyDjGY9H",
						"header": {
							"gv5qefTz": [ "5Olo2pMG", "PvvKWQU5" ],
							"SHOVq1Vv": [ "jntFhyym", "GYJh32pp" ]
						},
						"method": "T66MFBfR",
						"tcp": "bNnNfx2A",
						"interval": "22224s",
						"docker_container_id": "ipgdFtjd",
						"shell": "omVZq7Sz",
						"tls_skip_verify": true,
						"timeout": "18913s",
						"ttl": "44743s",
						"deregister_critical_service_after": "8482s"
					},
					{
						"id": "G79O6Mpr",
						"name": "IEqrzrsd",
						"notes": "SVqApqeM",
						"status": "XXkVoZXt",
						"script": "IXLZTM6E",
						"http": "kyICZsn8",
						"header": {
							"4ebP5vL4": [ "G20SrL5Q", "DwPKlMbo" ],
							"p2UI34Qz": [ "UsG1D0Qh", "NHhRiB6s" ]
						},
						"method": "ciYHWors",
						"tcp": "FfvCwlqH",
						"interval": "12356s",
						"docker_container_id": "HBndBU6R",
						"shell": "hVI33JjA",
						"tls_skip_verify": true,
						"timeout": "38282s",
						"ttl": "1181s",
						"deregister_critical_service_after": "4992s"
					}
				]
			},
			"services": [
				{
					"id": "wI1dzxS4",
					"name": "7IszXMQ1",
					"tags": ["0Zwg8l6v", "zebELdN5"],
					"address": "9RhqPSPB",
					"token": "myjKJkWH",
					"port": 72219,
					"enable_tag_override": true,
					"check": {
						"check_id": "qmfeO5if",
						"name": "atDGP7n5",
						"status": "pDQKEhWL",
						"notes": "Yt8EDLev",
						"script": "MDu7wjlD",
						"http": "qzHYvmJO",
						"header": {
							"UkpmZ3a3": ["2dfzXuxZ"],
							"cVFpko4u": ["gGqdEB6k", "9LsRo22u"]
						},
						"method": "X5DrovFc",
						"tcp": "ICbxkpSF",
						"interval": "24392s",
						"docker_container_id": "ZKXr68Yb",
						"shell": "CEfzx0Fo",
						"tls_skip_verify": true,
						"timeout": "38333s",
						"ttl": "57201s",
						"deregister_critical_service_after": "44214s"
					}
				},
				{
					"id": "MRHVMZuD",
					"name": "6L6BVfgH",
					"tags": ["7Ale4y6o", "PMBW08hy"],
					"address": "R6H6g8h0",
					"token": "ZgY8gjMI",
					"port": 38292,
					"enable_tag_override": true,
					"checks": [
						{
							"id": "GTti9hCo",
							"name": "9OOS93ne",
							"notes": "CQy86DH0",
							"status": "P0SWDvrk",
							"script": "6BhLJ7R9",
							"http": "u97ByEiW",
							"header": {
								"MUlReo8L": [ "AUZG7wHG", "gsN0Dc2N" ],
								"1UJXjVrT": [ "OJgxzTfk", "xZZrFsq7" ]
							},
							"method": "5wkAxCUE",
							"tcp": "MN3oA9D2",
							"interval": "32718s",
							"docker_container_id": "cU15LMet",
							"shell": "nEz9qz2l",
							"tls_skip_verify": true,
							"timeout": "34738s",
							"ttl": "22773s",
							"deregister_critical_service_after": "84282s"
						},
						{
							"id": "UHsDeLxG",
							"name": "PQSaPWlT",
							"notes": "jKChDOdl",
							"status": "5qFz6OZn",
							"script": "PbdxFZ3K",
							"http": "1LBDJhw4",
							"header": {
								"cXPmnv1M": [ "imDqfaBx", "NFxZ1bQe" ],
								"vr7wY7CS": [ "EtCoNPPL", "9vAarJ5s" ]
							},
							"method": "wzByP903",
							"tcp": "2exjZIGE",
							"interval": "5656s",
							"docker_container_id": "5tDBWpfA",
							"shell": "rlTpLM8s",
							"tls_skip_verify": true,
							"timeout": "4868s",
							"ttl": "11222s",
							"deregister_critical_service_after": "68482s"
						}
					]
				}
			],
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
			acl_datacenter = "m3urck3z"
			acl_default_policy = "ArK3WIfE"
			acl_down_policy = "vZXMfMP0"
			acl_enforce_version_8 = true
			acl_master_token = "C1Q1oIwh"
			acl_replication_token = "LMmgy5dO"
			acl_token = "O1El0wan"
			acl_ttl = "18060s"
			addresses = {
				dns = "kEtdOtsn"
				http = "uCOhLXzi"
				https = "z4j7tmn2"
			}
			advertise_addr = "zkCS5pci"
			advertise_addr_wan = "587rk4R8"
			advertise_addrs = {
				serf_lan = "XPYfEKBY"
				serf_wan = "53wnhkCC"
			}
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
			bootstrap = false
			bootstrap_expect = 53
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
						"ZBfTin3L" = [ "1sDbEqYG", "lJGASsWK" ]
						"Ui0nU99X" = [ "LMccm3Qe", "k5H5RggQ" ]
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
			datacenter = "rzo029wg"
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
			enable_ui = false
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
			serf_lan = "bdJGdMtR"
			serf_wan = "rSfygrZH"
			server = true
			server_name = "Oerr9n1G"
			service = {
				id = "dLOXpSCI"
				name = "o1ynPkp0"
				tags = ["nkwshvM5", "NTDWn3ek"]
				address = "cOlSOhbp"
				token = "msy7iWER"
				port = 24237
				enable_tag_override = true
				check = {
					check_id = "RMi85Dv8"
					name = "iehanzuq"
					status = "rCvn53TH"
					notes = "fti5lfF3"
					script = "rtj34nfd"
					http = "dl3Fgme3"
					header = {
						rjm4DEd3 = [ "2m3m2Fls" ]
						l4HwQ112 = [ "fk56MNlo", "dhLK56aZ" ]
					}
					method = "9afLm3Mj"
					tcp = "fjiLFqVd"
					interval = "23926s"
					docker_container_id = "dO5TtRHk"
					shell = "e6q2ttES"
					tls_skip_verify = true
					timeout = "38483s"
					ttl = "10943s"
					deregister_critical_service_after = "68787s"
				}
				checks = [
					{
						id = "Zv99e9Ka"
						name = "sgV4F7Pk"
						notes = "yP5nKbW0"
						status = "7oLMEyfu"
						script = "NlUQ3nTE"
						http = "KyDjGY9H"
						header = {
							"gv5qefTz" = [ "5Olo2pMG", "PvvKWQU5" ]
							"SHOVq1Vv" = [ "jntFhyym", "GYJh32pp" ]
						}
						method = "T66MFBfR"
						tcp = "bNnNfx2A"
						interval = "22224s"
						docker_container_id = "ipgdFtjd"
						shell = "omVZq7Sz"
						tls_skip_verify = true
						timeout = "18913s"
						ttl = "44743s"
						deregister_critical_service_after = "8482s"
					},
					{
						id = "G79O6Mpr"
						name = "IEqrzrsd"
						notes = "SVqApqeM"
						status = "XXkVoZXt"
						script = "IXLZTM6E"
						http = "kyICZsn8"
						header = {
							"4ebP5vL4" = [ "G20SrL5Q", "DwPKlMbo" ]
							"p2UI34Qz" = [ "UsG1D0Qh", "NHhRiB6s" ]
						}
						method = "ciYHWors"
						tcp = "FfvCwlqH"
						interval = "12356s"
						docker_container_id = "HBndBU6R"
						shell = "hVI33JjA"
						tls_skip_verify = true
						timeout = "38282s"
						ttl = "1181s"
						deregister_critical_service_after = "4992s"
					}
				]
			}
			services = [
				{
					id = "wI1dzxS4"
					name = "7IszXMQ1"
					tags = ["0Zwg8l6v", "zebELdN5"]
					address = "9RhqPSPB"
					token = "myjKJkWH"
					port = 72219
					enable_tag_override = true
					check = {
						check_id = "qmfeO5if"
						name = "atDGP7n5"
						status = "pDQKEhWL"
						notes = "Yt8EDLev"
						script = "MDu7wjlD"
						http = "qzHYvmJO"
						header = {
							UkpmZ3a3 = [ "2dfzXuxZ" ]
							cVFpko4u = [ "gGqdEB6k", "9LsRo22u" ]
						}
						method = "X5DrovFc"
						tcp = "ICbxkpSF"
						interval = "24392s"
						docker_container_id = "ZKXr68Yb"
						shell = "CEfzx0Fo"
						tls_skip_verify = true
						timeout = "38333s"
						ttl = "57201s"
						deregister_critical_service_after = "44214s"
					}
				},
				{
					id = "MRHVMZuD"
					name = "6L6BVfgH"
					tags = ["7Ale4y6o", "PMBW08hy"]
					address = "R6H6g8h0"
					token = "ZgY8gjMI"
					port = 38292
					enable_tag_override = true
					checks = [
						{
							id = "GTti9hCo"
							name = "9OOS93ne"
							notes = "CQy86DH0"
							status = "P0SWDvrk"
							script = "6BhLJ7R9"
							http = "u97ByEiW"
							header = {
								"MUlReo8L" = [ "AUZG7wHG", "gsN0Dc2N" ]
								"1UJXjVrT" = [ "OJgxzTfk", "xZZrFsq7" ]
							}
							method = "5wkAxCUE"
							tcp = "MN3oA9D2"
							interval = "32718s"
							docker_container_id = "cU15LMet"
							shell = "nEz9qz2l"
							tls_skip_verify = true
							timeout = "34738s"
							ttl = "22773s"
							deregister_critical_service_after = "84282s"
						},
						{
							id = "UHsDeLxG"
							name = "PQSaPWlT"
							notes = "jKChDOdl"
							status = "5qFz6OZn"
							script = "PbdxFZ3K"
							http = "1LBDJhw4"
							header = {
								"cXPmnv1M" = [ "imDqfaBx", "NFxZ1bQe" ],
								"vr7wY7CS" = [ "EtCoNPPL", "9vAarJ5s" ]
							}
							method = "wzByP903"
							tcp = "2exjZIGE"
							interval = "5656s"
							docker_container_id = "5tDBWpfA"
							shell = "rlTpLM8s"
							tls_skip_verify = true
							timeout = "4868s"
							ttl = "11222s"
							deregister_critical_service_after = "68482s"
						}
					]
				}
			]
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
		ACLDatacenter:                    "m3urck3z",
		ACLDefaultPolicy:                 "ArK3WIfE",
		ACLDownPolicy:                    "vZXMfMP0",
		ACLEnforceVersion8:               true,
		ACLMasterToken:                   "C1Q1oIwh",
		ACLReplicationToken:              "LMmgy5dO",
		ACLTTL:                           18060 * time.Second,
		ACLToken:                         "O1El0wan",
		AdvertiseAddrLAN:                 "zkCS5pci",
		AdvertiseAddrWAN:                 "587rk4R8",
		AutopilotCleanupDeadServers:      true,
		AutopilotDisableUpgradeMigration: true,
		AutopilotLastContactThreshold:    12705 * time.Second,
		AutopilotMaxTrailingLogs:         17849,
		AutopilotRedundancyZoneTag:       "3IsufDJf",
		AutopilotServerStabilizationTime: 23057 * time.Second,
		AutopilotUpgradeVersionTag:       "W9pDwFAL",
		BindAddrs:                        []string{"6rFPKyh6"},
		Bootstrap:                        false,
		BootstrapExpect:                  53,
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
					"ZBfTin3L": []string{"1sDbEqYG", "lJGASsWK"},
					"Ui0nU99X": []string{"LMccm3Qe", "k5H5RggQ"},
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
		CheckUpdateInterval:       16507 * time.Second,
		ClientAddrs:               []string{"e15dFavQ"},
		DNSAddrs:                  []string{"kEtdOtsn:7001"},
		DNSAllowStale:             true,
		DNSDisableCompression:     true,
		DNSDomain:                 "7W1xXSqd",
		DNSEnableTruncate:         true,
		DNSMaxStale:               29685 * time.Second,
		DNSNodeTTL:                7084 * time.Second,
		DNSOnlyPassing:            true,
		DNSPort:                   7001,
		DNSRecursorTimeout:        4427 * time.Second,
		DNSRecursors:              []string{"EZX7MOYF", "FtFhoUHl", "UYkwck1k"},
		DNSServiceTTL:             map[string]time.Duration{"*": 32030 * time.Second},
		DNSUDPAnswerLimit:         29909,
		DataDir:                   "oTOOIoV9",
		Datacenter:                "rzo029wg",
		DevMode:                   false,
		DisableAnonymousSignature: true,
		DisableCoordinates:        true,
		DisableHostNodeID:         true,
		DisableKeyringFile:        true,
		DisableRemoteExec:         true,
		DisableUpdateCheck:        true,
		EnableACLReplication:      true,
		EnableDebug:               true,
		EnableScriptChecks:        true,
		EnableSyslog:              true,
		EnableUI:                  false,
		EncryptKey:                "A4wELWqH",
		EncryptVerifyIncoming:     true,
		EncryptVerifyOutgoing:     true,
		HTTPAddrs:                 []string{"uCOhLXzi:7999"},
		HTTPBlockEndpoints:        []string{"RBvAFcGD", "fWOWFznh"},
		HTTPPort:                  7999,
		HTTPResponseHeaders:       map[string]string{"M6TKa9NP": "xjuxjOzQ", "JRCrHZed": "rl0mTx81"},
		HTTPSAddrs:                []string{"z4j7tmn2:15127"},
		HTTPSPort:                 15127,
		KeyFile:                   "IEkkwgIA",
		LeaveOnTerm:               true,
		LogLevel:                  "k1zo9Spt",
		NodeID:                    "AsUIlw99",
		NodeMeta:                  map[string]string{"5mgGQMBk": "mJLtVMSG", "A7ynFMJB": "0Nx6RGab"},
		NodeName:                  "otlLxGaI",
		NonVotingServer:           true,
		PerformanceRaftMultiplier: 22057,
		PidFile:                   "43xN80Km",
		RPCProtocol:               30793,
		RaftProtocol:              19016,
		ReconnectTimeoutLAN:       23739 * time.Second,
		ReconnectTimeoutWAN:       26694 * time.Second,
		RejoinAfterLeave:          true,
		RetryJoinIntervalLAN:      8067 * time.Second,
		RetryJoinIntervalWAN:      28866 * time.Second,
		RetryJoinLAN:              []string{"pbsSFY7U", "l0qLtWij"},
		RetryJoinMaxAttemptsLAN:   913,
		RetryJoinMaxAttemptsWAN:   23160,
		RetryJoinWAN:              []string{"PFsR02Ye", "rJdQIhER"},
		ServerMode:                true,
		ServerName:                "Oerr9n1G",
		Services: []*structs.ServiceDefinition{
			{
				ID:                "wI1dzxS4",
				Name:              "7IszXMQ1",
				Tags:              []string{"0Zwg8l6v", "zebELdN5"},
				Address:           "9RhqPSPB",
				Token:             "myjKJkWH",
				Port:              72219,
				EnableTagOverride: true,
				Checks: []*structs.CheckType{
					&structs.CheckType{
						CheckID: "qmfeO5if",
						Name:    "atDGP7n5",
						Status:  "pDQKEhWL",
						Notes:   "Yt8EDLev",
						Script:  "MDu7wjlD",
						HTTP:    "qzHYvmJO",
						Header: map[string][]string{
							"UkpmZ3a3": {"2dfzXuxZ"},
							"cVFpko4u": {"gGqdEB6k", "9LsRo22u"},
						},
						Method:            "X5DrovFc",
						TCP:               "ICbxkpSF",
						Interval:          24392 * time.Second,
						DockerContainerID: "ZKXr68Yb",
						Shell:             "CEfzx0Fo",
						TLSSkipVerify:     true,
						Timeout:           38333 * time.Second,
						TTL:               57201 * time.Second,
						DeregisterCriticalServiceAfter: 44214 * time.Second,
					},
				},
			},
			{
				ID:                "MRHVMZuD",
				Name:              "6L6BVfgH",
				Tags:              []string{"7Ale4y6o", "PMBW08hy"},
				Address:           "R6H6g8h0",
				Token:             "ZgY8gjMI",
				Port:              38292,
				EnableTagOverride: true,
				Checks: structs.CheckTypes{
					&structs.CheckType{
						CheckID: "GTti9hCo",
						Name:    "9OOS93ne",
						Notes:   "CQy86DH0",
						Status:  "P0SWDvrk",
						Script:  "6BhLJ7R9",
						HTTP:    "u97ByEiW",
						Header: map[string][]string{
							"MUlReo8L": {"AUZG7wHG", "gsN0Dc2N"},
							"1UJXjVrT": {"OJgxzTfk", "xZZrFsq7"},
						},
						Method:            "5wkAxCUE",
						TCP:               "MN3oA9D2",
						Interval:          32718 * time.Second,
						DockerContainerID: "cU15LMet",
						Shell:             "nEz9qz2l",
						TLSSkipVerify:     true,
						Timeout:           34738 * time.Second,
						TTL:               22773 * time.Second,
						DeregisterCriticalServiceAfter: 84282 * time.Second,
					},
					&structs.CheckType{
						CheckID: "UHsDeLxG",
						Name:    "PQSaPWlT",
						Notes:   "jKChDOdl",
						Status:  "5qFz6OZn",
						Script:  "PbdxFZ3K",
						HTTP:    "1LBDJhw4",
						Header: map[string][]string{
							"cXPmnv1M": {"imDqfaBx", "NFxZ1bQe"},
							"vr7wY7CS": {"EtCoNPPL", "9vAarJ5s"},
						},
						Method:            "wzByP903",
						TCP:               "2exjZIGE",
						Interval:          5656 * time.Second,
						DockerContainerID: "5tDBWpfA",
						Shell:             "rlTpLM8s",
						TLSSkipVerify:     true,
						Timeout:           4868 * time.Second,
						TTL:               11222 * time.Second,
						DeregisterCriticalServiceAfter: 68482 * time.Second,
					},
				},
			},
			{
				ID:                "dLOXpSCI",
				Name:              "o1ynPkp0",
				Tags:              []string{"nkwshvM5", "NTDWn3ek"},
				Address:           "cOlSOhbp",
				Token:             "msy7iWER",
				Port:              24237,
				EnableTagOverride: true,
				Checks: structs.CheckTypes{
					&structs.CheckType{
						CheckID: "Zv99e9Ka",
						Name:    "sgV4F7Pk",
						Notes:   "yP5nKbW0",
						Status:  "7oLMEyfu",
						Script:  "NlUQ3nTE",
						HTTP:    "KyDjGY9H",
						Header: map[string][]string{
							"gv5qefTz": {"5Olo2pMG", "PvvKWQU5"},
							"SHOVq1Vv": {"jntFhyym", "GYJh32pp"},
						},
						Method:            "T66MFBfR",
						TCP:               "bNnNfx2A",
						Interval:          22224 * time.Second,
						DockerContainerID: "ipgdFtjd",
						Shell:             "omVZq7Sz",
						TLSSkipVerify:     true,
						Timeout:           18913 * time.Second,
						TTL:               44743 * time.Second,
						DeregisterCriticalServiceAfter: 8482 * time.Second,
					},
					&structs.CheckType{
						CheckID: "G79O6Mpr",
						Name:    "IEqrzrsd",
						Notes:   "SVqApqeM",
						Status:  "XXkVoZXt",
						Script:  "IXLZTM6E",
						HTTP:    "kyICZsn8",
						Header: map[string][]string{
							"4ebP5vL4": {"G20SrL5Q", "DwPKlMbo"},
							"p2UI34Qz": {"UsG1D0Qh", "NHhRiB6s"},
						},
						Method:            "ciYHWors",
						TCP:               "FfvCwlqH",
						Interval:          12356 * time.Second,
						DockerContainerID: "HBndBU6R",
						Shell:             "hVI33JjA",
						TLSSkipVerify:     true,
						Timeout:           38282 * time.Second,
						TTL:               1181 * time.Second,
						DeregisterCriticalServiceAfter: 4992 * time.Second,
					},
					&structs.CheckType{
						CheckID: "RMi85Dv8",
						Name:    "iehanzuq",
						Status:  "rCvn53TH",
						Notes:   "fti5lfF3",
						Script:  "rtj34nfd",
						HTTP:    "dl3Fgme3",
						Header: map[string][]string{
							"rjm4DEd3": {"2m3m2Fls"},
							"l4HwQ112": {"fk56MNlo", "dhLK56aZ"},
						},
						Method:            "9afLm3Mj",
						TCP:               "fjiLFqVd",
						Interval:          23926 * time.Second,
						DockerContainerID: "dO5TtRHk",
						Shell:             "e6q2ttES",
						TLSSkipVerify:     true,
						Timeout:           38483 * time.Second,
						TTL:               10943 * time.Second,
						DeregisterCriticalServiceAfter: 68787 * time.Second,
					},
				},
			},
		},
		SerfAdvertiseAddrLAN:                        "XPYfEKBY",
		SerfAdvertiseAddrWAN:                        "53wnhkCC",
		SerfBindAddrLAN:                             "bdJGdMtR",
		SerfBindAddrWAN:                             "rSfygrZH",
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

	warns := []string{
		"BootstrapExpect mode enabled, expecting 53 servers",
	}

	// ensure that all fields are set to unique non-zero values
	// todo(fs): This currently fails since ServiceDefinition.Check is not used
	// if err := nonZero("RuntimeConfig", nil, want); err != nil {
	// t.Fatal(err)
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
			// t.Fatal(err)
			// }

			b := &Builder{Flags: flags, Default: &Config{}}
			if err := b.ReadBytes([]byte(s), format); err != nil {
				t.Fatalf("ReadBytes: %s", err)
			}
			rt, err := b.Build()
			if err != nil {
				t.Fatalf("Build: %s", err)
			}
			if err := b.Validate(rt); err != nil {
				t.Fatalf("Validate: %s", err)
			}
			if got, want := b.Warnings, warns; !verify.Values(t, "warnings", got, want) {
				t.FailNow()
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
			return fmt.Errorf("%q and %q both use vaule %q", name, other, v)
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
				if strings.Contains(err.Error(), "is zero value") {
					return fmt.Errorf("%q has zero value map key", name)
				}
				return err
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
