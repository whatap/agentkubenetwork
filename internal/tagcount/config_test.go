package tagcount

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func clearTagCountConfigEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"WHATAP_ACCESSKEY", "WHATAP_LICENSE", "WHATAP_SERVER_HOST", "WHATAP_SERVER_PORT", "WHATAP_OBJECT_NAME"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
}

func writeTagCountProperties(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "synthetic.properties")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireConfigRedactedError(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("accepted invalid configuration")
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(err.Error(), secret) {
			t.Fatal("configuration error disclosed a value or original line")
		}
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	clearTagCountConfigEnv(t)
	t.Setenv("WHATAP_ACCESSKEY", "synthetic-environment-key")
	t.Setenv("WHATAP_SERVER_HOST", "collector.example")
	first, err := LoadConfig("", "node-a", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if first.AccessKey != "synthetic-environment-key" {
		t.Fatal("access key was not preserved")
	}
	if !reflect.DeepEqual(first.Servers, []string{"collector.example:6600"}) || first.Timeout != 3*time.Second || first.ObjectName != "kube-network-node-a" {
		t.Fatal("incorrect defaults or timeout")
	}
	second, err := LoadConfig("", "node-a", time.Second)
	if err != nil || second.ObjectName != first.ObjectName {
		t.Fatal("object name is not stable", err)
	}
	first.Servers[0] = "changed.example:1"
	if second.Servers[0] != "collector.example:6600" {
		t.Fatal("configurations share their server slice")
	}
	third, err := LoadConfig("", "node-b", time.Second)
	if err != nil || third.ObjectName != "kube-network-node-b" {
		t.Fatal("default object name does not distinguish nodes", err)
	}
}

func TestLoadConfigProperties(t *testing.T) {
	clearTagCountConfigEnv(t)
	path := writeTagCountProperties(t, "\ufeff# synthetic configuration\r\n! comment\r\n\r\n accesskey = synthetic-file-key== \r\nwhatap.server.host = 192.0.2.10 / collector.example / 2001:db8::1 / [::1]\r\nwhatap.server.port = 7000\r\nwhatap.name = network-observer\r\nother.setting = ignored\r\nother.setting = also-ignored\r\n")
	cfg, err := LoadConfig(path, "ignored-node", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AccessKey != "synthetic-file-key==" {
		t.Fatal("property value containing equals was not preserved")
	}
	want := []string{"192.0.2.10:7000", "collector.example:7000", "[2001:db8::1]:7000", "[::1]:7000"}
	if !reflect.DeepEqual(cfg.Servers, want) || cfg.ObjectName != "network-observer" || cfg.Timeout != 2*time.Second {
		t.Fatal("incorrect properties configuration")
	}
}

func TestLoadConfigEnvironmentPrecedence(t *testing.T) {
	for _, key := range []string{"WHATAP_ACCESSKEY", "WHATAP_LICENSE"} {
		t.Run(key, func(t *testing.T) {
			clearTagCountConfigEnv(t)
			path := writeTagCountProperties(t, "accesskey=synthetic-file-key\nwhatap.server.host=file.example\nwhatap.server.port=7000\nnet_udp_port=7001\nwhatap.name=file-object\n")
			t.Setenv(key, "synthetic-environment-key==")
			t.Setenv("WHATAP_SERVER_HOST", "env.example/2001:db8::2")
			t.Setenv("WHATAP_SERVER_PORT", "8000")
			t.Setenv("WHATAP_OBJECT_NAME", "environment-object")
			cfg, err := LoadConfig(path, "node-a", time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.AccessKey != "synthetic-environment-key==" {
				t.Fatal("environment key did not override file key")
			}
			if !reflect.DeepEqual(cfg.Servers, []string{"env.example:8000", "[2001:db8::2]:8000"}) || cfg.ObjectName != "environment-object" {
				t.Fatal("environment did not override file settings")
			}
		})
	}
}

func TestLoadConfigAccessKeyAliases(t *testing.T) {
	cases := []struct {
		name    string
		text    string
		env     map[string]string
		wantErr bool
	}{
		{name: "file license", text: "license=synthetic-key\n"},
		{name: "matching file aliases", text: "accesskey=synthetic-key\nlicense=synthetic-key\n"},
		{name: "conflicting file aliases", text: "accesskey=synthetic-key\nlicense=synthetic-other-key\n", wantErr: true},
		{name: "empty file alias", text: "accesskey=\nlicense=synthetic-key\n", wantErr: true},
		{name: "environment license", env: map[string]string{"WHATAP_LICENSE": "synthetic-key"}},
		{name: "matching environment aliases", env: map[string]string{"WHATAP_ACCESSKEY": "synthetic-key", "WHATAP_LICENSE": "synthetic-key"}},
		{name: "conflicting environment aliases", env: map[string]string{"WHATAP_ACCESSKEY": "synthetic-key", "WHATAP_LICENSE": "synthetic-other-key"}, wantErr: true},
		{name: "empty environment alias", env: map[string]string{"WHATAP_ACCESSKEY": "", "WHATAP_LICENSE": "synthetic-key"}, wantErr: true},
		{name: "file conflict despite environment", text: "accesskey=synthetic-key\nlicense=synthetic-other-key\n", env: map[string]string{"WHATAP_ACCESSKEY": "synthetic-key"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearTagCountConfigEnv(t)
			t.Setenv("WHATAP_SERVER_HOST", "collector.example")
			for key, val := range tc.env {
				t.Setenv(key, val)
			}
			path := ""
			if tc.text != "" {
				path = writeTagCountProperties(t, tc.text)
			}
			cfg, err := LoadConfig(path, "node-a", time.Second)
			if tc.wantErr {
				requireConfigRedactedError(t, err, "synthetic-key", "synthetic-other-key", tc.text)
				return
			}
			if err != nil || cfg.AccessKey != "synthetic-key" {
				t.Fatal("access key alias was not loaded correctly", err)
			}
		})
	}
}

func TestLoadConfigMissingSettings(t *testing.T) {
	for _, missing := range []string{"both", "key", "host"} {
		t.Run(missing, func(t *testing.T) {
			clearTagCountConfigEnv(t)
			if missing == "key" {
				t.Setenv("WHATAP_SERVER_HOST", "collector.example")
			}
			if missing == "host" {
				t.Setenv("WHATAP_ACCESSKEY", "synthetic-key")
			}
			_, err := LoadConfig("", "node-a", time.Second)
			requireConfigRedactedError(t, err, "synthetic-key")
		})
	}
	for _, timeout := range []time.Duration{0, -time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			clearTagCountConfigEnv(t)
			t.Setenv("WHATAP_ACCESSKEY", "synthetic-key")
			t.Setenv("WHATAP_SERVER_HOST", "collector.example")
			_, err := LoadConfig("", "node-a", timeout)
			requireConfigRedactedError(t, err, "synthetic-key")
		})
	}
}

func TestLoadConfigExplicitEmptyEnvironment(t *testing.T) {
	for _, key := range []string{"WHATAP_ACCESSKEY", "WHATAP_LICENSE", "WHATAP_SERVER_HOST", "WHATAP_SERVER_PORT", "WHATAP_OBJECT_NAME"} {
		for _, empty := range []string{"", " \t "} {
			t.Run(key+"/"+empty, func(t *testing.T) {
				clearTagCountConfigEnv(t)
				path := writeTagCountProperties(t, "accesskey=synthetic-file-key\nwhatap.server.host=file.example\nwhatap.server.port=7000\nnet_udp_port=7001\nwhatap.name=file-object\n")
				t.Setenv(key, empty)
				_, err := LoadConfig(path, "node-a", time.Second)
				requireConfigRedactedError(t, err, "synthetic-file-key")
			})
		}
	}
}

func TestLoadConfigExplicitEmptyProperties(t *testing.T) {
	for _, key := range []string{"accesskey", "license", "whatap.server.host", "whatap.server.port", "net_udp_port", "whatap.name"} {
		t.Run(key, func(t *testing.T) {
			clearTagCountConfigEnv(t)
			text := ""
			if key != "accesskey" && key != "license" {
				text += "accesskey=synthetic-file-key\n"
			}
			if key != "whatap.server.host" {
				text += "whatap.server.host=file.example\n"
			}
			text += key + "=\n"
			_, err := LoadConfig(writeTagCountProperties(t, text), "node-a", time.Second)
			requireConfigRedactedError(t, err, "synthetic-file-key")
		})
	}
}

func TestLoadConfigPortSelection(t *testing.T) {
	cases := []struct {
		name string
		text string
		env  string
		want string
	}{
		{name: "default", want: "6600"},
		{name: "legacy TCP port", text: "net_udp_port=7001\n", want: "7001"},
		{name: "primary over legacy", text: "whatap.server.port=7000\nnet_udp_port=7001\n", want: "7000"},
		{name: "unused legacy", text: "whatap.server.port=7000\nnet_udp_port=synthetic-unused-port\n", want: "7000"},
		{name: "environment over file", text: "whatap.server.port=synthetic-unused-port\nnet_udp_port=7001\n", env: "8000", want: "8000"},
		{name: "minimum", text: "whatap.server.port=1\n", want: "1"},
		{name: "maximum", text: "whatap.server.port=65535\n", want: "65535"},
		{name: "decimal with leading zero", text: "whatap.server.port=06600\n", want: "6600"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearTagCountConfigEnv(t)
			t.Setenv("WHATAP_ACCESSKEY", "synthetic-key")
			t.Setenv("WHATAP_SERVER_HOST", "collector.example")
			if tc.env != "" {
				t.Setenv("WHATAP_SERVER_PORT", tc.env)
			}
			cfg, err := LoadConfig(writeTagCountProperties(t, tc.text), "node-a", time.Second)
			if err != nil || !reflect.DeepEqual(cfg.Servers, []string{"collector.example:" + tc.want}) {
				t.Fatal("incorrect TCP port selection", err)
			}
		})
	}
}

func TestLoadConfigInvalidPorts(t *testing.T) {
	for _, port := range []string{"", "0", "-1", "+6600", "65536", "6.6", "6_600", "6600/tcp", "18446744073709551616", "synthetic-secret-port"} {
		for _, source := range []string{"environment", "whatap.server.port", "net_udp_port"} {
			t.Run(source+"/"+port, func(t *testing.T) {
				clearTagCountConfigEnv(t)
				t.Setenv("WHATAP_ACCESSKEY", "synthetic-key")
				t.Setenv("WHATAP_SERVER_HOST", "collector.example")
				path := ""
				if source == "environment" {
					t.Setenv("WHATAP_SERVER_PORT", port)
				} else {
					path = writeTagCountProperties(t, source+"="+port+"\n")
				}
				_, err := LoadConfig(path, "node-a", time.Second)
				requireConfigRedactedError(t, err, "synthetic-key", "synthetic-secret-port", source+"="+port)
			})
		}
	}
	clearTagCountConfigEnv(t)
	t.Setenv("WHATAP_ACCESSKEY", "synthetic-key")
	t.Setenv("WHATAP_SERVER_HOST", "collector.example")
	_, err := LoadConfig(writeTagCountProperties(t, "whatap.server.port=\nnet_udp_port=7001\n"), "node-a", time.Second)
	requireConfigRedactedError(t, err, "synthetic-key")
}

func TestLoadConfigHosts(t *testing.T) {
	cases := []struct {
		hosts string
		want  []string
	}{
		{hosts: "collector.example", want: []string{"collector.example:6600"}},
		{hosts: "192.0.2.1/192.0.2.2", want: []string{"192.0.2.1:6600", "192.0.2.2:6600"}},
		{hosts: "2001:db8::1/[2001:db8::2]/::ffff:192.0.2.1", want: []string{"[2001:db8::1]:6600", "[2001:db8::2]:6600", "[::ffff:192.0.2.1]:6600"}},
		{hosts: " collector.example / ::1 ", want: []string{"collector.example:6600", "[::1]:6600"}},
	}
	for _, tc := range cases {
		t.Run(tc.hosts, func(t *testing.T) {
			clearTagCountConfigEnv(t)
			t.Setenv("WHATAP_ACCESSKEY", "synthetic-key")
			t.Setenv("WHATAP_SERVER_HOST", tc.hosts)
			cfg, err := LoadConfig("", "node-a", time.Second)
			if err != nil || !reflect.DeepEqual(cfg.Servers, tc.want) {
				t.Fatal("incorrect host list", err)
			}
		})
	}
	for _, hosts := range []string{"", "/collector.example", "collector.example/", "a//b", "a/ /b", "a:6600", "[::1]:6600", "[::1", "::bad:::address", "bad host", "a\nb", "a,b", "https://collector.example"} {
		t.Run("invalid/"+hosts, func(t *testing.T) {
			clearTagCountConfigEnv(t)
			t.Setenv("WHATAP_ACCESSKEY", "synthetic-key")
			t.Setenv("WHATAP_SERVER_HOST", hosts)
			_, err := LoadConfig("", "node-a", time.Second)
			requireConfigRedactedError(t, err, "synthetic-key")
		})
	}
}

func TestLoadConfigRelevantDuplicates(t *testing.T) {
	for _, key := range []string{"accesskey", "license", "whatap.server.host", "whatap.server.port", "net_udp_port", "whatap.name"} {
		t.Run(key, func(t *testing.T) {
			clearTagCountConfigEnv(t)
			t.Setenv("WHATAP_ACCESSKEY", "synthetic-environment-key")
			t.Setenv("WHATAP_SERVER_HOST", "collector.example")
			t.Setenv("WHATAP_SERVER_PORT", "6600")
			t.Setenv("WHATAP_OBJECT_NAME", "network-observer")
			text := key + "=synthetic-duplicate-value\n " + key + " = synthetic-duplicate-value\n"
			_, err := LoadConfig(writeTagCountProperties(t, text), "node-a", time.Second)
			requireConfigRedactedError(t, err, "synthetic-duplicate-value", "synthetic-environment-key", text)
		})
	}
}

func TestLoadConfigMalformedFiles(t *testing.T) {
	for _, text := range []string{"synthetic-secret-without-separator\n", "=synthetic-secret-empty-key\n", "accesskey=synthetic-secret\x00\n", "accesskey=synthetic-secret\xff\n"} {
		t.Run("malformed", func(t *testing.T) {
			clearTagCountConfigEnv(t)
			t.Setenv("WHATAP_ACCESSKEY", "synthetic-environment-key")
			t.Setenv("WHATAP_SERVER_HOST", "collector.example")
			_, err := LoadConfig(writeTagCountProperties(t, text), "node-a", time.Second)
			requireConfigRedactedError(t, err, "synthetic-secret", "synthetic-environment-key", text)
		})
	}
}

func TestLoadConfigFileBoundaryAndType(t *testing.T) {
	clearTagCountConfigEnv(t)
	text := "accesskey=synthetic-boundary-key\nwhatap.server.host=collector.example\n#"
	text += strings.Repeat("x", (64<<10)-len(text))
	if _, err := LoadConfig(writeTagCountProperties(t, text), "node-a", time.Second); err != nil {
		t.Fatal("64 KiB regular configuration rejected", err)
	}
	_, err := LoadConfig(writeTagCountProperties(t, text+"x"), "node-a", time.Second)
	requireConfigRedactedError(t, err, "synthetic-boundary-key")
	_, err = LoadConfig(t.TempDir(), "node-a", time.Second)
	requireConfigRedactedError(t, err)
	t.Setenv("WHATAP_ACCESSKEY", "synthetic-environment-key")
	t.Setenv("WHATAP_SERVER_HOST", "collector.example")
	_, err = LoadConfig(filepath.Join(t.TempDir(), "synthetic-secret-path"), "node-a", time.Second)
	requireConfigRedactedError(t, err, "synthetic-secret-path", "synthetic-environment-key")
}

func TestLoadConfigDoesNotReadImplicitFile(t *testing.T) {
	clearTagCountConfigEnv(t)
	t.Chdir(t.TempDir())
	if err := os.WriteFile("whatap.conf", []byte("accesskey=synthetic-implicit-key\nwhatap.server.host=collector.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig("", "node-a", time.Second)
	requireConfigRedactedError(t, err, "synthetic-implicit-key")
}
