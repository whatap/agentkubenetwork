package tagcount

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/whatap/agentkubenetwork/internal/whatap"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxConfigFileSize = 64 << 10

// LoadConfig reads only the explicitly supplied properties file and environment.
// The returned access key is for authentication and must not be logged.
func LoadConfig(path string, nodeName string, timeout time.Duration) (whatap.Config, error) {
	properties := make(map[string]string)
	if path != "" {
		var err error
		properties, err = readConfigProperties(path)
		if err != nil {
			return whatap.Config{}, err
		}
	}
	accessKey, hasAccessKey := properties["accesskey"]
	license, hasLicense := properties["license"]
	if hasAccessKey && hasLicense && accessKey != license {
		return whatap.Config{}, errors.New("conflicting access key aliases in configuration")
	}
	if !hasAccessKey {
		accessKey = license
	}
	envAccessKey, hasEnvAccessKey := os.LookupEnv("WHATAP_ACCESSKEY")
	envLicense, hasEnvLicense := os.LookupEnv("WHATAP_LICENSE")
	if hasEnvAccessKey && hasEnvLicense && envAccessKey != envLicense {
		return whatap.Config{}, errors.New("conflicting access key aliases in environment")
	}
	if hasEnvAccessKey {
		accessKey = envAccessKey
	} else if hasEnvLicense {
		accessKey = envLicense
	}
	if strings.TrimSpace(accessKey) == "" {
		return whatap.Config{}, errors.New("access key is required")
	}
	if timeout <= 0 {
		return whatap.Config{}, errors.New("positive collector timeout is required")
	}
	objectName := configSetting(properties, "whatap.name", "WHATAP_OBJECT_NAME", "kube-network-"+nodeName)
	if strings.TrimSpace(objectName) == "" {
		return whatap.Config{}, errors.New("collector object name is required")
	}
	port, hasPort := properties["net_udp_port"]
	if !hasPort {
		port = "6600"
	}
	port = configSetting(properties, "whatap.server.port", "WHATAP_SERVER_PORT", port)
	hosts := configSetting(properties, "whatap.server.host", "WHATAP_SERVER_HOST", "")
	servers, err := configServers(hosts, port)
	if err != nil {
		return whatap.Config{}, err
	}
	return whatap.Config{AccessKey: accessKey, Servers: servers, ObjectName: objectName, Timeout: timeout}, nil
}

func configSetting(properties map[string]string, key, env, fallback string) string {
	if val, ok := os.LookupEnv(env); ok {
		return val
	}
	if val, ok := properties[key]; ok {
		return val
	}
	return fallback
}

func readConfigProperties(path string) (map[string]string, error) {
	badFile := errors.New("configuration must be a readable regular file no larger than 64 KiB")
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxConfigFileSize {
		return nil, badFile
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, badFile
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxConfigFileSize {
		return nil, badFile
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigFileSize+1))
	if err != nil || len(data) > maxConfigFileSize {
		return nil, badFile
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return nil, errors.New("invalid configuration encoding")
	}
	properties := make(map[string]string)
	for i, line := range strings.Split(strings.TrimPrefix(string(data), "\ufeff"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("invalid configuration syntax at line %d", i+1)
		}
		switch key {
		case "accesskey", "license", "whatap.server.host", "whatap.server.port", "net_udp_port", "whatap.name":
			if _, exists := properties[key]; exists {
				return nil, fmt.Errorf("duplicate configuration setting at line %d", i+1)
			}
			properties[key] = strings.TrimSpace(val)
		}
	}
	return properties, nil
}

func configServers(hosts, port string) ([]string, error) {
	badPort := errors.New("collector port must be an integer from 1 to 65535")
	port = strings.TrimSpace(port)
	for _, digit := range port {
		if digit < '0' || digit > '9' {
			return nil, badPort
		}
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return nil, badPort
	}
	port = strconv.FormatUint(n, 10)
	badHosts := errors.New("invalid collector host list")
	parts := strings.Split(hosts, "/")
	servers := make([]string, 0, len(parts))
	for _, host := range parts {
		host = strings.TrimSpace(host)
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
			ip, err := netip.ParseAddr(host)
			if err != nil || !ip.Is6() {
				return nil, badHosts
			}
		}
		if host == "" || strings.ContainsAny(host, "[]\\,@?#") {
			return nil, badHosts
		}
		for _, char := range host {
			if unicode.IsSpace(char) || unicode.IsControl(char) {
				return nil, badHosts
			}
		}
		if strings.Contains(host, ":") {
			if _, err := netip.ParseAddr(host); err != nil {
				return nil, badHosts
			}
		} else if strings.Contains(host, "%") {
			return nil, badHosts
		}
		servers = append(servers, net.JoinHostPort(host, port))
	}
	return servers, nil
}
