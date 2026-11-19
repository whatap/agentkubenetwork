package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/whatap/agentkubenetwork/internal/topology"
)

// One WhaTap Kubernetes project monitors one cluster, so an unset topology
// cluster ID becomes the access key's project code. An explicit value is the
// display name and is kept. The caller's configuration is not modified.
func defaultTopologyClusterID(config *topology.Config, pcode int64) *topology.Config {
	if config == nil || config.ClusterID != "" {
		return config
	}
	resolved := *config
	resolved.ClusterID = strconv.FormatInt(pcode, 10)
	return &resolved
}

// Resolve environment values after CLI parsing, with the same validation and
// explicit-opt-in contract as the flags. Never echo environment values in errors.
func applyTopologyEnvironment(flags *flag.FlagSet) error {
	explicit := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	for _, setting := range []struct{ flagName, envName string }{
		{"topology-summary", "WHATAP_TOPOLOGY_SUMMARY"},
		{"topology-cluster-id", "WHATAP_TOPOLOGY_CLUSTER_ID"},
		{"topology-window", "WHATAP_TOPOLOGY_WINDOW"},
		{"topology-max-entries", "WHATAP_TOPOLOGY_MAX_ENTRIES"},
	} {
		if explicit[setting.flagName] {
			continue
		}
		value, present := os.LookupEnv(setting.envName)
		if !present {
			continue
		}
		if err := flags.Set(setting.flagName, value); err != nil {
			return fmt.Errorf("invalid %s; use the format required by -%s", setting.envName, setting.flagName)
		}
	}
	return nil
}
