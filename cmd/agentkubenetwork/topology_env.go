package main

import (
	"flag"
	"fmt"
	"os"
)

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
