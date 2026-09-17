package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"
)

// Resolve environment values after parsing so even invalid environment values
// cannot override an explicitly supplied CLI flag.
func applyLoggingEnvironment(flags *flag.FlagSet) error {
	explicit := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	for _, setting := range []struct{ flagName, envName string }{
		{"stdout", "WHATAP_STDOUT"},
		{"log-level", "WHATAP_LOG_LEVEL"},
		{"log-interval", "WHATAP_LOG_INTERVAL"},
	} {
		if explicit[setting.flagName] {
			continue
		}
		value, present := os.LookupEnv(setting.envName)
		if !present {
			continue
		}
		// Validate without including arbitrary environment contents in errors.
		switch setting.flagName {
		case "stdout":
			switch value {
			case "auto", "jsonl", "none":
			default:
				return errors.New("WHATAP_STDOUT must be auto, jsonl, or none")
			}
		case "log-level":
			if err := validateLogging(value, 0); err != nil {
				return fmt.Errorf("WHATAP_LOG_LEVEL: %w", err)
			}
		case "log-interval":
			interval, err := time.ParseDuration(value)
			if err != nil || interval < 0 {
				return errors.New("WHATAP_LOG_INTERVAL must be a nonnegative Go duration (or 0)")
			}
		}
		if err := flags.Set(setting.flagName, value); err != nil {
			return fmt.Errorf("cannot apply %s", setting.envName)
		}
	}
	return nil
}
