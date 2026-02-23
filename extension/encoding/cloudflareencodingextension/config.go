// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cloudflareencodingextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/encoding/cloudflareencodingextension"

import (
	"fmt"

	"go.opentelemetry.io/collector/confmap/xconfmap"
)

var _ xconfmap.Validator = (*Config)(nil)

const (
	defaultTimestampField  = "EdgeStartTimestamp"
	defaultTimestampFormat = "rfc3339"
	defaultSeparator       = "."
)

type Config struct {
	Attributes      map[string]string `mapstructure:"attributes"`
	TimestampField  string            `mapstructure:"timestamp_field"`
	TimestampFormat string            `mapstructure:"timestamp_format"`
	Separator       string            `mapstructure:"separator"`

	// prevent unkeyed literal initialization
	_ struct{}
}

func (cfg *Config) Validate() error {
	if cfg.TimestampFormat == "" {
		return nil
	}

	switch cfg.TimestampFormat {
	case "unix", "unixnano", "rfc3339":
		return nil
	default:
		return fmt.Errorf("invalid timestamp_format %q, must be one of: unix, unixnano, rfc3339", cfg.TimestampFormat)
	}
}
