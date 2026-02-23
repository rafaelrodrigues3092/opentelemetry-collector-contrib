// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cloudflareencodingextension // import "github.com/open-telemetry/opentelemetry-collector-contrib/extension/encoding/cloudflareencodingextension"

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/encoding"
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/encoding/cloudflareencodingextension/internal/metadata"
)

var _ encoding.LogsUnmarshalerExtension = (*encodingExtension)(nil)

type encodingExtension struct {
	cfg    *Config
	logger *zap.Logger
}

func (*encodingExtension) Start(context.Context, component.Host) error {
	return nil
}

func (*encodingExtension) Shutdown(context.Context) error {
	return nil
}

func (e *encodingExtension) UnmarshalLogs(buf []byte) (plog.Logs, error) {
	payload := buf
	if isGzipData(buf) {
		reader, err := gzip.NewReader(bytes.NewReader(buf))
		if err != nil {
			return plog.Logs{}, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer reader.Close()

		payload, err = io.ReadAll(reader)
		if err != nil {
			return plog.Logs{}, fmt.Errorf("failed to read gzip payload: %w", err)
		}
	}

	logs, err := parsePayload(payload)
	if err != nil {
		return plog.Logs{}, err
	}
	return e.processLogs(pcommon.NewTimestampFromTime(time.Now()), logs), nil
}

func parsePayload(payload []byte) ([]map[string]any, error) {
	lines := bytes.Split(payload, []byte("\n"))
	logs := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var log map[string]any
		err := json.Unmarshal(line, &log)
		if err != nil {
			return logs, err
		}
		logs = append(logs, log)
	}
	return logs, nil
}

func (e *encodingExtension) processLogs(now pcommon.Timestamp, logs []map[string]any) plog.Logs {
	pLogs := plog.NewLogs()

	groupedLogs := make(map[string][]map[string]any)
	for _, log := range logs {
		zone := ""
		if v, ok := log["ZoneName"]; ok {
			if stringV, ok := v.(string); ok {
				zone = stringV
			}
		}
		groupedLogs[zone] = append(groupedLogs[zone], log)
	}

	for zone, logGroup := range groupedLogs {
		resourceLogs := pLogs.ResourceLogs().AppendEmpty()
		if zone != "" {
			resource := resourceLogs.Resource()
			resource.Attributes().PutStr("cloudflare.zone", zone)
		}
		scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
		scopeLogs.Scope().SetName(metadata.ScopeName)

		for _, log := range logGroup {
			logRecord := scopeLogs.LogRecords().AppendEmpty()
			logRecord.SetObservedTimestamp(now)

			if v, ok := log[e.cfg.TimestampField]; ok {
				switch e.cfg.TimestampFormat {
				case "unix":
					var sec int64
					switch val := v.(type) {
					case int:
						sec = int64(val)
					case int64:
						sec = val
					case float64:
						sec = int64(val)
					case string:
						i, err := strconv.ParseInt(val, 10, 64)
						if err != nil {
							e.getLogger().Warn("unable to parse "+e.cfg.TimestampField+" as unix seconds", zap.Error(err), zap.String("value", val))
							continue
						}
						sec = i
					default:
						e.getLogger().Warn("unable to parse "+e.cfg.TimestampField, zap.String("unsupported type", fmt.Sprintf("%T", v)))
						continue
					}
					logRecord.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(sec, 0)))
				case "unixnano":
					var nano int64
					switch val := v.(type) {
					case int:
						nano = int64(val)
					case int64:
						nano = val
					case float64:
						nano = int64(val)
					case string:
						i, err := strconv.ParseInt(val, 10, 64)
						if err != nil {
							e.getLogger().Warn("unable to parse "+e.cfg.TimestampField+" as unixnano", zap.Error(err), zap.String("value", val))
							continue
						}
						nano = i
					default:
						e.getLogger().Warn("unable to parse "+e.cfg.TimestampField, zap.String("unsupported type", fmt.Sprintf("%T", v)))
						continue
					}
					logRecord.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(0, nano)))
				case "rfc3339":
					strVal, ok := v.(string)
					if !ok {
						e.getLogger().Warn("unable to parse "+e.cfg.TimestampField+" as rfc3339, not a string", zap.Any("value", v), zap.String("type", fmt.Sprintf("%T", v)))
						continue
					}
					ts, err := time.Parse(time.RFC3339, strVal)
					if err != nil {
						e.getLogger().Warn("unable to parse "+e.cfg.TimestampField+" as rfc3339", zap.Error(err), zap.String("value", strVal))
						continue
					}
					logRecord.SetTimestamp(pcommon.NewTimestampFromTime(ts))
				default:
					e.getLogger().Warn("unknown timestamp_format configuration", zap.String("timestamp_format", e.cfg.TimestampFormat))
				}
			} else {
				e.getLogger().Warn("unable to parse "+e.cfg.TimestampField, zap.Any("value", v))
			}

			if v, ok := log["EdgeResponseStatus"]; ok {
				sev := plog.SeverityNumberUnspecified
				switch v := v.(type) {
				case string:
					intV, err := strconv.ParseInt(v, 10, 64)
					if err != nil {
						e.getLogger().Warn("unable to parse EdgeResponseStatus", zap.Error(err), zap.String("value", v))
					} else {
						sev = severityFromStatusCode(intV)
					}
				case int64:
					sev = severityFromStatusCode(v)
				case float64:
					sev = severityFromStatusCode(int64(v))
				}
				if sev != plog.SeverityNumberUnspecified {
					logRecord.SetSeverityNumber(sev)
					logRecord.SetSeverityText(sev.String())
				}
			}

			attrs := logRecord.Attributes()
			for field, v := range log {
				attrName := field
				if len(e.cfg.Attributes) != 0 {
					mappedAttr, ok := e.cfg.Attributes[field]
					if !ok {
						continue
					}
					attrName = mappedAttr
				}

				switch v := v.(type) {
				case string:
					attrs.PutStr(attrName, v)
				case int:
					attrs.PutInt(attrName, int64(v))
				case int64:
					attrs.PutInt(attrName, v)
				case float64:
					attrs.PutDouble(attrName, v)
				case bool:
					attrs.PutBool(attrName, v)
				case map[string]any:
					flattened := make(map[string]any)
					flattenMap(v, attrName+e.cfg.Separator, e.cfg.Separator, flattened)
					for k, val := range flattened {
						switch v := val.(type) {
						case string:
							attrs.PutStr(k, v)
						case int:
							attrs.PutInt(k, int64(v))
						case int64:
							attrs.PutInt(k, v)
						case float64:
							attrs.PutDouble(k, v)
						case bool:
							attrs.PutBool(k, v)
						default:
							e.getLogger().Warn("unable to translate flattened field to attribute, unsupported type",
								zap.String("field", k),
								zap.Any("value", v),
								zap.String("type", fmt.Sprintf("%T", v)))
						}
					}
				default:
					e.getLogger().Warn("unable to translate field to attribute, unsupported type",
						zap.String("field", field),
						zap.Any("value", v),
						zap.String("type", fmt.Sprintf("%T", v)))
				}
			}

			err := logRecord.Body().SetEmptyMap().FromRaw(log)
			if err != nil {
				e.getLogger().Warn("unable to set body", zap.Error(err))
			}
		}
	}

	return pLogs
}

func severityFromStatusCode(statusCode int64) plog.SeverityNumber {
	switch {
	case statusCode < 300:
		return plog.SeverityNumberInfo
	case statusCode < 400:
		return plog.SeverityNumberInfo2
	case statusCode < 500:
		return plog.SeverityNumberWarn
	case statusCode < 600:
		return plog.SeverityNumberError
	default:
		return plog.SeverityNumberUnspecified
	}
}

func flattenMap(input map[string]any, prefix, separator string, result map[string]any) {
	for k, v := range input {
		k = strings.ReplaceAll(k, "-", "_")
		newKey := prefix + k
		switch val := v.(type) {
		case map[string]any:
			flattenMap(val, newKey+separator, separator, result)
		default:
			result[newKey] = v
		}
	}
}

func isGzipData(buf []byte) bool {
	return len(buf) > 2 && buf[0] == 0x1f && buf[1] == 0x8b
}

func (e *encodingExtension) getLogger() *zap.Logger {
	if e.logger == nil {
		return zap.NewNop()
	}
	return e.logger
}
