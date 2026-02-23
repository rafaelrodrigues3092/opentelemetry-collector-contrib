// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cloudflareencodingextension

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/extension/extensiontest"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestExtension_Start_Shutdown(t *testing.T) {
	e := &encodingExtension{}
	require.NoError(t, e.Start(t.Context(), componenttest.NewNopHost()))
	require.NoError(t, e.Shutdown(t.Context()))
}

func TestUnmarshalLogs(t *testing.T) {
	cfg := &Config{
		TimestampField:  "EdgeStartTimestamp",
		TimestampFormat: "rfc3339",
		Separator:       ".",
		Attributes: map[string]string{
			"ClientIP": "http_request.client_ip",
		},
	}
	ext := &encodingExtension{cfg: cfg, logger: extensiontest.NewNopSettings(extensiontest.NopType).Logger}

	payload, err := os.ReadFile(filepath.Join("testdata", "multiple_log_payload.txt"))
	require.NoError(t, err)

	got, err := ext.UnmarshalLogs(payload)
	require.NoError(t, err)

	resourceLogs := got.ResourceLogs()
	require.Equal(t, 3, resourceLogs.Len())

	// Map iteration order is non-deterministic, so collect results by zone name.
	zoneCounts := make(map[string]int)
	for i := 0; i < resourceLogs.Len(); i++ {
		rl := resourceLogs.At(i)
		zone := ""
		if v, ok := rl.Resource().Attributes().Get("cloudflare.zone"); ok {
			zone = v.Str()
		}
		recordCount := rl.ScopeLogs().At(0).LogRecords().Len()
		zoneCounts[zone] = recordCount
	}

	assert.Equal(t, 2, zoneCounts[""])
	assert.Equal(t, 2, zoneCounts["example.com"])
	assert.Equal(t, 1, zoneCounts["abc.com"])

	// Verify all records have timestamps, severity, and the mapped attribute.
	for i := 0; i < resourceLogs.Len(); i++ {
		records := resourceLogs.At(i).ScopeLogs().At(0).LogRecords()
		for j := 0; j < records.Len(); j++ {
			record := records.At(j)
			require.NotZero(t, record.Timestamp().AsTime().UnixNano())
			require.Equal(t, plog.SeverityNumberInfo, record.SeverityNumber())
			require.Equal(t, plog.SeverityNumberInfo.String(), record.SeverityText())
			_, ok := record.Attributes().Get("http_request.client_ip")
			require.True(t, ok)
		}
	}
}

func TestUnmarshalLogsGzip(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	ext := &encodingExtension{cfg: cfg, logger: extensiontest.NewNopSettings(extensiontest.NopType).Logger}

	payload, err := os.ReadFile(filepath.Join("testdata", "single_log_payload.txt"))
	require.NoError(t, err)

	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, err = zw.Write(payload)
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	got, err := ext.UnmarshalLogs(compressed.Bytes())
	require.NoError(t, err)
	require.Equal(t, 1, got.ResourceLogs().Len())
	require.Equal(t, 1, got.LogRecordCount())
}

func TestUnmarshalLogsError(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	ext := &encodingExtension{cfg: cfg, logger: extensiontest.NewNopSettings(extensiontest.NopType).Logger}

	_, err := ext.UnmarshalLogs([]byte(`{"not_json"`))
	require.Error(t, err)
}

func TestSeverityFromStatusCode(t *testing.T) {
	require.Equal(t, plog.SeverityNumberInfo, severityFromStatusCode(200))
	require.Equal(t, plog.SeverityNumberInfo2, severityFromStatusCode(304))
	require.Equal(t, plog.SeverityNumberWarn, severityFromStatusCode(404))
	require.Equal(t, plog.SeverityNumberError, severityFromStatusCode(503))
	require.Equal(t, plog.SeverityNumberUnspecified, severityFromStatusCode(1000))
}

func TestFlattenMap(t *testing.T) {
	in := map[string]any{
		"RequestHeaders": map[string]any{
			"Content-Type": map[string]any{
				"value": "application/json",
			},
		},
	}
	result := map[string]any{}
	flattenMap(in, "", ".", result)
	require.Equal(t, map[string]any{
		"RequestHeaders.Content_Type.value": "application/json",
	}, result)
}
