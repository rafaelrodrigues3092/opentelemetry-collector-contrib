// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package azureblobreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/azureblobreceiver"

import (
	"context"
	"fmt"
	"strings"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverhelper"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/azureblobreceiver/internal/metadata"
)

type encodingExtension struct {
	extension component.Component
	suffix    string
}

type encodingExtensions []encodingExtension

type logsDataConsumer interface {
	consumeLogs(ctx context.Context, blobName string, data []byte) error
	setNextLogsConsumer(nextLogsConsumer consumer.Logs)
}

type tracesDataConsumer interface {
	consumeTraces(ctx context.Context, blobName string, data []byte) error
	setNextTracesConsumer(nextracesConsumer consumer.Traces)
}

type blobReceiver struct {
	blobEventHandler   blobEventHandler
	logger             *zap.Logger
	logsUnmarshaler    plog.Unmarshaler
	tracesUnmarshaler  ptrace.Unmarshaler
	nextLogsConsumer   consumer.Logs
	nextTracesConsumer consumer.Traces
	obsrecv            *receiverhelper.ObsReport
	encodingsConfig    []Encoding
	extensions         encodingExtensions
}

func (b *blobReceiver) Start(ctx context.Context, host component.Host) error {
	var err error
	b.extensions, err = newEncodingExtensions(b.encodingsConfig, host)
	if err != nil {
		return err
	}

	return b.blobEventHandler.run(ctx)
}

func (b *blobReceiver) Shutdown(ctx context.Context) error {
	return b.blobEventHandler.close(ctx)
}

func (b *blobReceiver) setNextLogsConsumer(nextLogsConsumer consumer.Logs) {
	b.nextLogsConsumer = nextLogsConsumer
}

func (b *blobReceiver) setNextTracesConsumer(nextTracesConsumer consumer.Traces) {
	b.nextTracesConsumer = nextTracesConsumer
}

func (b *blobReceiver) consumeLogs(ctx context.Context, blobName string, data []byte) error {
	if b.nextLogsConsumer == nil {
		return nil
	}

	var unmarshaler plog.Unmarshaler
	var format string

	if extension, f := b.extensions.findExtension(blobName); extension != nil {
		unmarshaler, _ = extension.(plog.Unmarshaler)
		format = f
	}

	if unmarshaler == nil {
		unmarshaler = b.logsUnmarshaler
		format = metadata.Type.String()
	}

	logsContext := b.obsrecv.StartLogsOp(ctx)

	logs, err := unmarshaler.UnmarshalLogs(data)
	if err != nil {
		return fmt.Errorf("failed to unmarshal logs: %w", err)
	}

	err = b.nextLogsConsumer.ConsumeLogs(logsContext, logs)

	b.obsrecv.EndLogsOp(logsContext, format, logs.LogRecordCount(), err)

	return err
}

func (b *blobReceiver) consumeTraces(ctx context.Context, blobName string, data []byte) error {
	if b.nextTracesConsumer == nil {
		return nil
	}

	var unmarshaler ptrace.Unmarshaler
	var format string

	if extension, f := b.extensions.findExtension(blobName); extension != nil {
		unmarshaler, _ = extension.(ptrace.Unmarshaler)
		format = f
	}

	if unmarshaler == nil {
		unmarshaler = b.tracesUnmarshaler
		format = metadata.Type.String()
	}

	tracesContext := b.obsrecv.StartTracesOp(ctx)

	traces, err := unmarshaler.UnmarshalTraces(data)
	if err != nil {
		return fmt.Errorf("failed to unmarshal traces: %w", err)
	}

	err = b.nextTracesConsumer.ConsumeTraces(tracesContext, traces)

	b.obsrecv.EndTracesOp(tracesContext, format, traces.SpanCount(), err)

	return err
}

// Returns a new instance of the log receiver
func newReceiver(set receiver.Settings, blobEventHandler blobEventHandler, encodingsConfig []Encoding) (component.Component, error) {
	obsrecv, err := receiverhelper.NewObsReport(receiverhelper.ObsReportSettings{
		ReceiverID:             set.ID,
		Transport:              "event",
		ReceiverCreateSettings: set,
	})
	if err != nil {
		return nil, err
	}

	blobReceiver := &blobReceiver{
		blobEventHandler:  blobEventHandler,
		logger:            set.Logger,
		logsUnmarshaler:   &plog.JSONUnmarshaler{},
		tracesUnmarshaler: &ptrace.JSONUnmarshaler{},
		obsrecv:           obsrecv,
		encodingsConfig:   encodingsConfig,
	}

	blobEventHandler.setLogsDataConsumer(blobReceiver)
	blobEventHandler.setTracesDataConsumer(blobReceiver)

	return blobReceiver, nil
}

func newEncodingExtensions(encodingsConfig []Encoding, host component.Host) (encodingExtensions, error) {
	encodings := make(encodingExtensions, 0)
	extensions := host.GetExtensions()
	for _, configItem := range encodingsConfig {
		e, ok := extensions[configItem.Extension]
		if !ok {
			return nil, fmt.Errorf("extension %q not found", configItem.Extension)
		}
		encodings = append(encodings, encodingExtension{extension: e, suffix: configItem.Suffix})
	}
	return encodings, nil
}

func (encodings encodingExtensions) findExtension(key string) (component.Component, string) {
	for _, e := range encodings {
		if strings.HasSuffix(key, e.suffix) {
			return e.extension, e.suffix
		}
	}
	return nil, ""
}
