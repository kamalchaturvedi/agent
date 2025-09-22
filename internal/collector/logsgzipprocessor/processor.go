// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.
package logsgzipprocessor

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor"
	"go.uber.org/multierr"
	"go.uber.org/zap"
)

// nolint: ireturn
func NewFactory() processor.Factory {
	return processor.NewFactory(
		component.MustNewType("logsgzip"),
		func() component.Config {
			return &struct{}{}
		},
		processor.WithLogs(createLogsGzipProcessor, component.StabilityLevelBeta),
	)
}

// nolint: ireturn
func createLogsGzipProcessor(_ context.Context,
	settings processor.Settings,
	cfg component.Config,
	logs consumer.Logs,
) (processor.Logs, error) {
	logger := settings.Logger
	logger.Info("Creating logs gzip processor")

	return newLogsGzipProcessor(logs, settings), nil
}

// logsGzipProcessor is a custom-processor implementation for compressing log records batch into
// gzip format. This can be used to reduce the overall size of log records and improve performance when processing
// large log volumes. This processor will be used for SaaS connector POC, with NGINX One
// console (https://docs.nginx.com/nginx-one/about/).
type logsGzipProcessor struct {
	nextConsumer consumer.Logs
	// We use sync.Pool to efficiently manage and reuse gzip.Writer instances within this processor.
	// Otherwise, creating a new compressor for every log record would result in frequent memory allocations
	// and increased garbage collection overhead, especially under high-throughput workload like this one.
	// By pooling these objects, we minimize allocation churn, reduce GC pressure, and improve overall performance.
	pool            *sync.Pool
	settings        processor.Settings
	syslogASMRegexp *regexp.Regexp
}

type GzipWriter interface {
	Write(p []byte) (int, error)
	Close() error
	Reset(w io.Writer)
}

func newLogsGzipProcessor(logs consumer.Logs, settings processor.Settings) *logsGzipProcessor {
	return &logsGzipProcessor{
		nextConsumer: logs,
		pool: &sync.Pool{
			New: func() any {
				return gzip.NewWriter(nil)
			},
		},
		settings:        settings,
		syslogASMRegexp: regexp.MustCompile(`^<\d+>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+[\w\-.]+ ASM:`),
	}
}

func (p *logsGzipProcessor) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	var errs error
	resourceLogs := ld.ResourceLogs()
	for i := range resourceLogs.Len() {
		scopeLogs := resourceLogs.At(i).ScopeLogs()
		for j := range scopeLogs.Len() {
			err := p.processLogRecords(scopeLogs.At(j).LogRecords())
			if err != nil {
				errs = multierr.Append(errs, err)
			}
		}
	}
	if errs != nil {
		return fmt.Errorf("failed processing log records: %w", errs)
	}

	return p.nextConsumer.ConsumeLogs(ctx, ld)
}

func (p *logsGzipProcessor) processLogRecords(logRecords plog.LogRecordSlice) error {
	filtered := p.filterSupportedLogRecords(logRecords)
	if len(filtered) == 0 {
		return nil
	}
	combinedViolations := combineViolations(filtered)
	gzipped, err := p.gzipCompress([]byte(combinedViolations))
	if err != nil {
		return fmt.Errorf("failed to compress log record: %w", err)
	}
	replaceWithGzippedLogRecord(logRecords, gzipped)
	return nil
}

// filterSupportedLogRecords returns a slice of log record strings with supported types (STRING)
func (p *logsGzipProcessor) filterSupportedLogRecords(logRecords plog.LogRecordSlice) []string {
	var filtered []string
	logRecords.RemoveIf(func(l plog.LogRecord) bool {
		if l.Body().Type() == pcommon.ValueTypeStr {
			// && json.Valid([]byte(l.Body().Str()))
			filtered = append(filtered, p.syslogASMRegexp.ReplaceAllString(l.Body().Str(), ""))
			return false
		}
		p.settings.Logger.Warn("Skipping log record with unsupported body type or invalid JSON", zap.String("type", l.Body().Type().String()))
		return true
	})
	return filtered
}

func (p *logsGzipProcessor) gzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	var err error
	wIface := p.pool.Get()
	w, ok := wIface.(GzipWriter)
	if !ok {
		return nil, fmt.Errorf("writer of type %T not supported", wIface)
	}
	w.Reset(&buf)
	defer func() {
		if err = w.Close(); err != nil {
			p.settings.Logger.Error("Failed to close gzip writer", zap.Error(err))
		}
		p.pool.Put(w)
	}()

	_, err = w.Write(data)
	if err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (p *logsGzipProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{
		MutatesData: true,
	}
}

func (p *logsGzipProcessor) Start(ctx context.Context, _ component.Host) error {
	p.settings.Logger.Info("Starting logs gzip processor")
	return nil
}

func (p *logsGzipProcessor) Shutdown(ctx context.Context) error {
	p.settings.Logger.Info("Shutting down logs gzip processor")
	return nil
}

// combineViolations combines the filtered log record strings into a single JSON array string
func combineViolations(violations []string) string {
	return "[" + strings.Join(violations, ",") + "]"
}

// replaceWithGzippedLogRecord empties logRecords and adds a single logRecord with gzipped content
func replaceWithGzippedLogRecord(logRecords plog.LogRecordSlice, gzipped []byte) {
	logRecords.RemoveIf(func(plog.LogRecord) bool { return true })
	record := logRecords.AppendEmpty()
	// Set timestamps to zero, or could copy from previous if needed
	record.SetTimestamp(pcommon.NewTimestampFromTime(record.Timestamp().AsTime()))
	record.SetObservedTimestamp(pcommon.NewTimestampFromTime(record.ObservedTimestamp().AsTime()))
	_ = record.Body().FromRaw(gzipped)
}
