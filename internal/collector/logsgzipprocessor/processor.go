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
	var err error
	resourceLogs := ld.ResourceLogs()
	var filtered []string
	for i := range resourceLogs.Len() {
		scopeLogs := resourceLogs.At(i).ScopeLogs()
		for j := range scopeLogs.Len() {
			filtered = append(filtered, p.filterSupportedLogRecords(scopeLogs.At(j).LogRecords())...)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	var gzipped []byte
	gzipped, err = p.processLogRecords(filtered)
	if err != nil {
		return fmt.Errorf("failed to process log records: %w", err)
	}
	if resourceLogs.Len() > 0 {
		p.settings.Logger.Info("Final filtered log record value", zap.Strings("logs", filtered))
		p.settings.Logger.Info("Processing resource logs and converging")
		// Remove all but the first element from resourceLogs
		resourceLogs.RemoveIf(func(rl plog.ResourceLogs) bool { return resourceLogs.At(0) != rl })
		// Clear all scope logs from the first resource log
		rl := resourceLogs.At(0)
		sls := rl.ScopeLogs()
		sls.RemoveIf(func(sl plog.ScopeLogs) bool { return sls.At(0) != sl })
		logRecords := sls.At(0).LogRecords()
		replaceWithGzippedLogRecord(logRecords, gzipped)
		p.settings.Logger.Info("Compressed log records", zap.Int("count", len(filtered)), zap.Int("gzipped_size", len(gzipped)))
	}

	return p.nextConsumer.ConsumeLogs(ctx, ld)
}

func (p *logsGzipProcessor) processLogRecords(filtered []string) ([]byte, error) {
	combinedViolations := combineViolations(filtered)
	gzipped, err := p.gzipCompress([]byte(combinedViolations))
	if err != nil {
		return nil, fmt.Errorf("failed to compress log record: %w", err)
	}
	return gzipped, nil
}

// filterSupportedLogRecords returns a slice of log record strings with supported types (STRING)
func (p *logsGzipProcessor) filterSupportedLogRecords(logRecords plog.LogRecordSlice) []string {
	var filtered []string
	logRecords.RemoveIf(func(l plog.LogRecord) bool {
		if l.Body().Type() == pcommon.ValueTypeStr {
			parsedLogInput := l.Body().Str()
			p.settings.Logger.Debug("Original log record", zap.String("log", parsedLogInput))
			if idx := strings.Index(parsedLogInput, " ASM:"); idx != -1 && idx < 50 {
				// Only strip if ASM: is near the start (syslog prefix is usually short)
				parsedLogInput = parsedLogInput[idx+len(" ASM:"):]
			}
			filtered = append(filtered, parsedLogInput)
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
	// Clear existing log records
	logRecords.RemoveIf(func(lr plog.LogRecord) bool { return logRecords.At(0) != lr })

	// Modify the first log record to contain the gzipped data of all log records
	record := logRecords.At(0)
	_ = record.Body().FromRaw(gzipped)
}
