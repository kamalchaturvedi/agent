// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.
package logsgzipprocessor

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/processor"
)

// Helper to generate logs with variable size and content
func generateLogs(numRecords, recordSize int) plog.Logs {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()
	for range numRecords {
		lr := sl.LogRecords().AppendEmpty()
		content, _ := randomJSONString(recordSize)
		lr.Body().SetStr(content)
	}

	return logs
}

func randomJSONString(n int) (string, error) {
	// Generate a random JSON object with n key-value pairs
	const letters = "abcdefghijklmnopqrstuvwxyz"
	obj := make(map[string]string)
	for range n {
		// Random key
		keyLen := 5
		key := make([]byte, keyLen)
		for j := range key {
			num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
			if err != nil {
				return "", err
			}
			key[j] = letters[num.Int64()]
		}
		// Random value
		valLen := 8
		val := make([]byte, valLen)
		for j := range val {
			num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
			if err != nil {
				return "", err
			}
			val[j] = letters[num.Int64()]
		}
		obj[string(key)] = string(val)
	}
	// Marshal to JSON
	jsonBytes, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

func BenchmarkGzipProcessor(b *testing.B) {
	benchmarks := []struct {
		name       string
		numRecords int
		recordSize int
	}{
		{"SmallRecords", 100, 5},
		{"MediumRecords", 100, 50},
		{"LargeRecords", 100, 500},
		{"ManySmallRecords", 10000, 5},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			consumer := &consumertest.LogsSink{}
			p := newLogsGzipProcessor(consumer, processor.Settings{})
			logs := generateLogs(bm.numRecords, bm.recordSize)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = p.ConsumeLogs(context.Background(), logs)
			}
		})
	}
}

// Optional: Benchmark with concurrency to simulate real pipeline load
func BenchmarkGzipProcessor_Concurrent(b *testing.B) {
	// nolint:unused // concurrent runs require total parallel workers to be specified
	const workers = 8
	logs := generateLogs(1000, 1000)
	consumer := &consumertest.LogsSink{}
	p := newLogsGzipProcessor(consumer, processor.Settings{})

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = p.ConsumeLogs(context.Background(), logs)
		}
	})
}
