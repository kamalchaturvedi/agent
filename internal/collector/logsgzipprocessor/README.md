# Logs gzip processor

The Logs gzip processor gzips the input log record body, updating the log record in-place. 

For metrics and traces, this will just be a pass-through as it does not implement related interfaces.

## Configuration

No configuration needed.

## Benchmarking

We performed benchmark measuring the performance of serial and concurrent operations (more practical) of this processor, with and without the `sync.Pool`. Here are the results:

```
Concurrent Run: Without Sync Pool
goos: darwin
goarch: arm64
pkg: github.com/nginx/agent/v3/internal/collector/logsgzipprocessor
cpu: Apple M2 Pro
BenchmarkGzipProcessor_Concurrent-12               	       9	 112672514 ns/op	101317200 B/op	      62 allocs/op
PASS
ok      github.com/nginx/agent/v3/internal/collector/logsgzipprocessor  1.939s

Concurrent Run: With Sync Pool

goos: darwin
goarch: arm64
pkg: github.com/nginx/agent/v3/internal/collector/logsgzipprocessor
cpu: Apple M2 Pro
BenchmarkGzipProcessor_Concurrent-12               	       9	 128948593 ns/op	101317763 B/op	      63 allocs/op
PASS
ok      github.com/nginx/agent/v3/internal/collector/logsgzipprocessor  2.026s

————

Serial Run: Without Sync Pool

goos: darwin
goarch: arm64
pkg: github.com/nginx/agent/v3/internal/collector/logsgzipprocessor
cpu: Apple M2 Pro
BenchmarkGzipProcessor/SmallRecords-12  	23340325	        48.88 ns/op	      86 B/op	       0 allocs/op
BenchmarkGzipProcessor/MediumRecords-12 	19705053	        53.44 ns/op	      82 B/op	       0 allocs/op
BenchmarkGzipProcessor/LargeRecords-12  	19904542	        55.66 ns/op	      81 B/op	       0 allocs/op
BenchmarkGzipProcessor/ManySmallRecords-12         	21223381	        53.55 ns/op	      95 B/op	       0 allocs/op


Serial Run: With Sync Pool

goos: darwin
goarch: arm64
pkg: github.com/nginx/agent/v3/internal/collector/logsgzipprocessor
cpu: Apple M2 Pro
BenchmarkGzipProcessor/SmallRecords-12  	22997390	        45.57 ns/op	      87 B/op	       0 allocs/op
BenchmarkGzipProcessor/MediumRecords-12 	25295787	        58.89 ns/op	      99 B/op	       0 allocs/op
BenchmarkGzipProcessor/LargeRecords-12  	21036984	        57.85 ns/op	      96 B/op	       0 allocs/op
BenchmarkGzipProcessor/ManySmallRecords-12         	21605527	        63.60 ns/op	      93 B/op	       0 allocs/op
```


To run this benchmark yourself with syncpool implementation, you can run the tests in `processor_benchmark_test.go` in with the `sync.Pool` mode. 

To compare benchmark without syncpool, you can use this code block in `processor.go` and comment the existing `gzipCompress` function, and run `processor_benchmark_test.go` :

```
func (p *logsGzipProcessor) gzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err := w.Write(data)
	if err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
```
