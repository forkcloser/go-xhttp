package xhttp_test

// What the watch on a response body costs a read, beside net/http's own
// transport: a report, run by hand, that judges nothing. The watch arms and
// stops a timer around each read, so its cost is per read and shows with
// small reads; a consumer that copies a body reads 32 KiB at a time.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forkcloser/xhttp"
)

func BenchmarkBodyRead(b *testing.B) {
	const size = 32 << 20

	chunk := make([]byte, 64<<10)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for range size / len(chunk) {
			_, _ = w.Write(chunk)
		}
	}))
	b.Cleanup(server.Close)

	for _, reading := range []struct {
		name   string
		buffer int
	}{
		{"reads of 64 bytes", 64},
		{"reads of 32 KiB", 32 << 10},
	} {
		for _, through := range []struct {
			name      string
			transport http.RoundTripper
		}{
			{"net/http", &http.Transport{}},
			{"xhttp, not watched", xhttp.NewTransport(xhttp.Config{Cleartext: true, StallTimeout: -1})},
			{"xhttp, watched", xhttp.NewTransport(xhttp.Config{Cleartext: true})},
		} {
			b.Run(reading.name+"/"+through.name, func(b *testing.B) {
				buffer := make([]byte, reading.buffer)

				b.SetBytes(size)
				b.ReportAllocs()

				for b.Loop() {
					req, err := http.NewRequestWithContext(b.Context(), http.MethodGet, server.URL, http.NoBody)
					if err != nil {
						b.Fatal(err)
					}

					resp, err := through.transport.RoundTrip(req)
					if err != nil {
						b.Fatal(err)
					}

					// Not io.Copy: its buffer is its own, and the size of a
					// read is what is measured.
					for {
						if _, err = resp.Body.Read(buffer); err != nil {
							break
						}
					}

					_ = resp.Body.Close()

					if err != io.EOF { //nolint:errorlint // the end itself, as a Read gives it
						b.Fatal(err)
					}
				}
			})
		}
	}
}
