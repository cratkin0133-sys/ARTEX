package server

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

// decodeMaxBytes is the default JSON body cap. Multipart uploads are not capped
// here; those handlers set their own limit. A smaller MaxBytesReader installed
// by a handler still wins, because it sits inside this one.
const decodeMaxBytes = 32 << 20

// limitedBody records a MaxBytesError so a later 400 can be answered as 413.
type limitedBody struct {
	io.ReadCloser
	tooLarge bool
}

func (b *limitedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		b.tooLarge = true
	}
	return n, err
}

type bodyLimitWriter struct {
	http.ResponseWriter
	tooLarge func() bool
}

func (b *bodyLimitWriter) WriteHeader(code int) {
	if code == http.StatusBadRequest && b.tooLarge != nil && b.tooLarge() {
		code = http.StatusRequestEntityTooLarge
	}
	b.ResponseWriter.WriteHeader(code)
}

func (b *bodyLimitWriter) Flush() {
	if f, ok := b.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (b *bodyLimitWriter) Unwrap() http.ResponseWriter { return b.ResponseWriter }

// limitRequestBody caps a non-multipart body at decodeMaxBytes and passes the
// real ResponseWriter into MaxBytesReader. A handler that then answers 400 for
// that read is rewritten to 413.
func limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body == nil || r.Body == http.NoBody || isMultipart(r) {
			next.ServeHTTP(w, r)
			return
		}
		body := &limitedBody{ReadCloser: http.MaxBytesReader(w, r.Body, decodeMaxBytes)}
		r.Body = body
		next.ServeHTTP(&bodyLimitWriter{ResponseWriter: w, tooLarge: func() bool { return body.tooLarge }}, r)
	})
}

func isMultipart(r *http.Request) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return false
	}
	return strings.HasPrefix(media, "multipart/")
}

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	if r.Body != nil {
		if _, already := r.Body.(*limitedBody); !already {
			r.Body = &limitedBody{ReadCloser: http.MaxBytesReader(w, r.Body, decodeMaxBytes)}
		}
	}
	err := json.NewDecoder(r.Body).Decode(v)
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		if lb, ok := r.Body.(*limitedBody); ok {
			lb.tooLarge = true
		}
		// Return the original error: a caller that maps 413 itself keeps working,
		// and the middleware still rewrites a 400 for callers that do not.
		return tooLarge
	}
	return err
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func pathInt(r *http.Request, name string) (int64, bool) {
	n, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	return n, err == nil
}

func atoiDefault(s string, d int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return d
}
