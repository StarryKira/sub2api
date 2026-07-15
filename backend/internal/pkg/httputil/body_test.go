package httputil

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

const samplePayload = `{"model":"gpt-5.5","input":"hi","stream":false}`

func newRequestWithBody(t *testing.T, body []byte, encoding string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	req.ContentLength = int64(len(body))
	return req
}

func TestReadRequestBodyWithPrealloc_PassesThroughIdentity(t *testing.T) {
	req := newRequestWithBody(t, []byte(samplePayload), "")
	got, err := ReadRequestBodyWithPrealloc(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != samplePayload {
		t.Fatalf("body mismatch: got %q", got)
	}
}

func TestReadRequestBodyWithPrealloc_DecodesZstd(t *testing.T) {
	enc, _ := zstd.NewWriter(nil)
	compressed := enc.EncodeAll([]byte(samplePayload), nil)
	_ = enc.Close()

	req := newRequestWithBody(t, compressed, "zstd")
	got, err := ReadRequestBodyWithPrealloc(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != samplePayload {
		t.Fatalf("body mismatch: got %q", got)
	}
	if req.Header.Get("Content-Encoding") != "" {
		t.Fatalf("Content-Encoding should be cleared after decoding")
	}
	if req.ContentLength != int64(len(samplePayload)) {
		t.Fatalf("ContentLength not updated: %d", req.ContentLength)
	}
}

func TestReadRequestBodyWithPrealloc_DecodesGzip(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(samplePayload)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}

	req := newRequestWithBody(t, buf.Bytes(), "gzip")
	got, err := ReadRequestBodyWithPrealloc(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != samplePayload {
		t.Fatalf("body mismatch: got %q", got)
	}
}

func TestReadRequestBodyWithPrealloc_DecodesDeflate(t *testing.T) {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write([]byte(samplePayload)); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}

	req := newRequestWithBody(t, buf.Bytes(), "deflate")
	got, err := ReadRequestBodyWithPrealloc(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != samplePayload {
		t.Fatalf("body mismatch: got %q", got)
	}
}

func TestReadRequestBodyWithPrealloc_RejectsUnsupportedEncoding(t *testing.T) {
	req := newRequestWithBody(t, []byte(samplePayload), "br")
	_, err := ReadRequestBodyWithPrealloc(req)
	if err == nil {
		t.Fatal("expected error for unsupported encoding, got nil")
	}
	if !strings.Contains(err.Error(), "br") {
		t.Fatalf("error should mention encoding, got %v", err)
	}
}

func TestReadRequestBodyWithPrealloc_RejectsCorruptZstd(t *testing.T) {
	raw := []byte("not actually zstd")
	req := newRequestWithBody(t, raw, "zstd")
	_, err := ReadRequestBodyWithPrealloc(req)
	if err == nil {
		t.Fatal("expected error for corrupt zstd body, got nil")
	}
	var readErr *RequestBodyReadError
	if !errors.As(err, &readErr) {
		t.Fatalf("expected RequestBodyReadError, got %T", err)
	}
	if readErr.Stage != "decode" || readErr.ContentEncoding != "zstd" || readErr.BytesRead != int64(len(raw)) {
		t.Fatalf("unexpected diagnostics: %+v", readErr)
	}
}

func TestReadRequestBodyWithPrealloc_RecordsTransportReadFailure(t *testing.T) {
	req := newRequestWithBody(t, []byte("ignored"), "zstd")
	req.ContentLength = 12
	req.Body = io.NopCloser(io.MultiReader(strings.NewReader("abc"), errReader{}))

	_, err := ReadRequestBodyWithPrealloc(req)
	if err == nil {
		t.Fatal("expected transport read error, got nil")
	}
	var readErr *RequestBodyReadError
	if !errors.As(err, &readErr) {
		t.Fatalf("expected RequestBodyReadError, got %T", err)
	}
	if readErr.Stage != "read" || readErr.BytesRead != 3 || readErr.ContentLength != 12 {
		t.Fatalf("unexpected diagnostics: %+v", readErr)
	}
	if readErr.CompressedFrameComplete == nil || *readErr.CompressedFrameComplete {
		t.Fatalf("expected failed compressed-frame probe, got %+v", readErr)
	}
	if readErr.DecodeProbeErr == nil {
		t.Fatalf("expected compressed-frame probe error, got %+v", readErr)
	}
}

func TestReadRequestBodyWithPrealloc_DetectsCompleteZstdFrameAfterTransportEOF(t *testing.T) {
	enc, _ := zstd.NewWriter(nil)
	compressed := enc.EncodeAll([]byte(samplePayload), nil)
	_ = enc.Close()

	req := newRequestWithBody(t, compressed, "zstd")
	req.ContentLength = int64(len(compressed) + 17)
	req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(compressed), errReader{}))

	_, err := ReadRequestBodyWithPrealloc(req)
	if err == nil {
		t.Fatal("expected transport read error, got nil")
	}
	var readErr *RequestBodyReadError
	if !errors.As(err, &readErr) {
		t.Fatalf("expected RequestBodyReadError, got %T", err)
	}
	if readErr.CompressedFrameComplete == nil || !*readErr.CompressedFrameComplete {
		t.Fatalf("expected complete compressed frame, got %+v", readErr)
	}
	if readErr.DecodedBytes != int64(len(samplePayload)) || readErr.DecodeProbeErr != nil {
		t.Fatalf("unexpected compressed-frame diagnostics: %+v", readErr)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestReadRequestBodyWithPrealloc_NilBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "/v1/responses", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	got, err := ReadRequestBodyWithPrealloc(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil body, got %q", got)
	}
}

func TestReadRequestBodyWithPrealloc_RespectsIdentityEncoding(t *testing.T) {
	req := newRequestWithBody(t, []byte(samplePayload), "identity")
	got, err := ReadRequestBodyWithPrealloc(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != samplePayload {
		t.Fatalf("body mismatch: got %q", got)
	}
}
