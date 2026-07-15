package handler

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/config"
	pkghttputil "github.com/Wei-Shaw/sub2api/internal/pkg/httputil"
	"go.uber.org/zap"
)

func extractMaxBytesError(err error) (*http.MaxBytesError, bool) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return maxErr, true
	}
	return nil, false
}

func formatBodyLimit(limit int64) string {
	const mb = 1024 * 1024
	if limit >= mb {
		return fmt.Sprintf("%dMB", limit/mb)
	}
	return fmt.Sprintf("%dB", limit)
}

func buildBodyTooLargeMessage(limit int64) string {
	return fmt.Sprintf("Request body too large, limit is %s", formatBodyLimit(limit))
}

func readLenientJSONRequestBodyWithPrealloc(req *http.Request, cfg *config.Config) ([]byte, error) {
	return pkghttputil.ReadLenientJSONRequestBodyWithPrealloc(req, gatewayMaxBodySize(cfg))
}

func logRequestBodyReadFailure(log *zap.Logger, req *http.Request, err error) {
	if log == nil || err == nil {
		return
	}

	fields := []zap.Field{zap.Error(err)}
	var readErr *pkghttputil.RequestBodyReadError
	if errors.As(err, &readErr) {
		fields = append(fields,
			zap.String("error_stage", readErr.Stage),
			zap.String("content_encoding", readErr.ContentEncoding),
			zap.Int64("bytes_read", readErr.BytesRead),
			zap.Int64("declared_content_length", readErr.ContentLength),
		)
		if readErr.ContentLength >= 0 {
			fields = append(fields,
				zap.Int64("content_length_gap_bytes", readErr.ContentLength-readErr.BytesRead),
			)
		}
		if readErr.CompressedFrameComplete != nil {
			fields = append(fields,
				zap.Bool("compressed_frame_complete", *readErr.CompressedFrameComplete),
				zap.Int64("decoded_bytes_from_received_body", readErr.DecodedBytes),
			)
			if readErr.DecodeProbeErr != nil {
				fields = append(fields, zap.NamedError("compressed_frame_probe_error", readErr.DecodeProbeErr))
			}
		}
	}
	if req != nil {
		fields = append(fields,
			zap.String("request_content_encoding", req.Header.Get("Content-Encoding")),
			zap.Int64("request_content_length", req.ContentLength),
			zap.Strings("transfer_encoding", req.TransferEncoding),
			zap.String("protocol", req.Proto),
			zap.Bool("connection_close", req.Close),
		)
	}

	log.Warn("request_body_read_failed", fields...)
}

func gatewayMaxBodySize(cfg *config.Config) int64 {
	if cfg == nil {
		return 0
	}
	return cfg.Gateway.MaxBodySize
}
