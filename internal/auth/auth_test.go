package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		header  http.Header
		want    string
		wantErr error
	}{
		"auth header included, proper ApiKey": {
			buildHeader(map[string]string{
				"Authorization": "ApiKey 123456",
			}),
			"123456",
			nil,
		},
		"auth header included, malformed ApiKey": {
			buildHeader(map[string]string{
				"Authorization": "BadKey 123456",
			}),
			"123456",
			ErrMalformedAuthHeader,
		},
		"no auth header included": {
			buildHeader(map[string]string{}),
			"",
			ErrNoAuthHeaderIncluded,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.header)

			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tc.want {
					t.Fatalf("want %q, got %q", tc.want, got)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want error %v, got %v", tc.wantErr, err)
			}
			if got != "" {
				t.Fatalf("expected empty key, got %q", got)
			}
		})
	}
}

func buildHeader(fieldlines map[string]string) http.Header {
	headers := http.Header{}
	for k, v := range fieldlines {
		headers.Set(k, v)
	}
	return headers
}
