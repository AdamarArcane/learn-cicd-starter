package auth

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers http.Header
		want    string
		wantErr error
	}{
		"valid API key": {
			headers: http.Header{
				"Authorization": []string{"ApiKey validApiKey123"},
			},
			want:    "validApiKey123",
			wantErr: nil,
		},
		"no Authorization header": {
			headers: http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"malformed Authorization header (wrong keyword)": {
			headers: http.Header{
				"Authorization": []string{"Bearer validApiKey123"},
			},
			want:    "",
			wantErr: ErrMalformedAuthHeader,
		},
		"malformed Authorization header (no key provided)": {
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want:    "",
			wantErr: ErrMalformedAuthHeader,
		},
		"malformed Authorization header (incomplete split)": {
			headers: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			want:    "",
			wantErr: ErrMalformedAuthHeader,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.headers)

			// Compare the actual and expected output
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("GetAPIKey() mismatch (-want +got):\n%s", diff)
			}

			// Compare the actual error with the expected error using errors.Is()
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
