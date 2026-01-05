package auth

import (
	"net/http"
	"testing"
	"errors"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		header      http.Header
		wantKey     string
		wantErr     error
	}{
		{
			name:    "No Authorization Header",
			header:  http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header",
			header: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "Bearer somekey")
				return h
			}(),
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "Proper ApiKey Header",
			header: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey my-secret-key")
				return h
			}(),
			wantKey: "my-secret-key",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.header)
			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = %v, want %v", gotKey, tt.wantKey)
			}
			if (gotErr == nil && tt.wantErr != nil) ||
				(gotErr != nil && tt.wantErr == nil) ||
				(gotErr != nil && tt.wantErr != nil && gotErr.Error() != tt.wantErr.Error()) {
				t.Errorf("GetAPIKey() error = %v, want %v", gotErr, tt.wantErr)
			}
		})
	}
}
