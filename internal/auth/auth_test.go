package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		authHeader  string
		expectedKey string
		expectedErr error
	}{
		{
			name:        "No Authorization Header",
			authHeader:  "",
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Malformed Header - No ApiKey prefix",
			authHeader:  "Bearer sometoken",
			expectedKey: "",
			expectedErr: errString("malformed authorization header"),
		},
		{
			name:        "Malformed Header - Missing Token",
			authHeader:  "ApiKey",
			expectedKey: "",
			expectedErr: errString("malformed authorization header"),
		},
		{
			name:        "Valid Header",
			authHeader:  "ApiKey abc123",
			expectedKey: "abc123",
			expectedErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headers := http.Header{}
			if test.authHeader != "" {
				headers.Set("Authorization", test.authHeader)
			}

			apiKey, err := GetAPIKey(headers)

			if apiKey != test.expectedKey {
				t.Errorf("expected key %q, got %q", test.expectedKey, apiKey)
			}
			if (err != nil && test.expectedErr == nil) || (err == nil && test.expectedErr != nil) {
				t.Fatalf("expected error %v, got %v", test.expectedErr, err)
			}
			if err != nil && err.Error() != test.expectedErr.Error() {
				t.Errorf("expected error message %q, got %q", test.expectedErr.Error(), err.Error())
			}
		})
	}
}

// Helper to create error with string
func errString(msg string) error {
	return errors.New(msg)
}
