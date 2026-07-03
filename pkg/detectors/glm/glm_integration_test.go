//go:build detectors
// +build detectors

package glm

import (
	"context"
	"fmt"
	"os"
	"testing"
)

func TestGLM_FromChunk_Verified(t *testing.T) {
	apiKey := os.Getenv("GLM_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("ZHIPU_API_KEY")
	}
	if apiKey == "" {
		t.Skip("GLM_API_KEY or ZHIPU_API_KEY must be set")
	}

	tests := []struct {
		name     string
		data     []byte
		inactive bool
	}{
		{
			name: "valid API key",
			data: []byte(fmt.Sprintf("GLM_API_KEY=%s", apiKey)),
		},
		{
			name:     "inactive API key",
			data:     []byte("GLM_API_KEY=00000000000000000000000000000000.ABCDEFGHIJKLMNOP"),
			inactive: true,
		},
	}

	s := Scanner{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results, err := s.FromData(context.Background(), true, test.data)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			if results[0].Verified == test.inactive {
				t.Fatalf("Verified = %v, inactive = %v", results[0].Verified, test.inactive)
			}
		})
	}
}
