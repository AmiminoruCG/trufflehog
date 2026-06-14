//go:build detectors
// +build detectors

package moonshot

import (
	"context"
	"fmt"
	"os"
	"testing"
)

func TestMoonshot_FromChunk_Verified(t *testing.T) {
	apiKey := os.Getenv("MOONSHOT_API_KEY")
	if apiKey == "" {
		t.Skip("MOONSHOT_API_KEY must be set")
	}

	tests := []struct {
		name     string
		data     []byte
		inactive bool
	}{
		{
			name: "valid API key",
			data: []byte(fmt.Sprintf("MOONSHOT_API_KEY=%s", apiKey)),
		},
		{
			name:     "inactive API key",
			data:     []byte("MOONSHOT_API_KEY=sk-000000000000000000000000000000000000000000000000"),
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
