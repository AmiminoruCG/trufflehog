package openrouter

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestOpenRouter_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	canonicalKey := fakeKey("7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b")
	noSeparatorKey := fakeKeyNoSeparator(strings.Repeat("x", 36))
	firstKey := fakeKey(strings.Repeat("a", 64))
	secondKey := fakeKey(strings.Repeat("b", 64))

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "canonical API key",
			input: "OPENROUTER_API_KEY = '" + canonicalKey + "'",
			want:  []string{canonicalKey},
		},
		{
			name:  "AI key env var without separator",
			input: "OPENROUTER_AI_KEY=" + noSeparatorKey,
			want:  []string{noSeparatorKey},
		},
		{
			name: "finds all unique matches",
			input: `openrouter_key = "` + firstKey + `"
OPENROUTER_AI_KEY = "` + secondKey + `"`,
			want: []string{
				firstKey,
				secondKey,
			},
		},
		{
			name:  "too short",
			input: "OPENROUTER_AI_KEY = " + fakeKey("short"),
			want:  nil,
		},
		{
			name:  "wrong provider",
			input: "openrouter_key = sk-proj-7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}

func TestOpenRouter_Verify(t *testing.T) {
	verifyKey := fakeKey("7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b")
	tests := []struct {
		name                string
		client              *http.Client
		wantVerified        bool
		wantVerificationErr bool
	}{
		{
			name:         "verified",
			client:       common.ConstantResponseHttpClient(200, `{"data":{"label":"test-key"}}`),
			wantVerified: true,
		},
		{
			name:         "unauthorized is determinate",
			client:       common.ConstantResponseHttpClient(401, `{"error":{"message":"invalid key"}}`),
			wantVerified: false,
		},
		{
			name:                "unexpected status is indeterminate",
			client:              common.ConstantResponseHttpClient(500, `{"error":"server error"}`),
			wantVerified:        false,
			wantVerificationErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d := Scanner{client: test.client}
			results, err := d.FromData(context.Background(), true, []byte("OPENROUTER_AI_KEY="+verifyKey))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(results) != 1 {
				t.Fatalf("expected 1 result, got %d", len(results))
			}
			if results[0].Verified != test.wantVerified {
				t.Fatalf("Verified = %v, want %v", results[0].Verified, test.wantVerified)
			}
			if (results[0].VerificationError() != nil) != test.wantVerificationErr {
				t.Fatalf("wantVerificationError = %v, verification error = %v", test.wantVerificationErr, results[0].VerificationError())
			}
		})
	}
}

func fakeKey(suffix string) string {
	return "sk-or-" + "v1-" + suffix
}

func fakeKeyNoSeparator(suffix string) string {
	return "sk-or-" + "v1" + suffix
}
