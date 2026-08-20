package security

import (
	"context"
	"testing"
	"time"
)

// TestExtendExternalCollectorDeadlineAddsGraceWindow 用于执行TestExtendExternalCollectorDeadlineAddsGraceWindow流程。
func TestExtendExternalCollectorDeadlineAddsGraceWindow(t *testing.T) {
	base := 3 * time.Second
	got := extendExternalCollectorDeadline(base)
	want := base + externalCollectorCompletionGrace
	if got != want {
		t.Fatalf("unexpected extended timeout: got=%s want=%s", got, want)
	}
}

// TestRunExternalCollectorStepAllowsDegradedResultToReturnBeforeOuterTimeout 用于执行TestRunExternalCollectorStepAllowsDegradedResultToReturnBeforeOuterTimeout流程。
func TestRunExternalCollectorStepAllowsDegradedResultToReturnBeforeOuterTimeout(t *testing.T) {
	start := time.Now()
	result, err := runExternalCollectorStep(
		"base_info",
		"8.8.8.8",
		"p0-base-info",
		"test-config",
		50*time.Millisecond,
		time.Minute,
		func(ctx context.Context) (BaseInfoCollectedData, error) {
			<-ctx.Done()
			return BaseInfoCollectedData{
				IP:         "8.8.8.8",
				Country:    "UNKNOWN",
				Region:     "UNKNOWN",
				City:       "UNKNOWN",
				ISP:        "UNKNOWN",
				SourceName: "p0-base-info:degraded",
				RawPayload: map[string]any{
					"degraded":       true,
					"degradeReasons": []string{"rdap timeout"},
				},
			}, nil
		},
		validateBaseInfoCollectedData,
	)
	if err != nil {
		t.Fatalf("expected degraded result instead of timeout error, got=%v", err)
	}
	if result.SourceName != "p0-base-info:degraded" {
		t.Fatalf("unexpected source name: %s", result.SourceName)
	}
	if time.Since(start) < 50*time.Millisecond {
		t.Fatalf("collector returned before inner timeout elapsed")
	}
}
