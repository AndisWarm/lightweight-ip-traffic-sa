package security

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"lightweight-ip-traffic-sa/server/config"
)

// TestQueryRDAPWithFallbackStopsWhenParentContextCancelled 用于执行TestQueryRDAPWithFallbackStopsWhenParentContextCancelled流程。
func TestQueryRDAPWithFallbackStopsWhenParentContextCancelled(t *testing.T) {
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		time.Sleep(120 * time.Millisecond)
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Millisecond)
	defer cancel()

	_, _, err := queryRDAPWithFallback(ctx, "8.8.8.8", 200*time.Millisecond, config.RDAPSourceConfig{
		Enabled: true,
		BaseURL: server.URL + "/",
		BackupBaseURLs: []string{
			server.URL + "/backup-1/",
			server.URL + "/backup-2/",
			server.URL + "/backup-3/",
		},
	})
	if err == nil {
		t.Fatal("expected rdap fallback error")
	}
	if !errors.Is(err, context.DeadlineExceeded) && requestCount.Load() > 2 {
		t.Fatalf("expected fallback to stop early after parent cancellation, requestCount=%d err=%v", requestCount.Load(), err)
	}
	if requestCount.Load() > 2 {
		t.Fatalf("expected at most 2 requests before cancellation propagated, got=%d", requestCount.Load())
	}
}
