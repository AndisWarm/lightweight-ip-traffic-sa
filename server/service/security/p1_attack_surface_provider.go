package security

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"lightweight-ip-traffic-sa/server/config"
)

// limitedPortScanProvider 用于封装limitedPortScan数据源访问能力。
type limitedPortScanProvider struct{}

// portScanResult 用于承载有限端口探测结果。
type portScanResult struct {
	port    int
	open    bool
	timeout bool
	err     error
}

var highRiskPorts = map[int]struct{}{
	22:   {},
	445:  {},
	3389: {},
}

// Name 用于返回数据源名称。
func (p limitedPortScanProvider) Name() string {
	return "limited-port-scan"
}

// CollectAttackSurface 用于采集目标 IP 的攻击面信息。
func (p limitedPortScanProvider) CollectAttackSurface(ctx context.Context, targetIP string, baseInfo BaseInfoCollectedData, cfg config.SecurityConfig) (AttackSurfaceCollectedData, error) {
	ports := normalizeAttackSurfacePorts(cfg.Source.AttackSurface.Ports)
	perDialTimeout := resolveAttackSurfaceDialTimeout(cfg)
	maxConcurrency := resolveAttackSurfaceConcurrency(cfg)

	result := AttackSurfaceCollectedData{
		IP:                targetIP,
		OpenPortCount:     0,
		HighRiskPortCount: 0,
		GeoRiskFlag:       isGeoRiskCountry(baseInfo.Country),
		SourceName:        p.Name(),
		RawPayload: map[string]any{
			"sourceName":          p.Name(),
			"sourceChain":         []string{p.Name()},
			"enabled":             true,
			"monitoredPorts":      ports,
			"timeoutMilliseconds": cfg.Source.AttackSurface.TimeoutMilliseconds,
			"maxConcurrency":      maxConcurrency,
			"cacheTTLSeconds":     cfg.Source.AttackSurface.CacheTTLSeconds,
			"complianceBoundary":  "仅允许在已授权目标上执行有限 TCP 端口探测。",
		},
	}

	if len(ports) == 0 {
		result.RawPayload["degraded"] = true
		result.RawPayload["degradeReasons"] = []string{"未配置可扫描端口"}
		result.RawPayload["evidenceItems"] = []securityEvidenceItem{
			{
				Source:   p.Name(),
				Title:    "有限端口探测未执行",
				Summary:  "当前未配置探测端口，攻击面结果按空结果处理。",
				RiskHint: "LOW",
			},
		}
		return result, nil
	}

	results := scanTargetPorts(ctx, targetIP, ports, perDialTimeout, maxConcurrency)
	openPorts := make([]int, 0, len(ports))
	highRiskOpenPorts := make([]int, 0, len(ports))
	timeoutPorts := make([]int, 0, len(ports))
	failedPorts := make([]string, 0)

	for _, item := range results {
		if item.open {
			openPorts = append(openPorts, item.port)
			if _, ok := highRiskPorts[item.port]; ok {
				highRiskOpenPorts = append(highRiskOpenPorts, item.port)
			}
			continue
		}
		if item.timeout {
			timeoutPorts = append(timeoutPorts, item.port)
			continue
		}
		if item.err != nil {
			failedPorts = append(failedPorts, fmt.Sprintf("%d:%s", item.port, item.err.Error()))
		}
	}

	sort.Ints(openPorts)
	sort.Ints(highRiskOpenPorts)
	sort.Ints(timeoutPorts)

	result.OpenPortCount = len(openPorts)
	result.HighRiskPortCount = len(highRiskOpenPorts)
	result.RawPayload["openPorts"] = openPorts
	result.RawPayload["highRiskOpenPorts"] = highRiskOpenPorts
	result.RawPayload["timeoutPorts"] = timeoutPorts
	if len(failedPorts) > 0 {
		result.RawPayload["failedPorts"] = failedPorts
	}
	degradeReasons := make([]string, 0, 2)
	if len(timeoutPorts) > 0 {
		degradeReasons = append(degradeReasons, fmt.Sprintf("存在 %d 个端口探测超时", len(timeoutPorts)))
	}
	if len(failedPorts) > 0 {
		degradeReasons = append(degradeReasons, fmt.Sprintf("存在 %d 个端口探测失败", len(failedPorts)))
	}
	if len(degradeReasons) > 0 {
		result.RawPayload["degraded"] = true
		result.RawPayload["degradeReasons"] = degradeReasons
	}

	evidenceItems := []securityEvidenceItem{
		{
			Source:   p.Name(),
			Title:    "有限端口探测结果",
			Summary:  fmt.Sprintf("探测端口=%s，开放端口=%s，高危开放端口=%s。", joinPorts(ports), joinPorts(openPorts), joinPorts(highRiskOpenPorts)),
			RiskHint: attackSurfaceRiskHint(len(highRiskOpenPorts), len(openPorts)),
		},
		{
			Source:   p.Name(),
			Title:    "合规边界说明",
			Summary:  "仅对固定端口进行轻量探测，避免将重型扫描能力作为主链路硬依赖。",
			RiskHint: "INFO",
		},
	}
	if len(timeoutPorts) > 0 {
		evidenceItems = append(evidenceItems, securityEvidenceItem{
			Source:   p.Name(),
			Title:    "端口超时记录",
			Summary:  fmt.Sprintf("超时端口=%s，当前结果按部分失败降级处理，不阻断任务主链路。", joinPorts(timeoutPorts)),
			RiskHint: "LOW",
		})
	}
	if len(failedPorts) > 0 {
		evidenceItems = append(evidenceItems, securityEvidenceItem{
			Source:   p.Name(),
			Title:    "端口失败记录",
			Summary:  fmt.Sprintf("失败端口=%s，当前结果按部分失败降级处理，不阻断任务主链路。", strings.Join(failedPorts, ", ")),
			RiskHint: "LOW",
		})
	}
	result.RawPayload["evidenceItems"] = evidenceItems

	return result, nil
}

// scanTargetPorts 用于执行scanTargetPorts流程。
func scanTargetPorts(ctx context.Context, targetIP string, ports []int, timeout time.Duration, maxConcurrency int) []portScanResult {
	results := make([]portScanResult, 0, len(ports))
	resultCh := make(chan portScanResult, len(ports))
	semaphore := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for _, port := range ports {
		port := port
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				resultCh <- portScanResult{port: port, err: ctx.Err()}
				return
			}
			defer func() { <-semaphore }()

			dialer := net.Dialer{Timeout: timeout}
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(targetIP, strconv.Itoa(port)))
			if err == nil {
				_ = conn.Close()
				resultCh <- portScanResult{port: port, open: true}
				return
			}
			if ctx.Err() != nil {
				resultCh <- portScanResult{port: port, err: ctx.Err()}
				return
			}

			lower := strings.ToLower(err.Error())
			if isClosedPortError(lower) {
				resultCh <- portScanResult{port: port}
				return
			}
			timeoutFlag := strings.Contains(lower, "timeout") || strings.Contains(lower, "i/o timeout")
			resultCh <- portScanResult{port: port, timeout: timeoutFlag, err: err}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for item := range resultCh {
		results = append(results, item)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].port < results[j].port
	})
	return results
}

// resolveAttackSurfaceStepTimeout 用于解析AttackSurfaceStepTimeout。
func resolveAttackSurfaceStepTimeout(cfg config.SecurityConfig) time.Duration {
	ports := normalizeAttackSurfacePorts(cfg.Source.AttackSurface.Ports)
	if len(ports) == 0 {
		return 2 * time.Second
	}
	concurrency := resolveAttackSurfaceConcurrency(cfg)
	batches := len(ports) / concurrency
	if len(ports)%concurrency != 0 {
		batches++
	}
	return time.Duration(batches)*resolveAttackSurfaceDialTimeout(cfg) + time.Second
}

// resolveAttackSurfaceDialTimeout 用于解析AttackSurfaceDialTimeout。
func resolveAttackSurfaceDialTimeout(cfg config.SecurityConfig) time.Duration {
	timeoutMs := cfg.Source.AttackSurface.TimeoutMilliseconds
	if timeoutMs <= 0 {
		timeoutMs = 800
	}
	return time.Duration(timeoutMs) * time.Millisecond
}

// resolveAttackSurfaceConcurrency 用于解析AttackSurfaceConcurrency。
func resolveAttackSurfaceConcurrency(cfg config.SecurityConfig) int {
	if cfg.Source.AttackSurface.MaxConcurrency <= 0 {
		return 3
	}
	return cfg.Source.AttackSurface.MaxConcurrency
}

// normalizeAttackSurfacePorts 用于归一化输入参数或业务指标。
func normalizeAttackSurfacePorts(ports []int) []int {
	result := make([]int, 0, len(ports))
	seen := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			continue
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		result = append(result, port)
	}
	sort.Ints(result)
	return result
}

// joinPorts 用于拼接Ports。
func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return "无"
	}
	items := make([]string, 0, len(ports))
	for _, port := range ports {
		items = append(items, strconv.Itoa(port))
	}
	return strings.Join(items, ", ")
}

// attackSurfaceRiskHint 用于执行attackSurface风险Hint流程。
func attackSurfaceRiskHint(highRiskOpenCount int, openCount int) string {
	switch {
	case highRiskOpenCount > 0:
		return "HIGH"
	case openCount > 0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// isClosedPortError 用于判断输入是否满足指定条件。
func isClosedPortError(message string) bool {
	return strings.Contains(message, "connection refused") ||
		strings.Contains(message, "actively refused")
}
