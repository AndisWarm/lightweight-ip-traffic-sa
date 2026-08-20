package security

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"lightweight-ip-traffic-sa/server/config"
)

// nmapAttackSurfaceProvider 用于封装nmapAttackSurface数据源访问能力。
type nmapAttackSurfaceProvider struct{}

// nmapScanResult 用于承载 Nmap 端口扫描结果。
type nmapScanResult struct {
	openPorts         []int
	highRiskOpenPorts []int
	rawOutput         string
}

// Name 用于返回数据源名称。
func (p nmapAttackSurfaceProvider) Name() string {
	return "nmap-enhanced"
}

// CollectAttackSurface 用于采集目标 IP 的攻击面信息。
func (p nmapAttackSurfaceProvider) CollectAttackSurface(ctx context.Context, targetIP string, baseInfo BaseInfoCollectedData, cfg config.SecurityConfig) (AttackSurfaceCollectedData, error) {
	nmapResult, err := runNmapAttackSurface(ctx, targetIP, cfg)
	if err != nil {
		fallback, fallbackErr := limitedPortScanProvider{}.CollectAttackSurface(ctx, targetIP, baseInfo, cfg)
		if fallbackErr != nil {
			return AttackSurfaceCollectedData{}, fallbackErr
		}
		fallback.RawPayload["nmapEnabled"] = true
		fallback.RawPayload["nmapPrototype"] = true
		fallback.RawPayload["nmapFallback"] = true
		fallback.RawPayload["nmapDegradeReason"] = err.Error()
		fallback.RawPayload["prototypeBoundary"] = "enhanced-switch"
		evidenceItems := extractEvidenceItems(fallback.RawPayload)
		evidenceItems = append([]securityEvidenceItem{
			{
				Source:   "limited-port-scan",
				Title:    "Nmap 增强开关已回退",
				Summary:  fmt.Sprintf("Nmap 不可用或执行失败，攻击面结果继续使用默认 limited-port-scan 主链路。原因：%s。", err.Error()),
				RiskHint: "LOW",
			},
		}, evidenceItems...)
		fallback.RawPayload["evidenceItems"] = evidenceItems
		return fallback, nil
	}

	return AttackSurfaceCollectedData{
		IP:                targetIP,
		OpenPortCount:     len(nmapResult.openPorts),
		HighRiskPortCount: len(nmapResult.highRiskOpenPorts),
		GeoRiskFlag:       isGeoRiskCountry(baseInfo.Country),
		SourceName:        p.Name(),
		RawPayload: map[string]any{
			"sourceName":         p.Name(),
			"sourceChain":        []string{p.Name()},
			"nmapEnabled":        true,
			"nmapPrototype":      true,
			"prototypeBoundary":  "enhanced-switch",
			"nmapPath":           cfg.Source.AttackSurface.NmapPath,
			"nmapTimeoutSeconds": cfg.Source.AttackSurface.NmapTimeoutSeconds,
			"openPorts":          nmapResult.openPorts,
			"highRiskOpenPorts":  nmapResult.highRiskOpenPorts,
			"rawOutput":          nmapResult.rawOutput,
			"evidenceItems": []securityEvidenceItem{
				{
					Source:   p.Name(),
					Title:    "Nmap 增强扫描结果",
					Summary:  fmt.Sprintf("开放端口=%s，高危开放端口=%s。", joinPorts(nmapResult.openPorts), joinPorts(nmapResult.highRiskOpenPorts)),
					RiskHint: attackSurfaceRiskHint(len(nmapResult.highRiskOpenPorts), len(nmapResult.openPorts)),
				},
				{
					Source:   p.Name(),
					Title:    "增强能力说明",
					Summary:  "Nmap 仅作为攻击面增强开关接入，不作为默认主链路依赖；关闭或失败时自动回退。",
					RiskHint: "INFO",
				},
			},
		},
	}, nil
}

// runNmapAttackSurface 用于运行服务启动或业务执行流程。
func runNmapAttackSurface(ctx context.Context, targetIP string, cfg config.SecurityConfig) (nmapScanResult, error) {
	ports := normalizeAttackSurfacePorts(cfg.Source.AttackSurface.Ports)
	if len(ports) == 0 {
		return nmapScanResult{}, fmt.Errorf("nmap ports empty")
	}

	timeout := resolveSourceTTL(cfg.Source.AttackSurface.NmapTimeoutSeconds, 8*time.Second)
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := []string{
		"-Pn",
		"-n",
		"-T4",
		"-p", joinPortsForArg(ports),
		"-oG", "-",
		targetIP,
	}

	cmd := exec.CommandContext(commandCtx, cfg.Source.AttackSurface.NmapPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nmapScanResult{}, fmt.Errorf("nmap exec failed: %w", err)
	}

	return parseNmapGrepableOutput(string(output)), nil
}

// parseNmapGrepableOutput 用于解析输入数据并转换为内部模型。
func parseNmapGrepableOutput(output string) nmapScanResult {
	result := nmapScanResult{
		openPorts:         []int{},
		highRiskOpenPorts: []int{},
		rawOutput:         strings.TrimSpace(output),
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if !strings.Contains(line, "Ports:") {
			continue
		}
		segments := strings.SplitN(line, "Ports:", 2)
		if len(segments) != 2 {
			continue
		}
		for _, item := range strings.Split(strings.TrimSpace(segments[1]), ",") {
			fields := strings.Split(strings.TrimSpace(item), "/")
			if len(fields) < 2 {
				continue
			}
			port, err := strconv.Atoi(strings.TrimSpace(fields[0]))
			if err != nil || strings.TrimSpace(fields[1]) != "open" {
				continue
			}
			result.openPorts = append(result.openPorts, port)
			if _, ok := highRiskPorts[port]; ok {
				result.highRiskOpenPorts = append(result.highRiskOpenPorts, port)
			}
		}
	}

	sort.Ints(result.openPorts)
	sort.Ints(result.highRiskOpenPorts)
	result.openPorts = dedupeIntSlice(result.openPorts)
	result.highRiskOpenPorts = dedupeIntSlice(result.highRiskOpenPorts)
	return result
}

// joinPortsForArg 用于拼接PortsForArg。
func joinPortsForArg(ports []int) string {
	items := make([]string, 0, len(ports))
	for _, port := range ports {
		items = append(items, strconv.Itoa(port))
	}
	return strings.Join(items, ",")
}

// dedupeIntSlice 用于执行dedupeIntSlice流程。
func dedupeIntSlice(values []int) []int {
	if len(values) == 0 {
		return values
	}
	result := make([]int, 0, len(values))
	seen := make(map[int]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
