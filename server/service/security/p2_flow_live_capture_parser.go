package security

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	responseModel "lightweight-ip-traffic-sa/server/model/security/response"
)

// realOnlineCaptureFlowParser 用于解析realOnlineCapture流量输入并输出标准结果。
type realOnlineCaptureFlowParser struct{}

// windowsNetAdapterInfo 用于承载windowsNetAdapter信息数据。
type windowsNetAdapterInfo struct {
	Name                 string `json:"Name"`
	InterfaceDescription string `json:"InterfaceDescription"`
	InterfaceGuid        string `json:"InterfaceGuid"`
	IfIndex              int    `json:"ifIndex"`
	Status               string `json:"Status"`
}

// liveCaptureDeviceSelection 用于承载liveCaptureDeviceSelection数据。
type liveCaptureDeviceSelection struct {
	DeviceName  string
	Description string
	AliasName   string
	IfGuid      string
	IfIndex     int
	LocalIPs    []string
}

// Name 用于返回流量解析器名称。
func (p realOnlineCaptureFlowParser) Name() string {
	return "gopacket-live-capture-parser"
}

// Parse 用于解析流量输入并生成标准流量结果。
func (p realOnlineCaptureFlowParser) Parse(ctx context.Context, req FlowParseRequest) (FlowParseResult, error) {
	ifaceName := strings.TrimSpace(req.InterfaceName)
	if ifaceName == "" {
		return buildOnlineCaptureFailureResult(
			req,
			p.Name(),
			FlowStatusWaitingPermission,
			"在线抓包需要指定可授权网卡，当前仅保留入口状态。",
			newFlowParseErrorModel(FlowErrorCodeCapturePermissionNeeded, FlowErrorCategoryPermission, "未提供可授权的抓包网卡，在线抓包入口仍处于待授权状态。", false),
			map[string]any{"configuredInterfaceName": ifaceName},
			"在线抓包待授权",
		), nil
	}

	selection, adapterInfo, err := resolveLiveCaptureDeviceSelection(ctx, ifaceName)
	if err != nil {
		return buildOnlineCaptureFailureResult(
			req,
			p.Name(),
			FlowStatusEntryUnavailable,
			"在线抓包网卡不可用，当前仅保留独立入口状态。",
			newFlowParseErrorModel(FlowErrorCodeCaptureInterfaceInvalid, FlowErrorCategoryDependency, "指定网卡不存在、未被 Npcap 暴露，或当前进程无法访问。", true),
			map[string]any{"configuredInterfaceName": ifaceName, "failureCause": err.Error()},
			"在线抓包网卡不可用",
		), nil
	}

	// 在线抓包强依赖 Npcap 驱动 + 可授权网卡 + 管理员权限：缺少任一条件都会在下面失败，
	// 失败时按"权限缺失"或"网卡不可用"分类记录错误模型，不阻断主链路。
	metrics, debugPayload, err := captureOnlineTrafficWithPcap(ctx, req, selection, adapterInfo)
	if err != nil {
		status := FlowStatusParseFailed
		errorModel := newFlowParseErrorModel(FlowErrorCodeCaptureInterfaceNotReady, FlowErrorCategoryRuntime, "在线抓包启动失败，请检查 Npcap、网卡状态和管理员权限。", true)
		lowerErr := strings.ToLower(err.Error())
		// 错误信息含 permission/denied/access 时归类为权限问题，提示用管理员权限运行并确认 Npcap 可用，
		// 与"网卡不存在"区分开，便于用户对症修复。
		if strings.Contains(lowerErr, "permission") || strings.Contains(lowerErr, "denied") || strings.Contains(lowerErr, "access") {
			status = FlowStatusWaitingPermission
			errorModel = newFlowParseErrorModel(FlowErrorCodeCapturePermissionNeeded, FlowErrorCategoryPermission, "在线抓包受限，请以管理员权限运行并确认 Npcap 可用。", true)
		}
		debugPayload["failureCause"] = err.Error()
		return buildOnlineCaptureFailureResult(
			req,
			p.Name(),
			status,
			"在线抓包短时采集失败，当前仅保留入口状态与失败说明。",
			errorModel,
			debugPayload,
			"在线抓包失败",
		), nil
	}

	status := FlowStatusParsed
	if metrics.MatchedPacketCount == 0 {
		status = FlowStatusNoTargetTraffic
	}
	return FlowParseResult{
		Mode:                   FlowParseModeOnlineCapture,
		Status:                 status,
		Summary:                buildOnlineCaptureSessionSummary(metrics, selection.AliasName),
		BehaviorRiskScore:      buildFlowBehaviorRiskScore(metrics),
		SourceName:             resolveFlowCollectorSourceName(FlowParseModeOnlineCapture),
		SourceChain:            []string{resolveFlowCollectorSourceName(FlowParseModeOnlineCapture), "npcap-live-capture", "gopacket-live-parser"},
		ParserName:             p.Name(),
		ParserReady:            true,
		IntegrationStage:       "online-capture-npcap-gopacket",
		PrototypeBoundary:      "short-window-live-capture",
		InputKind:              "network-interface",
		InputSnapshot:          map[string]any{"interfaceName": selection.AliasName, "windowSeconds": req.WindowSeconds, "targetIP": req.TargetIP, "localIPs": append([]string(nil), selection.LocalIPs...)},
		ParsedMetrics:          buildFlowParsedMetricsMap(metrics),
		CollectedStableFields:  onlineCaptureCollectedStableFields(),
		NormalizedStableFields: defaultFlowNormalizedStableFields(),
		FutureStableFields:     defaultFlowFutureStableFields(),
		PrototypeOnlyFields:    defaultFlowPrototypeOnlyFields(FlowParseModeOnlineCapture),
		DebugOnlyFields:        defaultFlowDebugOnlyFields(FlowParseModeOnlineCapture),
		DebugPayload:           debugPayload,
		EvidenceItems:          buildFlowAnalysisEvidenceItems(FlowParseModeOnlineCapture, metrics, selection.AliasName),
	}, nil
}

// captureOnlineTrafficWithPcap 用于执行captureOnlineTrafficWithPCAP流程。
func captureOnlineTrafficWithPcap(
	ctx context.Context,
	req FlowParseRequest,
	selection liveCaptureDeviceSelection,
	adapterInfo *windowsNetAdapterInfo,
) (flowParseMetrics, map[string]any, error) {
	duration := resolveOnlineCaptureDuration(req)
	debugPayload := map[string]any{
		"configuredInterfaceName": selection.AliasName,
		"pcapDeviceName":          selection.DeviceName,
		"pcapDescription":         selection.Description,
		"interfaceGuid":           selection.IfGuid,
		"interfaceIndex":          selection.IfIndex,
		"localIPs":                append([]string(nil), selection.LocalIPs...),
		"captureSeconds":          int(duration / time.Second),
		"targetIP":                req.TargetIP,
		"windowSeconds":           req.WindowSeconds,
	}
	if adapterInfo != nil {
		debugPayload["adapterStatus"] = adapterInfo.Status
		debugPayload["adapterDescription"] = adapterInfo.InterfaceDescription
	}

	inactive, err := pcap.NewInactiveHandle(selection.DeviceName)
	if err != nil {
		return flowParseMetrics{}, debugPayload, fmt.Errorf("create inactive pcap handle failed: %w", err)
	}
	defer inactive.CleanUp()

	// 用 InactiveHandle 先配置抓包参数再 Activate：快照长度 65535（抓完整帧）、混杂模式（捕获非本机目的 MAC 的包）、
	// 读超时 500ms（让 ReadPacketData 周期返回，便于及时响应 ctx 取消）、立即模式（收到即返回，降低延迟）。
	_ = inactive.SetSnapLen(65535)
	_ = inactive.SetPromisc(true)
	_ = inactive.SetTimeout(500 * time.Millisecond)
	_ = inactive.SetImmediateMode(true)

	handle, err := inactive.Activate()
	if err != nil {
		return flowParseMetrics{}, debugPayload, fmt.Errorf("activate pcap handle failed: %w", err)
	}
	defer handle.Close()

	// BPF 过滤器在内核层过滤，只保留源或目的为目标 IP 的报文：网卡上无关流量远多于目标流量，
	// 先过滤再解析能大幅减少用户态拷贝与解析开销，也避免抓包缓冲被无关包占满导致丢包。
	if strings.TrimSpace(req.TargetIP) != "" {
		if err := handle.SetBPFFilter(fmt.Sprintf("host %s", req.TargetIP)); err != nil {
			return flowParseMetrics{}, debugPayload, fmt.Errorf("set pcap bpf filter failed: %w", err)
		}
	}

	accumulator := newFlowMetricsAccumulator(req.TargetIP, selection.LocalIPs, req.WindowSeconds)
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return flowParseMetrics{}, debugPayload, ctx.Err()
		default:
		}

		data, ci, err := handle.ReadPacketData()
		if err != nil {
			if nextError, ok := err.(pcap.NextError); ok && nextError == pcap.NextErrorTimeoutExpired {
				continue
			}
			if strings.Contains(strings.ToLower(err.Error()), "timeout") {
				continue
			}
			return flowParseMetrics{}, debugPayload, fmt.Errorf("read live packet failed: %w", err)
		}

		packet := gopacket.NewPacket(data, handle.LinkType(), gopacket.Lazy)
		packet.Metadata().CaptureInfo = ci
		accumulator.observe(packet)
	}

	if stats, err := handle.Stats(); err == nil && stats != nil {
		debugPayload["receivedPackets"] = stats.PacketsReceived
		debugPayload["droppedPackets"] = stats.PacketsDropped
		debugPayload["ifDroppedPackets"] = stats.PacketsIfDropped
	}
	return accumulator.finalize("pcap-live"), debugPayload, nil
}

// resolveOnlineCaptureDuration 用于解析OnlineCaptureDuration。
func resolveOnlineCaptureDuration(req FlowParseRequest) time.Duration {
	duration := req.Timeout
	if duration <= 0 {
		duration = 5 * time.Second
	}
	if req.WindowSeconds > 0 {
		windowDuration := time.Duration(req.WindowSeconds) * time.Second
		if windowDuration < duration {
			duration = windowDuration
		}
	}
	if req.Timeout > 3*time.Second && duration >= req.Timeout {
		duration = req.Timeout - 2*time.Second
	}
	if req.Timeout > 0 && duration > req.Timeout-2*time.Second && req.Timeout > 3*time.Second {
		duration = req.Timeout - 2*time.Second
	}
	if duration < time.Second {
		return time.Second
	}
	return duration
}

// resolveLiveCaptureDeviceSelection 用于解析LiveCaptureDeviceSelection。
func resolveLiveCaptureDeviceSelection(ctx context.Context, ifaceName string) (liveCaptureDeviceSelection, *windowsNetAdapterInfo, error) {
	ifaceName = strings.TrimSpace(ifaceName)
	if ifaceName == "" {
		return liveCaptureDeviceSelection{}, nil, fmt.Errorf("interface name empty")
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return liveCaptureDeviceSelection{}, nil, fmt.Errorf("list pcap devices failed: %w", err)
	}

	adapterInfo, _ := lookupWindowsNetAdapter(ctx, ifaceName)
	guidUpper := ""
	descLower := ""
	ifIndex := 0
	if adapterInfo != nil {
		guidUpper = strings.ToUpper(strings.TrimSpace(adapterInfo.InterfaceGuid))
		descLower = strings.ToLower(strings.TrimSpace(adapterInfo.InterfaceDescription))
		ifIndex = adapterInfo.IfIndex
	}

	// pcap 暴露的设备名是 \Device\NPF_{GUID} 形式，与 Windows 网卡名不一致；
	// 因此按"名称相等、描述相等、GUID 包含、描述包含"等维度加权打分，选最高分设备作为实际抓包句柄。
	bestScore := -1
	best := liveCaptureDeviceSelection{}
	for _, device := range devices {
		score := 0
		nameUpper := strings.ToUpper(strings.TrimSpace(device.Name))
		desc := strings.TrimSpace(device.Description)
		descLowerCandidate := strings.ToLower(desc)

		if strings.EqualFold(device.Name, ifaceName) {
			score += 200
		}
		if strings.EqualFold(desc, ifaceName) {
			score += 180
		}
		if strings.Contains(descLowerCandidate, strings.ToLower(ifaceName)) {
			score += 80
		}
		if guidUpper != "" && strings.Contains(nameUpper, strings.Trim(guidUpper, "{}")) {
			score += 220
		}
		if descLower != "" && strings.EqualFold(descLowerCandidate, descLower) {
			score += 150
		}
		if ifIndex > 0 {
			for _, address := range device.Addresses {
				if address.IP != nil && address.IP.To4() != nil {
					score += 5
					break
				}
			}
		}

		if score > bestScore {
			bestScore = score
			best = liveCaptureDeviceSelection{
				DeviceName:  strings.TrimSpace(device.Name),
				Description: desc,
				AliasName:   ifaceName,
				IfGuid:      guidUpper,
				IfIndex:     ifIndex,
				LocalIPs:    extractCaptureLocalIPs(device),
			}
		}
	}
	if bestScore < 0 || best.DeviceName == "" {
		return liveCaptureDeviceSelection{}, adapterInfo, fmt.Errorf("no npcap device matched interface %s", ifaceName)
	}
	return best, adapterInfo, nil
}

// lookupWindowsNetAdapter 用于执行lookupWindowsNetAdapter流程。
func lookupWindowsNetAdapter(ctx context.Context, ifaceName string) (*windowsNetAdapterInfo, error) {
	// 通过 PowerShell Get-NetAdapter 取 Windows 侧网卡元数据（GUID、ifIndex、状态），用于与 pcap 设备做 GUID 对齐；
	// 单引号转义防止网卡名里的引号注入命令。
	command := exec.CommandContext(
		ctx,
		"powershell",
		"-NoProfile",
		"-Command",
		fmt.Sprintf(
			"Get-NetAdapter -Name '%s' | Select-Object Name,InterfaceDescription,InterfaceGuid,ifIndex,Status | ConvertTo-Json -Compress",
			strings.ReplaceAll(ifaceName, "'", "''"),
		),
	)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(output))
	if text == "" {
		return nil, fmt.Errorf("empty Get-NetAdapter output")
	}
	var adapter windowsNetAdapterInfo
	if err := json.Unmarshal([]byte(text), &adapter); err != nil {
		return nil, err
	}
	return &adapter, nil
}

// listWindowsNetAdapters 用于分页或批量查询数据。
func listWindowsNetAdapters(ctx context.Context) ([]windowsNetAdapterInfo, error) {
	command := exec.CommandContext(
		ctx,
		"powershell",
		"-NoProfile",
		"-Command",
		"Get-NetAdapter | Select-Object Name,InterfaceDescription,InterfaceGuid,ifIndex,Status | ConvertTo-Json -Compress",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(output))
	if text == "" {
		return nil, fmt.Errorf("empty Get-NetAdapter output")
	}

	var single windowsNetAdapterInfo
	if err := json.Unmarshal([]byte(text), &single); err == nil && strings.TrimSpace(single.Name) != "" {
		return []windowsNetAdapterInfo{single}, nil
	}

	var items []windowsNetAdapterInfo
	if err := json.Unmarshal([]byte(text), &items); err != nil {
		return nil, err
	}
	return items, nil
}

// enumerateLiveCaptureInterfaces 用于执行enumerateLiveCaptureInterfaces流程。
func enumerateLiveCaptureInterfaces(ctx context.Context) ([]responseModel.FlowInterfaceOption, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("list pcap devices failed: %w", err)
	}
	adapters, err := listWindowsNetAdapters(ctx)
	if err != nil {
		return nil, fmt.Errorf("list windows adapters failed: %w", err)
	}

	deviceByGuid := make(map[string]pcap.Interface, len(devices))
	for _, device := range devices {
		nameUpper := strings.ToUpper(strings.TrimSpace(device.Name))
		if guid := extractNPFDeviceGUID(nameUpper); guid != "" {
			deviceByGuid[guid] = device
		}
	}

	result := make([]responseModel.FlowInterfaceOption, 0, len(adapters))
	for _, adapter := range adapters {
		guid := strings.ToUpper(strings.Trim(strings.TrimSpace(adapter.InterfaceGuid), "{}"))
		device, ok := deviceByGuid[guid]
		if !ok {
			continue
		}
		result = append(result, responseModel.FlowInterfaceOption{
			Name:                 strings.TrimSpace(adapter.Name),
			InterfaceDescription: strings.TrimSpace(adapter.InterfaceDescription),
			DeviceName:           strings.TrimSpace(device.Name),
			Status:               strings.TrimSpace(adapter.Status),
			IfIndex:              adapter.IfIndex,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].IfIndex == result[j].IfIndex {
			return result[i].Name < result[j].Name
		}
		return result[i].IfIndex < result[j].IfIndex
	})
	return result, nil
}

// extractNPFDeviceGUID 用于提取请求、令牌或流量中的关键信息。
func extractNPFDeviceGUID(deviceName string) string {
	const prefix = `\DEVICE\NPF_{`
	index := strings.Index(deviceName, prefix)
	if index < 0 {
		return ""
	}
	start := index + len(prefix)
	end := strings.Index(deviceName[start:], "}")
	if end < 0 {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(deviceName[start : start+end]))
}

// extractCaptureLocalIPs 用于提取请求、令牌或流量中的关键信息。
func extractCaptureLocalIPs(device pcap.Interface) []string {
	result := make([]string, 0, len(device.Addresses))
	seen := make(map[string]struct{}, len(device.Addresses))
	for _, address := range device.Addresses {
		if address.IP == nil {
			continue
		}
		value := strings.TrimSpace(address.IP.String())
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

// buildOnlineCaptureFailureResult 用于构建OnlineCaptureFailureResult。
func buildOnlineCaptureFailureResult(
	req FlowParseRequest,
	parserName string,
	status string,
	summary string,
	errorModel *FlowParseErrorModel,
	debugPayload map[string]any,
	evidenceTitle string,
) FlowParseResult {
	return FlowParseResult{
		Mode:                   FlowParseModeOnlineCapture,
		Status:                 status,
		Summary:                summary,
		BehaviorRiskScore:      0,
		SourceName:             resolveFlowCollectorSourceName(FlowParseModeOnlineCapture),
		SourceChain:            []string{resolveFlowCollectorSourceName(FlowParseModeOnlineCapture), "npcap-live-entry"},
		ParserName:             parserName,
		ParserReady:            false,
		IntegrationStage:       "online-capture-npcap-entry",
		PrototypeBoundary:      "short-window-live-capture",
		InputKind:              "network-interface",
		InputSnapshot:          map[string]any{"interfaceName": strings.TrimSpace(req.InterfaceName), "windowSeconds": req.WindowSeconds, "targetIP": req.TargetIP, "localIPs": append([]string(nil), req.LocalIPs...)},
		ErrorModel:             errorModel,
		DebugPayload:           debugPayload,
		CollectedStableFields:  defaultFlowCollectedStableFields(FlowParseModeOnlineCapture, false),
		NormalizedStableFields: defaultFlowNormalizedStableFields(),
		FutureStableFields:     defaultFlowFutureStableFields(),
		PrototypeOnlyFields:    defaultFlowPrototypeOnlyFields(FlowParseModeOnlineCapture),
		DebugOnlyFields:        defaultFlowDebugOnlyFields(FlowParseModeOnlineCapture),
		EvidenceItems: []securityEvidenceItem{
			{
				Source:   resolveFlowCollectorSourceName(FlowParseModeOnlineCapture),
				Title:    evidenceTitle,
				Summary:  summary,
				RiskHint: "INFO",
			},
		},
	}
}

// buildFlowParsedMetricsMap 用于构建流量ParsedMetricsMap。
func buildFlowParsedMetricsMap(metrics flowParseMetrics) map[string]any {
	parsedMetrics := map[string]any{
		"captureFormat":            metrics.CaptureFormat,
		"packetCount":              metrics.PacketCount,
		"matchedPacketCount":       metrics.MatchedPacketCount,
		"byteCount":                metrics.ByteCount,
		"sessionCount":             metrics.SessionCount,
		"protocolDistribution":     metrics.ProtocolCounts,
		"topPorts":                 sortStringIntMap(metrics.PortCounts),
		"peerEndpoints":            sortStringIntMap(metrics.PeerCounts),
		"anomalyCandidates":        metrics.AnomalyCandidates,
		"peakPps":                  metrics.PeakPPS,
		"burstScore":               metrics.BurstScore,
		"scanScore":                metrics.ScanScore,
		"dnsEventCount":            metrics.DNSEventCount,
		"httpEventCount":           metrics.HTTPEventCount,
		"tlsEventCount":            metrics.TLSEventCount,
		"dnsTopQuestions":          metrics.DNSTopQuestions,
		"dnsQueryTypeHints":        metrics.DNSQueryTypeHints,
		"httpMethodHints":          metrics.HTTPMethodHints,
		"httpHostHints":            metrics.HTTPHostHints,
		"httpStatusHints":          metrics.HTTPStatusHints,
		"tlsHandshakeHints":        metrics.TLSHandshakeHints,
		"tlsVersionHints":          metrics.TLSVersionHints,
		"applicationSignals":       metrics.ApplicationSignals,
		"directionalityIndicators": metrics.DirectionalityIndicators,
		"portDensityIndicators":    metrics.PortDensityIndicators,
		"payloadEntropyIndicators": metrics.PayloadEntropyIndicators,
		"windows":                  metrics.Windows,
	}
	if !metrics.FirstSeenAt.IsZero() {
		parsedMetrics["firstSeenAt"] = metrics.FirstSeenAt.Format(time.RFC3339)
	}
	if !metrics.LastSeenAt.IsZero() {
		parsedMetrics["lastSeenAt"] = metrics.LastSeenAt.Format(time.RFC3339)
	}
	return parsedMetrics
}

// buildOnlineCaptureSummary 用于构建OnlineCapture摘要。
func buildOnlineCaptureSummary(metrics flowParseMetrics, iface string) string {
	if metrics.MatchedPacketCount == 0 {
		return fmt.Sprintf("在线抓包网卡 %s 已完成短时采集，但未发现与目标 IP 相关的报文。", iface)
	}
	return fmt.Sprintf(
		"在线抓包网卡 %s 已完成短时采集：目标相关报文 %d 个，会话 %d 个，字节 %d，DNS/HTTP/TLS=%d/%d/%d。",
		iface,
		metrics.MatchedPacketCount,
		metrics.SessionCount,
		metrics.ByteCount,
		metrics.DNSEventCount,
		metrics.HTTPEventCount,
		metrics.TLSEventCount,
	)
}

// buildFlowAnalysisEvidenceItems 用于构建流量AnalysisEvidenceItems。
func buildFlowAnalysisEvidenceItems(mode FlowParseMode, metrics flowParseMetrics, sourceRef string) []securityEvidenceItem {
	source := resolveFlowCollectorSourceName(mode)
	items := []securityEvidenceItem{
		{
			Source:   source,
			Title:    "流量解析完成",
			Summary:  buildFlowAnalysisSummary(mode, metrics, sourceRef),
			RiskHint: selectFlowRiskHint(buildFlowBehaviorRiskScore(metrics)),
		},
	}
	if metrics.MatchedPacketCount > 0 {
		items = append(items, securityEvidenceItem{
			Source:   source,
			Title:    "协议与会话统计",
			Summary:  fmt.Sprintf("协议分布=%s；高频端口=%s；高频对端=%s；峰值PPS=%.2f；突发评分=%.2f；扫描评分=%.2f。", formatProtocolDistribution(metrics.ProtocolCounts), formatTopCounts(metrics.PortCounts), formatTopCounts(metrics.PeerCounts), metrics.PeakPPS, metrics.BurstScore, metrics.ScanScore),
			RiskHint: "INFO",
		})
	}
	if metrics.DNSEventCount > 0 || metrics.HTTPEventCount > 0 || metrics.TLSEventCount > 0 {
		items = append(items, securityEvidenceItem{
			Source:   source,
			Title:    "应用层候选摘要",
			Summary:  fmt.Sprintf("DNS Top=%s；DNS 类型=%s；HTTP Host=%s；HTTP 状态=%s；TLS SNI=%s；TLS 版本=%s。", formatTopFlowStringCounts(metrics.DNSTopQuestions), formatTopFlowStringCounts(metrics.DNSQueryTypeHints), formatTopFlowStringCounts(metrics.HTTPHostHints), formatTopFlowStringCounts(metrics.HTTPStatusHints), formatTLSHandshakeHints(metrics.TLSHandshakeHints), formatTopFlowStringCounts(metrics.TLSVersionHints)),
			RiskHint: "INFO",
		})
	}
	if len(metrics.DirectionalityIndicators) > 0 || len(metrics.PortDensityIndicators) > 0 || len(metrics.PayloadEntropyIndicators) > 0 {
		items = append(items, securityEvidenceItem{
			Source:   source,
			Title:    "动态行为侧写",
			Summary:  buildDynamicBehaviorSummary(metrics),
			RiskHint: selectFlowRiskHint(buildFlowBehaviorRiskScore(metrics)),
		})
	}
	if len(metrics.ApplicationSignals) > 0 {
		items = append(items, securityEvidenceItem{
			Source:   source,
			Title:    "应用层动态信号",
			Summary:  strings.Join(metrics.ApplicationSignals, "；"),
			RiskHint: "MEDIUM",
		})
	}
	if len(metrics.AnomalyCandidates) > 0 {
		items = append(items, securityEvidenceItem{
			Source:   source,
			Title:    "基础异常候选",
			Summary:  joinAnomalySummaries(metrics.AnomalyCandidates),
			RiskHint: selectAnomalyRiskHint(metrics.AnomalyCandidates),
		})
	}
	return items
}

// buildFlowAnalysisSummary 用于构建流量Analysis摘要。
func buildFlowAnalysisSummary(mode FlowParseMode, metrics flowParseMetrics, sourceRef string) string {
	prefix := "流量解析"
	switch mode {
	case FlowParseModeOfflinePCAP:
		prefix = fmt.Sprintf("离线文件 %s", sourceRef)
	case FlowParseModeOnlineCapture:
		prefix = fmt.Sprintf("在线抓包 %s", sourceRef)
	}
	if metrics.MatchedPacketCount == 0 {
		return fmt.Sprintf("%s 已完成，但未发现与目标 IP 相关的报文。", prefix)
	}
	return fmt.Sprintf(
		"%s 已完成：目标相关报文 %d 个，会话 %d 个，字节 %d，协议分布 %s，DNS/HTTP/TLS=%d/%d/%d。",
		prefix,
		metrics.MatchedPacketCount,
		metrics.SessionCount,
		metrics.ByteCount,
		formatProtocolDistribution(metrics.ProtocolCounts),
		metrics.DNSEventCount,
		metrics.HTTPEventCount,
		metrics.TLSEventCount,
	)
}

// formatTopFlowStringCounts 用于格式化Top流量StringCounts展示文本。
func formatTopFlowStringCounts(items []flowStringCount) string {
	if len(items) == 0 {
		return "-"
	}
	if len(items) > 3 {
		items = items[:3]
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("%s=%d", item.Key, item.Count))
	}
	return strings.Join(parts, ", ")
}

// formatTLSHandshakeHints 用于格式化TLSHandshakeHints展示文本。
func formatTLSHandshakeHints(items []flowTLSHandshakeHint) string {
	if len(items) == 0 {
		return "-"
	}
	if len(items) > 3 {
		items = items[:3]
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("%s=%d", item.ServerName, item.Count))
	}
	return strings.Join(parts, ", ")
}

// buildDynamicBehaviorSummary 用于构建DynamicBehavior摘要。
func buildDynamicBehaviorSummary(metrics flowParseMetrics) string {
	parts := make([]string, 0, 4)
	if directionality := metrics.DirectionalityIndicators; len(directionality) > 0 {
		parts = append(parts, fmt.Sprintf(
			"方向性=%v，入/出报文=%d/%d，packetBias=%.2f",
			directionality["dominantDirection"],
			toInt(directionality["inboundPacketCount"]),
			toInt(directionality["outboundPacketCount"]),
			toFloat64(directionality["packetBias"]),
		))
	}
	if density := metrics.PortDensityIndicators; len(density) > 0 {
		parts = append(parts, fmt.Sprintf(
			"目标端口=%d，高危端口=%d，端口密度=%.2f",
			toInt(density["uniqueTargetPortCount"]),
			toInt(density["highRiskTargetPortCount"]),
			toFloat64(density["targetPortDensity"]),
		))
	}
	if entropy := metrics.PayloadEntropyIndicators; len(entropy) > 0 {
		parts = append(parts, fmt.Sprintf(
			"高熵报文=%d，平均熵=%.2f",
			toInt(entropy["highEntropyPacketCount"]),
			toFloat64(entropy["averagePayloadEntropy"]),
		))
	}
	if len(parts) == 0 {
		return "当前暂无可归档的动态行为侧写。"
	}
	return strings.Join(parts, "；")
}
