package security

import (
	"context"
	"fmt"
	"strings"
	"time"

	"lightweight-ip-traffic-sa/server/config"
)

// FlowParseMode 用于承载流量ParseMode数据。
type FlowParseMode string

const (
	FlowParseModeDisabled      FlowParseMode = "disabled"
	FlowParseModeSample        FlowParseMode = "sample"
	FlowParseModeOfflinePCAP   FlowParseMode = "offline_pcap"
	FlowParseModeOnlineCapture FlowParseMode = "online_capture"
)

const (
	flowParseContractVersion = "flow-result-v2"

	FlowStatusDisabled          = "DISABLED"
	FlowStatusSampleOnly        = "SAMPLE_ONLY"
	FlowStatusConfigRequired    = "CONFIG_REQUIRED"
	FlowStatusInputInvalid      = "INPUT_INVALID"
	FlowStatusParseFailed       = "PARSE_FAILED"
	FlowStatusParsed            = "PARSED"
	FlowStatusNoTargetTraffic   = "NO_TARGET_TRAFFIC"
	FlowStatusWaitingPermission = "WAITING_PERMISSION"
	FlowStatusEntryReady        = "ENTRY_READY"
	FlowStatusEntryUnavailable  = "ENTRY_UNAVAILABLE"
)

const (
	FlowErrorCategoryConfig     = "config"
	FlowErrorCategoryInput      = "input"
	FlowErrorCategoryPermission = "permission"
	FlowErrorCategoryRuntime    = "runtime"
	FlowErrorCategoryDependency = "dependency"
)

const (
	FlowErrorCodePcapPathRequired         = "FLOW_PCAP_PATH_REQUIRED"
	FlowErrorCodePcapPathInvalid          = "FLOW_PCAP_PATH_INVALID"
	FlowErrorCodePcapFileUnavailable      = "FLOW_PCAP_FILE_UNAVAILABLE"
	FlowErrorCodePcapParseFailed          = "FLOW_PCAP_PARSE_FAILED"
	FlowErrorCodePcapParseTimeout         = "FLOW_PCAP_PARSE_TIMEOUT"
	FlowErrorCodeCapturePermissionNeeded  = "FLOW_CAPTURE_PERMISSION_REQUIRED"
	FlowErrorCodeCaptureInterfaceInvalid  = "FLOW_CAPTURE_INTERFACE_INVALID"
	FlowErrorCodeCaptureInterfaceNotReady = "FLOW_CAPTURE_INTERFACE_NOT_READY"
)

// FlowParseRequest 用于承载流量Parse接口的请求参数。
type FlowParseRequest struct {
	TargetIP      string
	LocalIPs      []string
	Mode          FlowParseMode
	Timeout       time.Duration
	WindowSeconds int
	SampleProfile string
	PcapFilePath  string
	InterfaceName string
}

// FlowParseErrorModel 用于承载流量ParseError模型数据。
type FlowParseErrorModel struct {
	Code      string `json:"code"`
	Category  string `json:"category"`
	Retryable bool   `json:"retryable"`
	Message   string `json:"message"`
}

// FlowParseResult 用于承载统一的流量解析输出。
type FlowParseResult struct {
	Mode                   FlowParseMode
	Status                 string
	Summary                string
	BehaviorRiskScore      float64
	SourceName             string
	SourceChain            []string
	EvidenceItems          []securityEvidenceItem
	ParserName             string
	ParserReady            bool
	IntegrationStage       string
	PrototypeBoundary      string
	InputKind              string
	InputSnapshot          map[string]any
	ParsedMetrics          map[string]any
	ErrorModel             *FlowParseErrorModel
	DebugPayload           map[string]any
	CollectedStableFields  []string
	NormalizedStableFields []string
	FutureStableFields     []string
	PrototypeOnlyFields    []string
	DebugOnlyFields        []string
}

// FlowParser 用于解析流量输入并输出标准结果。
type FlowParser interface {
	Name() string
	Parse(ctx context.Context, req FlowParseRequest) (FlowParseResult, error)
}

// buildEnhancedScoreFactors 用于构建Enhanced评分Factors。
// 在四维评分因子基础上，只对 behavior 因子补充“流量证据依据”，其余因子保持原样
func buildEnhancedScoreFactors(collected TaskCollectedData, cfg config.SecurityConfig, baseInfoRisk float64, attackRisk float64, behaviorRisk float64) []securityScoreFactor {
	factors := buildScoreFactors(collected, cfg, baseInfoRisk, attackRisk, behaviorRisk)
	for index := range factors {
		if factors[index].Key != "behavior" {
			continue
		}
		switch {
		case hasFlowRealMetrics(collected.Flow):
			// 有真实流量指标时，把报文数/会话数/DNS/HTTP/TLS 等摘要作为评分依据展示
			factors[index].Basis = buildFlowBehaviorBasis(collected, behaviorRisk)
		case isFlowPrototypeVisible(collected.Flow):
			factors[index].Basis = fmt.Sprintf("mode=%s, status=%s, summary=%s", collected.Flow.Mode, collected.Flow.Status, collected.Flow.Summary)
		case isFlowDisabled(collected.Flow):
			factors[index].Basis = "流量维默认关闭，当前不纳入默认来源链与证据链。"
		default:
			factors[index].Basis = "流量维仍处于原型增强边界内，当前只保留入口信息，不纳入默认来源链。"
		}
	}
	return factors
}

// buildCollectedEvidenceItemsV2 用于构建包含流量增强信息的证据条目。
func buildCollectedEvidenceItemsV2(collected TaskCollectedData) []securityEvidenceItem {
	items := buildCollectedEvidenceItems(collected)
	if jointEvidence := buildJointAnalysisEvidence(collected); jointEvidence != nil {
		items = append(items, *jointEvidence)
	}
	if shouldIncludeFlowSource(collected.Flow) {
		items = append(items, extractEvidenceItems(collected.Flow.RawPayload)...)
	}
	return items
}

// hasFlowRealMetrics 用于判断目标是否具备指定数据或能力。
func hasFlowRealMetrics(flow FlowCollectedData) bool {
	metrics := resolveFlowParsedMetrics(flow)
	return readFlowMetricUint64(metrics, "packetCount") > 0 ||
		readFlowMetricUint64(metrics, "byteCount") > 0 ||
		readFlowMetricUint64(metrics, "sessionCount") > 0 ||
		len(metrics) > 0
}

// buildFlowBehaviorBasis 用于构建流量BehaviorBasis。
func buildFlowBehaviorBasis(collected TaskCollectedData, behaviorRisk float64) string {
	metrics := resolveFlowParsedMetrics(collected.Flow)
	parts := []string{
		fmt.Sprintf("mode=%s", normalizeFlowBoundaryMode(collected.Flow.Mode)),
		fmt.Sprintf("status=%s", strings.ToUpper(strings.TrimSpace(collected.Flow.Status))),
		fmt.Sprintf("behaviorRisk=%.2f", round2(behaviorRisk)),
	}
	if packets := readFlowMetricUint64(metrics, "packetCount"); packets > 0 {
		parts = append(parts, fmt.Sprintf("packets=%d", packets))
	}
	if sessions := readFlowMetricUint64(metrics, "sessionCount"); sessions > 0 {
		parts = append(parts, fmt.Sprintf("sessions=%d", sessions))
	}
	if dnsEvents := readFlowMetricUint64(metrics, "dnsEventCount"); dnsEvents > 0 {
		parts = append(parts, fmt.Sprintf("dns=%d", dnsEvents))
	}
	if httpEvents := readFlowMetricUint64(metrics, "httpEventCount"); httpEvents > 0 {
		parts = append(parts, fmt.Sprintf("http=%d", httpEvents))
	}
	if tlsEvents := readFlowMetricUint64(metrics, "tlsEventCount"); tlsEvents > 0 {
		parts = append(parts, fmt.Sprintf("tls=%d", tlsEvents))
	}
	if signals, ok := metrics["applicationSignals"].([]string); ok && len(signals) > 0 {
		parts = append(parts, "signals="+strings.Join(signals, " / "))
	}
	if dnsTop := stringifyTopCountMetrics(metrics["dnsTopQuestions"]); dnsTop != "" {
		parts = append(parts, "dnsTop="+dnsTop)
	}
	if dnsType := stringifyTopCountMetrics(metrics["dnsQueryTypeHints"]); dnsType != "" {
		parts = append(parts, "dnsType="+dnsType)
	}
	if httpHosts := stringifyTopCountMetrics(metrics["httpHostHints"]); httpHosts != "" {
		parts = append(parts, "httpHosts="+httpHosts)
	}
	if httpStatus := stringifyTopCountMetrics(metrics["httpStatusHints"]); httpStatus != "" {
		parts = append(parts, "httpStatus="+httpStatus)
	}
	if tlsSNI := stringifyTLSHints(metrics["tlsHandshakeHints"]); tlsSNI != "" {
		parts = append(parts, "tlsSNI="+tlsSNI)
	}
	if tlsVersion := stringifyTopCountMetrics(metrics["tlsVersionHints"]); tlsVersion != "" {
		parts = append(parts, "tlsVersion="+tlsVersion)
	}
	if directionality := stringifyDirectionalityMetrics(metrics["directionalityIndicators"]); directionality != "" {
		parts = append(parts, directionality)
	}
	if portDensity := stringifyPortDensityMetrics(metrics["portDensityIndicators"]); portDensity != "" {
		parts = append(parts, portDensity)
	}
	if entropy := stringifyEntropyMetrics(metrics["payloadEntropyIndicators"]); entropy != "" {
		parts = append(parts, entropy)
	}
	return strings.Join(parts, ", ")
}

// buildJointAnalysisEvidence 用于构建JointAnalysisEvidence。
func buildJointAnalysisEvidence(collected TaskCollectedData) *securityEvidenceItem {
	if !hasFlowRealMetrics(collected.Flow) {
		return nil
	}
	metrics := resolveFlowParsedMetrics(collected.Flow)
	summaryParts := []string{
		fmt.Sprintf("基础画像=%s/%s", fallbackString(collected.BaseInfo.Country, "UNKNOWN"), fallbackString(collected.BaseInfo.WhoisOrg, "UNKNOWN")),
		fmt.Sprintf("信誉=%.2f", round2(collected.Reputation.ReputationScore)),
		fmt.Sprintf("攻击面=开放%d/高危%d", collected.AttackSurface.OpenPortCount, collected.AttackSurface.HighRiskPortCount),
		fmt.Sprintf("流量=%s:%s", normalizeFlowBoundaryMode(collected.Flow.Mode), strings.ToUpper(strings.TrimSpace(collected.Flow.Status))),
	}
	if packets := readFlowMetricUint64(metrics, "packetCount"); packets > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("报文=%d", packets))
	}
	if sessions := readFlowMetricUint64(metrics, "sessionCount"); sessions > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("会话=%d", sessions))
	}
	if peakPPS := readFlowMetricFloat64(metrics, "peakPps"); peakPPS > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("峰值PPS=%.2f", peakPPS))
	}
	if scanScore := readFlowMetricFloat64(metrics, "scanScore"); scanScore > 0 {
		summaryParts = append(summaryParts, fmt.Sprintf("扫描评分=%.2f", scanScore))
	}
	if signals, ok := metrics["applicationSignals"].([]string); ok && len(signals) > 0 {
		summaryParts = append(summaryParts, "应用信号="+strings.Join(signals, " / "))
	}
	if dnsTop := stringifyTopCountMetrics(metrics["dnsTopQuestions"]); dnsTop != "" {
		summaryParts = append(summaryParts, "DNS Top="+dnsTop)
	}
	if dnsType := stringifyTopCountMetrics(metrics["dnsQueryTypeHints"]); dnsType != "" {
		summaryParts = append(summaryParts, "DNS 类型="+dnsType)
	}
	if httpHosts := stringifyTopCountMetrics(metrics["httpHostHints"]); httpHosts != "" {
		summaryParts = append(summaryParts, "HTTP Host="+httpHosts)
	}
	if httpStatus := stringifyTopCountMetrics(metrics["httpStatusHints"]); httpStatus != "" {
		summaryParts = append(summaryParts, "HTTP 状态="+httpStatus)
	}
	if tlsSNI := stringifyTLSHints(metrics["tlsHandshakeHints"]); tlsSNI != "" {
		summaryParts = append(summaryParts, "TLS SNI="+tlsSNI)
	}
	if tlsVersion := stringifyTopCountMetrics(metrics["tlsVersionHints"]); tlsVersion != "" {
		summaryParts = append(summaryParts, "TLS 版本="+tlsVersion)
	}
	if directionality := stringifyDirectionalityMetrics(metrics["directionalityIndicators"]); directionality != "" {
		summaryParts = append(summaryParts, directionality)
	}
	if portDensity := stringifyPortDensityMetrics(metrics["portDensityIndicators"]); portDensity != "" {
		summaryParts = append(summaryParts, portDensity)
	}
	if entropy := stringifyEntropyMetrics(metrics["payloadEntropyIndicators"]); entropy != "" {
		summaryParts = append(summaryParts, entropy)
	}
	return &securityEvidenceItem{
		Source:   "joint-analysis",
		Title:    "联合判定依据",
		Summary:  strings.Join(summaryParts, "；"),
		RiskHint: selectFlowRiskHint(collected.Flow.BehaviorRiskScore),
	}
}

// buildCollectedFlowPrototypeItems 用于构建流量原型能力展示条目。
func buildCollectedFlowPrototypeItems(flow FlowCollectedData) []securityEvidenceItem {
	if !isFlowPrototypeVisible(flow) {
		return nil
	}
	return extractEvidenceItems(flow.RawPayload)
}

// buildFlowPrototypeSourceChain 用于构建流量Prototype来源链路。
func buildFlowPrototypeSourceChain(flow FlowCollectedData) []string {
	if !isFlowPrototypeVisible(flow) || !shouldDisplayFlowPrototype(flow.Mode, flow.Status) {
		return nil
	}
	return extractSourceChain(flow.RawPayload, flow.SourceName)
}

// buildFlowParseRequest 用于构建流量Parse请求。
func buildFlowParseRequest(targetIP string, cfg config.SecurityConfig) FlowParseRequest {
	return FlowParseRequest{
		TargetIP:      targetIP,
		Mode:          resolveFlowParseMode(cfg),
		Timeout:       resolveSourceTTL(cfg.Source.Flow.TimeoutSeconds, collectorTimeout),
		WindowSeconds: cfg.Source.Flow.WindowSeconds,
		SampleProfile: strings.TrimSpace(cfg.Source.Flow.SampleProfile),
		PcapFilePath:  strings.TrimSpace(cfg.Source.Flow.PcapFilePath),
		InterfaceName: strings.TrimSpace(cfg.Source.Flow.InterfaceName),
	}
}

// resolveFlowParseMode 用于解析流量ParseMode。
// 将配置里的字符串模式归一化为内部 FlowParseMode 枚举；关闭时直接 disabled，非法模式回退到 sample
func resolveFlowParseMode(cfg config.SecurityConfig) FlowParseMode {
	if !cfg.Source.Flow.Enabled {
		return FlowParseModeDisabled
	}
	switch normalizeFlowMode(cfg.Source.Flow.Mode) {
	case "offline_pcap":
		return FlowParseModeOfflinePCAP
	case "online_capture":
		return FlowParseModeOnlineCapture
	default:
		return FlowParseModeSample
	}
}

// resolveFlowCollectorSourceName 用于解析流量Collector来源名称。
func resolveFlowCollectorSourceName(mode FlowParseMode) string {
	switch mode {
	case FlowParseModeOfflinePCAP:
		return "flow-offline-pcap"
	case FlowParseModeOnlineCapture:
		return "flow-online-capture"
	case FlowParseModeDisabled:
		return "flow-disabled"
	default:
		return "flow-sample"
	}
}

// newFlowParseErrorModel 用于创建并返回新的业务实例。
func newFlowParseErrorModel(code string, category string, message string, retryable bool) *FlowParseErrorModel {
	code = strings.TrimSpace(code)
	message = strings.TrimSpace(message)
	if code == "" || message == "" {
		return nil
	}
	return &FlowParseErrorModel{
		Code:      code,
		Category:  strings.TrimSpace(category),
		Retryable: retryable,
		Message:   message,
	}
}

// finalizeFlowParseResult 用于补齐流量ParseResult最终结果。
func finalizeFlowParseResult(result FlowParseResult) FlowParseResult {
	result.Mode = FlowParseMode(normalizeFlowBoundaryMode(string(result.Mode)))
	result.Status = strings.ToUpper(strings.TrimSpace(result.Status))
	result.Summary = strings.TrimSpace(result.Summary)
	result.SourceName = strings.TrimSpace(result.SourceName)
	if result.SourceName == "" {
		result.SourceName = resolveFlowCollectorSourceName(result.Mode)
	}
	result.SourceChain = dedupeStrings(result.SourceChain)
	if len(result.SourceChain) == 0 && result.SourceName != "" {
		result.SourceChain = []string{result.SourceName}
	}
	result.ParserName = strings.TrimSpace(result.ParserName)
	result.IntegrationStage = strings.TrimSpace(result.IntegrationStage)
	result.PrototypeBoundary = strings.TrimSpace(result.PrototypeBoundary)
	result.InputKind = strings.TrimSpace(result.InputKind)
	result.InputSnapshot = compactFlowMap(result.InputSnapshot)
	result.ParsedMetrics = sanitizeFlowParsedMetrics(result.Mode, result.Status, result.ParserReady, result.ParsedMetrics)
	result.DebugPayload = compactFlowMap(result.DebugPayload)
	if result.ErrorModel != nil {
		result.ErrorModel.Code = strings.TrimSpace(result.ErrorModel.Code)
		result.ErrorModel.Category = strings.TrimSpace(result.ErrorModel.Category)
		result.ErrorModel.Message = strings.TrimSpace(result.ErrorModel.Message)
		if result.ErrorModel.Code == "" || result.ErrorModel.Message == "" {
			result.ErrorModel = nil
		}
	}
	if len(result.CollectedStableFields) == 0 {
		result.CollectedStableFields = defaultFlowCollectedStableFields(result.Mode, result.ParserReady)
	}
	if len(result.NormalizedStableFields) == 0 {
		result.NormalizedStableFields = defaultFlowNormalizedStableFields()
	}
	if len(result.FutureStableFields) == 0 {
		result.FutureStableFields = defaultFlowFutureStableFields()
	}
	if len(result.PrototypeOnlyFields) == 0 {
		result.PrototypeOnlyFields = defaultFlowPrototypeOnlyFields(result.Mode)
	}
	if len(result.DebugOnlyFields) == 0 {
		result.DebugOnlyFields = defaultFlowDebugOnlyFields(result.Mode)
	}
	return result
}

// compactFlowMap 用于压缩流量Map。
func compactFlowMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	result := make(map[string]any, len(input))
	for key, value := range input {
		if value == nil {
			continue
		}
		if typed, ok := value.(string); ok && strings.TrimSpace(typed) == "" {
			continue
		}
		result[key] = value
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// sanitizeFlowParsedMetrics 用于清理流量ParsedMetrics展示数据。
// 解析指标只在“解析器就绪 + 状态为已解析/无目标流量”时才对外暴露，
// 避免把失败态或原型态的中间字段当成可信统计结果消费
func sanitizeFlowParsedMetrics(mode FlowParseMode, status string, parserReady bool, parsedMetrics map[string]any) map[string]any {
	parsedMetrics = compactFlowMap(parsedMetrics)
	if len(parsedMetrics) == 0 {
		return nil
	}
	if !parserReady {
		return nil
	}

	switch FlowParseMode(normalizeFlowBoundaryMode(string(mode))) {
	case FlowParseModeOfflinePCAP:
		switch strings.ToUpper(strings.TrimSpace(status)) {
		case FlowStatusParsed, FlowStatusNoTargetTraffic:
			return parsedMetrics
		default:
			return nil
		}
	case FlowParseModeOnlineCapture:
		switch strings.ToUpper(strings.TrimSpace(status)) {
		case FlowStatusParsed, FlowStatusNoTargetTraffic:
			return parsedMetrics
		default:
			return nil
		}
	default:
		return nil
	}
}

// buildFlowStatusMeta 用于构建流量StatusMeta。
func buildFlowStatusMeta(result FlowParseResult) map[string]any {
	return map[string]any{
		"contractVersion":           flowParseContractVersion,
		"mode":                      string(result.Mode),
		"statusCode":                strings.TrimSpace(result.Status),
		"statusClass":               resolveFlowStatusClass(result.Mode, result.Status),
		"displayInPrototypePanel":   result.Mode != FlowParseModeDisabled,
		"defaultPipelineDependency": false,
		"failureState":              isFlowFailureStatus(result.Status),
	}
}

// resolveFlowStatusClass 用于解析流量StatusClass。
func resolveFlowStatusClass(mode FlowParseMode, status string) string {
	normalizedStatus := strings.ToUpper(strings.TrimSpace(status))
	switch normalizedStatus {
	case FlowStatusDisabled:
		return "disabled"
	case FlowStatusSampleOnly:
		return "sample"
	case FlowStatusParsed, FlowStatusNoTargetTraffic:
		return "parsed"
	case FlowStatusEntryReady:
		return "entry-ready"
	case FlowStatusConfigRequired, FlowStatusWaitingPermission:
		return "blocked"
	case FlowStatusInputInvalid, FlowStatusParseFailed, FlowStatusEntryUnavailable:
		return "error"
	default:
		if mode == FlowParseModeDisabled {
			return "disabled"
		}
		return "prototype"
	}
}

// isFlowDegradedResult 用于判断输入是否满足指定条件。
func isFlowDegradedResult(result FlowParseResult) bool {
	return result.ErrorModel != nil && isFlowFailureStatus(result.Status)
}

// isFlowFailureStatus 用于判断输入是否满足指定条件。
func isFlowFailureStatus(status string) bool {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case FlowStatusConfigRequired, FlowStatusInputInvalid, FlowStatusParseFailed, FlowStatusWaitingPermission, FlowStatusEntryUnavailable:
		return true
	default:
		return false
	}
}

// buildFlowErrorModelPayload 用于构建流量Error模型载荷。
func buildFlowErrorModelPayload(model *FlowParseErrorModel) map[string]any {
	if model == nil {
		return nil
	}
	return map[string]any{
		"code":      strings.TrimSpace(model.Code),
		"category":  strings.TrimSpace(model.Category),
		"retryable": model.Retryable,
		"message":   strings.TrimSpace(model.Message),
	}
}

// buildFlowMappingBoundary 用于构建流量MappingBoundary。
func buildFlowMappingBoundary(result FlowParseResult) map[string]any {
	return map[string]any{
		"contractVersion": flowParseContractVersion,
		"flowParseResult": map[string]any{
			"stableFields":    []string{"mode", "status", "summary", "behaviorRiskScore", "sourceName", "sourceChain", "evidenceItems"},
			"prototypeFields": []string{"parserName", "parserReady", "integrationStage", "prototypeBoundary", "inputKind", "inputSnapshot"},
			"debugFields":     []string{"debugPayload"},
		},
		"flowCollectedData": map[string]any{
			"stableFields":    append([]string(nil), result.CollectedStableFields...),
			"prototypeFields": append([]string(nil), result.PrototypeOnlyFields...),
			"debugFields":     append([]string(nil), result.DebugOnlyFields...),
		},
		"normalizedFeatureSet": map[string]any{
			"stableFields":    append([]string(nil), result.NormalizedStableFields...),
			"prototypeFields": defaultFlowNormalizedPrototypeFields(),
			"debugFields":     defaultFlowNormalizedDebugFields(),
		},
		"rawPayload": map[string]any{
			"stableFields":    buildFlowRawPayloadStableFields(result.Mode, result.ParserReady),
			"prototypeFields": buildFlowRawPayloadPrototypeFields(result.Mode),
			"debugFields":     buildFlowRawPayloadDebugFields(result.Mode),
		},
		"parsedMetrics": map[string]any{
			"stableFields":          flowStableParsedMetricFieldNames(result.Mode, result.ParserReady),
			"prototypeFields":       defaultFlowParsedMetricPrototypeFields(result.Mode, result.ParserReady),
			"debugFields":           defaultFlowParsedMetricDebugFields(result.Mode),
			"disallowedContent":     defaultFlowParsedMetricDisallowedContent(),
			"directConsumptionRule": "仅允许直接依赖 stableFields 中列出的解析统计键；未列出的键视为原型或内部字段。",
		},
		"futureStableFields": append([]string(nil), result.FutureStableFields...),
		"discouragedDirectFields": []string{
			"parsedMetrics",
			"rawPayload.inputSnapshot",
			"rawPayload.debugPayload",
			"rawPayload.parserName",
			"rawPayload.integrationStage",
			"rawPayload.prototypeBoundary",
		},
		"parsedMetricsResponsibility":   "仅承载解析器真实产出的统计指标，不承载输入参数、状态文案或调试上下文。",
		"mappingBoundaryResponsibility": "仅承载字段分层、契约版本和禁止依赖说明，不承载实时解析值。",
		"defaultPipelineDependency":     false,
	}
}

// buildFlowParseResultPayload 用于构建流量ParseResult载荷。
func buildFlowParseResultPayload(result FlowParseResult) map[string]any {
	result = finalizeFlowParseResult(result)
	payload := map[string]any{
		"contractVersion":         flowParseContractVersion,
		"sourceChain":             dedupeStrings(result.SourceChain),
		"evidenceItems":           result.EvidenceItems,
		"includeInDataSources":    false,
		"displayInPrototypePanel": result.Mode != FlowParseModeDisabled,
		"parserName":              result.ParserName,
		"parserReady":             result.ParserReady,
		"parserMode":              string(result.Mode),
		"integrationStage":        strings.TrimSpace(result.IntegrationStage),
		"prototypeBoundary":       result.PrototypeBoundary,
		"inputKind":               result.InputKind,
		"inputSnapshot":           result.InputSnapshot,
		"parsedMetrics":           result.ParsedMetrics,
		"statusMeta":              buildFlowStatusMeta(result),
		"errorModel":              buildFlowErrorModelPayload(result.ErrorModel),
		"debugPayload":            result.DebugPayload,
		"degraded":                isFlowDegradedResult(result),
		"mappingBoundary":         buildFlowMappingBoundary(result),
	}
	return payload
}

// mapFlowParseResultToCollectedData 用于把流量解析结果转换为采集结果。
// 统一把解析器输出映射为 FlowCollectedData，供评分因子、证据链、任务详情等处消费
func mapFlowParseResultToCollectedData(targetIP string, result FlowParseResult) FlowCollectedData {
	result = finalizeFlowParseResult(result)
	return FlowCollectedData{
		IP:                     targetIP,
		Mode:                   normalizeFlowBoundaryMode(string(result.Mode)),
		Status:                 strings.ToUpper(strings.TrimSpace(result.Status)),
		BehaviorRiskScore:      result.BehaviorRiskScore,
		Summary:                strings.TrimSpace(result.Summary),
		SourceName:             strings.TrimSpace(result.SourceName),
		SourceChain:            append([]string(nil), result.SourceChain...),
		EvidenceItems:          append([]securityEvidenceItem(nil), result.EvidenceItems...),
		ParserName:             strings.TrimSpace(result.ParserName),
		ParserReady:            result.ParserReady,
		IntegrationStage:       strings.TrimSpace(result.IntegrationStage),
		PrototypeBoundary:      strings.TrimSpace(result.PrototypeBoundary),
		InputKind:              strings.TrimSpace(result.InputKind),
		InputSnapshot:          cloneMap(result.InputSnapshot),
		ParsedMetrics:          cloneMap(result.ParsedMetrics),
		CollectedStableFields:  append([]string(nil), result.CollectedStableFields...),
		NormalizedStableFields: append([]string(nil), result.NormalizedStableFields...),
		FutureStableFields:     append([]string(nil), result.FutureStableFields...),
		PrototypeOnlyFields:    append([]string(nil), result.PrototypeOnlyFields...),
		DebugOnlyFields:        append([]string(nil), result.DebugOnlyFields...),
		RawPayload:             buildFlowParseResultPayload(result),
	}
}

// defaultFlowCollectedStableFields 用于声明流量采集结果的稳定字段。
func defaultFlowCollectedStableFields(mode FlowParseMode, parserReady bool) []string {
	fields := []string{
		"mode",
		"status",
		"behaviorRiskScore",
		"summary",
		"sourceName",
		"sourceChain",
		"evidenceItems",
		"rawPayload.statusMeta",
		"rawPayload.errorModel",
		"rawPayload.degraded",
	}
	if parserReady {
		fields = append(fields, flowRawParsedMetricStableFields(mode)...)
	}
	return dedupeStrings(fields)
}

// defaultFlowNormalizedStableFields 用于提供流量NormalizedStableFields默认字段集合。
func defaultFlowNormalizedStableFields() []string {
	return []string{
		"flowMode",
		"flowStatus",
		"flowSummary",
		"flowSourceChain",
		"flowPrototypeItems",
	}
}

// defaultFlowNormalizedPrototypeFields 用于提供流量NormalizedPrototypeFields默认字段集合。
func defaultFlowNormalizedPrototypeFields() []string {
	return []string{
		"flowParserName",
		"flowParserReady",
		"flowIntegrationStage",
		"flowPrototypeBoundary",
		"flowInputKind",
		"flowInputSnapshot",
		"flowParsedMetrics",
		"flowCollectedStableFields",
		"flowNormalizedStableFields",
		"flowFutureStableFields",
		"flowPrototypeOnlyFields",
	}
}

// defaultFlowNormalizedDebugFields 用于提供流量NormalizedDebugFields默认字段集合。
func defaultFlowNormalizedDebugFields() []string {
	return []string{"flowDebugOnlyFields"}
}

// defaultFlowFutureStableFields 用于提供流量FutureStableFields默认字段集合。
func defaultFlowFutureStableFields() []string {
	return []string{"applicationSignals", "payloadEntropyIndicators", "tlsHandshakeHints", "tlsVersionHints", "httpMethodHints", "httpStatusHints", "dnsTopQuestions", "dnsQueryTypeHints", "httpHostHints", "directionalityIndicators", "portDensityIndicators"}
}

// defaultFlowPrototypeOnlyFields 用于提供流量PrototypeOnlyFields默认字段集合。
func defaultFlowPrototypeOnlyFields(mode FlowParseMode) []string {
	fields := []string{
		"parserName",
		"parserReady",
		"integrationStage",
		"prototypeBoundary",
		"inputKind",
		"inputSnapshot",
		"parsedMetrics",
		"rawPayload.parserName",
		"rawPayload.parserReady",
		"rawPayload.parserMode",
		"rawPayload.integrationStage",
		"rawPayload.prototypeBoundary",
		"rawPayload.displayInPrototypePanel",
		"rawPayload.inputKind",
		"rawPayload.inputSnapshot",
		"rawPayload.includeInDataSources",
	}
	switch mode {
	case FlowParseModeSample:
		fields = append(fields, "inputSnapshot.sampleProfile")
	case FlowParseModeOfflinePCAP:
		fields = append(fields, "inputSnapshot.pcapFilePath")
	case FlowParseModeOnlineCapture:
		fields = append(fields, "inputSnapshot.interfaceName")
	}
	return dedupeStrings(fields)
}

// defaultFlowDebugOnlyFields 用于提供流量DebugOnlyFields默认字段集合。
func defaultFlowDebugOnlyFields(mode FlowParseMode) []string {
	fields := []string{"rawPayload.debugPayload"}
	switch mode {
	case FlowParseModeOfflinePCAP:
		fields = append(fields, "rawPayload.debugPayload.resolvedPcapPath", "rawPayload.debugPayload.fileSize", "rawPayload.debugPayload.failureCause")
	case FlowParseModeOnlineCapture:
		fields = append(fields, "rawPayload.debugPayload.interfaceIndex", "rawPayload.debugPayload.mtu", "rawPayload.debugPayload.flags", "rawPayload.debugPayload.failureCause")
	case FlowParseModeSample:
		fields = append(fields, "rawPayload.debugPayload.failureCause")
	default:
		fields = append(fields, "rawPayload.debugPayload.failureCause")
	}
	return dedupeStrings(fields)
}

// flowRawParsedMetricStableFields 用于执行flowRawParsedMetricStableFields流程。
func flowRawParsedMetricStableFields(mode FlowParseMode) []string {
	switch mode {
	case FlowParseModeOfflinePCAP:
		fallthrough
	case FlowParseModeOnlineCapture:
		return []string{
			"rawPayload.parsedMetrics.captureFormat",
			"rawPayload.parsedMetrics.packetCount",
			"rawPayload.parsedMetrics.matchedPacketCount",
			"rawPayload.parsedMetrics.byteCount",
			"rawPayload.parsedMetrics.sessionCount",
			"rawPayload.parsedMetrics.protocolDistribution",
			"rawPayload.parsedMetrics.topPorts",
			"rawPayload.parsedMetrics.peerEndpoints",
			"rawPayload.parsedMetrics.anomalyCandidates",
			"rawPayload.parsedMetrics.firstSeenAt",
			"rawPayload.parsedMetrics.lastSeenAt",
		}
	default:
		return nil
	}
}

// flowStableParsedMetricFieldNames 用于执行flowStableParsedMetricFieldNames流程。
func flowStableParsedMetricFieldNames(mode FlowParseMode, parserReady bool) []string {
	if !parserReady {
		return nil
	}
	switch mode {
	case FlowParseModeOfflinePCAP:
		fallthrough
	case FlowParseModeOnlineCapture:
		return []string{
			"captureFormat",
			"packetCount",
			"matchedPacketCount",
			"byteCount",
			"sessionCount",
			"protocolDistribution",
			"topPorts",
			"peerEndpoints",
			"anomalyCandidates",
			"firstSeenAt",
			"lastSeenAt",
		}
	default:
		return nil
	}
}

// defaultFlowParsedMetricPrototypeFields 用于提供流量ParsedMetricPrototypeFields默认字段集合。
func defaultFlowParsedMetricPrototypeFields(mode FlowParseMode, parserReady bool) []string {
	if !parserReady {
		return nil
	}
	switch mode {
	case FlowParseModeOfflinePCAP:
		fallthrough
	case FlowParseModeOnlineCapture:
		return []string{
			"windows",
			"peakPps",
			"burstScore",
			"scanScore",
			"dnsEventCount",
			"httpEventCount",
			"tlsEventCount",
			"dnsQueryTypeHints",
			"httpMethodHints",
			"httpHostHints",
			"httpStatusHints",
			"tlsHandshakeHints",
			"tlsVersionHints",
			"applicationSignals",
			"dnsTopQuestions",
			"directionalityIndicators",
			"portDensityIndicators",
			"payloadEntropyIndicators",
		}
	default:
		return nil
	}
}

// stringifyTopCountMetrics 用于把TopCountMetrics转为展示文本。
func stringifyTopCountMetrics(value any) string {
	items, ok := value.([]flowStringCount)
	if ok && len(items) > 0 {
		return formatTopCountMetrics(items)
	}
	if rawItems, ok := value.([]any); ok && len(rawItems) > 0 {
		decoded := make([]flowStringCount, 0, len(rawItems))
		for _, raw := range rawItems {
			itemMap, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			decoded = append(decoded, flowStringCount{
				Key:   strings.TrimSpace(fmt.Sprintf("%v", itemMap["key"])),
				Count: toInt(itemMap["count"]),
			})
		}
		return formatTopCountMetrics(decoded)
	}
	return ""
}

// formatTopCountMetrics 用于格式化TopCountMetrics展示文本。
func formatTopCountMetrics(items []flowStringCount) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) > 3 {
		items = items[:3]
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item.Key) == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%d", item.Key, item.Count))
	}
	return strings.Join(parts, ", ")
}

// stringifyTLSHints 用于把TLSHints转为展示文本。
func stringifyTLSHints(value any) string {
	items, ok := value.([]flowTLSHandshakeHint)
	if ok && len(items) > 0 {
		return formatTLSHintMetrics(items)
	}
	if rawItems, ok := value.([]any); ok && len(rawItems) > 0 {
		decoded := make([]flowTLSHandshakeHint, 0, len(rawItems))
		for _, raw := range rawItems {
			itemMap, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			decoded = append(decoded, flowTLSHandshakeHint{
				ServerName: strings.TrimSpace(fmt.Sprintf("%v", itemMap["serverName"])),
				Count:      toInt(itemMap["count"]),
			})
		}
		return formatTLSHintMetrics(decoded)
	}
	return ""
}

// formatTLSHintMetrics 用于格式化TLSHintMetrics展示文本。
func formatTLSHintMetrics(items []flowTLSHandshakeHint) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) > 3 {
		items = items[:3]
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item.ServerName) == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%d", item.ServerName, item.Count))
	}
	return strings.Join(parts, ", ")
}

// stringifyDirectionalityMetrics 用于把DirectionalityMetrics转为展示文本。
func stringifyDirectionalityMetrics(value any) string {
	itemMap, ok := value.(map[string]any)
	if !ok || len(itemMap) == 0 {
		return ""
	}
	return fmt.Sprintf(
		"方向性=%s(%d/%d, bias=%.2f)",
		strings.TrimSpace(fmt.Sprintf("%v", itemMap["dominantDirection"])),
		toInt(itemMap["inboundPacketCount"]),
		toInt(itemMap["outboundPacketCount"]),
		toFloat64(itemMap["packetBias"]),
	)
}

// stringifyPortDensityMetrics 用于把PortDensityMetrics转为展示文本。
func stringifyPortDensityMetrics(value any) string {
	itemMap, ok := value.(map[string]any)
	if !ok || len(itemMap) == 0 {
		return ""
	}
	return fmt.Sprintf(
		"端口密度=%d端口/%.2f(高危=%d)",
		toInt(itemMap["uniqueTargetPortCount"]),
		toFloat64(itemMap["targetPortDensity"]),
		toInt(itemMap["highRiskTargetPortCount"]),
	)
}

// stringifyEntropyMetrics 用于把EntropyMetrics转为展示文本。
func stringifyEntropyMetrics(value any) string {
	itemMap, ok := value.(map[string]any)
	if !ok || len(itemMap) == 0 {
		return ""
	}
	return fmt.Sprintf(
		"高熵=%d(avg=%.2f)",
		toInt(itemMap["highEntropyPacketCount"]),
		toFloat64(itemMap["averagePayloadEntropy"]),
	)
}

// defaultFlowParsedMetricDebugFields 用于提供流量ParsedMetricDebugFields默认字段集合。
func defaultFlowParsedMetricDebugFields(mode FlowParseMode) []string {
	return nil
}

// defaultFlowParsedMetricDisallowedContent 用于提供流量ParsedMetricDisallowedContent默认字段集合。
func defaultFlowParsedMetricDisallowedContent() []string {
	return []string{
		"sampleProfile",
		"pcapFilePath",
		"interfaceName",
		"parserReady",
		"integrationStage",
		"prototypeBoundary",
		"summary",
		"status",
		"errorMessage",
		"failureCause",
		"debugPayload",
	}
}

// buildFlowRawPayloadStableFields 用于构建流量Raw载荷StableFields。
func buildFlowRawPayloadStableFields(mode FlowParseMode, parserReady bool) []string {
	fields := []string{
		"rawPayload.contractVersion",
		"rawPayload.sourceChain",
		"rawPayload.evidenceItems",
		"rawPayload.statusMeta",
		"rawPayload.errorModel",
		"rawPayload.degraded",
		"rawPayload.mappingBoundary",
	}
	if parserReady {
		fields = append(fields, flowRawParsedMetricStableFields(mode)...)
	}
	return dedupeStrings(fields)
}

// buildFlowRawPayloadPrototypeFields 用于构建流量Raw载荷PrototypeFields。
func buildFlowRawPayloadPrototypeFields(mode FlowParseMode) []string {
	fields := []string{
		"rawPayload.parserName",
		"rawPayload.parserReady",
		"rawPayload.parserMode",
		"rawPayload.integrationStage",
		"rawPayload.prototypeBoundary",
		"rawPayload.displayInPrototypePanel",
		"rawPayload.inputKind",
		"rawPayload.inputSnapshot",
		"rawPayload.includeInDataSources",
	}
	switch mode {
	case FlowParseModeSample:
		fields = append(fields, "rawPayload.inputSnapshot.sampleProfile")
	case FlowParseModeOfflinePCAP:
		fields = append(fields, "rawPayload.inputSnapshot.pcapFilePath")
	case FlowParseModeOnlineCapture:
		fields = append(fields, "rawPayload.inputSnapshot.interfaceName")
	}
	return dedupeStrings(fields)
}

// buildFlowRawPayloadDebugFields 用于构建流量Raw载荷DebugFields。
func buildFlowRawPayloadDebugFields(mode FlowParseMode) []string {
	return append([]string(nil), defaultFlowDebugOnlyFields(mode)...)
}

// offlinePCAPCollectedStableFields 用于声明离线流量采集的稳定字段。
func offlinePCAPCollectedStableFields() []string {
	return defaultFlowCollectedStableFields(FlowParseModeOfflinePCAP, true)
}

// onlineCaptureCollectedStableFields 用于声明在线抓包采集的稳定字段。
func onlineCaptureCollectedStableFields() []string {
	return defaultFlowCollectedStableFields(FlowParseModeOnlineCapture, true)
}

// buildFlowDisplayFields 用于构建流量DisplayFields。
func buildFlowDisplayFields(flow FlowCollectedData) (string, string, string) {
	if !shouldDisplayFlowPrototype(flow.Mode, flow.Status) || !isFlowPrototypeVisible(flow) {
		return "", "", ""
	}
	return normalizeFlowBoundaryMode(flow.Mode), strings.ToUpper(strings.TrimSpace(flow.Status)), strings.TrimSpace(flow.Summary)
}

// shouldIncludeFlowSource 用于执行shouldInclude流量来源流程。
func shouldIncludeFlowSource(flow FlowCollectedData) bool {
	if isFlowDisabled(flow) {
		return false
	}
	if include, ok := readFlowPayloadBool(flow.RawPayload, "includeInDataSources"); ok {
		return include
	}
	return false
}

// isFlowPrototypeVisible 用于判断输入是否满足指定条件。
func isFlowPrototypeVisible(flow FlowCollectedData) bool {
	if isFlowDisabled(flow) {
		return false
	}
	if visible, ok := readFlowPayloadBool(flow.RawPayload, "displayInPrototypePanel"); ok {
		return visible
	}
	return strings.TrimSpace(flow.SourceName) != ""
}

// shouldDisplayFlowPrototype 用于执行shouldDisplay流量Prototype流程。
func shouldDisplayFlowPrototype(mode string, status string) bool {
	normalizedMode := normalizeFlowBoundaryMode(mode)
	normalizedStatus := strings.ToUpper(strings.TrimSpace(status))
	if normalizedStatus == "DISABLED" {
		return false
	}
	switch normalizedMode {
	case "sample", "offline_pcap", "online_capture":
		return true
	default:
		return false
	}
}

// normalizeFlowBoundaryMode 用于归一化输入参数或业务指标。
func normalizeFlowBoundaryMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "sample":
		return "sample"
	case "offline_pcap":
		return "offline_pcap"
	case "online_capture":
		return "online_capture"
	case "disabled":
		return "disabled"
	default:
		return ""
	}
}

// isAllowedFlowStatusForMode 用于判断输入是否满足指定条件。
func isAllowedFlowStatusForMode(mode string, status string) bool {
	normalizedMode := normalizeFlowBoundaryMode(mode)
	normalizedStatus := strings.ToUpper(strings.TrimSpace(status))
	switch normalizedMode {
	case "disabled":
		return normalizedStatus == FlowStatusDisabled
	case "sample":
		return normalizedStatus == FlowStatusSampleOnly
	case "offline_pcap":
		switch normalizedStatus {
		case FlowStatusConfigRequired, FlowStatusInputInvalid, FlowStatusEntryUnavailable, FlowStatusParseFailed, FlowStatusParsed, FlowStatusNoTargetTraffic:
			return true
		default:
			return false
		}
	case "online_capture":
		switch normalizedStatus {
		case FlowStatusWaitingPermission, FlowStatusEntryUnavailable, FlowStatusEntryReady, FlowStatusParseFailed, FlowStatusParsed, FlowStatusNoTargetTraffic:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

// isFlowDisabled 用于判断输入是否满足指定条件。
func isFlowDisabled(flow FlowCollectedData) bool {
	sourceName := strings.ToLower(strings.TrimSpace(flow.SourceName))
	mode := normalizeFlowBoundaryMode(flow.Mode)
	status := strings.ToUpper(strings.TrimSpace(flow.Status))
	switch {
	case sourceName == "":
		return true
	case sourceName == "flow-disabled":
		return true
	case mode == "" || mode == "disabled":
		return true
	case status == "DISABLED":
		return true
	default:
		return false
	}
}

// readFlowPayloadBool 用于读取流量载荷Bool。
func readFlowPayloadBool(payload map[string]any, key string) (bool, bool) {
	if len(payload) == 0 {
		return false, false
	}
	value, ok := payload[key]
	if !ok {
		return false, false
	}
	flag, ok := value.(bool)
	if !ok {
		return false, false
	}
	return flag, true
}
