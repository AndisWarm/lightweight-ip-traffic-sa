package security

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// persistedScoreFactor 用于承载persisted评分Factor数据。
type persistedScoreFactor struct {
	Key          string  `json:"key"`
	Label        string  `json:"label"`
	RawScore     float64 `json:"rawScore"`
	Weight       float64 `json:"weight"`
	Contribution float64 `json:"contribution"`
	Basis        string  `json:"basis"`
	DisplayBasis string  `json:"displayBasis"`
}

// persistedFeaturePayload 用于承载persisted特征载荷载荷内容。
type persistedFeaturePayload struct {
	ContractVersion            string                 `json:"contractVersion,omitempty"`
	DataSources                []string               `json:"dataSources,omitempty"`
	DataSourceChains           map[string][]string    `json:"dataSourceChains,omitempty"`
	SourceSummary              string                 `json:"sourceSummary,omitempty"`
	SourceGroups               []canonicalSourceGroup `json:"sourceGroups,omitempty"`
	FlowSourceChain            []string               `json:"flowSourceChain,omitempty"`
	EvidenceItems              []securityEvidenceItem `json:"evidenceItems,omitempty"`
	FlowPrototypeItems         []securityEvidenceItem `json:"flowPrototypeItems,omitempty"`
	ScoreFactors               []persistedScoreFactor `json:"scoreFactors,omitempty"`
	FlowMode                   string                 `json:"flowMode,omitempty"`
	FlowStatus                 string                 `json:"flowStatus,omitempty"`
	FlowSummary                string                 `json:"flowSummary,omitempty"`
	FlowParserName             string                 `json:"flowParserName,omitempty"`
	FlowParserReady            bool                   `json:"flowParserReady,omitempty"`
	FlowIntegrationStage       string                 `json:"flowIntegrationStage,omitempty"`
	FlowPrototypeBoundary      string                 `json:"flowPrototypeBoundary,omitempty"`
	FlowInputKind              string                 `json:"flowInputKind,omitempty"`
	FlowInputSnapshot          map[string]any         `json:"flowInputSnapshot,omitempty"`
	FlowParsedMetrics          map[string]any         `json:"flowParsedMetrics,omitempty"`
	FlowCollectedStableFields  []string               `json:"flowCollectedStableFields,omitempty"`
	FlowNormalizedStableFields []string               `json:"flowNormalizedStableFields,omitempty"`
	FlowFutureStableFields     []string               `json:"flowFutureStableFields,omitempty"`
	FlowPrototypeOnlyFields    []string               `json:"flowPrototypeOnlyFields,omitempty"`
}

const persistedMainChainContractVersion = "mainchain-summary-v1"

// dashboardSourceCoverageItem 用于承载dashboard来源Coverage列表展示条目。
type dashboardSourceCoverageItem struct {
	Source string
	Count  int64
}

// canonicalSourceGroup 用于组织canonical来源分组数据。
type canonicalSourceGroup struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Chain   []string `json:"chain"`
	Summary string   `json:"summary"`
}

// canonicalSourceSummary 用于承载canonical来源摘要汇总结果。
type canonicalSourceSummary struct {
	Summary         string
	Groups          []canonicalSourceGroup
	GroupMap        map[string][]string
	FlowSourceChain []string
}

// buildTaskSourceSummary 用于构建任务来源摘要。
func buildTaskSourceSummary(baseInfoRaw string, normalizedRaw string) string {
	baseSources := extractStringSliceFromJSON(baseInfoRaw, "sourceChain")
	summary := extractPersistedSourceSummary(normalizedRaw, baseSources)
	return fallbackString(summary.Summary, "-")
}

// buildSourceCoverageItems 用于构建来源CoverageItems。
func buildSourceCoverageItems(counter map[string]int64) []dashboardSourceCoverageItem {
	items := make([]dashboardSourceCoverageItem, 0, len(counter))
	for source, count := range counter {
		items = append(items, dashboardSourceCoverageItem{
			Source: source,
			Count:  count,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Source < items[j].Source
		}
		return items[i].Count > items[j].Count
	})
	return items
}

// buildSourceCoverageItemsWithDefaults 用于构建来源CoverageItemsWithDefaults。
func buildSourceCoverageItemsWithDefaults(counter map[string]int64, defaults []string) []dashboardSourceCoverageItem {
	merged := make(map[string]int64, len(counter)+len(defaults))
	for source, count := range counter {
		merged[source] = count
	}
	for _, source := range defaults {
		source = strings.TrimSpace(source)
		if source == "" {
			continue
		}
		if _, exists := merged[source]; !exists {
			merged[source] = 0
		}
	}
	return buildSourceCoverageItems(merged)
}

// extractStringSliceFromJSON 用于提取请求、令牌或流量中的关键信息。
func extractStringSliceFromJSON(raw string, key string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil
	}
	value, ok := payload[key]
	if !ok {
		return nil
	}
	bytes, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var items []string
	if err := json.Unmarshal(bytes, &items); err != nil {
		return nil
	}
	return items
}

// decodePersistedFeaturePayload 用于反序列化Persisted特征载荷。
func decodePersistedFeaturePayload(raw string) (persistedFeaturePayload, bool) {
	if strings.TrimSpace(raw) == "" {
		return persistedFeaturePayload{}, false
	}
	var payload persistedFeaturePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return persistedFeaturePayload{}, false
	}
	return payload, true
}

// buildPersistedFeaturePayload 用于构建Persisted特征载荷。
func buildPersistedFeaturePayload(normalized NormalizedFeatureSet) persistedFeaturePayload {
	return persistedFeaturePayload{
		ContractVersion:            persistedMainChainContractVersion,
		SourceSummary:              strings.TrimSpace(normalized.SourceSummary),
		SourceGroups:               normalizeCanonicalSourceGroups(normalized.SourceGroups),
		FlowSourceChain:            dedupeStrings(normalized.FlowSourceChain),
		EvidenceItems:              append([]securityEvidenceItem(nil), normalized.EvidenceItems...),
		FlowPrototypeItems:         append([]securityEvidenceItem(nil), normalized.FlowPrototypeItems...),
		ScoreFactors:               toPersistedScoreFactors(normalized.ScoreFactors),
		FlowMode:                   strings.TrimSpace(normalized.FlowMode),
		FlowStatus:                 strings.TrimSpace(normalized.FlowStatus),
		FlowSummary:                strings.TrimSpace(normalized.FlowSummary),
		FlowParserName:             strings.TrimSpace(normalized.FlowParserName),
		FlowParserReady:            normalized.FlowParserReady,
		FlowIntegrationStage:       strings.TrimSpace(normalized.FlowIntegrationStage),
		FlowPrototypeBoundary:      strings.TrimSpace(normalized.FlowPrototypeBoundary),
		FlowInputKind:              strings.TrimSpace(normalized.FlowInputKind),
		FlowInputSnapshot:          cloneMap(normalized.FlowInputSnapshot),
		FlowParsedMetrics:          cloneMap(normalized.FlowParsedMetrics),
		FlowCollectedStableFields:  cloneStringList(normalized.FlowCollectedStableFields),
		FlowNormalizedStableFields: cloneStringList(normalized.FlowNormalizedStableFields),
		FlowFutureStableFields:     cloneStringList(normalized.FlowFutureStableFields),
		FlowPrototypeOnlyFields:    cloneStringList(normalized.FlowPrototypeOnlyFields),
	}
}

// toPersistedScoreFactors 用于转换并生成Persisted评分Factors。
func toPersistedScoreFactors(items []securityScoreFactor) []persistedScoreFactor {
	if len(items) == 0 {
		return nil
	}
	result := make([]persistedScoreFactor, 0, len(items))
	for _, item := range items {
		basis := ""
		if strings.TrimSpace(item.DisplayBasis) == "" {
			basis = item.Basis
		}
		result = append(result, persistedScoreFactor{
			Key:          item.Key,
			Label:        item.Label,
			RawScore:     item.RawScore,
			Weight:       item.Weight,
			Contribution: item.Contribution,
			Basis:        basis,
			DisplayBasis: item.DisplayBasis,
		})
	}
	return result
}

// extractDataSourceChains 用于提取请求、令牌或流量中的关键信息。
func extractDataSourceChains(raw string) map[string][]string {
	payload, ok := decodePersistedFeaturePayload(raw)
	if !ok {
		return nil
	}
	return payload.DataSourceChains
}

// extractPersistedSourceSummary 用于提取请求、令牌或流量中的关键信息。
func extractPersistedSourceSummary(raw string, baseSources []string) canonicalSourceSummary {
	payload, ok := decodePersistedFeaturePayload(raw)
	if !ok {
		return buildCanonicalSourceSummary(baseSources, nil, "", "", nil)
	}

	summary := canonicalSourceSummary{
		Summary:         strings.TrimSpace(payload.SourceSummary),
		Groups:          normalizeCanonicalSourceGroups(payload.SourceGroups),
		FlowSourceChain: dedupeStrings(payload.FlowSourceChain),
	}
	if len(summary.Groups) == 0 {
		summary = buildCanonicalSourceSummary(baseSources, payload.DataSourceChains, payload.FlowMode, payload.FlowStatus, payload.FlowSourceChain)
	} else {
		if summary.Summary == "" {
			summary.Summary = buildSourceSummaryFromGroups(summary.Groups)
		}
		if len(summary.FlowSourceChain) == 0 {
			summary.FlowSourceChain = resolveFlowSourceChain(payload.FlowSourceChain, payload.DataSourceChains, payload.FlowMode, payload.FlowStatus)
		}
		summary.GroupMap = buildCanonicalSourceChainMap(summary.Groups)
	}
	return summary
}

// buildCanonicalSourceSummary 用于构建Canonical来源摘要。
func buildCanonicalSourceSummary(
	baseSources []string,
	sourceChains map[string][]string,
	flowMode string,
	flowStatus string,
	explicitFlowSourceChain []string,
) canonicalSourceSummary {
	groups := buildCanonicalSourceGroups(baseSources, sourceChains)
	return canonicalSourceSummary{
		Summary:         buildSourceSummaryFromGroups(groups),
		Groups:          groups,
		GroupMap:        buildCanonicalSourceChainMap(groups),
		FlowSourceChain: resolveFlowSourceChain(explicitFlowSourceChain, sourceChains, flowMode, flowStatus),
	}
}

// buildSourceSummaryFromChains 用于构建来源摘要FromChains。
func buildSourceSummaryFromChains(baseSources []string, sourceChains map[string][]string) string {
	return buildCanonicalSourceSummary(baseSources, sourceChains, "", "", nil).Summary
}

// buildCanonicalSourceGroups 用于构建Canonical来源Groups。
func buildCanonicalSourceGroups(baseSources []string, sourceChains map[string][]string) []canonicalSourceGroup {
	groupDefs := []canonicalSourceGroup{
		{
			Key:   "base_info",
			Label: "基础画像来源",
			Chain: firstNonEmptySourceChain(baseSources, sourceChains["base_info"]),
		},
		{
			Key:   "reputation",
			Label: "信誉来源",
			Chain: dedupeStrings(sourceChains["reputation"]),
		},
		{
			Key:   "attack_surface",
			Label: "攻击面来源",
			Chain: sanitizeAttackSurfaceChain(sourceChains["attack_surface"]),
		},
	}

	result := make([]canonicalSourceGroup, 0, len(groupDefs))
	for _, group := range groupDefs {
		if len(group.Chain) == 0 {
			continue
		}
		group.Summary = formatSourceChain(group.Chain)
		result = append(result, group)
	}
	return result
}

// normalizeCanonicalSourceGroups 用于归一化输入参数或业务指标。
func normalizeCanonicalSourceGroups(groups []canonicalSourceGroup) []canonicalSourceGroup {
	if len(groups) == 0 {
		return nil
	}
	result := make([]canonicalSourceGroup, 0, len(groups))
	for _, group := range groups {
		switch group.Key {
		case "attack_surface":
			group.Chain = sanitizeAttackSurfaceChain(group.Chain)
		default:
			group.Chain = dedupeStrings(group.Chain)
		}
		if len(group.Chain) == 0 {
			continue
		}
		if strings.TrimSpace(group.Summary) == "" {
			group.Summary = formatSourceChain(group.Chain)
		}
		result = append(result, group)
	}
	return result
}

// buildCanonicalSourceChainMap 用于构建Canonical来源链路Map。
func buildCanonicalSourceChainMap(groups []canonicalSourceGroup) map[string][]string {
	result := make(map[string][]string, len(groups))
	for _, group := range groups {
		if len(group.Chain) == 0 {
			continue
		}
		result[group.Key] = append([]string(nil), group.Chain...)
	}
	return result
}

// buildSourceSummaryFromGroups 用于构建来源摘要FromGroups。
func buildSourceSummaryFromGroups(groups []canonicalSourceGroup) string {
	if len(groups) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(groups))
	for _, group := range groups {
		summary := strings.TrimSpace(group.Summary)
		if summary == "" {
			summary = formatSourceChain(group.Chain)
		}
		parts = append(parts, fmt.Sprintf("%s=%s", group.Label, summary))
	}
	return strings.Join(parts, " | ")
}

// buildFlowSourceChain 用于构建流量来源链路。
func buildFlowSourceChain(sourceChains map[string][]string, flowMode string, flowStatus string) []string {
	mode := strings.ToLower(strings.TrimSpace(flowMode))
	status := strings.ToUpper(strings.TrimSpace(flowStatus))
	chain := dedupeStrings(sourceChains["flow"])
	if len(chain) == 0 || mode == "" || mode == "disabled" || status == "DISABLED" {
		return nil
	}
	return chain
}

// resolveFlowSourceChain 用于解析流量来源链路。
func resolveFlowSourceChain(explicit []string, sourceChains map[string][]string, flowMode string, flowStatus string) []string {
	if shouldDisplayFlowPrototype(flowMode, flowStatus) {
		if items := dedupeStrings(explicit); len(items) > 0 {
			return items
		}
	}
	return buildFlowSourceChain(sourceChains, flowMode, flowStatus)
}

// firstNonEmptySourceChain 用于选取首个可用的NonEmpty来源链路。
func firstNonEmptySourceChain(primary []string, fallback []string) []string {
	if items := dedupeStrings(primary); len(items) > 0 {
		return items
	}
	return dedupeStrings(fallback)
}

// formatSourceChain 用于格式化来源链路展示文本。
func formatSourceChain(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	return strings.Join(items, " -> ")
}

// classifyEvidenceCategory 用于执行classifyEvidenceCategory流程。
func classifyEvidenceCategory(source string) (string, string) {
	lower := strings.ToLower(strings.TrimSpace(source))
	switch {
	case strings.Contains(lower, "geolite2"), strings.Contains(lower, "rdap"), strings.Contains(lower, "p0-base-info"):
		return "base_info", "基础画像证据"
	case strings.Contains(lower, "blacklist"), strings.Contains(lower, "abuseipdb"), strings.Contains(lower, "reputation"):
		return "reputation", "信誉证据"
	case strings.Contains(lower, "port-scan"), strings.Contains(lower, "attack"), strings.Contains(lower, "nmap"):
		return "attack_surface", "攻击面证据"
	case strings.Contains(lower, "joint-analysis"), strings.Contains(lower, "fusion"):
		return "joint_analysis", "联合判定依据"
	case strings.Contains(lower, "flow"), strings.Contains(lower, "pcap"), strings.Contains(lower, "capture"):
		return "flow", "流量增强证据"
	default:
		return "other", "其他证据"
	}
}

// decorateScoreFactorsWithDisplayBasis 用于执行decorate评分FactorsWithDisplayBasis流程。
func decorateScoreFactorsWithDisplayBasis(
	items []securityScoreFactor,
	summary canonicalSourceSummary,
	flowMode string,
	flowStatus string,
	flowSummary string,
) []securityScoreFactor {
	if len(items) == 0 {
		return nil
	}
	result := make([]securityScoreFactor, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item.DisplayBasis) == "" {
			item.DisplayBasis = buildScoreFactorDisplayBasis(item, summary, flowMode, flowStatus, flowSummary)
		}
		result = append(result, item)
	}
	return result
}

// buildScoreFactorDisplayBasis 用于构建评分FactorDisplayBasis。
func buildScoreFactorDisplayBasis(
	item securityScoreFactor,
	summary canonicalSourceSummary,
	flowMode string,
	flowStatus string,
	flowSummary string,
) string {
	switch item.Key {
	case "whois":
		return joinDisplayParts(
			formatDisplayChain("基础画像来源", summary.GroupMap["base_info"]),
			strings.TrimSpace(item.Basis),
		)
	case "reputation":
		sourceChain, extra := splitSourceBasis(item.Basis)
		if len(summary.GroupMap["reputation"]) > 0 {
			sourceChain = formatSourceChain(summary.GroupMap["reputation"])
		}
		return joinDisplayParts(
			formatDisplayText("信誉来源", sourceChain),
			extra,
		)
	case "attack_surface":
		sourceChain, extra := splitSourceBasis(item.Basis)
		if len(summary.GroupMap["attack_surface"]) > 0 {
			sourceChain = formatSourceChain(summary.GroupMap["attack_surface"])
		}
		return joinDisplayParts(
			formatDisplayText("攻击面来源", sourceChain),
			extra,
		)
	case "behavior":
		if !shouldDisplayFlowPrototype(flowMode, flowStatus) {
			return "流量原型默认关闭，当前不纳入默认主链路来源、证据链和评分说明"
		}
		return joinDisplayParts(
			formatDisplayText("流量模式", flowMode),
			formatDisplayText("流量状态", flowStatus),
			formatDisplayText("流量摘要", flowSummary),
			formatDisplayChain("流量入口", summary.FlowSourceChain),
			strings.TrimSpace(item.Basis),
			"仅作为流量增强主链参与解释，不计入默认业务主链来源覆盖",
		)
	default:
		return fallbackString(strings.TrimSpace(item.Basis), "-")
	}
}

// splitSourceBasis 用于拆分来源Basis。
func splitSourceBasis(basis string) (string, string) {
	trimmed := strings.TrimSpace(basis)
	const prefix = "sourceChain="
	if !strings.HasPrefix(trimmed, prefix) {
		return "", trimmed
	}
	parts := strings.SplitN(strings.TrimPrefix(trimmed, prefix), ";", 2)
	sourceChain := strings.TrimSpace(parts[0])
	if len(parts) == 1 {
		return sourceChain, ""
	}
	return sourceChain, strings.TrimSpace(parts[1])
}

// joinDisplayParts 用于拼接DisplayParts。
func joinDisplayParts(parts ...string) string {
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			continue
		}
		filtered = append(filtered, strings.TrimSpace(part))
	}
	if len(filtered) == 0 {
		return "-"
	}
	return strings.Join(filtered, "；")
}

// formatDisplayChain 用于格式化Display链路展示文本。
func formatDisplayChain(label string, chain []string) string {
	if len(chain) == 0 {
		return ""
	}
	return formatDisplayText(label, formatSourceChain(chain))
}

// formatDisplayText 用于格式化DisplayText展示文本。
func formatDisplayText(label string, value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	return fmt.Sprintf("%s=%s", label, trimmed)
}

// extractReputationSource 用于提取请求、令牌或流量中的关键信息。
func extractReputationSource(raw string) string {
	summary := extractPersistedSourceSummary(raw, nil)
	if len(summary.GroupMap["reputation"]) > 0 {
		return formatSourceChain(summary.GroupMap["reputation"])
	}

	payload, ok := decodePersistedFeaturePayload(raw)
	if !ok {
		return ""
	}
	for _, factor := range payload.ScoreFactors {
		if factor.Key != "reputation" {
			continue
		}
		sourceChain, _ := splitSourceBasis(factor.Basis)
		return strings.TrimSpace(sourceChain)
	}
	return ""
}

// extractAttackSurfaceSummary 用于提取请求、令牌或流量中的关键信息。
func extractAttackSurfaceSummary(raw string) (string, string) {
	summary := extractPersistedSourceSummary(raw, nil)
	attackSource := ""
	if len(summary.GroupMap["attack_surface"]) > 0 {
		attackSource = formatSourceChain(summary.GroupMap["attack_surface"])
	}

	payload, ok := decodePersistedFeaturePayload(raw)
	if !ok {
		return attackSource, ""
	}
	for _, factor := range payload.ScoreFactors {
		if factor.Key != "attack_surface" {
			continue
		}
		if attackSource == "" {
			sourceChain, _ := splitSourceBasis(factor.Basis)
			attackSource = strings.TrimSpace(sourceChain)
		}
		return attackSource, normalizeAttackSurfaceBasis(factor.Basis)
	}
	if attackSource == "" {
		attackSource = extractAttackSurfaceSource(payload.DataSources)
	}
	return attackSource, ""
}

// extractAttackSurfaceSource 用于提取请求、令牌或流量中的关键信息。
func extractAttackSurfaceSource(sources []string) string {
	items := sanitizeAttackSurfaceDataSources(sources)
	if len(items) == 0 {
		return ""
	}
	for _, source := range items {
		lower := strings.ToLower(strings.TrimSpace(source))
		if strings.Contains(lower, "port-scan") || strings.Contains(lower, "attack") || strings.Contains(lower, "nmap") {
			return source
		}
	}
	return ""
}

// normalizeAttackSurfaceBasis 用于归一化输入参数或业务指标。
func normalizeAttackSurfaceBasis(basis string) string {
	_, extra := splitSourceBasis(basis)
	return strings.TrimSpace(extra)
}

// sanitizeAttackSurfaceChain 用于清理AttackSurface链路展示数据。
func sanitizeAttackSurfaceChain(chain []string) []string {
	items := dedupeStrings(chain)
	if len(items) == 0 {
		return nil
	}
	if containsSourcePattern(items, "limited-port-scan") {
		return []string{"limited-port-scan"}
	}
	return items
}

// sanitizeAttackSurfaceDataSources 用于清理AttackSurfaceDataSources展示数据。
func sanitizeAttackSurfaceDataSources(sources []string) []string {
	items := dedupeStrings(sources)
	if len(items) == 0 {
		return nil
	}
	if !containsSourcePattern(items, "limited-port-scan") {
		return items
	}
	result := make([]string, 0, len(items))
	for _, source := range items {
		lower := strings.ToLower(strings.TrimSpace(source))
		if strings.Contains(lower, "nmap") {
			continue
		}
		result = append(result, source)
	}
	return dedupeStrings(result)
}

// containsSourcePattern 用于判断集合中是否包含来源Pattern。
func containsSourcePattern(items []string, pattern string) bool {
	for _, item := range items {
		if strings.Contains(strings.ToLower(strings.TrimSpace(item)), pattern) {
			return true
		}
	}
	return false
}

// extractFlowSummary 用于提取请求、令牌或流量中的关键信息。
func extractFlowSummary(raw string) string {
	payload, ok := decodePersistedFeaturePayload(raw)
	if !ok {
		return ""
	}
	mode := strings.TrimSpace(payload.FlowMode)
	status := strings.TrimSpace(payload.FlowStatus)
	if mode == "" || mode == "disabled" || strings.EqualFold(status, "DISABLED") {
		return ""
	}
	if strings.TrimSpace(payload.FlowSummary) != "" {
		return payload.FlowSummary
	}
	if status == "" {
		return "流量=" + mode
	}
	return fmt.Sprintf("流量=%s(%s)", mode, status)
}

// buildRecordFlowSummary 用于构建记录流量摘要。
func buildRecordFlowSummary(raw string) string {
	payload, ok := decodePersistedFeaturePayload(raw)
	if !ok {
		return ""
	}
	if summary := strings.TrimSpace(payload.FlowSummary); summary != "" {
		return summary
	}
	if !shouldDisplayFlowPrototype(payload.FlowMode, payload.FlowStatus) {
		return ""
	}
	mode := normalizeFlowBoundaryMode(payload.FlowMode)
	status := strings.ToUpper(strings.TrimSpace(payload.FlowStatus))
	if mode == "" {
		return ""
	}
	if status == "" {
		return fmt.Sprintf("流量模式=%s", mode)
	}
	return fmt.Sprintf("流量模式=%s，状态=%s", mode, status)
}

// buildRecordFlowSummaryWithCollection 用于构建记录流量摘要WithCollection。
func buildRecordFlowSummaryWithCollection(
	raw string,
	collectionSummary string,
	collectionStatus string,
	parserName string,
	windowCount int64,
	highRiskPortHits int64,
	dnsEventCount int64,
	httpEventCount int64,
	tlsEventCount int64,
	behaviorRiskScore float64,
	highEntropyPacketCount int64,
	uniqueTargetPortCount int64,
	highRiskTargetPortCount int64,
	targetPortDensity float64,
	dominantDirection string,
) string {
	baseSummary := ""
	if summary := strings.TrimSpace(collectionSummary); summary != "" {
		baseSummary = summary
	} else if summary := buildRecordFlowSummary(raw); summary != "" {
		baseSummary = summary
	} else {
		status := strings.ToUpper(strings.TrimSpace(collectionStatus))
		if status != "" {
			baseSummary = fmt.Sprintf("流量采集状态=%s", status)
		}
	}

	supplements := make([]string, 0, 5)
	if strings.TrimSpace(parserName) != "" {
		supplements = append(supplements, fmt.Sprintf("解析器=%s", strings.TrimSpace(parserName)))
	}
	if windowCount > 0 {
		supplements = append(supplements, fmt.Sprintf("窗口=%d", windowCount))
	}
	if highRiskPortHits > 0 {
		supplements = append(supplements, fmt.Sprintf("高危端口命中=%d", highRiskPortHits))
	}
	if dnsEventCount > 0 || httpEventCount > 0 || tlsEventCount > 0 {
		supplements = append(supplements, fmt.Sprintf("协议事件(DNS/HTTP/TLS)=%d/%d/%d", dnsEventCount, httpEventCount, tlsEventCount))
	}
	if behaviorRiskScore > 0 {
		supplements = append(supplements, fmt.Sprintf("行为风险=%.2f", round2(behaviorRiskScore)))
	}
	if highEntropyPacketCount > 0 {
		supplements = append(supplements, fmt.Sprintf("高熵报文=%d", highEntropyPacketCount))
	}
	if uniqueTargetPortCount > 0 {
		supplements = append(supplements, fmt.Sprintf("目标端口=%d", uniqueTargetPortCount))
	}
	if highRiskTargetPortCount > 0 {
		supplements = append(supplements, fmt.Sprintf("高危目标端口=%d", highRiskTargetPortCount))
	}
	if targetPortDensity > 0 {
		supplements = append(supplements, fmt.Sprintf("端口密度=%.2f", round2(targetPortDensity)))
	}
	if strings.TrimSpace(dominantDirection) != "" {
		supplements = append(supplements, fmt.Sprintf("主导流向=%s", strings.TrimSpace(dominantDirection)))
	}

	switch {
	case baseSummary == "" && len(supplements) == 0:
		return ""
	case baseSummary == "":
		return strings.Join(supplements, "；")
	case len(supplements) == 0:
		return baseSummary
	default:
		return strings.Join(append([]string{baseSummary}, supplements...), "；")
	}
}
