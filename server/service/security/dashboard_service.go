package security

import (
	"fmt"
	"log"
	"strings"
	"time"

	"lightweight-ip-traffic-sa/server/config"
	"lightweight-ip-traffic-sa/server/global"
	responseModel "lightweight-ip-traffic-sa/server/model/security/response"
	"lightweight-ip-traffic-sa/server/repository"
	repositorySecurity "lightweight-ip-traffic-sa/server/repository/security"
	"lightweight-ip-traffic-sa/server/utils"
)

// DashboardService 用于编排安全态势模块的业务流程。
type DashboardService struct{}

// GetGeoRisk 用于查询总览详情并组装响应。
func (s *DashboardService) GetGeoRisk() (responseModel.DashboardGeoRiskResponse, error) {
	type geoRiskRow struct {
		TargetIP   string
		Country    string
		Region     string
		City       string
		RawPayload string
		RiskLevel  string
		TaskCount  int64
		AlertCount int64
	}

	// 关联任务/基础画像/评分/预警四表，聚合每个 IP 的任务数与预警数，并取 GeoLite2 经纬度供热力图展示
	var rows []geoRiskRow
	start := time.Now().AddDate(0, 0, -7)
	err := global.DB.Table("sec_ip_task AS t").
		Joins("LEFT JOIN sec_ip_base_info AS b ON b.task_id = t.id").
		Joins("LEFT JOIN sec_risk_score AS s ON s.task_id = t.id").
		Joins("LEFT JOIN sec_alert_record AS a ON a.task_id = t.id").
		Select(`t.target_ip, COALESCE(b.country, '') AS country, COALESCE(b.region, '') AS region, COALESCE(b.city, '') AS city,
			COALESCE(b.raw_payload, '{}') AS raw_payload, COALESCE(s.risk_level, 'LOW') AS risk_level,
			COUNT(DISTINCT t.id) AS task_count, COUNT(DISTINCT a.id) AS alert_count`).
		Where("t.created_at >= ?", start).
		Group("t.target_ip, b.country, b.region, b.city, b.raw_payload, s.risk_level").
		Order("task_count DESC, alert_count DESC, t.target_ip ASC").
		Scan(&rows).Error
	if err != nil {
		return responseModel.DashboardGeoRiskResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取风险 IP 热力图失败，请稍后重试", err)
	}

	items := make([]responseModel.DashboardGeoRiskItem, 0, len(rows))
	for _, row := range rows {
		payload := decodeJSONMap(row.RawPayload)
		geoLite2Payload := extractMap(payload, "geoLite2")
		lat := extractFloat64(geoLite2Payload, "latitude")
		lng := extractFloat64(geoLite2Payload, "longitude")
		items = append(items, responseModel.DashboardGeoRiskItem{
			TargetIP:      row.TargetIP,
			Country:       row.Country,
			Region:        row.Region,
			City:          row.City,
			RiskLevel:     row.RiskLevel,
			TaskCount:     row.TaskCount,
			AlertCount:    row.AlertCount,
			Latitude:      lat,
			Longitude:     lng,
			HasCoordinate: lat != 0 || lng != 0,
		})
	}
	return responseModel.DashboardGeoRiskResponse{Items: items}, nil
}

// GetSummary 用于查询总览详情并组装响应。
// 总览聚合：一次请求汇总任务数、风险分布、7 天趋势、预警数、来源覆盖与流量趋势，
// 结果用短 TTL 缓存，任务创建成功或预警产生时主动清缓存以保证首页尽快反映最新态势
func (s *DashboardService) GetSummary() (responseModel.DashboardSummaryResponse, error) {
	runtimeCfg := loadRuntimeSecurityConfig()
	var cached responseModel.DashboardSummaryResponse
	if hit, err := utils.CacheGetJSON(utils.SecurityDashboardSummaryCacheKey, &cached); err == nil && hit {
		return cached, nil
	} else if err != nil {
		log.Printf("总览聚合缓存读取失败，继续查询数据库，key=%s err=%v", utils.SecurityDashboardSummaryCacheKey, err)
	}

	repo := repository.RepositoryGroupApp.SecurityRepositoryGroup
	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	// 趋势回溯起点：往前推 6 天，加上今天共 7 个自然日
	trendStart := dayStart.AddDate(0, 0, -6)

	taskSummary, err := repo.TaskRepository.CountSummary(global.DB, dayStart)
	if err != nil {
		return responseModel.DashboardSummaryResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取总览数据失败，请稍后重试", err)
	}
	riskRows, err := repo.ScoreRepository.CountRiskDistribution(global.DB)
	if err != nil {
		return responseModel.DashboardSummaryResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取总览数据失败，请稍后重试", err)
	}
	riskTrendRows, err := repo.ScoreRepository.CountRiskTrend(global.DB, trendStart)
	if err != nil {
		return responseModel.DashboardSummaryResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取总览数据失败，请稍后重试", err)
	}
	taskTrendRows, err := repo.TaskRepository.CountDailyTrend(global.DB, trendStart)
	if err != nil {
		return responseModel.DashboardSummaryResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取总览数据失败，请稍后重试", err)
	}
	alertTrendRows, err := repo.AlertRepository.CountDailyTrend(global.DB, trendStart)
	if err != nil {
		return responseModel.DashboardSummaryResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取总览数据失败，请稍后重试", err)
	}
	alertCount, err := repo.AlertRepository.CountAll(global.DB)
	if err != nil {
		return responseModel.DashboardSummaryResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取总览数据失败，请稍后重试", err)
	}
	featurePayloadRows, err := repo.FeatureRepository.ListPayloads(global.DB)
	if err != nil {
		return responseModel.DashboardSummaryResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取总览数据失败，请稍后重试", err)
	}
	attackSurfaceSummary, err := repo.FeatureRepository.CountAttackSurfaceSummary(global.DB)
	if err != nil {
		return responseModel.DashboardSummaryResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取总览数据失败，请稍后重试", err)
	}
	flowModeRows, err := repo.FlowCollectionRepository.CountModeDistribution(global.DB, trendStart)
	if err != nil {
		return responseModel.DashboardSummaryResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取总览数据失败，请稍后重试", err)
	}
	flowTrendRows, err := repo.FlowCollectionRepository.CountDailyTrend(global.DB, trendStart)
	if err != nil {
		return responseModel.DashboardSummaryResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取总览数据失败，请稍后重试", err)
	}
	flowWindowTrendRows, err := repo.FlowWindowAggregateRepository.CountDailySummary(global.DB, trendStart)
	if err != nil {
		return responseModel.DashboardSummaryResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取总览数据失败，请稍后重试", err)
	}
	flowBehaviorRows, err := repo.FlowFeatureSnapshotRepository.CountBehaviorTrend(global.DB, trendStart)
	if err != nil {
		return responseModel.DashboardSummaryResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取总览数据失败，请稍后重试", err)
	}

	riskDistribution := buildRiskDistribution(riskRows)
	highRiskCount := getRiskCount(riskDistribution, "HIGH")
	criticalRiskCount := getRiskCount(riskDistribution, "CRITICAL")
	baseSourceCounter := make(map[string]int64)
	reputationSourceCounter := make(map[string]int64)
	attackSourceCounter := make(map[string]int64)
	for _, row := range featurePayloadRows {
		summary := extractPersistedSourceSummary(row.NormalizedFeatures, nil)
		for _, group := range summary.Groups {
			for _, source := range group.Chain {
				switch group.Key {
				case "base_info":
					baseSourceCounter[source]++
				case "reputation":
					reputationSourceCounter[source]++
				case "attack_surface":
					attackSourceCounter[source]++
				}
			}
		}
	}

	resp := responseModel.DashboardSummaryResponse{
		TotalTaskCount:          taskSummary.TotalTasks,
		HighRiskCount:           highRiskCount,
		CriticalRiskCount:       criticalRiskCount,
		AlertCount:              alertCount,
		TodayDetections:         taskSummary.TodayDetections,
		ExposedTaskCount:        attackSurfaceSummary.ExposedTaskCount,
		HighRiskPortTasks:       attackSurfaceSummary.HighRiskPortTasks,
		Trend:                   buildDashboardTrend(trendStart, taskTrendRows, alertTrendRows),
		RiskTrend:               buildDashboardRiskTrend(trendStart, riskTrendRows),
		RiskDistribution:        riskDistribution,
		BaseInfoSources:         toResponseSourceCoverage(buildSourceCoverageItemsWithDefaults(baseSourceCounter, buildDefaultBaseInfoCoverageSources(runtimeCfg))),
		ReputationSources:       toResponseSourceCoverage(buildSourceCoverageItemsWithDefaults(reputationSourceCounter, buildDefaultReputationCoverageSources(runtimeCfg))),
		AttackSources:           toResponseSourceCoverage(buildSourceCoverageItemsWithDefaults(attackSourceCounter, buildDefaultAttackCoverageSources(runtimeCfg))),
		FlowEnabled:             runtimeCfg.Source.Flow.Enabled,
		ActiveFlowMode:          resolveDashboardActiveFlowMode(runtimeCfg),
		FlowCollectionCount:     sumFlowCollectionCount(flowModeRows),
		FlowModeDistribution:    toResponseFlowModeDistribution(flowModeRows),
		FlowTrend:               buildDashboardFlowTrend(trendStart, flowTrendRows, flowWindowTrendRows, flowBehaviorRows),
		FlowHistorySourceTable:  "sec_flow_collection",
		FlowTrendSourceTable:    "sec_flow_window_aggregate",
		FlowEvidenceSourceTable: "sec_flow_feature_snapshot",
		FlowCapabilitySummary:   buildFlowCapabilitySummary(runtimeCfg, flowModeRows),
		StableChain:             buildStableDefaultChain(runtimeCfg),
		EnhancedSwitches:        buildEnhancedSwitches(runtimeCfg),
		PrototypeSources:        buildPrototypeSources(runtimeCfg),
		BoundarySummary:         buildBoundarySummary(runtimeCfg),
		PrototypeNote:           buildPrototypeNote(runtimeCfg),
	}

	if err := utils.CacheSetJSON(utils.SecurityDashboardSummaryCacheKey, resp, utils.DashboardSummaryCacheTTL()); err != nil {
		log.Printf("总览聚合缓存写入失败，已返回实时数据，key=%s err=%v", utils.SecurityDashboardSummaryCacheKey, err)
	}

	return resp, nil
}

// buildDashboardTrend 用于构建总览Trend。
// 把任务/预警按日期落到 map，再按 7 天补齐缺失日期（无数据的日期补 0），保证前端折线连续
func buildDashboardTrend(start time.Time, taskRows []repositorySecurity.DailyCountRow, alertRows []repositorySecurity.AlertDailyCountRow) []responseModel.DashboardTrendItem {
	taskMap := make(map[string]int64, len(taskRows))
	for _, row := range taskRows {
		taskMap[row.Date] = row.Count
	}

	alertMap := make(map[string]int64, len(alertRows))
	for _, row := range alertRows {
		alertMap[row.Date] = row.Count
	}

	items := make([]responseModel.DashboardTrendItem, 0, 7)
	for offset := 0; offset < 7; offset++ {
		current := start.AddDate(0, 0, offset).Format("2006-01-02")
		items = append(items, responseModel.DashboardTrendItem{
			Date:       current,
			TaskCount:  taskMap[current],
			AlertCount: alertMap[current],
		})
	}
	return items
}

// buildDashboardRiskTrend 用于构建总览风险Trend。
// 与任务趋势同理，按 7 天补齐高风险/严重任务数，缺失日期补 0
func buildDashboardRiskTrend(start time.Time, rows []repositorySecurity.RiskTrendCountRow) []responseModel.DashboardRiskTrendItem {
	riskMap := make(map[string]repositorySecurity.RiskTrendCountRow, len(rows))
	for _, row := range rows {
		riskMap[row.Date] = row
	}

	items := make([]responseModel.DashboardRiskTrendItem, 0, 7)
	for offset := 0; offset < 7; offset++ {
		current := start.AddDate(0, 0, offset).Format("2006-01-02")
		row := riskMap[current]
		items = append(items, responseModel.DashboardRiskTrendItem{
			Date:              current,
			HighRiskTaskCount: row.HighRiskTaskCount,
			CriticalTaskCount: row.CriticalTaskCount,
		})
	}
	return items
}

// buildRiskDistribution 用于构建风险Distribution。
// 按固定的 LOW/MEDIUM/HIGH/CRITICAL 顺序输出，缺失等级补 0，保证前端饼图顺序稳定
func buildRiskDistribution(rows []repositorySecurity.RiskLevelCountRow) []responseModel.DashboardRiskDistributionItem {
	order := []string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}
	countMap := make(map[string]int64, len(rows))
	for _, row := range rows {
		countMap[row.RiskLevel] = row.Count
	}

	items := make([]responseModel.DashboardRiskDistributionItem, 0, len(order))
	for _, riskLevel := range order {
		items = append(items, responseModel.DashboardRiskDistributionItem{
			RiskLevel: riskLevel,
			Count:     countMap[riskLevel],
		})
	}
	return items
}

// getRiskCount 用于执行get风险Count流程。
func getRiskCount(items []responseModel.DashboardRiskDistributionItem, riskLevel string) int64 {
	for _, item := range items {
		if item.RiskLevel == riskLevel {
			return item.Count
		}
	}
	return 0
}

// toResponseSourceCoverage 用于转换并生成响应来源Coverage。
func toResponseSourceCoverage(items []dashboardSourceCoverageItem) []responseModel.DashboardSourceCoverageItem {
	result := make([]responseModel.DashboardSourceCoverageItem, 0, len(items))
	for _, item := range items {
		result = append(result, responseModel.DashboardSourceCoverageItem{
			Source: item.Source,
			Count:  item.Count,
		})
	}
	return result
}

// toResponseFlowModeDistribution 用于转换并生成响应流量ModeDistribution。
func toResponseFlowModeDistribution(rows []repositorySecurity.FlowModeCountRow) []responseModel.DashboardFlowModeItem {
	result := make([]responseModel.DashboardFlowModeItem, 0, len(rows))
	for _, row := range rows {
		result = append(result, responseModel.DashboardFlowModeItem{
			Mode:  normalizeFlowMode(row.CollectionMode),
			Count: row.Count,
		})
	}
	return result
}

// buildDashboardFlowTrend 用于构建总览流量Trend。
// 合并流量三表（采集/窗口聚合/特征快照）的按日统计，报文/字节/会话优先取窗口聚合值、缺失时回退采集值
func buildDashboardFlowTrend(
	start time.Time,
	collectionRows []repositorySecurity.FlowCollectionTrendRow,
	windowRows []repositorySecurity.FlowWindowSummaryRow,
	behaviorRows []repositorySecurity.FlowBehaviorTrendRow,
) []responseModel.DashboardFlowTrendItem {
	collectionMap := make(map[string]repositorySecurity.FlowCollectionTrendRow, len(collectionRows))
	for _, row := range collectionRows {
		collectionMap[row.Date] = row
	}
	windowMap := make(map[string]repositorySecurity.FlowWindowSummaryRow, len(windowRows))
	for _, row := range windowRows {
		windowMap[row.Date] = row
	}
	behaviorMap := make(map[string]repositorySecurity.FlowBehaviorTrendRow, len(behaviorRows))
	for _, row := range behaviorRows {
		behaviorMap[row.Date] = row
	}

	items := make([]responseModel.DashboardFlowTrendItem, 0, 7)
	for offset := 0; offset < 7; offset++ {
		current := start.AddDate(0, 0, offset).Format("2006-01-02")
		collectionRow := collectionMap[current]
		windowRow := windowMap[current]
		behaviorRow := behaviorMap[current]
		// 用两个布尔标记区分“有窗口聚合数据”与“有特征快照数据”，前端据此决定是否展示对应图表
		hasWindowMetrics := windowRow.PacketCount > 0 || windowRow.ByteCount > 0 || windowRow.ConversationCount > 0
		hasBehaviorSnapshot := behaviorRow.HighBehaviorRiskCount > 0 ||
			behaviorRow.TrackedConversationSum > 0 ||
			behaviorRow.AverageBehaviorRisk > 0 ||
			behaviorRow.HighEntropyPacketCount > 0 ||
			behaviorRow.AveragePortDensity > 0 ||
			behaviorRow.DirectionalBiasCount > 0
		items = append(items, responseModel.DashboardFlowTrendItem{
			Date:                   current,
			CollectionCount:        collectionRow.CollectionCount,
			PacketCount:            pickNonZeroInt64(windowRow.PacketCount, collectionRow.PacketCount),
			ByteCount:              pickNonZeroInt64(windowRow.ByteCount, collectionRow.ByteCount),
			ConversationCount:      pickNonZeroInt64(windowRow.ConversationCount, collectionRow.ConversationCount),
			HighRiskPortHitCount:   windowRow.HighRiskPortHitCount,
			DNSEventCount:          windowRow.DNSEventCount,
			HTTPEventCount:         windowRow.HTTPEventCount,
			TLSEventCount:          windowRow.TLSEventCount,
			HighBehaviorRiskCount:  behaviorRow.HighBehaviorRiskCount,
			AverageBehaviorRisk:    round2(behaviorRow.AverageBehaviorRisk),
			TrackedConversationSum: behaviorRow.TrackedConversationSum,
			HighEntropyPacketCount: behaviorRow.HighEntropyPacketCount,
			AveragePortDensity:     round2(behaviorRow.AveragePortDensity),
			DirectionalBiasCount:   behaviorRow.DirectionalBiasCount,
			HasWindowMetrics:       hasWindowMetrics,
			HasBehaviorSnapshot:    hasBehaviorSnapshot,
		})
	}
	return items
}

// pickNonZeroInt64 用于选取NonZeroInt64。
func pickNonZeroInt64(primary int64, fallback int64) int64 {
	if primary != 0 {
		return primary
	}
	return fallback
}

// sumFlowCollectionCount 用于执行sum流量CollectionCount流程。
func sumFlowCollectionCount(rows []repositorySecurity.FlowModeCountRow) int64 {
	var total int64
	for _, row := range rows {
		total += row.Count
	}
	return total
}

// buildFlowCapabilitySummary 用于构建流量Capability摘要。
// 根据流量开关与活动模式生成一句给前端展示的能力说明，明确“流量维不进入默认来源覆盖”的边界
func buildFlowCapabilitySummary(cfg config.SecurityConfig, rows []repositorySecurity.FlowModeCountRow) string {
	mode := resolveDashboardActiveFlowMode(cfg)
	if !cfg.Source.Flow.Enabled {
		return "流量维默认关闭；总览仅在存在真实流量采集记录时展示趋势，详情追溯入口保留在任务详情页。"
	}
	return fmt.Sprintf("当前流量原型已启用，活动模式=%s；总览趋势只统计已落库的流量采集记录，默认主链路来源覆盖仍不计入流量维；近 7 天已落库流量记录 %d 条。", mode, sumFlowCollectionCount(rows))
}

// resolveDashboardActiveFlowMode 用于解析总览Active流量Mode。
func resolveDashboardActiveFlowMode(cfg config.SecurityConfig) string {
	if !cfg.Source.Flow.Enabled {
		return "disabled"
	}
	return normalizeFlowMode(cfg.Source.Flow.Mode)
}

// buildStableDefaultChain 用于构建StableDefault链路。
func buildStableDefaultChain(cfg config.SecurityConfig) []string {
	items := make([]string, 0, 4)
	if cfg.Source.GeoLite2.Enabled {
		items = append(items, "GeoLite2")
	}
	if cfg.Source.RDAP.Enabled {
		items = append(items, "RDAP")
	}
	if cfg.Source.LocalBlacklist.Enabled {
		items = append(items, "local-blacklist")
	}
	if cfg.Source.AttackSurface.Enabled {
		items = append(items, "limited-port-scan")
	}
	return items
}

// buildDefaultBaseInfoCoverageSources 用于构建Default基础信息CoverageSources。
func buildDefaultBaseInfoCoverageSources(cfg config.SecurityConfig) []string {
	items := make([]string, 0, 2)
	if cfg.Source.GeoLite2.Enabled {
		items = append(items, "GeoLite2")
	}
	if cfg.Source.RDAP.Enabled {
		items = append(items, "RDAP")
	}
	return items
}

// buildDefaultReputationCoverageSources 用于构建DefaultReputationCoverageSources。
func buildDefaultReputationCoverageSources(cfg config.SecurityConfig) []string {
	items := make([]string, 0, 2)
	if cfg.Source.LocalBlacklist.Enabled {
		items = append(items, "local-blacklist")
	}
	if cfg.Source.AbuseIPDB.Enabled {
		items = append(items, "abuseipdb")
	}
	return items
}

// buildDefaultAttackCoverageSources 用于构建DefaultAttackCoverageSources。
func buildDefaultAttackCoverageSources(cfg config.SecurityConfig) []string {
	items := make([]string, 0, 2)
	if cfg.Source.AttackSurface.Enabled {
		items = append(items, "limited-port-scan")
	}
	if cfg.Source.AttackSurface.Enabled && cfg.Source.AttackSurface.NmapEnabled {
		items = append(items, "nmap-enhanced")
	}
	return items
}

// buildEnhancedSwitches 用于构建EnhancedSwitches。
func buildEnhancedSwitches(cfg config.SecurityConfig) []string {
	items := make([]string, 0, 2)
	if cfg.Source.AbuseIPDB.Enabled {
		items = append(items, "AbuseIPDB(增强开关:启用)")
	} else {
		items = append(items, "AbuseIPDB(增强开关:关闭)")
	}
	if cfg.Source.AttackSurface.NmapEnabled {
		items = append(items, "Nmap(P2增强:启用)")
	} else {
		items = append(items, "Nmap(P2增强:关闭)")
	}
	return items
}

// buildPrototypeSources 用于构建PrototypeSources。
func buildPrototypeSources(cfg config.SecurityConfig) []string {
	items := []string{
		"flow sample(样本原型)",
		"offline pcap(独立编排入口)",
		"online capture(独立编排入口)",
	}
	if cfg.Source.Flow.Enabled && strings.TrimSpace(cfg.Source.Flow.Mode) != "" && !strings.EqualFold(cfg.Source.Flow.Mode, "disabled") {
		items = append(items, "当前流量模式="+normalizeFlowMode(cfg.Source.Flow.Mode)+"(已启用原型)")
	} else {
		items = append(items, "当前流量模式=disabled(默认关闭)")
	}
	return items
}

// buildBoundarySummary 用于构建Boundary摘要。
func buildBoundarySummary(cfg config.SecurityConfig) string {
	stable := strings.Join(buildStableDefaultChain(cfg), " + ")
	if strings.TrimSpace(stable) == "" {
		stable = "当前未启用稳定默认链路"
	}
	return fmt.Sprintf("%s 为当前默认主链路；总览来源覆盖仅统计基础画像、信誉、攻击面三类已落地来源；AbuseIPDB 与 Nmap 仅作为可开关增强，其中 Nmap 失败时必须回退到 limited-port-scan；flow sample 仅为样本原型，offline pcap 与 online capture 仅为独立流量编排入口；流量维默认关闭时不写入 DataSources、证据链和页面来源展示。", stable)
}

// buildPrototypeNote 用于构建PrototypeNote。
func buildPrototypeNote(cfg config.SecurityConfig) string {
	if cfg.Source.Flow.Enabled && strings.TrimSpace(cfg.Source.Flow.Mode) != "" && !strings.EqualFold(cfg.Source.Flow.Mode, "disabled") {
		return "当前仅开放流量原型入口；样本模式与 pcap/在线抓包入口只在独立区域启用，不计入默认来源覆盖。"
	}
	return "流量维默认关闭；样本模式与 pcap/在线抓包入口仅在独立区域启用，不计入默认来源覆盖。"
}
