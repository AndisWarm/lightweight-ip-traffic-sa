package security

import (
	"fmt"
	"sort"
	"strings"

	"lightweight-ip-traffic-sa/server/global"
	requestModel "lightweight-ip-traffic-sa/server/model/security/request"
	responseModel "lightweight-ip-traffic-sa/server/model/security/response"
	"lightweight-ip-traffic-sa/server/repository"
	repositorySecurity "lightweight-ip-traffic-sa/server/repository/security"
	"lightweight-ip-traffic-sa/server/utils"
)

// RecordService 用于编排安全态势模块的业务流程。
type RecordService struct{}

// ListRecords 用于查询记录列表并组装响应。
func (s *RecordService) ListRecords(query requestModel.RecordListQuery, claims *utils.TokenClaims) (responseModel.PagedRecordResponse, error) {
	query.Page = utils.NormalizePage(query.Page)
	query.PageSize = utils.NormalizePageSize(query.PageSize)
	if claims != nil && strings.EqualFold(strings.TrimSpace(claims.RoleCode), "USER") {
		query.CreatedBy = strings.TrimSpace(claims.Username)
	}

	repo := repository.RepositoryGroupApp.SecurityRepositoryGroup.RecordRepository
	items := make([]responseModel.RecordListItem, 0)

	if query.EventType == "" || query.EventType == "ALL" || query.EventType == "TASK" {
		taskRows, err := repo.ListTaskRecords(global.DB, query.Keyword, query.CreatedBy)
		if err != nil {
			return responseModel.PagedRecordResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取历史记录失败，请稍后重试", err)
		}
		for _, row := range taskRows {
			hasRealMetrics := row.FlowPacketCount > 0 || row.FlowConversationCount > 0 || row.FlowBehaviorRiskScore > 0
			isTraceable := row.FlowCollectionID > 0
			items = append(items, responseModel.RecordListItem{
				ID:                          row.ID,
				EventType:                   "TASK",
				Title:                       fmt.Sprintf("检测任务 %s", row.TaskNo),
				Description:                 fmt.Sprintf("系统已完成对目标 IP %s 的检测任务，可继续查看基础画像、评分结果和预警摘要。", row.TargetIP),
				TargetIP:                    row.TargetIP,
				OriginalTarget:              row.OriginalTarget,
				TaskNo:                      row.TaskNo,
				SourceSummary:               buildTaskSourceSummary(row.BaseInfoRawPayload, row.NormalizedFeatures),
				FlowSummary:                 buildRecordFlowSummaryWithCollection(row.NormalizedFeatures, row.FlowCollectionSummary, row.FlowCollectionStatus, row.FlowParserName, row.FlowWindowCount, row.FlowHighRiskPortHits, row.FlowDNSEventCount, row.FlowHTTPEventCount, row.FlowTLSEventCount, row.FlowBehaviorRiskScore, row.FlowHighEntropyPacketCount, row.FlowUniqueTargetPortCount, row.FlowHighRiskTargetPortCount, row.FlowTargetPortDensity, row.FlowDominantDirection),
				FlowHistorySourceTable:      resolveFlowHistorySourceTable(row.FlowCollectionID),
				FlowTrendSourceTable:        resolveFlowTrendSourceTable(row.FlowCollectionID),
				FlowEvidenceSourceTable:     resolveFlowEvidenceSourceTable(row.FlowCollectionID),
				FlowCollectionMode:          row.FlowCollectionMode,
				FlowCollectionStatus:        row.FlowCollectionStatus,
				FlowSourceName:              row.FlowSourceName,
				FlowParserName:              row.FlowParserName,
				FlowPacketCount:             row.FlowPacketCount,
				FlowConversationCount:       row.FlowConversationCount,
				FlowWindowCount:             row.FlowWindowCount,
				FlowHighRiskPortHits:        row.FlowHighRiskPortHits,
				FlowDNSEventCount:           row.FlowDNSEventCount,
				FlowHTTPEventCount:          row.FlowHTTPEventCount,
				FlowTLSEventCount:           row.FlowTLSEventCount,
				FlowBehaviorRiskScore:       row.FlowBehaviorRiskScore,
				FlowHighEntropyPacketCount:  row.FlowHighEntropyPacketCount,
				FlowUniqueTargetPortCount:   row.FlowUniqueTargetPortCount,
				FlowHighRiskTargetPortCount: row.FlowHighRiskTargetPortCount,
				FlowTargetPortDensity:       row.FlowTargetPortDensity,
				FlowDominantDirection:       row.FlowDominantDirection,
				FlowFeatureDigest:           row.FlowFeatureDigest,
				FlowHasRealMetrics:          hasRealMetrics,
				FlowIsTraceable:             isTraceable,
				Level:                       row.RiskLevel,
				Status:                      row.TaskStatus,
				Time:                        row.CreatedAt.Format("2006-01-02 15:04:05"),
				DetailRoute:                 fmt.Sprintf("/security/task/%d", row.ID),
			})
		}
	}

	if query.EventType == "" || query.EventType == "ALL" || query.EventType == "ALERT" {
		alertRows, err := repo.ListAlertRecords(global.DB, query.Keyword, query.CreatedBy)
		if err != nil {
			return responseModel.PagedRecordResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取历史记录失败，请稍后重试", err)
		}
		for _, row := range alertRows {
			if query.CreatedBy != "" && !canUserAccessRecordAlertRow(row, query.CreatedBy) {
				continue
			}
			hasRealMetrics := row.FlowPacketCount > 0 || row.FlowConversationCount > 0 || row.FlowBehaviorRiskScore > 0
			isTraceable := row.FlowCollectionID > 0
			items = append(items, responseModel.RecordListItem{
				ID:                          row.ID,
				EventType:                   "ALERT",
				Title:                       fmt.Sprintf("预警事件 %d", row.ID),
				Description:                 fmt.Sprintf("系统识别到目标 IP %s 触发预警，可查看关联任务与评分结果。", row.TargetIP),
				TargetIP:                    row.TargetIP,
				OriginalTarget:              row.OriginalTarget,
				TaskNo:                      row.TaskNo,
				SourceSummary:               buildTaskSourceSummary(row.BaseInfoRawPayload, row.NormalizedFeatures),
				FlowSummary:                 buildRecordFlowSummaryWithCollection(row.NormalizedFeatures, row.FlowCollectionSummary, row.FlowCollectionStatus, row.FlowParserName, row.FlowWindowCount, row.FlowHighRiskPortHits, row.FlowDNSEventCount, row.FlowHTTPEventCount, row.FlowTLSEventCount, row.FlowBehaviorRiskScore, row.FlowHighEntropyPacketCount, row.FlowUniqueTargetPortCount, row.FlowHighRiskTargetPortCount, row.FlowTargetPortDensity, row.FlowDominantDirection),
				FlowHistorySourceTable:      resolveFlowHistorySourceTable(row.FlowCollectionID),
				FlowTrendSourceTable:        resolveFlowTrendSourceTable(row.FlowCollectionID),
				FlowEvidenceSourceTable:     resolveFlowEvidenceSourceTable(row.FlowCollectionID),
				FlowCollectionMode:          row.FlowCollectionMode,
				FlowCollectionStatus:        row.FlowCollectionStatus,
				FlowSourceName:              row.FlowSourceName,
				FlowParserName:              row.FlowParserName,
				FlowPacketCount:             row.FlowPacketCount,
				FlowConversationCount:       row.FlowConversationCount,
				FlowWindowCount:             row.FlowWindowCount,
				FlowHighRiskPortHits:        row.FlowHighRiskPortHits,
				FlowDNSEventCount:           row.FlowDNSEventCount,
				FlowHTTPEventCount:          row.FlowHTTPEventCount,
				FlowTLSEventCount:           row.FlowTLSEventCount,
				FlowBehaviorRiskScore:       row.FlowBehaviorRiskScore,
				FlowHighEntropyPacketCount:  row.FlowHighEntropyPacketCount,
				FlowUniqueTargetPortCount:   row.FlowUniqueTargetPortCount,
				FlowHighRiskTargetPortCount: row.FlowHighRiskTargetPortCount,
				FlowTargetPortDensity:       row.FlowTargetPortDensity,
				FlowDominantDirection:       row.FlowDominantDirection,
				FlowFeatureDigest:           row.FlowFeatureDigest,
				FlowHasRealMetrics:          hasRealMetrics,
				FlowIsTraceable:             isTraceable,
				Level:                       row.AlertLevel,
				Status:                      row.SendStatus,
				Time:                        row.CreatedAt.Format("2006-01-02 15:04:05"),
				DetailRoute:                 fmt.Sprintf("/security/alert/%d", row.ID),
			})
		}
	}

	sort.Slice(items, func(i, j int) bool {
		return items[i].Time > items[j].Time
	})

	total := len(items)
	start := (query.Page - 1) * query.PageSize
	if start > total {
		start = total
	}
	end := start + query.PageSize
	if end > total {
		end = total
	}

	return responseModel.PagedRecordResponse{
		Page:     query.Page,
		PageSize: query.PageSize,
		Total:    total,
		Items:    items[start:end],
	}, nil
}

// resolveFlowHistorySourceTable 用于解析流量History来源表。
func resolveFlowHistorySourceTable(flowCollectionID uint64) string {
	if flowCollectionID == 0 {
		return ""
	}
	return "sec_flow_collection"
}

// resolveFlowTrendSourceTable 用于解析流量Trend来源表。
func resolveFlowTrendSourceTable(flowCollectionID uint64) string {
	if flowCollectionID == 0 {
		return ""
	}
	return "sec_flow_window_aggregate"
}

// resolveFlowEvidenceSourceTable 用于解析流量Evidence来源表。
func resolveFlowEvidenceSourceTable(flowCollectionID uint64) string {
	if flowCollectionID == 0 {
		return ""
	}
	return "sec_flow_feature_snapshot"
}

// canUserAccessRecordAlertRow 用于判断是否允许用户Access记录预警Row。
func canUserAccessRecordAlertRow(row repositorySecurity.AlertRecordRow, username string) bool {
	if strings.TrimSpace(row.TaskNo) != "" {
		return true
	}
	return canUserAccessFlowMonitorAlert(row.MonitorSessionID, username)
}
