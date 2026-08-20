package security

import (
	"log"
	"strings"

	"lightweight-ip-traffic-sa/server/global"
	securityModel "lightweight-ip-traffic-sa/server/model/security"
	requestModel "lightweight-ip-traffic-sa/server/model/security/request"
	responseModel "lightweight-ip-traffic-sa/server/model/security/response"
	"lightweight-ip-traffic-sa/server/repository"
	"lightweight-ip-traffic-sa/server/utils"
)

// AlertService 用于编排安全态势模块的业务流程。
type AlertService struct{}

var ErrAlertNotFound = NewServiceError(ServiceErrorCategoryNotFound, "预警记录不存在或已删除")

// ListAlerts 用于查询预警列表并组装响应。
func (s *AlertService) ListAlerts(query requestModel.AlertListQuery, claims *utils.TokenClaims) (responseModel.PagedAlertResponse, error) {
	query.Page = utils.NormalizePage(query.Page)
	query.PageSize = utils.NormalizePageSize(query.PageSize)
	if claims != nil && strings.EqualFold(strings.TrimSpace(claims.RoleCode), "USER") {
		query.CreatedBy = strings.TrimSpace(claims.Username)
	}

	rows, _, err := repository.RepositoryGroupApp.SecurityRepositoryGroup.AlertRepository.List(global.DB, query)
	if err != nil {
		return responseModel.PagedAlertResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取预警列表失败，请稍后重试", err)
	}

	items := make([]responseModel.AlertListItem, 0, len(rows))
	for _, row := range rows {
		if query.CreatedBy != "" && strings.EqualFold(strings.TrimSpace(row.SourceType), "FLOW_MONITOR") && !canUserAccessFlowMonitorAlert(row.SourceLabel, query.CreatedBy) {
			continue
		}
		items = append(items, responseModel.AlertListItem{
			AlertID:     row.ID,
			TaskNo:      row.TaskNo,
			TargetIP:    row.IP,
			SourceType:  row.SourceType,
			SourceLabel: row.SourceLabel,
			AlertLevel:  row.AlertLevel,
			Channel:     row.Channel,
			SendStatus:  row.SendStatus,
			CreatedAt:   row.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}

	return responseModel.PagedAlertResponse{
		Page:     query.Page,
		PageSize: query.PageSize,
		Total:    int64(len(items)),
		Items:    items,
	}, nil
}

// GetAlertDetail 用于查询预警详情并组装响应。
func (s *AlertService) GetAlertDetail(alertID uint64, claims *utils.TokenClaims) (responseModel.AlertDetailResponse, error) {
	repo := repository.RepositoryGroupApp.SecurityRepositoryGroup
	cacheKey := utils.BuildAlertDetailCacheKey(alertID)

	var cached responseModel.AlertDetailResponse
	if hit, err := utils.CacheGetJSON(cacheKey, &cached); err == nil && hit {
		if claims != nil && strings.EqualFold(strings.TrimSpace(claims.RoleCode), "USER") {
			if cached.Task != nil {
				task, taskErr := repo.TaskRepository.FindByID(global.DB, cached.Task.TaskID)
				if taskErr == nil && !strings.EqualFold(strings.TrimSpace(task.CreatedBy), strings.TrimSpace(claims.Username)) {
					return responseModel.AlertDetailResponse{}, ErrAlertNotFound
				}
			} else if !canUserAccessFlowMonitorAlert(cached.MonitorSessionID, strings.TrimSpace(claims.Username)) {
				return responseModel.AlertDetailResponse{}, ErrAlertNotFound
			}
		}
		return cached, nil
	} else if err != nil {
		log.Printf("预警详情缓存读取失败，继续查询数据库，key=%s err=%v", cacheKey, err)
	}

	detail, err := repo.AlertRepository.FindDetailByID(global.DB, alertID)
	if err != nil {
		return responseModel.AlertDetailResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取预警详情失败，请稍后重试", err)
	}
	if detail == nil || detail.Alert == nil {
		return responseModel.AlertDetailResponse{}, ErrAlertNotFound
	}
	if claims != nil && strings.EqualFold(strings.TrimSpace(claims.RoleCode), "USER") {
		if detail.Task != nil {
			if !strings.EqualFold(strings.TrimSpace(detail.Task.CreatedBy), strings.TrimSpace(claims.Username)) {
				return responseModel.AlertDetailResponse{}, ErrAlertNotFound
			}
		} else if !canUserAccessFlowMonitorAlert(detail.Alert.MonitorSessionID, strings.TrimSpace(claims.Username)) {
			return responseModel.AlertDetailResponse{}, ErrAlertNotFound
		}
	}

	resp := responseModel.AlertDetailResponse{
		AlertID:          detail.Alert.ID,
		AlertLevel:       detail.Alert.AlertLevel,
		AlertTitle:       detail.Alert.AlertTitle,
		AlertContent:     detail.Alert.AlertContent,
		Channel:          detail.Alert.Channel,
		SendStatus:       detail.Alert.SendStatus,
		SendTime:         formatTimePtr(detail.Alert.SendTime),
		CreatedAt:        detail.Alert.CreatedAt.Format("2006-01-02 15:04:05"),
		SourceType:       resolveAlertSourceType(detail.Alert),
		SourceLabel:      resolveAlertSourceLabel(detail.Alert, detail.Task),
		MonitorSessionID: strings.TrimSpace(detail.Alert.MonitorSessionID),
	}

	if detail.Task != nil {
		resp.Task = &responseModel.AlertTask{
			TaskID:     detail.Task.ID,
			TaskNo:     detail.Task.TaskNo,
			TargetIP:   detail.Task.TargetIP,
			TaskStatus: detail.Task.TaskStatus,
		}
	}

	if detail.Score != nil {
		resp.Score = &responseModel.AlertScore{
			BaseScore:           detail.Score.BaseScore,
			ReputationScore:     detail.Score.ReputationScore,
			AttackSurfaceScore:  detail.Score.AttackSurfaceScore,
			BehaviorScore:       detail.Score.BehaviorScore,
			RuleAdjustmentValue: detail.Score.RuleAdjustmentValue,
			ScoreValue:          detail.Score.ScoreValue,
			RiskLevel:           detail.Score.RiskLevel,
			ScoreReason:         detail.Score.ScoreReason,
			RuleAdjustment:      detail.Score.RuleAdjustment,
			AlgorithmVersion:    detail.Score.AlgorithmVersion,
			WeightProfile:       decodeWeightProfile(detail.Score.WeightProfile),
		}
	}

	if err := utils.CacheSetJSON(cacheKey, resp, utils.DetailQueryCacheTTL()); err != nil {
		log.Printf("预警详情缓存写入失败，已返回实时数据，key=%s err=%v", cacheKey, err)
	}

	return resp, nil
}

// resolveAlertSourceType 用于解析预警来源Type。
func resolveAlertSourceType(alert *securityModel.AlertRecord) string {
	if alert == nil {
		return ""
	}
	if value := strings.TrimSpace(alert.SourceType); value != "" {
		return value
	}
	if alert.TaskID == nil || *alert.TaskID == 0 {
		return "FLOW_MONITOR"
	}
	return "TASK"
}

// resolveAlertSourceLabel 用于解析预警来源Label。
func resolveAlertSourceLabel(alert *securityModel.AlertRecord, task *securityModel.IPTask) string {
	if alert == nil {
		return ""
	}
	if value := strings.TrimSpace(alert.SourceLabel); value != "" {
		return value
	}
	if task != nil && strings.TrimSpace(task.TaskNo) != "" {
		return strings.TrimSpace(task.TaskNo)
	}
	return strings.TrimSpace(alert.IP)
}

// canUserAccessFlowMonitorAlert 用于判断是否允许用户Access流量监控预警。
func canUserAccessFlowMonitorAlert(sessionID string, username string) bool {
	sessionID = strings.TrimSpace(sessionID)
	username = strings.TrimSpace(username)
	if sessionID == "" || username == "" {
		return false
	}
	state, ok := flowMonitorSessions.get(sessionID)
	if !ok || state == nil {
		return false
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	return strings.EqualFold(strings.TrimSpace(state.OwnerUsername), username)
}
