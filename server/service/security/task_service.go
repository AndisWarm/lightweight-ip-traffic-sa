package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"lightweight-ip-traffic-sa/server/config"
	"lightweight-ip-traffic-sa/server/global"
	securityModel "lightweight-ip-traffic-sa/server/model/security"
	requestModel "lightweight-ip-traffic-sa/server/model/security/request"
	responseModel "lightweight-ip-traffic-sa/server/model/security/response"
	"lightweight-ip-traffic-sa/server/repository"
	"lightweight-ip-traffic-sa/server/utils"

	"gorm.io/gorm"
)

// TaskService 用于编排安全态势模块的业务流程。
type TaskService struct{}

var taskNoSequence atomic.Uint64

type securityTaskExecutionContext struct {
	TaskID   uint64
	TaskNo   string
	TargetIP string
	Actor    string
}

var taskPipelineAsyncExecutor = func(task securityTaskExecutionContext) {
	(&TaskService{}).runTaskPipeline(task)
}

var (
	ErrTaskTargetIPRequired    = NewServiceError(ServiceErrorCategoryInvalidArgument, "目标 IP 不能为空")
	ErrTaskTargetIPInvalid     = NewServiceError(ServiceErrorCategoryInvalidArgument, "目标 IP 或域名格式不合法")
	ErrTaskDomainResolveFailed = NewServiceError(ServiceErrorCategoryInvalidArgument, "域名解析失败，无法发起检测任务")
	ErrTaskNotFound            = NewServiceError(ServiceErrorCategoryNotFound, "任务不存在或已删除")
)

// CreateTask 用于创建任务并触发后续流程。
func (s *TaskService) CreateTask(req requestModel.CreateTaskRequest) (responseModel.TaskCreateResponse, error) {
	return s.CreateTaskWithActor(req, "")
}

// CreateTaskWithActor 用于创建任务并触发后续流程。
func (s *TaskService) CreateTaskWithActor(req requestModel.CreateTaskRequest, actor string) (responseModel.TaskCreateResponse, error) {
	resolvedTarget, err := validateCreateTaskRequest(req)
	if err != nil {
		return responseModel.TaskCreateResponse{}, err
	}

	now := time.Now()
	createdBy := actor
	if createdBy == "" {
		createdBy = req.RequestedBy
	}
	if createdBy == "" {
		createdBy = global.AppConfig.Security.DefaultCreatedBy
	}

	task := securityModel.IPTask{
		TaskNo:       buildTaskNo(now),
		InputType:    resolvedTarget.InputType,
		InputValue:   resolvedTarget.InputValue,
		TargetIP:     resolvedTarget.TargetIP,
		CreatedBy:    createdBy,
		TaskStatus:   "PENDING",
		ErrorMessage: "",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	repo := repository.RepositoryGroupApp.SecurityRepositoryGroup

	if err := repo.TaskRepository.Create(global.DB, &task); err != nil {
		return responseModel.TaskCreateResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "创建检测任务失败，请稍后重试", err)
	}

	startedAt := time.Now()
	if err := repo.TaskRepository.UpdateStatus(global.DB, task.ID, map[string]interface{}{
		"task_status":   "RUNNING",
		"started_at":    &startedAt,
		"updated_at":    startedAt,
		"error_message": "",
	}); err != nil {
		return responseModel.TaskCreateResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "创建检测任务失败，请稍后重试", err)
	}

	task.TaskStatus = "RUNNING"
	task.StartedAt = &startedAt
	task.UpdatedAt = startedAt

	_ = utils.CacheDelete(utils.SecurityDashboardSummaryCacheKey)

	go taskPipelineAsyncExecutor(securityTaskExecutionContext{
		TaskID:   task.ID,
		TaskNo:   task.TaskNo,
		TargetIP: task.TargetIP,
		Actor:    createdBy,
	})

	return responseModel.TaskCreateResponse{
		TaskID:       task.ID,
		TaskNo:       task.TaskNo,
		TargetIP:     task.TargetIP,
		TaskStatus:   "RUNNING",
		ScoreValue:   0,
		RiskLevel:    "",
		AlertCreated: false,
	}, nil
}

func (s *TaskService) runTaskPipeline(task securityTaskExecutionContext) {
	repo := repository.RepositoryGroupApp.SecurityRepositoryGroup
	runtimeConfig := loadRuntimeSecurityConfig()
	pipeline := NewTaskPipelineBuilder(runtimeConfig)
	pipelineResult, err := pipeline.Build(task.TaskID, task.TaskNo, task.TargetIP, runtimeConfig)
	if err != nil {
		if failErr := s.markTaskFailed(task.TaskID, err.Error()); failErr != nil {
			log.Printf("async task pipeline failed and status update failed, taskID=%d err=%v markErr=%v", task.TaskID, err, failErr)
			return
		}
		log.Printf("async task pipeline failed, taskID=%d err=%v", task.TaskID, wrapTaskPipelineError(err))
		_ = utils.CacheDelete(utils.SecurityDashboardSummaryCacheKey)
		return
	}

	err = global.DB.Transaction(func(tx *gorm.DB) error {
		if err := repo.BaseInfoRepository.Create(tx, &pipelineResult.BaseInfo); err != nil {
			return err
		}
		if err := repo.FeatureRepository.Create(tx, &pipelineResult.FeatureSnapshot); err != nil {
			return err
		}
		if err := repo.ScoreRepository.Create(tx, &pipelineResult.RiskScore); err != nil {
			return err
		}

		if pipelineResult.AlertRecord != nil {
			scoreID := pipelineResult.RiskScore.ID
			pipelineResult.AlertRecord.ScoreID = &scoreID
			if err := repo.AlertRepository.Create(tx, pipelineResult.AlertRecord); err != nil {
				return err
			}
		}
		if pipelineResult.FlowCollection != nil {
			if err := repo.FlowCollectionRepository.Create(tx, pipelineResult.FlowCollection); err != nil {
				return err
			}
		}
		if len(pipelineResult.FlowWindows) > 0 && pipelineResult.FlowCollection != nil {
			for index := range pipelineResult.FlowWindows {
				pipelineResult.FlowWindows[index].CollectionID = pipelineResult.FlowCollection.ID
			}
			if err := repo.FlowWindowAggregateRepository.CreateInBatches(tx, pipelineResult.FlowWindows, 200); err != nil {
				return err
			}
		}
		if pipelineResult.FlowFeature != nil && pipelineResult.FlowCollection != nil {
			pipelineResult.FlowFeature.CollectionID = pipelineResult.FlowCollection.ID
			if err := repo.FlowFeatureSnapshotRepository.Create(tx, pipelineResult.FlowFeature); err != nil {
				return err
			}
		}

		finishedAt := time.Now()
		return repo.TaskRepository.UpdateStatus(tx, task.TaskID, map[string]interface{}{
			"task_status":   "SUCCESS",
			"finished_at":   &finishedAt,
			"updated_at":    finishedAt,
			"error_message": "",
		})
	})
	if err != nil {
		if failErr := s.markTaskFailed(task.TaskID, err.Error()); failErr != nil {
			log.Printf("async task persistence failed and status update failed, taskID=%d err=%v markErr=%v", task.TaskID, err, failErr)
			return
		}
		log.Printf("async task persistence failed, taskID=%d err=%v", task.TaskID, err)
		_ = utils.CacheDelete(utils.SecurityDashboardSummaryCacheKey)
		return
	}

	_ = utils.CacheDelete(utils.SecurityDashboardSummaryCacheKey)

	score := pipelineResult.RiskScore
	recordSecurityAuditLog(AuditLogEntry{
		Category:    "TASK",
		Action:      "CREATE_TASK",
		Actor:       task.Actor,
		TargetType:  "task",
		TargetID:    fmt.Sprintf("%d", task.TaskID),
		TargetLabel: task.TargetIP,
		Status:      "SUCCESS",
		Summary:     fmt.Sprintf("任务创建成功，风险等级=%s，最终评分=%.2f", score.RiskLevel, score.ScoreValue),
	})
}

// ListTasks 用于查询任务列表并组装响应。
func (s *TaskService) ListTasks(query requestModel.TaskListQuery) (responseModel.PagedTaskResponse, error) {
	query.Normalize()
	query.Page = utils.NormalizePage(query.Page)
	query.PageSize = utils.NormalizePageSize(query.PageSize)

	rows, total, err := repository.RepositoryGroupApp.SecurityRepositoryGroup.TaskRepository.List(global.DB, query)
	if err != nil {
		return responseModel.PagedTaskResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取任务列表失败，请稍后重试", err)
	}

	items := make([]responseModel.TaskListItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, responseModel.TaskListItem{
			TaskID:     row.ID,
			TaskNo:     row.TaskNo,
			TargetIP:   row.TargetIP,
			TaskStatus: row.TaskStatus,
			ScoreValue: row.ScoreValue,
			RiskLevel:  row.RiskLevel,
			CreatedAt:  row.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}

	return responseModel.PagedTaskResponse{
		Page:      query.Page,
		PageSize:  query.PageSize,
		Total:     total,
		SortBy:    query.SortBy,
		SortOrder: query.SortOrder,
		Items:     items,
	}, nil
}

// GetTaskDetail 用于查询任务详情并组装响应。
func (s *TaskService) GetTaskDetail(taskID uint64) (responseModel.TaskDetailResponse, error) {
	repo := repository.RepositoryGroupApp.SecurityRepositoryGroup
	cacheKey := utils.BuildTaskDetailCacheKey(taskID)

	var cached responseModel.TaskDetailResponse
	if hit, err := utils.CacheGetJSON(cacheKey, &cached); err == nil && hit {
		if isTaskDetailCacheUsable(cached) {
			return cached, nil
		}
		_ = utils.CacheDelete(cacheKey)
	} else if err != nil {
		log.Printf("任务详情缓存读取失败，继续查询数据库，key=%s err=%v", cacheKey, err)
	}

	detail, err := repo.TaskRepository.FindDetailByID(global.DB, taskID)
	if err != nil {
		return responseModel.TaskDetailResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取任务详情失败，请稍后重试", err)
	}
	if detail == nil || detail.Task == nil {
		return responseModel.TaskDetailResponse{}, ErrTaskNotFound
	}

	resp := responseModel.TaskDetailResponse{
		TaskID:       detail.Task.ID,
		TaskNo:       detail.Task.TaskNo,
		InputType:    detail.Task.InputType,
		InputValue:   detail.Task.InputValue,
		TargetIP:     detail.Task.TargetIP,
		TaskStatus:   detail.Task.TaskStatus,
		ScoreValue:   0,
		RiskLevel:    "",
		AlertCreated: false,
		CreatedBy:    detail.Task.CreatedBy,
		StartedAt:    formatTimePtr(detail.Task.StartedAt),
		FinishedAt:   formatTimePtr(detail.Task.FinishedAt),
		CreatedAt:    detail.Task.CreatedAt.Format("2006-01-02 15:04:05"),
		ErrorMessage: detail.Task.ErrorMessage,
	}

	var baseSourceChain []string
	normalizedFeature := NormalizedFeatureSet{}
	if detail.BaseInfo != nil {
		rawPayload := decodeJSONMap(detail.BaseInfo.RawPayload)
		enrichTaskBaseInfoGeoPayload(rawPayload, detail.Task.TargetIP, global.AppConfig.Security)
		baseSourceChain = resolveTaskBaseInfoSourceChain(rawPayload)
		geoLite2Payload := extractMap(rawPayload, "geoLite2")
		resp.BaseInfo = &responseModel.TaskBaseInfo{
			Country:        detail.BaseInfo.Country,
			Region:         detail.BaseInfo.Region,
			City:           detail.BaseInfo.City,
			ISP:            detail.BaseInfo.ISP,
			WhoisOrg:       detail.BaseInfo.WhoisOrg,
			WhoisContact:   detail.BaseInfo.WhoisContact,
			Latitude:       extractFloat64(geoLite2Payload, "latitude"),
			Longitude:      extractFloat64(geoLite2Payload, "longitude"),
			TimeZone:       strings.TrimSpace(extractString(geoLite2Payload, "timeZone")),
			AccuracyRadius: extractInt(geoLite2Payload, "accuracyRadius"),
			SourceName:     resolveTaskBaseInfoSourceName(rawPayload, baseSourceChain),
			SourceChain:    baseSourceChain,
			SourceSummary:  resolveTaskBaseInfoSourceSummary(rawPayload, baseSourceChain),
			RawPayload:     rawPayload,
		}
	}

	if detail.Feature != nil {
		normalizedFeature = decodeNormalizedFeatureSet(detail.Feature.NormalizedFeatures)
		defaultSourceChains := sanitizeTaskDetailSourceChains(normalizedFeature.DataSourceChains)
		defaultEvidenceItems, flowPrototypeItems := splitTaskDetailEvidenceItems(normalizedFeature.EvidenceItems)
		if len(normalizedFeature.FlowPrototypeItems) > 0 {
			flowPrototypeItems = normalizedFeature.FlowPrototypeItems
		}
		flowMode, flowStatus, flowSummary := sanitizeTaskDetailFlowPresentation(normalizedFeature.FlowMode, normalizedFeature.FlowStatus, normalizedFeature.FlowSummary)
		sourceSummary := buildCanonicalSourceSummary(baseSourceChain, defaultSourceChains, flowMode, flowStatus, normalizedFeature.FlowSourceChain)
		if strings.TrimSpace(normalizedFeature.SourceSummary) != "" {
			sourceSummary.Summary = normalizedFeature.SourceSummary
		}
		if len(normalizedFeature.SourceGroups) > 0 {
			sourceSummary.Groups = normalizeCanonicalSourceGroups(normalizedFeature.SourceGroups)
			sourceSummary.GroupMap = buildCanonicalSourceChainMap(sourceSummary.Groups)
			if strings.TrimSpace(sourceSummary.Summary) == "" {
				sourceSummary.Summary = buildSourceSummaryFromGroups(sourceSummary.Groups)
			}
		}
		if len(normalizedFeature.FlowSourceChain) > 0 {
			sourceSummary.FlowSourceChain = dedupeStrings(normalizedFeature.FlowSourceChain)
		}
		if len(sourceSummary.FlowSourceChain) == 0 {
			sourceSummary.FlowSourceChain = buildEvidenceSourceChain(flowPrototypeItems)
		}
		defaultSourceChains = mergeTaskDetailSourceChains(defaultSourceChains, sourceSummary.GroupMap)
		defaultDataSources := buildTaskDetailCompatDataSources(normalizedFeature.DataSources, sourceSummary.Groups)
		compatSourceName := buildTaskDetailCompatSourceName(normalizedFeature.SourceName, defaultDataSources)
		evidenceGroups := toResponseEvidenceGroups(defaultEvidenceItems)
		scoreFactors := decorateScoreFactorsWithDisplayBasis(
			normalizedFeature.ScoreFactors,
			sourceSummary,
			flowMode,
			flowStatus,
			flowSummary,
		)
		resp.Features = &responseModel.TaskFeature{
			ReputationScore:    detail.Feature.ReputationScore,
			OpenPortCount:      detail.Feature.OpenPortCount,
			HighRiskPortCount:  detail.Feature.HighRiskPortCount,
			GeoRiskFlag:        detail.Feature.GeoRiskFlag,
			FlowMode:           flowMode,
			FlowStatus:         flowStatus,
			FlowSummary:        flowSummary,
			FlowCapabilityText: buildTaskDetailFlowCapabilityText(flowMode, flowStatus, sourceSummary.FlowSourceChain),
			FlowBoundaryText:   buildTaskDetailFlowBoundaryText(flowMode, flowStatus),
			FlowSourceSummary:  buildTaskDetailFlowSourceSummary(sourceSummary.FlowSourceChain),
			FeatureDigest:      detail.Feature.FeatureDigest,
			NormalizedFeatures: decodeJSONMap(detail.Feature.NormalizedFeatures),
			SourceName:         compatSourceName,
			DataSources:        defaultDataSources,
			DataSourceChains:   defaultSourceChains,
			SourceSummary:      sourceSummary.Summary,
			SourceChainGroups:  toResponseSourceChainGroups(sourceSummary.Groups),
			FlowSourceChain:    sourceSummary.FlowSourceChain,
			EvidenceItems:      toResponseEvidenceItems(defaultEvidenceItems),
			EvidenceGroups:     evidenceGroups,
			FlowPrototypeItems: toResponseEvidenceItems(flowPrototypeItems),
			ScoreFactors:       toResponseScoreFactors(scoreFactors),
		}
	}
	resp.Flow = buildTaskFlowDetail(detail.FlowCollection, detail.FlowWindows, detail.FlowFeature, normalizedFeature)
	if resp.Flow != nil {
		resp.Flow.CollectionHistory = s.buildTaskFlowHistory(taskID)
	}

	if detail.Score != nil {
		resp.ScoreValue = detail.Score.ScoreValue
		resp.RiskLevel = detail.Score.RiskLevel
		resp.AlertCreated = detail.Score.IsAlertTriggered
		resp.Score = &responseModel.TaskScore{
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
			IsAlertTriggered:    detail.Score.IsAlertTriggered,
		}
	}

	if detail.Alert != nil {
		resp.AlertCreated = true
		resp.Alert = &responseModel.TaskAlertSummary{
			AlertID:      detail.Alert.ID,
			AlertLevel:   detail.Alert.AlertLevel,
			AlertTitle:   detail.Alert.AlertTitle,
			AlertContent: detail.Alert.AlertContent,
			Channel:      detail.Alert.Channel,
			SendStatus:   detail.Alert.SendStatus,
			SendTime:     formatTimePtr(detail.Alert.SendTime),
			CreatedAt:    detail.Alert.CreatedAt.Format("2006-01-02 15:04:05"),
		}
	}

	if err := utils.CacheSetJSON(cacheKey, resp, utils.DetailQueryCacheTTL()); err != nil {
		log.Printf("任务详情缓存写入失败，已返回实时数据，key=%s err=%v", cacheKey, err)
	}

	return resp, nil
}

// DeleteTask 用于删除任务及关联数据。
func (s *TaskService) DeleteTask(taskID uint64) error {
	repo := repository.RepositoryGroupApp.SecurityRepositoryGroup

	task, err := repo.TaskRepository.FindByID(global.DB, taskID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrTaskNotFound
		}
		return WrapServiceError(ServiceErrorCategoryInternal, "删除检测任务失败，请稍后重试", err)
	}

	var alertIDs []uint64
	if alert, err := repo.AlertRepository.FindByTaskID(global.DB, taskID); err == nil && alert != nil {
		alertIDs = append(alertIDs, alert.ID)
	}

	err = global.DB.Transaction(func(tx *gorm.DB) error {
		if err := repo.AlertRepository.DeleteByTaskID(tx, taskID); err != nil {
			return err
		}
		if err := repo.FlowFeatureSnapshotRepository.DeleteByTaskID(tx, taskID); err != nil {
			return err
		}
		if err := repo.FlowWindowAggregateRepository.DeleteByTaskID(tx, taskID); err != nil {
			return err
		}
		if err := repo.FlowCollectionRepository.DeleteByTaskID(tx, taskID); err != nil {
			return err
		}
		if err := repo.ScoreRepository.DeleteByTaskID(tx, taskID); err != nil {
			return err
		}
		if err := repo.FeatureRepository.DeleteByTaskID(tx, taskID); err != nil {
			return err
		}
		if err := repo.BaseInfoRepository.DeleteByTaskID(tx, taskID); err != nil {
			return err
		}
		if err := repo.TaskRepository.DeleteByID(tx, taskID); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return WrapServiceError(ServiceErrorCategoryInternal, "删除检测任务失败，请稍后重试", err)
	}

	cacheKeys := []string{utils.BuildTaskDetailCacheKey(taskID), utils.SecurityDashboardSummaryCacheKey}
	for _, alertID := range alertIDs {
		cacheKeys = append(cacheKeys, utils.BuildAlertDetailCacheKey(alertID))
	}
	_ = utils.CacheDelete(cacheKeys...)
	log.Printf("检测任务已删除，taskID=%d taskNo=%s targetIP=%s", taskID, task.TaskNo, task.TargetIP)
	recordSecurityAuditLog(AuditLogEntry{
		Category:    "TASK",
		Action:      "DELETE_TASK",
		Actor:       task.CreatedBy,
		TargetType:  "task",
		TargetID:    fmt.Sprintf("%d", taskID),
		TargetLabel: task.TargetIP,
		Status:      "SUCCESS",
		Summary:     "任务及其关联流量、评分、预警记录已删除",
	})
	return nil
}

// markTaskFailed 用于标记任务执行状态。
func (s *TaskService) markTaskFailed(taskID uint64, errorMessage string) error {
	finishedAt := time.Now()
	return repository.RepositoryGroupApp.SecurityRepositoryGroup.TaskRepository.UpdateStatus(global.DB, taskID, map[string]interface{}{
		"task_status":   "FAILED",
		"finished_at":   &finishedAt,
		"updated_at":    finishedAt,
		"error_message": errorMessage,
	})
}

// buildTaskNo 用于构建任务No。
func buildTaskNo(now time.Time) string {
	return fmt.Sprintf("TASK-%s-%09d-%d-%d", now.Format("20060102150405"), now.Nanosecond(), os.Getpid(), taskNoSequence.Add(1))
}

// formatTimePtr 用于格式化TimePtr展示文本。
func formatTimePtr(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.Format("2006-01-02 15:04:05")
}

// validateCreateTaskRequest 用于校验输入参数和业务约束。
func validateCreateTaskRequest(req requestModel.CreateTaskRequest) (requestModel.ResolvedTaskTarget, error) {
	target := strings.TrimSpace(req.TargetIP)
	if target == "" {
		return requestModel.ResolvedTaskTarget{}, ErrTaskTargetIPRequired
	}
	if parsed := net.ParseIP(target); parsed != nil {
		return requestModel.ResolvedTaskTarget{
			InputType:  "IP",
			InputValue: target,
			TargetIP:   parsed.String(),
		}, nil
	}
	if !isValidDomainName(target) {
		return requestModel.ResolvedTaskTarget{}, ErrTaskTargetIPInvalid
	}
	resolvedIP, err := resolveDomainToIP(target)
	if err != nil {
		return requestModel.ResolvedTaskTarget{}, ErrTaskDomainResolveFailed
	}
	return requestModel.ResolvedTaskTarget{
		InputType:  "DOMAIN",
		InputValue: target,
		TargetIP:   resolvedIP,
	}, nil
}

// wrapTaskPipelineError 用于执行wrap任务PipelineError流程。
func wrapTaskPipelineError(err error) error {
	if errors.Is(err, ErrExternalProviderUnavailable) {
		return WrapServiceError(ServiceErrorCategoryExternalDependency, "任务特征采集依赖暂时不可用，请稍后重试", err)
	}
	return WrapServiceError(ServiceErrorCategoryInternal, "创建检测任务失败，请稍后重试", err)
}

// isValidDomainName 用于判断输入是否满足指定条件。
func isValidDomainName(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > 253 || strings.HasPrefix(trimmed, ".") || strings.HasSuffix(trimmed, ".") {
		return false
	}
	labels := strings.Split(trimmed, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		for index, ch := range label {
			isAlphaNum := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
			if ch == '-' {
				if index == 0 || index == len(label)-1 {
					return false
				}
				continue
			}
			if !isAlphaNum {
				return false
			}
		}
	}
	return true
}

// resolveDomainToIP 用于解析DomainToIP。
func resolveDomainToIP(domain string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil || len(addresses) == 0 {
		return "", fmt.Errorf("resolve domain failed: %w", err)
	}
	for _, item := range addresses {
		if ip4 := item.IP.To4(); ip4 != nil {
			return ip4.String(), nil
		}
	}
	return addresses[0].IP.String(), nil
}

// decodeJSONMap 用于反序列化JSONMap。
func decodeJSONMap(raw string) map[string]any {
	if strings.TrimSpace(raw) == "" {
		return map[string]any{}
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return map[string]any{"_raw": raw}
	}
	return payload
}

// decodeJSONArrayOfObjects 用于反序列化JSONArrayOfObjects。
func decodeJSONArrayOfObjects(raw string) []map[string]any {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var payload []map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return []map[string]any{{"_raw": raw}}
	}
	if len(payload) == 0 {
		return nil
	}
	return payload
}

// decodeStringArray 用于反序列化StringArray。
func decodeStringArray(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var payload []string
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil
	}
	if len(payload) == 0 {
		return nil
	}
	return payload
}

// decodeWeightProfile 用于反序列化WeightProfile。
func decodeWeightProfile(raw string) map[string]float64 {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var payload map[string]float64
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil
	}
	if len(payload) == 0 {
		return nil
	}
	return payload
}

// decodeNormalizedFeatureSet 用于反序列化Normalized特征Set。
func decodeNormalizedFeatureSet(raw string) NormalizedFeatureSet {
	if strings.TrimSpace(raw) == "" {
		return NormalizedFeatureSet{}
	}
	var payload NormalizedFeatureSet
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return NormalizedFeatureSet{}
	}
	return payload
}

// extractString 用于提取请求、令牌或流量中的关键信息。
func extractString(payload map[string]any, key string) string {
	value, ok := payload[key]
	if !ok {
		return ""
	}
	text, _ := value.(string)
	return text
}

// extractStringSlice 用于提取请求、令牌或流量中的关键信息。
func extractStringSlice(payload map[string]any, key string) []string {
	value, ok := payload[key]
	if !ok {
		return nil
	}
	bytes, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var result []string
	if err := json.Unmarshal(bytes, &result); err != nil {
		return nil
	}
	return result
}

// extractFloat64 用于提取请求、令牌或流量中的关键信息。
func extractFloat64(payload map[string]any, key string) float64 {
	if len(payload) == 0 {
		return 0
	}
	value, ok := payload[key]
	if !ok {
		return 0
	}
	switch typed := value.(type) {
	case float64:
		return typed
	case float32:
		return float64(typed)
	case int:
		return float64(typed)
	case int32:
		return float64(typed)
	case int64:
		return float64(typed)
	case uint:
		return float64(typed)
	case uint32:
		return float64(typed)
	case uint64:
		return float64(typed)
	default:
		return 0
	}
}

// extractInt 用于提取请求、令牌或流量中的关键信息。
func extractInt(payload map[string]any, key string) int {
	return int(extractFloat64(payload, key))
}

// enrichTaskBaseInfoGeoPayload 用于执行enrich任务基础信息地理载荷流程。
func enrichTaskBaseInfoGeoPayload(rawPayload map[string]any, targetIP string, cfg config.SecurityConfig) {
	if len(rawPayload) == 0 || !cfg.Source.GeoLite2.Enabled {
		return
	}
	geoLite2Payload := extractMap(rawPayload, "geoLite2")
	if hasTaskBaseInfoGeoPayload(geoLite2Payload) {
		return
	}
	lookup, err := queryGeoLite2(targetIP, cfg.Source.GeoLite2)
	if err != nil {
		return
	}
	if geoLite2Payload == nil {
		geoLite2Payload = map[string]any{}
	}
	if _, ok := geoLite2Payload["country"]; !ok && strings.TrimSpace(lookup.Country) != "" {
		geoLite2Payload["country"] = lookup.Country
	}
	if _, ok := geoLite2Payload["region"]; !ok && strings.TrimSpace(lookup.Region) != "" {
		geoLite2Payload["region"] = lookup.Region
	}
	if _, ok := geoLite2Payload["city"]; !ok && strings.TrimSpace(lookup.City) != "" {
		geoLite2Payload["city"] = lookup.City
	}
	if _, ok := geoLite2Payload["isp"]; !ok && strings.TrimSpace(lookup.ISP) != "" {
		geoLite2Payload["isp"] = lookup.ISP
	}
	if _, ok := geoLite2Payload["asn"]; !ok && lookup.ASN > 0 {
		geoLite2Payload["asn"] = lookup.ASN
	}
	if _, ok := geoLite2Payload["latitude"]; !ok && lookup.Latitude != 0 {
		geoLite2Payload["latitude"] = lookup.Latitude
	}
	if _, ok := geoLite2Payload["longitude"]; !ok && lookup.Longitude != 0 {
		geoLite2Payload["longitude"] = lookup.Longitude
	}
	if _, ok := geoLite2Payload["timeZone"]; !ok && strings.TrimSpace(lookup.TimeZone) != "" {
		geoLite2Payload["timeZone"] = lookup.TimeZone
	}
	if _, ok := geoLite2Payload["accuracyRadius"]; !ok && lookup.AccuracyRadius > 0 {
		geoLite2Payload["accuracyRadius"] = lookup.AccuracyRadius
	}
	rawPayload["geoLite2"] = geoLite2Payload
}

// hasTaskBaseInfoGeoPayload 用于判断目标是否具备指定数据或能力。
func hasTaskBaseInfoGeoPayload(payload map[string]any) bool {
	if len(payload) == 0 {
		return false
	}
	if extractFloat64(payload, "latitude") != 0 || extractFloat64(payload, "longitude") != 0 {
		return true
	}
	if strings.TrimSpace(extractString(payload, "timeZone")) != "" {
		return true
	}
	return extractInt(payload, "accuracyRadius") > 0
}

// isTaskDetailCacheUsable 用于判断输入是否满足指定条件。
func isTaskDetailCacheUsable(detail responseModel.TaskDetailResponse) bool {
	if detail.TaskID == 0 || detail.BaseInfo == nil {
		return false
	}
	if strings.TrimSpace(detail.BaseInfo.Country) == "" &&
		strings.TrimSpace(detail.BaseInfo.Region) == "" &&
		strings.TrimSpace(detail.BaseInfo.City) == "" &&
		strings.TrimSpace(detail.BaseInfo.ISP) == "" &&
		strings.TrimSpace(detail.BaseInfo.WhoisOrg) == "" &&
		strings.TrimSpace(detail.BaseInfo.WhoisContact) == "" {
		return false
	}
	return true
}

// resolveTaskBaseInfoSourceChain 用于解析任务基础信息来源链路。
func resolveTaskBaseInfoSourceChain(rawPayload map[string]any) []string {
	if chain := dedupeStrings(extractStringSlice(rawPayload, "sourceChain")); len(chain) > 0 {
		return chain
	}
	if sourceName := strings.TrimSpace(extractString(rawPayload, "sourceName")); sourceName != "" {
		return []string{sourceName}
	}
	if source := strings.TrimSpace(extractString(rawPayload, "source")); source != "" {
		return []string{source}
	}
	if _, ok := rawPayload["rdap"]; ok {
		return []string{"RDAP"}
	}
	if _, ok := rawPayload["geoLite2"]; ok {
		return []string{"GeoLite2"}
	}
	return nil
}

// resolveTaskBaseInfoSourceName 用于解析任务基础信息来源名称。
func resolveTaskBaseInfoSourceName(rawPayload map[string]any, sourceChain []string) string {
	if sourceName := strings.TrimSpace(extractString(rawPayload, "sourceName")); sourceName != "" {
		return sourceName
	}
	if len(sourceChain) == 1 {
		return sourceChain[0]
	}
	if len(sourceChain) > 1 {
		return strings.Join(sourceChain, "+")
	}
	if source := strings.TrimSpace(extractString(rawPayload, "source")); source != "" {
		return source
	}
	return ""
}

// resolveTaskBaseInfoSourceSummary 用于解析任务基础信息来源摘要。
func resolveTaskBaseInfoSourceSummary(rawPayload map[string]any, sourceChain []string) string {
	if len(sourceChain) > 0 {
		return formatSourceChain(sourceChain)
	}
	if source := strings.TrimSpace(extractString(rawPayload, "source")); source != "" {
		return source
	}
	return "-"
}

// sanitizeTaskDetailSourceChains 用于清理任务Detail来源Chains展示数据。
func sanitizeTaskDetailSourceChains(sourceChains map[string][]string) map[string][]string {
	if len(sourceChains) == 0 {
		return nil
	}
	result := make(map[string][]string, len(sourceChains))
	for key, items := range sourceChains {
		switch key {
		case "flow":
			continue
		case "attack_surface":
			if chain := sanitizeAttackSurfaceChain(items); len(chain) > 0 {
				result[key] = chain
			}
		default:
			if chain := dedupeStrings(items); len(chain) > 0 {
				result[key] = chain
			}
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// sanitizeTaskDetailDataSources 用于清理任务DetailDataSources展示数据。
func sanitizeTaskDetailDataSources(sources []string) []string {
	items := sanitizeAttackSurfaceDataSources(sources)
	if len(items) == 0 {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		categoryKey, _ := classifyEvidenceCategory(item)
		if categoryKey == "flow" {
			continue
		}
		result = append(result, item)
	}
	return dedupeStrings(result)
}

// buildTaskDetailCompatDataSources 用于构建任务DetailCompatDataSources。
func buildTaskDetailCompatDataSources(legacySources []string, groups []canonicalSourceGroup) []string {
	if items := sanitizeTaskDetailDataSources(legacySources); len(items) > 0 {
		return items
	}
	result := make([]string, 0, len(groups)*2)
	for _, group := range groups {
		result = append(result, group.Chain...)
	}
	if items := sanitizeTaskDetailDataSources(result); len(items) > 0 {
		return items
	}
	return nil
}

// buildTaskDetailCompatSourceName 用于构建任务DetailCompat来源名称。
func buildTaskDetailCompatSourceName(legacySourceName string, dataSources []string) string {
	if strings.TrimSpace(legacySourceName) != "" {
		return strings.TrimSpace(legacySourceName)
	}
	return joinOrFallback(dataSources, "")
}

// mergeTaskDetailSourceChains 用于合并任务Detail来源Chains。
func mergeTaskDetailSourceChains(
	legacy map[string][]string,
	groupMap map[string][]string,
) map[string][]string {
	if len(groupMap) == 0 {
		return legacy
	}
	result := make(map[string][]string, len(groupMap)+len(legacy))
	for key, items := range groupMap {
		if chain := dedupeStrings(items); len(chain) > 0 {
			result[key] = chain
		}
	}
	for key, items := range legacy {
		if len(result[key]) > 0 {
			continue
		}
		if chain := dedupeStrings(items); len(chain) > 0 {
			result[key] = chain
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// splitTaskDetailEvidenceItems 用于拆分任务DetailEvidenceItems。
func splitTaskDetailEvidenceItems(items []securityEvidenceItem) ([]securityEvidenceItem, []securityEvidenceItem) {
	if len(items) == 0 {
		return nil, nil
	}
	defaultItems := make([]securityEvidenceItem, 0, len(items))
	flowItems := make([]securityEvidenceItem, 0, len(items))
	for _, item := range items {
		categoryKey, _ := classifyEvidenceCategory(item.Source)
		if categoryKey == "flow" {
			flowItems = append(flowItems, item)
			continue
		}
		defaultItems = append(defaultItems, item)
	}
	return defaultItems, flowItems
}

// sanitizeTaskDetailFlowPresentation 用于清理任务Detail流量Presentation展示数据。
func sanitizeTaskDetailFlowPresentation(mode string, status string, summary string) (string, string, string) {
	if !shouldDisplayFlowPrototype(mode, status) {
		return "", "", ""
	}
	return normalizeFlowBoundaryMode(mode), strings.ToUpper(strings.TrimSpace(status)), strings.TrimSpace(summary)
}

// buildTaskDetailFlowCapabilityText 用于构建任务Detail流量CapabilityText。
func buildTaskDetailFlowCapabilityText(mode string, status string, flowSourceChain []string) string {
	switch mode {
	case "sample":
		return fmt.Sprintf("样本原型已启用（状态：%s）", fallbackString(status, "-"))
	case "offline_pcap":
		if status == FlowStatusParsed || status == FlowStatusNoTargetTraffic {
			return fmt.Sprintf("离线 pcap 真实解析已完成（状态：%s）", fallbackString(status, "-"))
		}
		return fmt.Sprintf("离线 pcap 独立编排入口（状态：%s）", fallbackString(status, "-"))
	case "online_capture":
		if status == FlowStatusParsed || status == FlowStatusNoTargetTraffic {
			return fmt.Sprintf("在线抓包短时采集已完成（状态：%s）", fallbackString(status, "-"))
		}
		return fmt.Sprintf("在线抓包独立编排入口（状态：%s）", fallbackString(status, "-"))
	default:
		if len(flowSourceChain) == 0 {
			return "默认关闭，不纳入默认主链路"
		}
		return fmt.Sprintf("已启用（状态：%s）", fallbackString(status, "-"))
	}
}

// buildTaskDetailFlowBoundaryText 用于构建任务Detail流量BoundaryText。
func buildTaskDetailFlowBoundaryText(mode string, status string) string {
	switch mode {
	case "sample":
		return "只用于流量样本演示，不写入默认来源链、证据链和来源覆盖统计。"
	case "offline_pcap":
		if status == FlowStatusParsed || status == FlowStatusNoTargetTraffic {
			return "当前已支持离线 pcap 真实解析，但更完整的应用层协议和更强解释型特征仍在继续补强。"
		}
		return "仅保留离线 pcap 独立编排入口；即使入口已装载，也不代表真实解析能力已完成。"
	case "online_capture":
		if status == FlowStatusParsed || status == FlowStatusNoTargetTraffic {
			return "当前已支持指定网卡的短时真实抓包，但不做常驻守护进程、多网卡调度或长期连续采集。"
		}
		return "仅保留在线抓包独立编排入口；待授权环境与解析器接入后再评估真实能力。"
	default:
		return "当前默认关闭，不纳入默认主链路。"
	}
}

// buildTaskDetailFlowSourceSummary 用于构建任务Detail流量来源摘要。
func buildTaskDetailFlowSourceSummary(flowSourceChain []string) string {
	if len(flowSourceChain) == 0 {
		return ""
	}
	return formatSourceChain(flowSourceChain)
}

// buildEvidenceSourceChain 用于构建Evidence来源链路。
func buildEvidenceSourceChain(items []securityEvidenceItem) []string {
	if len(items) == 0 {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item.Source) == "" {
			continue
		}
		result = append(result, strings.TrimSpace(item.Source))
	}
	return dedupeStrings(result)
}

// toResponseEvidenceItems 用于转换并生成响应EvidenceItems。
func toResponseEvidenceItems(items []securityEvidenceItem) []responseModel.TaskEvidenceItem {
	if len(items) == 0 {
		return nil
	}
	result := make([]responseModel.TaskEvidenceItem, 0, len(items))
	for _, item := range items {
		categoryKey, categoryLabel := classifyEvidenceCategory(item.Source)
		result = append(result, responseModel.TaskEvidenceItem{
			CategoryKey:   categoryKey,
			CategoryLabel: categoryLabel,
			Source:        item.Source,
			Title:         item.Title,
			Summary:       item.Summary,
			RiskHint:      item.RiskHint,
		})
	}
	return result
}

// toResponseSourceChainGroups 用于转换并生成响应来源链路Groups。
func toResponseSourceChainGroups(items []canonicalSourceGroup) []responseModel.TaskSourceChainGroup {
	if len(items) == 0 {
		return nil
	}
	result := make([]responseModel.TaskSourceChainGroup, 0, len(items))
	for _, item := range items {
		result = append(result, responseModel.TaskSourceChainGroup{
			Key:     item.Key,
			Label:   item.Label,
			Chain:   append([]string(nil), item.Chain...),
			Summary: fallbackString(strings.TrimSpace(item.Summary), formatSourceChain(item.Chain)),
		})
	}
	return result
}

// toResponseScoreFactors 用于转换并生成响应评分Factors。
func toResponseScoreFactors(items []securityScoreFactor) []responseModel.TaskScoreFactor {
	if len(items) == 0 {
		return nil
	}
	result := make([]responseModel.TaskScoreFactor, 0, len(items))
	for _, item := range items {
		result = append(result, responseModel.TaskScoreFactor{
			Key:          item.Key,
			Label:        item.Label,
			RawScore:     item.RawScore,
			Weight:       item.Weight,
			Contribution: item.Contribution,
			Basis:        item.Basis,
			DisplayBasis: item.DisplayBasis,
		})
	}
	return result
}

// toResponseEvidenceGroups 用于转换并生成响应EvidenceGroups。
func toResponseEvidenceGroups(items []securityEvidenceItem) []responseModel.TaskEvidenceGroup {
	if len(items) == 0 {
		return nil
	}

	order := []string{"base_info", "reputation", "attack_surface", "joint_analysis", "other"}
	groupMap := make(map[string]*responseModel.TaskEvidenceGroup, len(order))
	orderIndex := make(map[string]int, len(order))
	for index, key := range order {
		orderIndex[key] = index
	}

	for _, item := range items {
		categoryKey, categoryLabel := classifyEvidenceCategory(item.Source)
		group, ok := groupMap[categoryKey]
		if !ok {
			group = &responseModel.TaskEvidenceGroup{
				Key:   categoryKey,
				Title: categoryLabel,
				Items: make([]responseModel.TaskEvidenceItem, 0, 4),
			}
			groupMap[categoryKey] = group
		}
		group.Items = append(group.Items, responseModel.TaskEvidenceItem{
			CategoryKey:   categoryKey,
			CategoryLabel: categoryLabel,
			Source:        item.Source,
			Title:         item.Title,
			Summary:       item.Summary,
			RiskHint:      item.RiskHint,
		})
	}

	result := make([]responseModel.TaskEvidenceGroup, 0, len(groupMap))
	for _, key := range order {
		if group, ok := groupMap[key]; ok && len(group.Items) > 0 {
			result = append(result, *group)
			delete(groupMap, key)
		}
	}
	if len(groupMap) == 0 {
		return result
	}

	otherKeys := make([]string, 0, len(groupMap))
	for key := range groupMap {
		otherKeys = append(otherKeys, key)
	}
	sort.Slice(otherKeys, func(i, j int) bool {
		left, leftOk := orderIndex[otherKeys[i]]
		right, rightOk := orderIndex[otherKeys[j]]
		if leftOk && rightOk {
			return left < right
		}
		if leftOk {
			return true
		}
		if rightOk {
			return false
		}
		return otherKeys[i] < otherKeys[j]
	})
	for _, key := range otherKeys {
		group := groupMap[key]
		if group != nil && len(group.Items) > 0 {
			result = append(result, *group)
		}
	}
	return result
}

// buildTaskFlowDetail 用于构建任务流量Detail。
func buildTaskFlowDetail(
	collection *securityModel.FlowCollection,
	windows []securityModel.FlowWindowAggregate,
	feature *securityModel.FlowFeatureSnapshot,
	normalized NormalizedFeatureSet,
) *responseModel.TaskFlowDetail {
	if collection == nil && !shouldDisplayFlowPrototype(normalized.FlowMode, normalized.FlowStatus) {
		return nil
	}

	payload := map[string]any{}
	if collection != nil {
		payload = decodeJSONMap(collection.EvidencePayload)
	}
	featurePayload := map[string]any{}
	if feature != nil {
		featurePayload = decodeJSONMap(feature.EvidencePayload)
	}

	sourceChain := extractStringSlice(payload, "sourceChain")
	if len(sourceChain) == 0 {
		sourceChain = extractStringSlice(featurePayload, "sourceChain")
	}
	if len(sourceChain) == 0 {
		sourceChain = dedupeStrings(normalized.FlowSourceChain)
	}

	evidenceItems := extractEvidenceItems(featurePayload)
	if len(evidenceItems) == 0 {
		evidenceItems = extractEvidenceItems(payload)
	}
	if len(evidenceItems) == 0 {
		evidenceItems = append(evidenceItems, normalized.FlowPrototypeItems...)
	}

	collectionMode := normalizeFlowBoundaryMode(normalized.FlowMode)
	collectionStatus := strings.ToUpper(strings.TrimSpace(normalized.FlowStatus))
	sourceName := strings.TrimSpace(extractString(payload, "sourceName"))
	parserName := strings.TrimSpace(normalized.FlowParserName)
	summary := strings.TrimSpace(normalized.FlowSummary)
	windowSeconds := 0
	sampleProfile := ""
	interfaceName := ""
	pcapFilePath := ""
	behaviorRiskScore := normalized.BehaviorRisk
	packetCount := uint64(0)
	byteCount := uint64(0)
	conversationCount := uint32(0)
	startedAt := ""
	finishedAt := ""
	createdAt := ""

	if collection != nil {
		if collectionMode == "" {
			collectionMode = normalizeFlowBoundaryMode(collection.CollectionMode)
		}
		if collectionStatus == "" {
			collectionStatus = strings.ToUpper(strings.TrimSpace(collection.CollectionStatus))
		}
		if sourceName == "" {
			sourceName = strings.TrimSpace(collection.SourceName)
		}
		if parserName == "" {
			parserName = strings.TrimSpace(collection.ParserName)
		}
		if summary == "" {
			summary = strings.TrimSpace(collection.Summary)
		}
		windowSeconds = collection.WindowSeconds
		sampleProfile = strings.TrimSpace(collection.SampleProfile)
		interfaceName = strings.TrimSpace(collection.InterfaceName)
		pcapFilePath = strings.TrimSpace(collection.PcapFilePath)
		packetCount = collection.PacketCount
		byteCount = collection.ByteCount
		conversationCount = collection.ConversationCount
		startedAt = formatTimePtr(valueOrTimePtr(collection.StartedAt))
		finishedAt = formatTimePtr(valueOrTimePtr(collection.FinishedAt))
		createdAt = formatTimePtr(valueOrTimePtr(collection.CreatedAt))
	}
	if feature != nil {
		parserName = fallbackString(parserName, strings.TrimSpace(feature.ParserName))
		if behaviorRiskScore == 0 {
			behaviorRiskScore = feature.BehaviorRiskScore
		}
		packetCount = feature.PacketCount
		byteCount = feature.ByteCount
		conversationCount = feature.ConversationCount
	}
	parsedMetrics := firstNonEmptyMap(
		cloneMap(normalized.FlowParsedMetrics),
		firstNonEmptyMap(extractMap(featurePayload, "parsedMetrics"), extractMap(payload, "parsedMetrics")),
	)
	isTraceable := collection != nil

	detail := &responseModel.TaskFlowDetail{
		CollectionID: func() uint64 {
			if collection != nil {
				return collection.ID
			}
			return 0
		}(),
		CollectionMode:           collectionMode,
		CollectionStatus:         collectionStatus,
		HistorySourceTable:       "",
		TrendSourceTable:         "",
		EvidenceSourceTable:      "",
		IsTraceable:              isTraceable,
		HasRealMetrics:           packetCount > 0 || byteCount > 0 || conversationCount > 0 || len(windows) > 0 || len(parsedMetrics) > 0,
		SourceName:               sourceName,
		SourceChain:              sourceChain,
		ParserName:               parserName,
		ParserReady:              normalized.FlowParserReady || boolFromPayload(payload, "parserReady"),
		IntegrationStage:         fallbackString(strings.TrimSpace(normalized.FlowIntegrationStage), extractString(payload, "integrationStage")),
		PrototypeBoundary:        fallbackString(strings.TrimSpace(normalized.FlowPrototypeBoundary), extractString(payload, "prototypeBoundary")),
		InputKind:                fallbackString(strings.TrimSpace(normalized.FlowInputKind), extractString(payload, "inputKind")),
		Summary:                  summary,
		BehaviorRiskScore:        behaviorRiskScore,
		WindowSeconds:            windowSeconds,
		SampleProfile:            sampleProfile,
		InterfaceName:            interfaceName,
		PcapFilePath:             pcapFilePath,
		PacketCount:              packetCount,
		ByteCount:                byteCount,
		ConversationCount:        conversationCount,
		WindowCount:              len(windows),
		InputSnapshot:            firstNonEmptyMap(cloneMap(normalized.FlowInputSnapshot), extractMap(payload, "inputSnapshot")),
		ParsedMetrics:            parsedMetrics,
		EvidenceSnapshot:         firstNonEmptyMap(cloneMap(featurePayload), cloneMap(payload)),
		FeatureDigest:            "",
		PeakPPS:                  0,
		BurstScore:               0,
		ScanScore:                0,
		ProtocolDistribution:     nil,
		DNSTopQuestions:          nil,
		DNSQueryTypeHints:        nil,
		HTTPHostHints:            nil,
		HTTPMethodHints:          nil,
		HTTPStatusHints:          nil,
		TLSHandshakeHints:        nil,
		TLSVersionHints:          nil,
		ApplicationSignals:       nil,
		DirectionalityIndicators: nil,
		PortDensityIndicators:    nil,
		PayloadEntropyIndicators: nil,
		TopPorts:                 nil,
		PeerEndpoints:            nil,
		MappingBoundary:          extractMap(payload, "mappingBoundary"),
		EvidenceItems:            toResponseEvidenceItems(evidenceItems),
		Trend:                    toResponseFlowWindows(windows, false),
		EvidenceTimeline:         toResponseFlowWindows(windows, true),
		StartedAt:                startedAt,
		FinishedAt:               finishedAt,
		CreatedAt:                createdAt,
	}
	if isTraceable {
		detail.HistorySourceTable = "sec_flow_collection"
		detail.TrendSourceTable = "sec_flow_window_aggregate"
		detail.EvidenceSourceTable = "sec_flow_feature_snapshot"
	}
	if feature != nil {
		detail.FeatureDigest = strings.TrimSpace(feature.FeatureDigest)
		detail.PeakPPS = feature.PeakPPS
		detail.BurstScore = feature.BurstScore
		detail.ScanScore = feature.ScanScore
		if payload := decodeJSONMap(feature.ProtocolDistribution); len(payload) > 0 {
			detail.ProtocolDistribution = payload
		}
		if payload := decodeJSONArrayOfObjects(feature.DNSTopQuestions); len(payload) > 0 {
			detail.DNSTopQuestions = payload
		}
		if payload := decodeJSONArrayOfObjects(feature.DNSQueryTypeHints); len(payload) > 0 {
			detail.DNSQueryTypeHints = payload
		}
		if payload := decodeJSONArrayOfObjects(feature.HTTPHostHints); len(payload) > 0 {
			detail.HTTPHostHints = payload
		}
		if payload := decodeJSONArrayOfObjects(feature.HTTPMethodHints); len(payload) > 0 {
			detail.HTTPMethodHints = payload
		}
		if payload := decodeJSONArrayOfObjects(feature.HTTPStatusHints); len(payload) > 0 {
			detail.HTTPStatusHints = payload
		}
		if payload := decodeJSONArrayOfObjects(feature.TLSHandshakeHints); len(payload) > 0 {
			detail.TLSHandshakeHints = payload
		}
		if payload := decodeJSONArrayOfObjects(feature.TLSVersionHints); len(payload) > 0 {
			detail.TLSVersionHints = payload
		}
		if payload := decodeStringArray(feature.ApplicationSignals); len(payload) > 0 {
			detail.ApplicationSignals = payload
		}
		if payload := decodeJSONMap(feature.DirectionalityIndicators); len(payload) > 0 {
			detail.DirectionalityIndicators = payload
		}
		if payload := decodeJSONMap(feature.PortDensityIndicators); len(payload) > 0 {
			detail.PortDensityIndicators = payload
		}
		if payload := decodeJSONMap(feature.PayloadEntropyIndicators); len(payload) > 0 {
			detail.PayloadEntropyIndicators = payload
		}
		if payload := decodeJSONArrayOfObjects(feature.TopPorts); len(payload) > 0 {
			detail.TopPorts = payload
		}
		if payload := decodeJSONArrayOfObjects(feature.PeerEndpoints); len(payload) > 0 {
			detail.PeerEndpoints = payload
		}
	}
	if payload := decodeJSONArrayOfObjects(mustJSON(parsedMetrics["dnsTopQuestions"])); len(payload) > 0 {
		detail.DNSTopQuestions = payload
	}
	if payload := decodeJSONArrayOfObjects(mustJSON(parsedMetrics["dnsQueryTypeHints"])); len(payload) > 0 {
		detail.DNSQueryTypeHints = payload
	}
	if payload := decodeJSONArrayOfObjects(mustJSON(parsedMetrics["httpHostHints"])); len(payload) > 0 {
		detail.HTTPHostHints = payload
	}
	if payload := decodeJSONArrayOfObjects(mustJSON(parsedMetrics["httpMethodHints"])); len(payload) > 0 {
		detail.HTTPMethodHints = payload
	}
	if payload := decodeJSONArrayOfObjects(mustJSON(parsedMetrics["httpStatusHints"])); len(payload) > 0 {
		detail.HTTPStatusHints = payload
	}
	if payload := decodeJSONArrayOfObjects(mustJSON(parsedMetrics["tlsHandshakeHints"])); len(payload) > 0 {
		detail.TLSHandshakeHints = payload
	}
	if payload := decodeJSONArrayOfObjects(mustJSON(parsedMetrics["tlsVersionHints"])); len(payload) > 0 {
		detail.TLSVersionHints = payload
	}
	if signals := decodeStringArray(mustJSON(parsedMetrics["applicationSignals"])); len(signals) > 0 {
		detail.ApplicationSignals = signals
	}
	if payload := decodeJSONMap(mustJSON(parsedMetrics["directionalityIndicators"])); len(payload) > 0 {
		detail.DirectionalityIndicators = payload
	}
	if payload := decodeJSONMap(mustJSON(parsedMetrics["portDensityIndicators"])); len(payload) > 0 {
		detail.PortDensityIndicators = payload
	}
	if payload := decodeJSONMap(mustJSON(parsedMetrics["payloadEntropyIndicators"])); len(payload) > 0 {
		detail.PayloadEntropyIndicators = payload
	}

	if detail.CollectionMode == "" || detail.CollectionMode == "disabled" {
		detail.CollectionMode = normalizeFlowBoundaryMode(normalized.FlowMode)
	}
	if !shouldDisplayFlowPrototype(detail.CollectionMode, detail.CollectionStatus) {
		return nil
	}
	return detail
}

// toResponseFlowWindows 用于转换并生成响应流量Windows。
func toResponseFlowWindows(items []securityModel.FlowWindowAggregate, reverse bool) []responseModel.TaskFlowWindowItem {
	if len(items) == 0 {
		return nil
	}
	ordered := make([]securityModel.FlowWindowAggregate, len(items))
	copy(ordered, items)
	sort.Slice(ordered, func(i, j int) bool {
		if reverse {
			if ordered[i].WindowStart.Equal(ordered[j].WindowStart) {
				return ordered[i].WindowNo > ordered[j].WindowNo
			}
			return ordered[i].WindowStart.After(ordered[j].WindowStart)
		}
		if ordered[i].WindowStart.Equal(ordered[j].WindowStart) {
			return ordered[i].WindowNo < ordered[j].WindowNo
		}
		return ordered[i].WindowStart.Before(ordered[j].WindowStart)
	})
	result := make([]responseModel.TaskFlowWindowItem, 0, len(ordered))
	for _, item := range ordered {
		result = append(result, responseModel.TaskFlowWindowItem{
			WindowNo:             item.WindowNo,
			WindowStart:          item.WindowStart.Format("2006-01-02 15:04:05"),
			WindowEnd:            item.WindowEnd.Format("2006-01-02 15:04:05"),
			PacketCount:          item.PacketCount,
			ByteCount:            item.ByteCount,
			ConversationCount:    item.ConversationCount,
			InboundPacketCount:   item.InboundPacketCount,
			OutboundPacketCount:  item.OutboundPacketCount,
			InboundByteCount:     item.InboundByteCount,
			OutboundByteCount:    item.OutboundByteCount,
			TCPPacketCount:       item.TCPPacketCount,
			UDPPacketCount:       item.UDPPacketCount,
			ICMPPacketCount:      item.ICMPPacketCount,
			DNSEventCount:        item.DNSEventCount,
			HTTPEventCount:       item.HTTPEventCount,
			TLSEventCount:        item.TLSEventCount,
			HighRiskPortHitCount: item.HighRiskPortHitCount,
			EvidencePayload:      decodeJSONMap(item.EvidencePayload),
		})
	}
	return result
}

// extractMap 用于提取请求、令牌或流量中的关键信息。
func extractMap(payload map[string]any, key string) map[string]any {
	value, ok := payload[key]
	if !ok {
		return nil
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return cloneMap(result)
}

// boolFromPayload 用于执行boolFrom载荷流程。
func boolFromPayload(payload map[string]any, key string) bool {
	value, ok := readFlowPayloadBool(payload, key)
	return ok && value
}

// firstNonEmptyMap 用于选取首个可用的NonEmptyMap。
func firstNonEmptyMap(primary map[string]any, fallback map[string]any) map[string]any {
	if len(primary) != 0 {
		return primary
	}
	if len(fallback) != 0 {
		return fallback
	}
	return nil
}

// valueOrTimePtr 用于执行valueOrTimePtr流程。
func valueOrTimePtr(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	v := value
	return &v
}

// buildTaskFlowHistory 用于构建任务响应数据。
func (s *TaskService) buildTaskFlowHistory(taskID uint64) []responseModel.TaskFlowHistoryItem {
	repo := repository.RepositoryGroupApp.SecurityRepositoryGroup
	collections, err := repo.FlowCollectionRepository.ListByTaskID(global.DB, taskID)
	if err != nil || len(collections) == 0 {
		return nil
	}
	result := make([]responseModel.TaskFlowHistoryItem, 0, len(collections))
	for _, collection := range collections {
		feature, _ := repo.FlowFeatureSnapshotRepository.FindByCollectionID(global.DB, collection.ID)
		windowRows, _ := repo.FlowWindowAggregateRepository.ListByCollectionID(global.DB, collection.ID, 0)
		behaviorRiskScore := 0.0
		featureDigest := ""
		if feature != nil {
			behaviorRiskScore = feature.BehaviorRiskScore
			featureDigest = strings.TrimSpace(feature.FeatureDigest)
		}
		result = append(result, responseModel.TaskFlowHistoryItem{
			CollectionID:      collection.ID,
			CollectionMode:    normalizeFlowBoundaryMode(collection.CollectionMode),
			CollectionStatus:  strings.ToUpper(strings.TrimSpace(collection.CollectionStatus)),
			ParserName:        strings.TrimSpace(collection.ParserName),
			SourceName:        strings.TrimSpace(collection.SourceName),
			Summary:           strings.TrimSpace(collection.Summary),
			PacketCount:       collection.PacketCount,
			ByteCount:         collection.ByteCount,
			ConversationCount: collection.ConversationCount,
			WindowCount:       len(windowRows),
			BehaviorRiskScore: behaviorRiskScore,
			FeatureDigest:     featureDigest,
			CreatedAt:         formatTimePtr(valueOrTimePtr(collection.CreatedAt)),
		})
	}
	return result
}
