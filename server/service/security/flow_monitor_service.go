package security

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"lightweight-ip-traffic-sa/server/config"
	"lightweight-ip-traffic-sa/server/global"
	securityModel "lightweight-ip-traffic-sa/server/model/security"
	requestModel "lightweight-ip-traffic-sa/server/model/security/request"
	responseModel "lightweight-ip-traffic-sa/server/model/security/response"
	"lightweight-ip-traffic-sa/server/repository"
	"lightweight-ip-traffic-sa/server/utils"
)

// FlowMonitorService 用于编排安全态势模块的业务流程。
type FlowMonitorService struct{}

const (
	// 每个分析窗口 5 秒：实时监控按固定窗口采样，窗口越短响应越快，太短则统计噪声大
	flowMonitorWindowSeconds      = 5
	flowMonitorRefreshIntervalSec = 5
	// 单次抓包最长 7 秒：给 5 秒窗口留缓冲，避免边界处因调度抖动提前结束
	flowMonitorCaptureTimeout     = 7 * time.Second
	// 预警冷却 30 秒：同一指纹在冷却期内不再重复告警，避免持续高风险刷屏
	flowMonitorAlertCooldown      = 30 * time.Second
)

var (
	errFlowMonitorSessionNotFound = NewServiceError(ServiceErrorCategoryNotFound, "实时流量监控会话不存在")
	errFlowMonitorAlreadyRunning  = NewServiceError(ServiceErrorCategoryConflict, "已有实时流量监控正在运行，请先暂停当前监控")
	// 监控会话只保存在内存 map 中：会话生命周期短、停止即失效，落库会带来无意义的 IO 与表膨胀
	flowMonitorSessions           = newFlowMonitorSessionStore()
)

// flowMonitorLatestAlert 用于承载flow监控Latest预警数据。
type flowMonitorLatestAlert struct {
	AlertID          uint64
	AlertLevel       string
	AlertTitle       string
	AlertContent     string
	CreatedAt        time.Time
	SourceLabel      string
	MonitorSessionID string
}

// flowMonitorSessionState 用于保存flow监控SessionState运行状态。
type flowMonitorSessionState struct {
	mu sync.RWMutex

	ID                 string
	OwnerUserID        uint64
	OwnerUsername      string
	OwnerDisplayName   string
	OwnerRoleCode      string
	InterfaceName      string
	Status             string
	LastAnalysisStatus string
	Summary            string
	ParserName         string
	StartedAt          time.Time
	FinishedAt         *time.Time
	LastAnalyzedAt     *time.Time
	Result             FlowParseResult
	ErrorMessage       string
	LatestAlert        *flowMonitorLatestAlert

	WindowSeconds          int
	RefreshIntervalSeconds int
	MetricTrend            []responseModel.FlowMonitorMetricPoint
	cancel                 context.CancelFunc
	lastAlertFingerprint   string
	lastAlertAt            *time.Time
}

// flowMonitorSessionStore 用于承载flow监控SessionStore数据。
type flowMonitorSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*flowMonitorSessionState
}

// newFlowMonitorSessionStore 用于创建并返回新的业务实例。
func newFlowMonitorSessionStore() *flowMonitorSessionStore {
	return &flowMonitorSessionStore{sessions: make(map[string]*flowMonitorSessionState)}
}

// get 用于读取实时流量监控会话状态。
func (s *flowMonitorSessionStore) get(id string) (*flowMonitorSessionState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.sessions[id]
	return value, ok
}

// set 用于写入实时流量监控会话状态。
func (s *flowMonitorSessionStore) set(value *flowMonitorSessionState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[value.ID] = value
}

// findRunning 用于查找运行中的实时流量监控会话。
func (s *flowMonitorSessionStore) findRunning() (*flowMonitorSessionState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.sessions {
		if item == nil {
			continue
		}
		item.mu.RLock()
		running := strings.EqualFold(item.Status, "RUNNING")
		item.mu.RUnlock()
		if running {
			return item, true
		}
	}
	return nil, false
}

// findRunningByOwner 用于查找运行中的实时流量监控会话。
func (s *flowMonitorSessionStore) findRunningByOwner(ownerUserID uint64) (*flowMonitorSessionState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.sessions {
		if item == nil {
			continue
		}
		item.mu.RLock()
		matched := strings.EqualFold(item.Status, "RUNNING") && item.OwnerUserID == ownerUserID
		item.mu.RUnlock()
		if matched {
			return item, true
		}
	}
	return nil, false
}

// listByRole 用于列出可观察的实时流量监控会话。
func (s *flowMonitorSessionStore) listByRole(roleCode string) []*flowMonitorSessionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*flowMonitorSessionState, 0, len(s.sessions))
	for _, item := range s.sessions {
		if item == nil {
			continue
		}
		item.mu.RLock()
		matched := strings.EqualFold(strings.TrimSpace(item.OwnerRoleCode), strings.TrimSpace(roleCode))
		item.mu.RUnlock()
		if matched {
			result = append(result, item)
		}
	}
	return result
}

// StartSession 用于启动流量监控流程。
func (svc *FlowMonitorService) StartSession(req requestModel.StartFlowMonitorSessionRequest, claims *utils.TokenClaims) (responseModel.FlowMonitorSessionResponse, error) {
	interfaceName := strings.TrimSpace(req.InterfaceName)
	if interfaceName == "" {
		return responseModel.FlowMonitorSessionResponse{}, NewServiceError(ServiceErrorCategoryInvalidArgument, "请选择需要监听的网卡")
	}
	if claims == nil {
		return responseModel.FlowMonitorSessionResponse{}, NewServiceError(ServiceErrorCategoryUnauthenticated, "登录状态已失效")
	}
	if _, running := flowMonitorSessions.findRunning(); running {
		return responseModel.FlowMonitorSessionResponse{}, errFlowMonitorAlreadyRunning
	}

	sessionID := fmt.Sprintf("fm-%d", time.Now().UnixNano())
	ctx, cancel := context.WithCancel(context.Background())
	state := &flowMonitorSessionState{
		ID:                     sessionID,
		OwnerUserID:            claims.UserID,
		OwnerUsername:          strings.TrimSpace(claims.Username),
		OwnerDisplayName:       strings.TrimSpace(claims.DisplayName),
		OwnerRoleCode:          strings.TrimSpace(claims.RoleCode),
		InterfaceName:          interfaceName,
		Status:                 "RUNNING",
		Summary:                "监控已启动，等待首个 5 秒分析窗口。",
		StartedAt:              time.Now(),
		WindowSeconds:          flowMonitorWindowSeconds,
		RefreshIntervalSeconds: flowMonitorRefreshIntervalSec,
		cancel:                 cancel,
	}
	flowMonitorSessions.set(state)

	go svc.runSession(ctx, state)

	recordSecurityAuditLog(AuditLogEntry{
		Category:    "FLOW_MONITOR",
		Action:      "START_SESSION",
		TargetType:  "flow-monitor-session",
		TargetID:    state.ID,
		TargetLabel: state.InterfaceName,
		Status:      "RUNNING",
		Summary:     "实时流量监控已启动",
		Detail:      mustJSONText(map[string]any{"interfaceName": state.InterfaceName, "windowSeconds": flowMonitorWindowSeconds}),
	})

	return buildFlowMonitorSessionResponse(state), nil
}

// runSession 用于编排流量监控服务流程。
// 实时监控的核心循环：以 5 秒窗口反复抓包解析 → 计算行为风险 → 判定预警，直到 ctx 被取消
// 结果只写入内存态的会话对象，不写流量三表，避免持续监听导致表无限膨胀
func (svc *FlowMonitorService) runSession(ctx context.Context, state *flowMonitorSessionState) {
	parser := realOnlineCaptureFlowParser{}
	for {
		if ctx.Err() != nil {
			svc.markSessionStopped(state, "已暂停实时流量监控")
			return
		}

		parseReq := FlowParseRequest{
			Mode:          FlowParseModeOnlineCapture,
			InterfaceName: state.InterfaceName,
			WindowSeconds: flowMonitorWindowSeconds,
			Timeout:       flowMonitorCaptureTimeout,
		}
		result, err := parser.Parse(ctx, parseReq)
		if ctx.Err() != nil {
			svc.markSessionStopped(state, "已暂停实时流量监控")
			return
		}

		analyzedAt := time.Now()
		if err != nil {
			// 抓包失败不终止会话，标记失败后继续下一轮，便于网卡短暂异常后自动恢复
			svc.updateSessionFailure(state, analyzedAt, err)
			continue
		}
		result = tuneFlowMonitorResult(result)
		svc.updateSessionResult(state, analyzedAt, result)

		if latestAlert, alertErr := svc.tryCreateMonitorAlert(state, result); alertErr == nil && latestAlert != nil {
			state.mu.Lock()
			state.LatestAlert = latestAlert
			state.mu.Unlock()
		}
	}
}

// updateSessionResult 用于编排流量监控服务流程。
func (svc *FlowMonitorService) updateSessionResult(state *flowMonitorSessionState, analyzedAt time.Time, result FlowParseResult) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.Result = result
	state.LastAnalysisStatus = strings.ToUpper(strings.TrimSpace(result.Status))
	state.ParserName = strings.TrimSpace(result.ParserName)
	state.Summary = strings.TrimSpace(result.Summary)
	state.LastAnalyzedAt = &analyzedAt
	state.ErrorMessage = ""
	state.MetricTrend = appendFlowMonitorMetricPoint(state.MetricTrend, analyzedAt, result)
	if strings.TrimSpace(state.Summary) == "" {
		state.Summary = "最近一轮监控分析已完成。"
	}
}

// updateSessionFailure 用于编排流量监控服务流程。
func (svc *FlowMonitorService) updateSessionFailure(state *flowMonitorSessionState, analyzedAt time.Time, err error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.LastAnalysisStatus = FlowStatusParseFailed
	state.LastAnalyzedAt = &analyzedAt
	state.ErrorMessage = strings.TrimSpace(err.Error())
	state.Summary = fmt.Sprintf("最近一轮监控分析失败：%s", state.ErrorMessage)
}

// markSessionStopped 用于标记流量监控执行状态。
func (svc *FlowMonitorService) markSessionStopped(state *flowMonitorSessionState, summary string) {
	now := time.Now()
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.FinishedAt == nil {
		state.FinishedAt = &now
	}
	state.Status = "STOPPED"
	if strings.TrimSpace(summary) != "" {
		state.Summary = strings.TrimSpace(summary)
	}
}

// tryCreateMonitorAlert 用于编排流量监控服务流程。
// 行为风险达到高风险阈值时尝试生成预警；用“指纹 + 冷却时间”去重，防止持续高风险每 5 秒刷一条告警
func (svc *FlowMonitorService) tryCreateMonitorAlert(state *flowMonitorSessionState, result FlowParseResult) (*flowMonitorLatestAlert, error) {
	cfg := loadRuntimeSecurityConfig()
	score := buildAdjustedFlowMonitorScoreResult(result, cfg)
	targetLabel := resolveFlowMonitorAlertTarget(result, state.InterfaceName)
	decision, err := ThresholdAlertDecider{}.Decide(0, "实时流量监控", targetLabel, score, cfg)
	if err != nil || decision == nil || !decision.ShouldAlert {
		return nil, err
	}

	now := time.Now()
	// 指纹包含网卡 + 风险等级 + 异常候选名，同指纹在冷却期内视为“同一次告警”
	fingerprint := buildFlowMonitorAlertFingerprint(decision, result, state.InterfaceName)
	state.mu.RLock()
	lastFingerprint := state.lastAlertFingerprint
	lastAlertAt := state.lastAlertAt
	state.mu.RUnlock()
	if fingerprint != "" && lastFingerprint == fingerprint && lastAlertAt != nil && now.Sub(*lastAlertAt) < flowMonitorAlertCooldown {
		return nil, nil
	}

	alertRecord := toFlowMonitorAlertRecordModel(state.ID, state.InterfaceName, targetLabel, decision)
	if err := repository.RepositoryGroupApp.SecurityRepositoryGroup.AlertRepository.Create(global.DB, alertRecord); err != nil {
		return nil, err
	}
	// 预警写库后清空总览缓存，让首页的预警数尽快刷新
	_ = utils.CacheDelete(utils.SecurityDashboardSummaryCacheKey)

	latest := &flowMonitorLatestAlert{
		AlertID:          alertRecord.ID,
		AlertLevel:       alertRecord.AlertLevel,
		AlertTitle:       alertRecord.AlertTitle,
		AlertContent:     alertRecord.AlertContent,
		CreatedAt:        alertRecord.CreatedAt,
		SourceLabel:      alertRecord.SourceLabel,
		MonitorSessionID: alertRecord.MonitorSessionID,
	}

	state.mu.Lock()
	state.lastAlertFingerprint = fingerprint
	state.lastAlertAt = &now
	state.mu.Unlock()

	recordSecurityAuditLog(AuditLogEntry{
		Category:    "ALERT",
		Action:      "CREATE_FLOW_MONITOR_ALERT",
		TargetType:  "flow-monitor-session",
		TargetID:    state.ID,
		TargetLabel: state.InterfaceName,
		Status:      strings.ToUpper(strings.TrimSpace(alertRecord.AlertLevel)),
		Summary:     fmt.Sprintf("实时监控命中预警：%s", alertRecord.AlertTitle),
		Detail:      mustJSONText(map[string]any{"alertId": alertRecord.ID, "sourceLabel": alertRecord.SourceLabel, "target": alertRecord.IP}),
	})

	return latest, nil
}

// buildFlowMonitorScoreResult 用于构建流量监控评分Result。
// 实时监控不绑定任务，因此只有行为风险分参与评分，其余三维固定为 0，算法版本单独标注
func buildFlowMonitorScoreResult(result FlowParseResult, cfg config.SecurityConfig) ScoreResult {
	scoreValue := round2(result.BehaviorRiskScore)
	return ScoreResult{
		BaseScore:           0,
		ReputationScore:     0,
		AttackSurfaceScore:  0,
		BehaviorScore:       scoreValue,
		RuleAdjustmentValue: 0,
		ScoreValue:          scoreValue,
		RiskLevel:           mapRiskLevel(scoreValue, cfg),
		ScoreReason:         strings.TrimSpace(result.Summary),
		RuleAdjustment:      "实时监控未绑定任务，按流量行为风险独立判定",
		AlgorithmVersion:    "flow-monitor-behavior-only",
		WeightProfile: map[string]float64{
			"behavior": 1,
		},
		IsAlertTriggered: scoreValue >= cfg.HighRiskThreshold,
	}
}

// resolveFlowMonitorAlertTarget 用于解析流量监控预警Target。
func resolveFlowMonitorAlertTarget(result FlowParseResult, interfaceName string) string {
	metrics := result.ParsedMetrics
	peerEndpoints := decodeJSONArrayOfObjects(mustJSONText(metrics["peerEndpoints"]))
	for _, item := range peerEndpoints {
		value := strings.TrimSpace(fmt.Sprintf("%v", item["key"]))
		if value != "" {
			return value
		}
	}
	return strings.TrimSpace(interfaceName)
}

// buildFlowMonitorAlertFingerprint 用于构建流量监控预警Fingerprint。
// 指纹 = 网卡 + 风险等级 + 异常候选名，用于冷却期去重；没有异常候选时用扫描/突发分补充分量，
// 保证“同一风险形态”能被识别为同一条告警，而风险形态变化后又能再次告警
func buildFlowMonitorAlertFingerprint(decision *AlertDecision, result FlowParseResult, interfaceName string) string {
	parts := []string{strings.TrimSpace(interfaceName)}
	if decision != nil {
		parts = append(parts, strings.TrimSpace(decision.AlertLevel))
	}
	anomalies := decodeJSONArrayOfObjects(mustJSONText(result.ParsedMetrics["anomalyCandidates"]))
	for _, item := range anomalies {
		name := strings.TrimSpace(fmt.Sprintf("%v", item["name"]))
		if name != "" {
			parts = append(parts, name)
		}
	}
	if len(parts) == 2 {
		parts = append(parts, fmt.Sprintf("scan=%.2f", readFlowMetricFloat64(result.ParsedMetrics, "scanScore")))
		parts = append(parts, fmt.Sprintf("burst=%.2f", readFlowMetricFloat64(result.ParsedMetrics, "burstScore")))
	}
	return strings.Join(parts, "|")
}

// toFlowMonitorAlertRecordModel 用于转换并生成流量监控预警记录模型。
// 实时监控预警无任务 ID / 评分 ID，SourceType 固定为 FLOW_MONITOR，与任务预警区分开
func toFlowMonitorAlertRecordModel(sessionID string, interfaceName string, targetLabel string, decision *AlertDecision) *securityModel.AlertRecord {
	if decision == nil || !decision.ShouldAlert {
		return nil
	}
	cfg := loadRuntimeSecurityConfig()
	sendStatus, sendTime, err := sendAlertByConfiguredChannel(decision, cfg)
	now := time.Now()
	if err != nil {
		sendStatus = "FAILED"
	}
	return &securityModel.AlertRecord{
		TaskID:           nil,
		ScoreID:          nil,
		IP:               strings.TrimSpace(targetLabel),
		SourceType:       "FLOW_MONITOR",
		SourceLabel:      strings.TrimSpace(interfaceName),
		MonitorSessionID: strings.TrimSpace(sessionID),
		AlertLevel:       strings.TrimSpace(decision.AlertLevel),
		AlertTitle:       strings.TrimSpace(decision.Title),
		AlertContent:     strings.TrimSpace(decision.Content),
		Channel:          strings.TrimSpace(decision.Channel),
		SendStatus:       sendStatus,
		SendTime:         sendTime,
		CreatedAt:        now,
	}
}

// GetSession 用于查询流量监控详情并组装响应。
func (svc *FlowMonitorService) GetSession(sessionID string, claims *utils.TokenClaims) (responseModel.FlowMonitorSessionResponse, error) {
	state, ok := flowMonitorSessions.get(strings.TrimSpace(sessionID))
	if !ok {
		return responseModel.FlowMonitorSessionResponse{}, errFlowMonitorSessionNotFound
	}
	if err := ensureFlowMonitorSessionReadable(state, claims); err != nil {
		return responseModel.FlowMonitorSessionResponse{}, err
	}
	return buildFlowMonitorSessionResponse(state), nil
}

// GetCurrentRunningSession 用于查询流量监控详情并组装响应。
func (svc *FlowMonitorService) GetCurrentRunningSession(claims *utils.TokenClaims) (*responseModel.FlowMonitorSessionResponse, error) {
	if claims == nil {
		return nil, NewServiceError(ServiceErrorCategoryUnauthenticated, "登录状态已失效")
	}
	state, ok := flowMonitorSessions.findRunningByOwner(claims.UserID)
	if !ok {
		return nil, nil
	}
	resp := buildFlowMonitorSessionResponse(state)
	return &resp, nil
}

// StopSession 用于停止流量监控流程。
func (svc *FlowMonitorService) StopSession(sessionID string, claims *utils.TokenClaims) (responseModel.FlowMonitorSessionResponse, error) {
	state, ok := flowMonitorSessions.get(strings.TrimSpace(sessionID))
	if !ok {
		return responseModel.FlowMonitorSessionResponse{}, errFlowMonitorSessionNotFound
	}
	if err := ensureFlowMonitorSessionWritable(state, claims); err != nil {
		return responseModel.FlowMonitorSessionResponse{}, err
	}

	state.mu.Lock()
	cancel := state.cancel
	state.cancel = nil
	now := time.Now()
	if state.FinishedAt == nil {
		state.FinishedAt = &now
	}
	state.Status = "STOPPED"
	if strings.TrimSpace(state.Summary) == "" || state.Summary == "监控已启动，等待首个 5 秒分析窗口。" {
		state.Summary = "已暂停实时流量监控"
	}
	state.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	recordSecurityAuditLog(AuditLogEntry{
		Category:    "FLOW_MONITOR",
		Action:      "STOP_SESSION",
		TargetType:  "flow-monitor-session",
		TargetID:    state.ID,
		TargetLabel: state.InterfaceName,
		Status:      "STOPPED",
		Summary:     "实时流量监控已暂停",
	})
	return buildFlowMonitorSessionResponse(state), nil
}

// GetObserverPanel 用于查询流量监控详情并组装响应。
func (svc *FlowMonitorService) GetObserverPanel(targetUsername string, targetRoleCode string, claims *utils.TokenClaims) (responseModel.FlowMonitorObserverPanelResponse, error) {
	if claims == nil {
		return responseModel.FlowMonitorObserverPanelResponse{}, NewServiceError(ServiceErrorCategoryUnauthenticated, "登录状态已失效")
	}
	roleCode := strings.ToUpper(strings.TrimSpace(claims.RoleCode))
	if roleCode != "ADMIN" && roleCode != "MANAGER" {
		return responseModel.FlowMonitorObserverPanelResponse{}, NewServiceError(ServiceErrorCategoryPermissionDenied, "当前账号无权查看用户实时流量面板")
	}
	targetUsername = strings.TrimSpace(targetUsername)
	if targetUsername == "" {
		targetUsername = "user"
	}
	targetRoleCode = strings.ToUpper(strings.TrimSpace(targetRoleCode))
	if targetRoleCode == "" {
		targetRoleCode = "USER"
	}

	states := flowMonitorSessions.listByRole(targetRoleCode)
	resp := responseModel.FlowMonitorObserverPanelResponse{
		TargetUsername: targetUsername,
		TargetRoleCode: targetRoleCode,
		Sessions:       make([]responseModel.FlowMonitorSessionResponse, 0, len(states)),
	}
	for _, state := range states {
		if state == nil {
			continue
		}
		state.mu.RLock()
		username := strings.TrimSpace(state.OwnerUsername)
		displayName := strings.TrimSpace(state.OwnerDisplayName)
		running := strings.EqualFold(state.Status, "RUNNING")
		lastAnalyzedAt := ""
		if state.LastAnalyzedAt != nil {
			lastAnalyzedAt = state.LastAnalyzedAt.Format("2006-01-02 15:04:05")
		}
		state.mu.RUnlock()
		if username != targetUsername {
			continue
		}
		item := buildFlowMonitorSessionResponse(state)
		resp.Sessions = append(resp.Sessions, item)
		resp.TotalSessionCount++
		if running {
			resp.RunningSessionCount++
		}
		resp.TotalPacketCount += item.PacketCount
		resp.TotalByteCount += item.ByteCount
		if item.BehaviorRiskScore > resp.MaxBehaviorRiskScore {
			resp.MaxBehaviorRiskScore = item.BehaviorRiskScore
		}
		if lastAnalyzedAt > resp.LatestAnalyzedAt {
			resp.LatestAnalyzedAt = lastAnalyzedAt
		}
		if resp.TargetDisplayName == "" && displayName != "" {
			resp.TargetDisplayName = displayName
		}
	}
	return resp, nil
}

// GetTaskRelationGraph 用于查询流量监控详情并组装响应。
func (svc *FlowMonitorService) GetTaskRelationGraph(taskID uint64) (responseModel.TaskRelationGraphResponse, error) {
	detail, err := repository.RepositoryGroupApp.SecurityRepositoryGroup.TaskRepository.FindDetailByID(global.DB, taskID)
	if err != nil {
		return responseModel.TaskRelationGraphResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取关联图谱失败，请稍后重试", err)
	}
	if detail == nil || detail.Task == nil {
		return responseModel.TaskRelationGraphResponse{}, ErrTaskNotFound
	}

	nodes := make([]responseModel.RelationGraphNode, 0)
	edges := make([]responseModel.RelationGraphEdge, 0)
	taskNodeID := fmt.Sprintf("task:%d", taskID)
	nodes = append(nodes, responseModel.RelationGraphNode{
		ID:       taskNodeID,
		Label:    detail.Task.TargetIP,
		Category: "target-ip",
		Value:    100,
		Meta: map[string]any{
			"taskNo":     detail.Task.TaskNo,
			"riskLevel":  safeRiskLevel(detail.Score),
			"taskStatus": detail.Task.TaskStatus,
		},
	})

	addNode := func(id string, label string, category string, value float64, meta map[string]any) {
		for _, item := range nodes {
			if item.ID == id {
				return
			}
		}
		nodes = append(nodes, responseModel.RelationGraphNode{ID: id, Label: label, Category: category, Value: value, Meta: meta})
	}

	addEdge := func(source string, target string, label string, value float64, meta map[string]any) {
		edges = append(edges, responseModel.RelationGraphEdge{Source: source, Target: target, Label: label, Value: value, Meta: meta})
	}

	if detail.FlowFeature != nil {
		for _, peer := range decodeJSONArrayOfObjects(detail.FlowFeature.PeerEndpoints) {
			label := strings.TrimSpace(extractString(peer, "peer"))
			if label == "" {
				label = strings.TrimSpace(extractString(peer, "ip"))
			}
			if label == "" {
				label = strings.TrimSpace(extractString(peer, "key"))
			}
			if label == "" {
				continue
			}
			nodeID := "peer:" + label
			addNode(nodeID, label, "peer-ip", float64(extractInt(peer, "count")), peer)
			addEdge(taskNodeID, nodeID, "peer", float64(extractInt(peer, "count")), peer)
		}
		for _, port := range decodeJSONArrayOfObjects(detail.FlowFeature.TopPorts) {
			portValue := extractInt(port, "port")
			if portValue == 0 {
				portValue = extractInt(port, "key")
			}
			label := fmt.Sprintf(":%d", portValue)
			nodeID := "port:" + label
			addNode(nodeID, label, "port", float64(extractInt(port, "count")), port)
			addEdge(taskNodeID, nodeID, "top-port", float64(extractInt(port, "count")), port)
		}
		for _, host := range decodeJSONArrayOfObjects(detail.FlowFeature.HTTPHostHints) {
			label := strings.TrimSpace(extractString(host, "key"))
			if label == "" {
				continue
			}
			nodeID := "host:" + label
			addNode(nodeID, label, "http-host", float64(extractInt(host, "count")), host)
			addEdge(taskNodeID, nodeID, "http-host", float64(extractInt(host, "count")), host)
		}
		for _, hint := range decodeJSONArrayOfObjects(detail.FlowFeature.TLSHandshakeHints) {
			label := strings.TrimSpace(extractString(hint, "serverName"))
			if label == "" {
				continue
			}
			nodeID := "sni:" + label
			addNode(nodeID, label, "tls-sni", float64(extractInt(hint, "count")), hint)
			addEdge(taskNodeID, nodeID, "tls-sni", float64(extractInt(hint, "count")), hint)
		}
		for protocol, count := range decodeJSONMap(detail.FlowFeature.ProtocolDistribution) {
			nodeID := "protocol:" + protocol
			addNode(nodeID, protocol, "protocol", toFloat64(count), map[string]any{"count": count})
			addEdge(taskNodeID, nodeID, "protocol", toFloat64(count), map[string]any{"count": count})
		}
	}

	return responseModel.TaskRelationGraphResponse{
		TaskID: taskID,
		Nodes:  nodes,
		Edges:  edges,
	}, nil
}

// buildFlowMonitorSessionResponse 用于构建流量监控Session响应。
func buildFlowMonitorSessionResponse(state *flowMonitorSessionState) responseModel.FlowMonitorSessionResponse {
	state.mu.RLock()
	defer state.mu.RUnlock()

	metrics := resolveFlowParsedMetrics(mapFlowParseResultToCollectedData("", state.Result))
	resp := responseModel.FlowMonitorSessionResponse{
		SessionID:                state.ID,
		OwnerUserID:              state.OwnerUserID,
		OwnerUsername:            state.OwnerUsername,
		OwnerDisplayName:         state.OwnerDisplayName,
		OwnerRoleCode:            state.OwnerRoleCode,
		InterfaceName:            state.InterfaceName,
		Status:                   state.Status,
		LastAnalysisStatus:       state.LastAnalysisStatus,
		Summary:                  state.Summary,
		ParserName:               state.ParserName,
		StartedAt:                state.StartedAt.Format("2006-01-02 15:04:05"),
		WindowSeconds:            state.WindowSeconds,
		RefreshIntervalSeconds:   state.RefreshIntervalSeconds,
		PacketCount:              readFlowMetricUint64(metrics, "packetCount"),
		ByteCount:                readFlowMetricUint64(metrics, "byteCount"),
		ConversationCount:        uint32(readFlowMetricUint64(metrics, "sessionCount")),
		BehaviorRiskScore:        state.Result.BehaviorRiskScore,
		PeakPPS:                  readFlowMetricFloat64(metrics, "peakPps"),
		BurstScore:               readFlowMetricFloat64(metrics, "burstScore"),
		ScanScore:                readFlowMetricFloat64(metrics, "scanScore"),
		DNSEventCount:            readFlowMetricUint64(metrics, "dnsEventCount"),
		HTTPEventCount:           readFlowMetricUint64(metrics, "httpEventCount"),
		TLSEventCount:            readFlowMetricUint64(metrics, "tlsEventCount"),
		ProtocolDistribution:     decodeJSONMap(mustJSONText(metrics["protocolDistribution"])),
		DNSTopQuestions:          decodeJSONArrayOfObjects(mustJSONText(metrics["dnsTopQuestions"])),
		HTTPHostHints:            decodeJSONArrayOfObjects(mustJSONText(metrics["httpHostHints"])),
		TLSHandshakeHints:        decodeJSONArrayOfObjects(mustJSONText(metrics["tlsHandshakeHints"])),
		ApplicationSignals:       decodeStringArray(mustJSONText(metrics["applicationSignals"])),
		DirectionalityIndicators: decodeJSONMap(mustJSONText(metrics["directionalityIndicators"])),
		PortDensityIndicators:    decodeJSONMap(mustJSONText(metrics["portDensityIndicators"])),
		PayloadEntropyIndicators: decodeJSONMap(mustJSONText(metrics["payloadEntropyIndicators"])),
		MetricTrend:              append([]responseModel.FlowMonitorMetricPoint(nil), state.MetricTrend...),
		ErrorMessage:             state.ErrorMessage,
		DebugPayload:             cloneMap(state.Result.DebugPayload),
	}
	if state.FinishedAt != nil {
		resp.FinishedAt = state.FinishedAt.Format("2006-01-02 15:04:05")
	}
	if state.LastAnalyzedAt != nil {
		resp.LastAnalyzedAt = state.LastAnalyzedAt.Format("2006-01-02 15:04:05")
	}
	if state.LatestAlert != nil {
		resp.LatestAlert = &responseModel.FlowMonitorAlertSummary{
			AlertID:          state.LatestAlert.AlertID,
			AlertLevel:       state.LatestAlert.AlertLevel,
			AlertTitle:       state.LatestAlert.AlertTitle,
			AlertContent:     state.LatestAlert.AlertContent,
			CreatedAt:        state.LatestAlert.CreatedAt.Format("2006-01-02 15:04:05"),
			SourceLabel:      state.LatestAlert.SourceLabel,
			MonitorSessionID: state.LatestAlert.MonitorSessionID,
		}
	}
	return resp
}

// safeRiskLevel 用于执行safe风险Level流程。
func safeRiskLevel(score *securityModel.RiskScore) string {
	if score == nil {
		return "LOW"
	}
	return score.RiskLevel
}

// ensureFlowMonitorSessionReadable 用于确保基础数据或配置满足运行要求。
func ensureFlowMonitorSessionReadable(state *flowMonitorSessionState, claims *utils.TokenClaims) error {
	if claims == nil {
		return NewServiceError(ServiceErrorCategoryUnauthenticated, "登录状态已失效")
	}
	state.mu.RLock()
	ownerUserID := state.OwnerUserID
	state.mu.RUnlock()
	if ownerUserID == 0 || ownerUserID == claims.UserID {
		return nil
	}
	roleCode := strings.ToUpper(strings.TrimSpace(claims.RoleCode))
	if roleCode == "ADMIN" || roleCode == "MANAGER" {
		return nil
	}
	return NewServiceError(ServiceErrorCategoryPermissionDenied, "当前账号无权查看其他用户的实时流量会话")
}

// ensureFlowMonitorSessionWritable 用于确保基础数据或配置满足运行要求。
func ensureFlowMonitorSessionWritable(state *flowMonitorSessionState, claims *utils.TokenClaims) error {
	if claims == nil {
		return NewServiceError(ServiceErrorCategoryUnauthenticated, "登录状态已失效")
	}
	state.mu.RLock()
	ownerUserID := state.OwnerUserID
	state.mu.RUnlock()
	if ownerUserID == 0 || ownerUserID == claims.UserID {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(claims.RoleCode), "ADMIN") {
		return nil
	}
	return NewServiceError(ServiceErrorCategoryPermissionDenied, "当前账号无权停止其他用户的实时流量会话")
}

// appendFlowMonitorMetricPoint 用于追加业务明细或展示条目。
func appendFlowMonitorMetricPoint(points []responseModel.FlowMonitorMetricPoint, analyzedAt time.Time, result FlowParseResult) []responseModel.FlowMonitorMetricPoint {
	metrics := resolveFlowParsedMetrics(mapFlowParseResultToCollectedData("", result))
	point := responseModel.FlowMonitorMetricPoint{
		AnalyzedAt:        analyzedAt.Format("2006-01-02 15:04:05"),
		PacketCount:       readFlowMetricUint64(metrics, "packetCount"),
		ByteCount:         readFlowMetricUint64(metrics, "byteCount"),
		ConversationCount: uint32(readFlowMetricUint64(metrics, "sessionCount")),
		BehaviorRiskScore: result.BehaviorRiskScore,
		PeakPPS:           readFlowMetricFloat64(metrics, "peakPps"),
		BurstScore:        readFlowMetricFloat64(metrics, "burstScore"),
		ScanScore:         readFlowMetricFloat64(metrics, "scanScore"),
		DNSEventCount:     readFlowMetricUint64(metrics, "dnsEventCount"),
		HTTPEventCount:    readFlowMetricUint64(metrics, "httpEventCount"),
		TLSEventCount:     readFlowMetricUint64(metrics, "tlsEventCount"),
	}
	points = append(points, point)
	// 趋势只保留最近 24 个采样点，避免长时间监控时内存无限增长（这也是实时监控不写库的原因之一）
	if len(points) > 24 {
		return append([]responseModel.FlowMonitorMetricPoint(nil), points[len(points)-24:]...)
	}
	return points
}

// buildAdjustedFlowMonitorScoreResult 用于构建Adjusted流量监控评分Result。
// 与任务评分不同：实时监控只用行为风险独立判定，并叠加“良性 Web 流量抑制”等调权说明
func buildAdjustedFlowMonitorScoreResult(result FlowParseResult, cfg config.SecurityConfig) ScoreResult {
	scoreValue := round2(result.BehaviorRiskScore)
	ruleAdjustment := "实时监控未绑定任务，按流量行为风险独立判定"
	if adjustment := readFlowMonitorAdjustmentSummary(result.ParsedMetrics); adjustment != "" {
		ruleAdjustment += "；" + adjustment
	}
	return ScoreResult{
		BaseScore:           0,
		ReputationScore:     0,
		AttackSurfaceScore:  0,
		BehaviorScore:       scoreValue,
		RuleAdjustmentValue: 0,
		ScoreValue:          scoreValue,
		RiskLevel:           mapRiskLevel(scoreValue, cfg),
		ScoreReason:         strings.TrimSpace(result.Summary),
		RuleAdjustment:      ruleAdjustment,
		AlgorithmVersion:    "flow-monitor-behavior-only-v2",
		WeightProfile: map[string]float64{
			"behavior": 1,
		},
		IsAlertTriggered: shouldTriggerFlowMonitorAlert(scoreValue, result.ParsedMetrics, cfg),
	}
}

// tuneFlowMonitorResult 用于执行tune流量监控Result流程。
func tuneFlowMonitorResult(result FlowParseResult) FlowParseResult {
	adjustedScore, adjustmentSummary := normalizeFlowMonitorBehaviorScore(result.BehaviorRiskScore, result.ParsedMetrics)
	result.BehaviorRiskScore = adjustedScore
	if strings.TrimSpace(adjustmentSummary) == "" {
		return result
	}
	if len(result.ParsedMetrics) == 0 {
		result.ParsedMetrics = make(map[string]any)
	}
	result.ParsedMetrics["monitorAdjustmentSummary"] = adjustmentSummary
	result.ParsedMetrics["monitorAdjustedBehaviorRiskScore"] = adjustedScore
	if strings.TrimSpace(result.Summary) == "" {
		result.Summary = adjustmentSummary
	} else {
		result.Summary = strings.TrimSpace(result.Summary + "；" + adjustmentSummary)
	}
	return result
}

// normalizeFlowMonitorBehaviorScore 用于归一化输入参数或业务指标。
// 实时监控误报率较高，这里做“向下调权”：识别为常见 Web 浏览流量时压低风险上限，
// 没有高置信度扫描/突发特征时抑制高分放大，最终仍夹在 0~100
func normalizeFlowMonitorBehaviorScore(rawScore float64, metrics map[string]any) (float64, string) {
	score := round2(rawScore)
	if score <= 0 {
		return 0, ""
	}
	adjustments := make([]string, 0, 2)
	if isLikelyBenignWebTraffic(metrics) {
		capValue := 32.0
		if hasOnlyLowConfidenceFlowMonitorSignals(metrics) {
			capValue = 42.0
		}
		if score > capValue {
			score = capValue
			adjustments = append(adjustments, "识别为常见 Web 浏览流量，已下调 DNS/TLS 活跃度带来的风险放大")
		}
	}
	if !hasStrongFlowMonitorSignal(metrics) {
		scanScore := readFlowMetricFloat64(metrics, "scanScore")
		burstScore := readFlowMetricFloat64(metrics, "burstScore")
		if scanScore < 45 && burstScore < 55 && score > 58 {
			score = 58
			adjustments = append(adjustments, "未命中高置信度扫描或突发特征，已抑制实时监控高风险放大")
		}
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return round2(score), strings.Join(adjustments, "；")
}

// shouldTriggerFlowMonitorAlert 用于执行shouldTrigger流量监控预警流程。
// 预警判定：分数 >= 高风险阈值，且不是“看起来像良性 Web 浏览又无强异常信号”的流量
func shouldTriggerFlowMonitorAlert(score float64, metrics map[string]any, cfg config.SecurityConfig) bool {
	if score < cfg.HighRiskThreshold {
		return false
	}
	if isLikelyBenignWebTraffic(metrics) && !hasStrongFlowMonitorSignal(metrics) {
		return false
	}
	return true
}

// readFlowMonitorAdjustmentSummary 用于读取流量监控Adjustment摘要。
func readFlowMonitorAdjustmentSummary(metrics map[string]any) string {
	if len(metrics) == 0 {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", metrics["monitorAdjustmentSummary"]))
}

// isLikelyBenignWebTraffic 用于判断输入是否满足指定条件。
// 通过 HTTP/TLS 线索 + 低端口密度 + 低扫描/突发分判断“像正常网页浏览”，用于抑制误报
func isLikelyBenignWebTraffic(metrics map[string]any) bool {
	if len(metrics) == 0 {
		return false
	}
	httpHosts := decodeJSONArrayOfObjects(mustJSONText(metrics["httpHostHints"]))
	tlsHints := decodeJSONArrayOfObjects(mustJSONText(metrics["tlsHandshakeHints"]))
	// 没有任何 HTTP Host 或 TLS SNI 线索，谈不上“网页浏览”
	if len(httpHosts) == 0 && len(tlsHints) == 0 {
		return false
	}
	// 一旦命中高置信度异常候选（端口扫描/ICMP 探测），优先按恶意处理，不做良性降权
	if hasHighConfidenceFlowMonitorAnomaly(metrics) {
		return false
	}
	portDensity := decodeJSONMap(mustJSONText(metrics["portDensityIndicators"]))
	uniquePorts := extractInt(portDensity, "uniqueTargetPortCount")
	highRiskPorts := extractInt(portDensity, "highRiskTargetPortCount")
	scanScore := readFlowMetricFloat64(metrics, "scanScore")
	burstScore := readFlowMetricFloat64(metrics, "burstScore")
	httpCount := readFlowMetricUint64(metrics, "httpEventCount")
	tlsCount := readFlowMetricUint64(metrics, "tlsEventCount")
	dnsCount := readFlowMetricUint64(metrics, "dnsEventCount")
	return uniquePorts > 0 &&
		uniquePorts <= 4 &&
		highRiskPorts == 0 &&
		scanScore < 35 &&
		burstScore < 55 &&
		(httpCount+tlsCount >= 6 || dnsCount >= 10)
}

// hasOnlyLowConfidenceFlowMonitorSignals 用于判断目标是否具备指定数据或能力。
func hasOnlyLowConfidenceFlowMonitorSignals(metrics map[string]any) bool {
	if len(metrics) == 0 {
		return false
	}
	if hasHighConfidenceFlowMonitorAnomaly(metrics) {
		return false
	}
	return len(extractFlowMonitorAnomalyNames(metrics)) > 0
}

// hasStrongFlowMonitorSignal 用于判断目标是否具备指定数据或能力。
// 高置信度异常候选，或扫描/突发/高危端口达到显著水平时，视为“强信号”，不可按良性降权
func hasStrongFlowMonitorSignal(metrics map[string]any) bool {
	if hasHighConfidenceFlowMonitorAnomaly(metrics) {
		return true
	}
	portDensity := decodeJSONMap(mustJSONText(metrics["portDensityIndicators"]))
	return readFlowMetricFloat64(metrics, "scanScore") >= 55 ||
		readFlowMetricFloat64(metrics, "burstScore") >= 70 ||
		extractInt(portDensity, "highRiskTargetPortCount") >= 2
}

// hasHighConfidenceFlowMonitorAnomaly 用于判断目标是否具备指定数据或能力。
// 端口扫描与 ICMP 探测是最强的攻击信号，命中即视为高置信度异常
func hasHighConfidenceFlowMonitorAnomaly(metrics map[string]any) bool {
	names := extractFlowMonitorAnomalyNames(metrics)
	for _, name := range names {
		switch name {
		case "port-scan-candidate", "icmp-probe-candidate":
			return true
		}
	}
	return false
}

// extractFlowMonitorAnomalyNames 用于提取请求、令牌或流量中的关键信息。
func extractFlowMonitorAnomalyNames(metrics map[string]any) []string {
	if len(metrics) == 0 {
		return nil
	}
	items := decodeJSONArrayOfObjects(mustJSONText(metrics["anomalyCandidates"]))
	result := make([]string, 0, len(items))
	for _, item := range items {
		name := strings.TrimSpace(fmt.Sprintf("%v", item["name"]))
		if name == "" {
			continue
		}
		result = append(result, name)
	}
	return result
}

// mustJSONText 用于执行mustJSONText流程。
func mustJSONText(value any) string {
	bytes, _ := json.Marshal(value)
	return string(bytes)
}
