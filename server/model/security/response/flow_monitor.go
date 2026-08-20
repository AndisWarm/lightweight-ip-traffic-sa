package response

// FlowMonitorSessionResponse 用于承载流量监控Session接口的响应数据。
type FlowMonitorSessionResponse struct {
	SessionID                string                   `json:"sessionId"`
	OwnerUserID              uint64                   `json:"ownerUserId"`
	OwnerUsername            string                   `json:"ownerUsername"`
	OwnerDisplayName         string                   `json:"ownerDisplayName"`
	OwnerRoleCode            string                   `json:"ownerRoleCode"`
	InterfaceName            string                   `json:"interfaceName"`
	Status                   string                   `json:"status"`
	LastAnalysisStatus       string                   `json:"lastAnalysisStatus"`
	Summary                  string                   `json:"summary"`
	ParserName               string                   `json:"parserName"`
	StartedAt                string                   `json:"startedAt"`
	FinishedAt               string                   `json:"finishedAt"`
	LastAnalyzedAt           string                   `json:"lastAnalyzedAt"`
	WindowSeconds            int                      `json:"windowSeconds"`
	RefreshIntervalSeconds   int                      `json:"refreshIntervalSeconds"`
	PacketCount              uint64                   `json:"packetCount"`
	ByteCount                uint64                   `json:"byteCount"`
	ConversationCount        uint32                   `json:"conversationCount"`
	BehaviorRiskScore        float64                  `json:"behaviorRiskScore"`
	PeakPPS                  float64                  `json:"peakPps"`
	BurstScore               float64                  `json:"burstScore"`
	ScanScore                float64                  `json:"scanScore"`
	DNSEventCount            uint64                   `json:"dnsEventCount"`
	HTTPEventCount           uint64                   `json:"httpEventCount"`
	TLSEventCount            uint64                   `json:"tlsEventCount"`
	ProtocolDistribution     map[string]any           `json:"protocolDistribution"`
	DNSTopQuestions          []map[string]any         `json:"dnsTopQuestions"`
	HTTPHostHints            []map[string]any         `json:"httpHostHints"`
	TLSHandshakeHints        []map[string]any         `json:"tlsHandshakeHints"`
	ApplicationSignals       []string                 `json:"applicationSignals"`
	DirectionalityIndicators map[string]any           `json:"directionalityIndicators"`
	PortDensityIndicators    map[string]any           `json:"portDensityIndicators"`
	PayloadEntropyIndicators map[string]any           `json:"payloadEntropyIndicators"`
	MetricTrend              []FlowMonitorMetricPoint `json:"metricTrend"`
	LatestAlert              *FlowMonitorAlertSummary `json:"latestAlert"`
	ErrorMessage             string                   `json:"errorMessage"`
	DebugPayload             map[string]any           `json:"debugPayload"`
}

// FlowMonitorMetricPoint 用于映射流量监控MetricPoint数据库记录。
type FlowMonitorMetricPoint struct {
	AnalyzedAt        string  `json:"analyzedAt"`
	PacketCount       uint64  `json:"packetCount"`
	ByteCount         uint64  `json:"byteCount"`
	ConversationCount uint32  `json:"conversationCount"`
	BehaviorRiskScore float64 `json:"behaviorRiskScore"`
	PeakPPS           float64 `json:"peakPps"`
	BurstScore        float64 `json:"burstScore"`
	ScanScore         float64 `json:"scanScore"`
	DNSEventCount     uint64  `json:"dnsEventCount"`
	HTTPEventCount    uint64  `json:"httpEventCount"`
	TLSEventCount     uint64  `json:"tlsEventCount"`
}

// FlowMonitorAlertSummary 用于映射流量监控预警摘要数据库记录。
type FlowMonitorAlertSummary struct {
	AlertID          uint64 `json:"alertId"`
	AlertLevel       string `json:"alertLevel"`
	AlertTitle       string `json:"alertTitle"`
	AlertContent     string `json:"alertContent"`
	CreatedAt        string `json:"createdAt"`
	SourceLabel      string `json:"sourceLabel"`
	MonitorSessionID string `json:"monitorSessionId"`
}

// FlowMonitorObserverPanelResponse 用于承载流量监控ObserverPanel接口的响应数据。
type FlowMonitorObserverPanelResponse struct {
	TargetUsername       string                       `json:"targetUsername"`
	TargetDisplayName    string                       `json:"targetDisplayName"`
	TargetRoleCode       string                       `json:"targetRoleCode"`
	RunningSessionCount  int                          `json:"runningSessionCount"`
	TotalSessionCount    int                          `json:"totalSessionCount"`
	TotalPacketCount     uint64                       `json:"totalPacketCount"`
	TotalByteCount       uint64                       `json:"totalByteCount"`
	MaxBehaviorRiskScore float64                      `json:"maxBehaviorRiskScore"`
	LatestAnalyzedAt     string                       `json:"latestAnalyzedAt"`
	Sessions             []FlowMonitorSessionResponse `json:"sessions"`
}
