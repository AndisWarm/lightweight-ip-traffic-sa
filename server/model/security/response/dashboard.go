package response

// DashboardTrendItem 用于承载总览Trend列表展示条目。
type DashboardTrendItem struct {
	Date       string `json:"date"`
	TaskCount  int64  `json:"taskCount"`
	AlertCount int64  `json:"alertCount"`
}

// DashboardRiskTrendItem 用于承载总览风险Trend列表展示条目。
type DashboardRiskTrendItem struct {
	Date              string `json:"date"`
	HighRiskTaskCount int64  `json:"highRiskTaskCount"`
	CriticalTaskCount int64  `json:"criticalTaskCount"`
}

// DashboardRiskDistributionItem 用于承载总览风险Distribution列表展示条目。
type DashboardRiskDistributionItem struct {
	RiskLevel string `json:"riskLevel"`
	Count     int64  `json:"count"`
}

// DashboardSourceCoverageItem 用于承载总览来源Coverage列表展示条目。
type DashboardSourceCoverageItem struct {
	Source string `json:"source"`
	Count  int64  `json:"count"`
}

// DashboardFlowModeItem 用于承载总览流量Mode列表展示条目。
type DashboardFlowModeItem struct {
	Mode  string `json:"mode"`
	Count int64  `json:"count"`
}

// DashboardFlowTrendItem 是总览流量趋势的逐日数据点；HasWindowMetrics/HasBehaviorSnapshot
// 标记当日是否真的有窗口/行为数据（而非全部为 0 的占位点），供前端决定是否渲染折线。
// DashboardFlowTrendItem 用于承载总览流量Trend列表展示条目。
type DashboardFlowTrendItem struct {
	Date                   string  `json:"date"`
	CollectionCount        int64   `json:"collectionCount"`
	PacketCount            int64   `json:"packetCount"`
	ByteCount              int64   `json:"byteCount"`
	ConversationCount      int64   `json:"conversationCount"`
	HighRiskPortHitCount   int64   `json:"highRiskPortHitCount"`
	DNSEventCount          int64   `json:"dnsEventCount"`
	HTTPEventCount         int64   `json:"httpEventCount"`
	TLSEventCount          int64   `json:"tlsEventCount"`
	HighBehaviorRiskCount  int64   `json:"highBehaviorRiskCount"`
	AverageBehaviorRisk    float64 `json:"averageBehaviorRisk"`
	TrackedConversationSum int64   `json:"trackedConversationSum"`
	HighEntropyPacketCount int64   `json:"highEntropyPacketCount"`
	AveragePortDensity     float64 `json:"averagePortDensity"`
	DirectionalBiasCount   int64   `json:"directionalBiasCount"`
	HasWindowMetrics       bool    `json:"hasWindowMetrics"`
	HasBehaviorSnapshot    bool    `json:"hasBehaviorSnapshot"`
}

// DashboardRecentFlowItem 用于承载总览Recent流量列表展示条目。
type DashboardRecentFlowItem struct {
	CollectionID      uint64 `json:"collectionId"`
	TaskID            uint64 `json:"taskId"`
	IP                string `json:"ip"`
	CollectionMode    string `json:"collectionMode"`
	CollectionStatus  string `json:"collectionStatus"`
	SourceName        string `json:"sourceName"`
	ParserName        string `json:"parserName"`
	PacketCount       uint64 `json:"packetCount"`
	ByteCount         uint64 `json:"byteCount"`
	ConversationCount uint32 `json:"conversationCount"`
	Summary           string `json:"summary"`
	CreatedAt         string `json:"createdAt"`
}

// DashboardSummaryResponse 是总览页接口的出参，一次返回全部统计块（任务/风险/预警/来源覆盖/流量），
// 避免前端并发请求多个统计接口。末尾的 StableChain/EnhancedSwitches 等字段用于标注原型能力边界。
// DashboardSummaryResponse 用于承载总览摘要接口的响应数据。
type DashboardSummaryResponse struct {
	TotalTaskCount          int64                           `json:"totalTaskCount"`
	HighRiskCount           int64                           `json:"highRiskCount"`
	CriticalRiskCount       int64                           `json:"criticalRiskCount"`
	AlertCount              int64                           `json:"alertCount"`
	TodayDetections         int64                           `json:"todayDetections"`
	ExposedTaskCount        int64                           `json:"exposedTaskCount"`
	HighRiskPortTasks       int64                           `json:"highRiskPortTasks"`
	Trend                   []DashboardTrendItem            `json:"trend"`
	RiskTrend               []DashboardRiskTrendItem        `json:"riskTrend"`
	RiskDistribution        []DashboardRiskDistributionItem `json:"riskDistribution"`
	BaseInfoSources         []DashboardSourceCoverageItem   `json:"baseInfoSources"`
	ReputationSources       []DashboardSourceCoverageItem   `json:"reputationSources"`
	AttackSources           []DashboardSourceCoverageItem   `json:"attackSources"`
	FlowEnabled             bool                            `json:"flowEnabled"`
	ActiveFlowMode          string                          `json:"activeFlowMode"`
	FlowCollectionCount     int64                           `json:"flowCollectionCount"`
	FlowModeDistribution    []DashboardFlowModeItem         `json:"flowModeDistribution"`
	FlowTrend               []DashboardFlowTrendItem        `json:"flowTrend"`
	RecentFlowCollections   []DashboardRecentFlowItem       `json:"recentFlowCollections"`
	FlowHistorySourceTable  string                          `json:"flowHistorySourceTable"`
	FlowTrendSourceTable    string                          `json:"flowTrendSourceTable"`
	FlowEvidenceSourceTable string                          `json:"flowEvidenceSourceTable"`
	FlowCapabilitySummary   string                          `json:"flowCapabilitySummary"`
	StableChain             []string                        `json:"stableChain"`
	EnhancedSwitches        []string                        `json:"enhancedSwitches"`
	PrototypeSources        []string                        `json:"prototypeSources"`
	BoundarySummary         string                          `json:"boundarySummary"`
	PrototypeNote           string                          `json:"prototypeNote"`
}
