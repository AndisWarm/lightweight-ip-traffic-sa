package response

// TaskCreateResponse 用于承载任务Create接口的响应数据。
type TaskCreateResponse struct {
	TaskID       uint64  `json:"taskId"`
	TaskNo       string  `json:"taskNo"`
	TargetIP     string  `json:"targetIp"`
	TaskStatus   string  `json:"taskStatus"`
	ScoreValue   float64 `json:"scoreValue"`
	RiskLevel    string  `json:"riskLevel"`
	AlertCreated bool    `json:"alertCreated"`
}

// TaskListItem 是任务列表单条展示项，CreatedAt 为格式化字符串；未评分任务的 ScoreValue 为 0、RiskLevel 为 LOW。
// TaskListItem 用于承载任务List列表展示条目。
type TaskListItem struct {
	TaskID     uint64  `json:"taskId"`
	TaskNo     string  `json:"taskNo"`
	TargetIP   string  `json:"targetIp"`
	TaskStatus string  `json:"taskStatus"`
	ScoreValue float64 `json:"scoreValue"`
	RiskLevel  string  `json:"riskLevel"`
	CreatedAt  string  `json:"createdAt"`
}

// PagedTaskResponse 是任务列表接口的出参，回显 SortBy/SortOrder 让前端保持当前排序状态。
// PagedTaskResponse 用于承载Paged任务接口的响应数据。
type PagedTaskResponse struct {
	Page      int            `json:"page"`
	PageSize  int            `json:"pageSize"`
	Total     int64          `json:"total"`
	SortBy    string         `json:"sortBy"`
	SortOrder string         `json:"sortOrder"`
	Items     []TaskListItem `json:"items"`
}

// TaskBaseInfo 用于映射任务基础信息数据库记录。
type TaskBaseInfo struct {
	Country        string         `json:"country"`
	Region         string         `json:"region"`
	City           string         `json:"city"`
	ISP            string         `json:"isp"`
	WhoisOrg       string         `json:"whoisOrg"`
	WhoisContact   string         `json:"whoisContact"`
	Latitude       float64        `json:"latitude"`
	Longitude      float64        `json:"longitude"`
	TimeZone       string         `json:"timeZone"`
	AccuracyRadius int            `json:"accuracyRadius"`
	SourceName     string         `json:"sourceName"`
	SourceChain    []string       `json:"sourceChain"`
	SourceSummary  string         `json:"sourceSummary"`
	RawPayload     map[string]any `json:"rawPayload"`
}

// TaskEvidenceItem 用于承载任务Evidence列表展示条目。
type TaskEvidenceItem struct {
	CategoryKey   string `json:"categoryKey"`
	CategoryLabel string `json:"categoryLabel"`
	Source        string `json:"source"`
	Title         string `json:"title"`
	Summary       string `json:"summary"`
	RiskHint      string `json:"riskHint"`
}

// TaskScoreFactor 用于映射任务评分Factor数据库记录。
type TaskScoreFactor struct {
	Key          string  `json:"key"`
	Label        string  `json:"label"`
	RawScore     float64 `json:"rawScore"`
	Weight       float64 `json:"weight"`
	Contribution float64 `json:"contribution"`
	// 兼容字段：仅供旧数据回退或调试使用，新展示逻辑应优先消费 displayBasis。
	Basis        string `json:"basis"`
	DisplayBasis string `json:"displayBasis"`
}

// TaskSourceChainGroup 用于组织任务来源链路分组数据。
type TaskSourceChainGroup struct {
	Key     string   `json:"key"`
	Label   string   `json:"label"`
	Chain   []string `json:"chain"`
	Summary string   `json:"summary"`
}

// TaskEvidenceGroup 用于组织任务Evidence分组数据。
type TaskEvidenceGroup struct {
	Key   string             `json:"key"`
	Title string             `json:"title"`
	Items []TaskEvidenceItem `json:"items"`
}

// TaskFeature 用于映射任务特征数据库记录。
type TaskFeature struct {
	ReputationScore    float64        `json:"reputationScore"`
	OpenPortCount      int            `json:"openPortCount"`
	HighRiskPortCount  int            `json:"highRiskPortCount"`
	GeoRiskFlag        bool           `json:"geoRiskFlag"`
	FlowMode           string         `json:"flowMode"`
	FlowStatus         string         `json:"flowStatus"`
	FlowSummary        string         `json:"flowSummary"`
	FlowCapabilityText string         `json:"flowCapabilityText"`
	FlowBoundaryText   string         `json:"flowBoundaryText"`
	FlowSourceSummary  string         `json:"flowSourceSummary"`
	FeatureDigest      string         `json:"featureDigest"`
	NormalizedFeatures map[string]any `json:"normalizedFeatures"`
	// 兼容字段：仅供旧页面或调试回退使用，新逻辑请优先消费 sourceSummary/sourceChainGroups。
	SourceName string `json:"sourceName"`
	// 兼容字段：仅供旧页面或调试回退使用，新逻辑请优先消费 sourceSummary/sourceChainGroups。
	DataSources []string `json:"dataSources"`
	// 兼容字段：仅供旧页面或调试回退使用，新逻辑请优先消费 sourceSummary/sourceChainGroups。
	DataSourceChains   map[string][]string    `json:"dataSourceChains"`
	SourceSummary      string                 `json:"sourceSummary"`
	SourceChainGroups  []TaskSourceChainGroup `json:"sourceChainGroups"`
	FlowSourceChain    []string               `json:"flowSourceChain"`
	EvidenceItems      []TaskEvidenceItem     `json:"evidenceItems"`
	EvidenceGroups     []TaskEvidenceGroup    `json:"evidenceGroups"`
	FlowPrototypeItems []TaskEvidenceItem     `json:"flowPrototypeItems"`
	ScoreFactors       []TaskScoreFactor      `json:"scoreFactors"`
}

// TaskFlowDetail 用于映射任务流量Detail数据库记录。
type TaskFlowDetail struct {
	CollectionID             uint64                `json:"collectionId"`
	CollectionMode           string                `json:"collectionMode"`
	CollectionStatus         string                `json:"collectionStatus"`
	HistorySourceTable       string                `json:"historySourceTable"`
	TrendSourceTable         string                `json:"trendSourceTable"`
	EvidenceSourceTable      string                `json:"evidenceSourceTable"`
	IsTraceable              bool                  `json:"isTraceable"`
	HasRealMetrics           bool                  `json:"hasRealMetrics"`
	SourceName               string                `json:"sourceName"`
	SourceChain              []string              `json:"sourceChain"`
	ParserName               string                `json:"parserName"`
	ParserReady              bool                  `json:"parserReady"`
	IntegrationStage         string                `json:"integrationStage"`
	PrototypeBoundary        string                `json:"prototypeBoundary"`
	InputKind                string                `json:"inputKind"`
	Summary                  string                `json:"summary"`
	BehaviorRiskScore        float64               `json:"behaviorRiskScore"`
	WindowSeconds            int                   `json:"windowSeconds"`
	SampleProfile            string                `json:"sampleProfile"`
	InterfaceName            string                `json:"interfaceName"`
	PcapFilePath             string                `json:"pcapFilePath"`
	PacketCount              uint64                `json:"packetCount"`
	ByteCount                uint64                `json:"byteCount"`
	ConversationCount        uint32                `json:"conversationCount"`
	WindowCount              int                   `json:"windowCount"`
	InputSnapshot            map[string]any        `json:"inputSnapshot"`
	ParsedMetrics            map[string]any        `json:"parsedMetrics"`
	EvidenceSnapshot         map[string]any        `json:"evidenceSnapshot"`
	FeatureDigest            string                `json:"featureDigest"`
	PeakPPS                  float64               `json:"peakPps"`
	BurstScore               float64               `json:"burstScore"`
	ScanScore                float64               `json:"scanScore"`
	ProtocolDistribution     map[string]any        `json:"protocolDistribution"`
	DNSTopQuestions          []map[string]any      `json:"dnsTopQuestions"`
	DNSQueryTypeHints        []map[string]any      `json:"dnsQueryTypeHints"`
	HTTPHostHints            []map[string]any      `json:"httpHostHints"`
	HTTPMethodHints          []map[string]any      `json:"httpMethodHints"`
	HTTPStatusHints          []map[string]any      `json:"httpStatusHints"`
	TLSHandshakeHints        []map[string]any      `json:"tlsHandshakeHints"`
	TLSVersionHints          []map[string]any      `json:"tlsVersionHints"`
	ApplicationSignals       []string              `json:"applicationSignals"`
	DirectionalityIndicators map[string]any        `json:"directionalityIndicators"`
	PortDensityIndicators    map[string]any        `json:"portDensityIndicators"`
	PayloadEntropyIndicators map[string]any        `json:"payloadEntropyIndicators"`
	TopPorts                 []map[string]any      `json:"topPorts"`
	PeerEndpoints            []map[string]any      `json:"peerEndpoints"`
	MappingBoundary          map[string]any        `json:"mappingBoundary"`
	EvidenceItems            []TaskEvidenceItem    `json:"evidenceItems"`
	CollectionHistory        []TaskFlowHistoryItem `json:"collectionHistory"`
	Trend                    []TaskFlowWindowItem  `json:"trend"`
	EvidenceTimeline         []TaskFlowWindowItem  `json:"evidenceTimeline"`
	StartedAt                string                `json:"startedAt"`
	FinishedAt               string                `json:"finishedAt"`
	CreatedAt                string                `json:"createdAt"`
}

// TaskFlowHistoryItem 用于承载任务流量History列表展示条目。
type TaskFlowHistoryItem struct {
	CollectionID      uint64  `json:"collectionId"`
	CollectionMode    string  `json:"collectionMode"`
	CollectionStatus  string  `json:"collectionStatus"`
	ParserName        string  `json:"parserName"`
	SourceName        string  `json:"sourceName"`
	Summary           string  `json:"summary"`
	PacketCount       uint64  `json:"packetCount"`
	ByteCount         uint64  `json:"byteCount"`
	ConversationCount uint32  `json:"conversationCount"`
	WindowCount       int     `json:"windowCount"`
	BehaviorRiskScore float64 `json:"behaviorRiskScore"`
	FeatureDigest     string  `json:"featureDigest"`
	CreatedAt         string  `json:"createdAt"`
}

// TaskFlowWindowItem 用于承载任务流量Window列表展示条目。
type TaskFlowWindowItem struct {
	WindowNo             uint32         `json:"windowNo"`
	WindowStart          string         `json:"windowStart"`
	WindowEnd            string         `json:"windowEnd"`
	PacketCount          uint64         `json:"packetCount"`
	ByteCount            uint64         `json:"byteCount"`
	ConversationCount    uint32         `json:"conversationCount"`
	InboundPacketCount   uint64         `json:"inboundPacketCount"`
	OutboundPacketCount  uint64         `json:"outboundPacketCount"`
	InboundByteCount     uint64         `json:"inboundByteCount"`
	OutboundByteCount    uint64         `json:"outboundByteCount"`
	TCPPacketCount       uint64         `json:"tcpPacketCount"`
	UDPPacketCount       uint64         `json:"udpPacketCount"`
	ICMPPacketCount      uint64         `json:"icmpPacketCount"`
	DNSEventCount        uint32         `json:"dnsEventCount"`
	HTTPEventCount       uint32         `json:"httpEventCount"`
	TLSEventCount        uint32         `json:"tlsEventCount"`
	HighRiskPortHitCount uint32         `json:"highRiskPortHitCount"`
	EvidencePayload      map[string]any `json:"evidencePayload"`
}

// TaskScore 用于映射任务评分数据库记录。
type TaskScore struct {
	BaseScore           float64            `json:"baseScore"`
	ReputationScore     float64            `json:"reputationScore"`
	AttackSurfaceScore  float64            `json:"attackSurfaceScore"`
	BehaviorScore       float64            `json:"behaviorScore"`
	RuleAdjustmentValue float64            `json:"ruleAdjustmentValue"`
	ScoreValue          float64            `json:"scoreValue"`
	RiskLevel           string             `json:"riskLevel"`
	ScoreReason         string             `json:"scoreReason"`
	RuleAdjustment      string             `json:"ruleAdjustment"`
	AlgorithmVersion    string             `json:"algorithmVersion"`
	WeightProfile       map[string]float64 `json:"weightProfile"`
	IsAlertTriggered    bool               `json:"isAlertTriggered"`
}

// TaskAlertSummary 用于映射任务预警摘要数据库记录。
type TaskAlertSummary struct {
	AlertID      uint64 `json:"alertId"`
	AlertLevel   string `json:"alertLevel"`
	AlertTitle   string `json:"alertTitle"`
	AlertContent string `json:"alertContent"`
	Channel      string `json:"channel"`
	SendStatus   string `json:"sendStatus"`
	SendTime     string `json:"sendTime"`
	CreatedAt    string `json:"createdAt"`
}

// TaskDetailResponse 是任务详情接口的出参，内嵌 BaseInfo/Features/Flow/Score/Alert 五个子对象，
// 由 service 层把 repository 聚合的 TaskDetailBundle 翻译成前端友好的结构。
// TaskDetailResponse 用于承载任务Detail接口的响应数据。
type TaskDetailResponse struct {
	TaskID       uint64            `json:"taskId"`
	TaskNo       string            `json:"taskNo"`
	InputType    string            `json:"inputType"`
	InputValue   string            `json:"inputValue"`
	TargetIP     string            `json:"targetIp"`
	TaskStatus   string            `json:"taskStatus"`
	ScoreValue   float64           `json:"scoreValue"`
	RiskLevel    string            `json:"riskLevel"`
	AlertCreated bool              `json:"alertCreated"`
	CreatedBy    string            `json:"createdBy"`
	StartedAt    string            `json:"startedAt"`
	FinishedAt   string            `json:"finishedAt"`
	CreatedAt    string            `json:"createdAt"`
	ErrorMessage string            `json:"errorMessage"`
	BaseInfo     *TaskBaseInfo     `json:"baseInfo"`
	Features     *TaskFeature      `json:"features"`
	Flow         *TaskFlowDetail   `json:"flow"`
	Score        *TaskScore        `json:"score"`
	Alert        *TaskAlertSummary `json:"alert"`
}
