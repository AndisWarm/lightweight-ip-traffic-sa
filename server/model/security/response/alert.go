package response

// AlertListItem 是预警列表单条展示项，CreatedAt 为格式化后的字符串（非原始 time.Time），便于前端直接展示。
// AlertListItem 用于承载预警List列表展示条目。
type AlertListItem struct {
	AlertID     uint64 `json:"alertId"`
	TaskNo      string `json:"taskNo"`
	TargetIP    string `json:"targetIp"`
	SourceType  string `json:"sourceType"`
	SourceLabel string `json:"sourceLabel"`
	AlertLevel  string `json:"alertLevel"`
	Channel     string `json:"channel"`
	SendStatus  string `json:"sendStatus"`
	CreatedAt   string `json:"createdAt"`
}

// PagedAlertResponse 是预警列表接口的出参：Page/PageSize/Total 回显分页信息，Items 为当前页数据。
// PagedAlertResponse 用于承载Paged预警接口的响应数据。
type PagedAlertResponse struct {
	Page     int             `json:"page"`
	PageSize int             `json:"pageSize"`
	Total    int64           `json:"total"`
	Items    []AlertListItem `json:"items"`
}

// AlertTask 用于映射预警任务数据库记录。
type AlertTask struct {
	TaskID     uint64 `json:"taskId"`
	TaskNo     string `json:"taskNo"`
	TargetIP   string `json:"targetIp"`
	TaskStatus string `json:"taskStatus"`
}

// AlertScore 用于映射预警评分数据库记录。
type AlertScore struct {
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
}

// AlertDetailResponse 是预警详情接口的出参，内嵌 Task/Score 子对象；实时监控预警因无任务，
// Task/Score 可能为 nil，前端需做空值容错。
// AlertDetailResponse 用于承载预警Detail接口的响应数据。
type AlertDetailResponse struct {
	AlertID          uint64      `json:"alertId"`
	AlertLevel       string      `json:"alertLevel"`
	AlertTitle       string      `json:"alertTitle"`
	AlertContent     string      `json:"alertContent"`
	Channel          string      `json:"channel"`
	SendStatus       string      `json:"sendStatus"`
	SendTime         string      `json:"sendTime"`
	CreatedAt        string      `json:"createdAt"`
	SourceType       string      `json:"sourceType"`
	SourceLabel      string      `json:"sourceLabel"`
	MonitorSessionID string      `json:"monitorSessionId"`
	Task             *AlertTask  `json:"task"`
	Score            *AlertScore `json:"score"`
}
