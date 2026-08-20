package request

// ConfigWeightRequest 用于承载配置Weight接口的请求参数。
type ConfigWeightRequest struct {
	WhoisWeight         float64 `json:"whoisWeight" binding:"required"`
	ReputationWeight    float64 `json:"reputationWeight" binding:"required"`
	AttackSurfaceWeight float64 `json:"attackSurfaceWeight" binding:"required"`
	BehaviorWeight      float64 `json:"behaviorWeight" binding:"required"`
}

// UpdateConfigRequest 用于承载Update配置接口的请求参数。
type UpdateConfigRequest struct {
	WhoisEndpoint         string              `json:"whoisEndpoint" binding:"required"`
	ReputationEndpoint    string              `json:"reputationEndpoint" binding:"required"`
	AttackSurfaceEndpoint string              `json:"attackSurfaceEndpoint" binding:"required"`
	FlowEnabled           bool                `json:"flowEnabled"`
	FlowMode              string              `json:"flowMode"`
	FlowInterfaceName     string              `json:"flowInterfaceName"`
	FlowPcapFilePath      string              `json:"flowPcapFilePath"`
	FlowSampleProfile     string              `json:"flowSampleProfile"`
	FlowWindowSeconds     int                 `json:"flowWindowSeconds"`
	FlowTimeoutSeconds    int                 `json:"flowTimeoutSeconds"`
	NotifyChannel         string              `json:"notifyChannel" binding:"required"`
	MailEnabled           bool                `json:"mailEnabled"`
	MailSender            string              `json:"mailSender"`
	MailRecipient         string              `json:"mailRecipient"`
	SMTPHost              string              `json:"smtpHost"`
	SMTPPort              int                 `json:"smtpPort"`
	SMTPUsername          string              `json:"smtpUsername"`
	SMTPPassword          string              `json:"smtpPassword"`
	SMTPUseTLS            bool                `json:"smtpUseTLS"`
	HighRiskThreshold     float64             `json:"highRiskThreshold" binding:"required"`
	CriticalRiskThreshold float64             `json:"criticalRiskThreshold" binding:"required"`
	Weights               ConfigWeightRequest `json:"weights" binding:"required"`
}

// UpdateFlowToggleRequest 用于承载Update流量Toggle接口的请求参数。
type UpdateFlowToggleRequest struct {
	Enabled *bool `json:"enabled" binding:"required"`
}
