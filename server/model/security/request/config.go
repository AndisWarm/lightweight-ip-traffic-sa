package request

// ConfigWeightRequest 是配置权重子对象的入参，四个维度权重均必填（binding:"required"），
// 由 UpdateConfigRequest.Weights 内嵌承载。
// ConfigWeightRequest 用于承载配置Weight接口的请求参数。
type ConfigWeightRequest struct {
	WhoisWeight         float64 `json:"whoisWeight" binding:"required"`
	ReputationWeight    float64 `json:"reputationWeight" binding:"required"`
	AttackSurfaceWeight float64 `json:"attackSurfaceWeight" binding:"required"`
	BehaviorWeight      float64 `json:"behaviorWeight" binding:"required"`
}

// UpdateConfigRequest 是更新安全配置接口的入参（JSON body）。核心字段（whois/信誉/攻击面端点、
// 通知渠道、高低危阈值、权重）必填；邮件/SMTP、流量采集字段按需填写。
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

// UpdateFlowToggleRequest 是流量开关接口的入参。Enabled 用指针 + required 校验，
// 以区分“显式传入 false”与“未传该字段”两种情况。
// UpdateFlowToggleRequest 用于承载Update流量Toggle接口的请求参数。
type UpdateFlowToggleRequest struct {
	Enabled *bool `json:"enabled" binding:"required"`
}
