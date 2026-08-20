package response

// ConfigWeightResponse 用于承载配置Weight接口的响应数据。
type ConfigWeightResponse struct {
	WhoisWeight         float64 `json:"whoisWeight"`
	ReputationWeight    float64 `json:"reputationWeight"`
	AttackSurfaceWeight float64 `json:"attackSurfaceWeight"`
	BehaviorWeight      float64 `json:"behaviorWeight"`
}

// ConfigResponse 用于承载配置接口的响应数据。
type ConfigResponse struct {
	DemoMode              bool                 `json:"demoMode"`
	WhoisEndpoint         string               `json:"whoisEndpoint"`
	ReputationEndpoint    string               `json:"reputationEndpoint"`
	AttackSurfaceEndpoint string               `json:"attackSurfaceEndpoint"`
	FlowEnabled           bool                 `json:"flowEnabled"`
	FlowMode              string               `json:"flowMode"`
	FlowInterfaceName     string               `json:"flowInterfaceName"`
	FlowPcapFilePath      string               `json:"flowPcapFilePath"`
	FlowSampleProfile     string               `json:"flowSampleProfile"`
	FlowWindowSeconds     int                  `json:"flowWindowSeconds"`
	FlowTimeoutSeconds    int                  `json:"flowTimeoutSeconds"`
	NotifyChannel         string               `json:"notifyChannel"`
	MailEnabled           bool                 `json:"mailEnabled"`
	MailSender            string               `json:"mailSender"`
	MailRecipient         string               `json:"mailRecipient"`
	SMTPHost              string               `json:"smtpHost"`
	SMTPPort              int                  `json:"smtpPort"`
	SMTPUsername          string               `json:"smtpUsername"`
	SMTPUseTLS            bool                 `json:"smtpUseTLS"`
	HighRiskThreshold     float64              `json:"highRiskThreshold"`
	CriticalRiskThreshold float64              `json:"criticalRiskThreshold"`
	Weights               ConfigWeightResponse `json:"weights"`
}

// FlowInterfaceOption 用于映射流量InterfaceOption数据库记录。
type FlowInterfaceOption struct {
	Name                 string `json:"name"`
	InterfaceDescription string `json:"interfaceDescription"`
	DeviceName           string `json:"deviceName"`
	Status               string `json:"status"`
	IfIndex              int    `json:"ifIndex"`
}
