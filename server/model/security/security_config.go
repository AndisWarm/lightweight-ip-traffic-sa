package security

import "time"

// SecurityConfig 对应 sec_security_config 表，设计为单行运行时配置：流量采集参数、通知/SMTP 参数、
// 高低危阈值与各维度权重，可在线修改而无需重启服务（优先级高于 config.yaml 默认值）。
// SecurityConfig 用于承载安全运行配置。
type SecurityConfig struct {
	ID                    uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	WhoisEndpoint         string    `gorm:"size:255;not null" json:"whoisEndpoint"`
	ReputationEndpoint    string    `gorm:"size:255;not null" json:"reputationEndpoint"`
	AttackSurfaceEndpoint string    `gorm:"column:attack_surface_endpoint;size:255;not null;default:'limited-port-scan'" json:"attackSurfaceEndpoint"`
	FlowEnabled           bool      `gorm:"column:flow_enabled;not null;default:false" json:"flowEnabled"`
	FlowMode              string    `gorm:"column:flow_mode;size:32;not null;default:'sample'" json:"flowMode"`
	FlowInterfaceName     string    `gorm:"column:flow_interface_name;size:128" json:"flowInterfaceName"`
	FlowPcapFilePath      string    `gorm:"column:flow_pcap_file_path;size:255" json:"flowPcapFilePath"`
	FlowSampleProfile     string    `gorm:"column:flow_sample_profile;size:128" json:"flowSampleProfile"`
	FlowWindowSeconds     int       `gorm:"column:flow_window_seconds;not null;default:60" json:"flowWindowSeconds"`
	FlowTimeoutSeconds    int       `gorm:"column:flow_timeout_seconds;not null;default:5" json:"flowTimeoutSeconds"`
	NotifyChannel         string    `gorm:"size:64;not null" json:"notifyChannel"`
	MailEnabled           bool      `gorm:"column:mail_enabled;not null;default:false" json:"mailEnabled"`
	MailSender            string    `gorm:"column:mail_sender;size:255" json:"mailSender"`
	MailRecipient         string    `gorm:"column:mail_recipient;size:255" json:"mailRecipient"`
	SMTPHost              string    `gorm:"column:smtp_host;size:255" json:"smtpHost"`
	SMTPPort              int       `gorm:"column:smtp_port;not null;default:25" json:"smtpPort"`
	SMTPUsername          string    `gorm:"column:smtp_username;size:255" json:"smtpUsername"`
	SMTPPassword          string    `gorm:"column:smtp_password;size:255" json:"smtpPassword"`
	SMTPUseTLS            bool      `gorm:"column:smtp_use_tls;not null;default:false" json:"smtpUseTLS"`
	HighRiskThreshold     float64   `gorm:"type:decimal(10,2);not null" json:"highRiskThreshold"`
	CriticalRiskThreshold float64   `gorm:"type:decimal(10,2);not null" json:"criticalRiskThreshold"`
	WhoisWeight           float64   `gorm:"type:decimal(10,4);not null" json:"whoisWeight"`
	ReputationWeight      float64   `gorm:"type:decimal(10,4);not null" json:"reputationWeight"`
	AttackSurfaceWeight   float64   `gorm:"type:decimal(10,4);not null" json:"attackSurfaceWeight"`
	BehaviorWeight        float64   `gorm:"type:decimal(10,4);not null" json:"behaviorWeight"`
	CreatedAt             time.Time `gorm:"autoCreateTime" json:"createdAt"`
	UpdatedAt             time.Time `gorm:"autoUpdateTime" json:"updatedAt"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (SecurityConfig) TableName() string {
	return "sec_security_config"
}
