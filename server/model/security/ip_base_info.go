package security

import "time"

// IPBaseInfo 对应 sec_ip_base_info 表，保存 IP 的基础画像（地理位置/ISP/WHOIS），
// task_id 唯一索引保证一个任务只有一条画像；raw_payload 存 GeoLite2/RDAP 原始 JSON 供后续分析。
// IPBaseInfo 用于映射IP基础信息数据库记录。
type IPBaseInfo struct {
	ID           uint64    `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	TaskID       uint64    `json:"taskId" gorm:"column:task_id;uniqueIndex"`
	IP           string    `json:"ip" gorm:"column:ip;size:64;index"`
	Country      string    `json:"country" gorm:"column:country;size:64"`
	Region       string    `json:"region" gorm:"column:region;size:64"`
	City         string    `json:"city" gorm:"column:city;size:64"`
	ISP          string    `json:"isp" gorm:"column:isp;size:128"`
	WhoisOrg     string    `json:"whoisOrg" gorm:"column:whois_org;size:255"`
	WhoisContact string    `json:"whoisContact" gorm:"column:whois_contact;size:255"`
	RawPayload   string    `json:"rawPayload" gorm:"column:raw_payload;type:json"`
	CreatedAt    time.Time `json:"createdAt" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt    time.Time `json:"updatedAt" gorm:"column:updated_at;autoUpdateTime"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (IPBaseInfo) TableName() string {
	return "sec_ip_base_info"
}
