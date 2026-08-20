package security

import "time"

// FeatureSnapshot 对应 sec_feature_snapshot 表，保存单任务的静态特征快照（信誉分/开放端口/地理风险），
// 是评分引擎的输入之一；normalized_features 以 JSON 存储归一化后的完整特征。
// FeatureSnapshot 用于映射特征快照数据库记录。
type FeatureSnapshot struct {
	ID                 uint64    `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	TaskID             uint64    `json:"taskId" gorm:"column:task_id;uniqueIndex"`
	IP                 string    `json:"ip" gorm:"column:ip;size:64;index"`
	ReputationScore    float64   `json:"reputationScore" gorm:"column:reputation_score;type:decimal(10,2)"`
	OpenPortCount      int       `json:"openPortCount" gorm:"column:open_port_count"`
	HighRiskPortCount  int       `json:"highRiskPortCount" gorm:"column:high_risk_port_count"`
	GeoRiskFlag        bool      `json:"geoRiskFlag" gorm:"column:geo_risk_flag"`
	NormalizedFeatures string    `json:"normalizedFeatures" gorm:"column:normalized_features;type:json"`
	FeatureDigest      string    `json:"featureDigest" gorm:"column:feature_digest;size:128"`
	CreatedAt          time.Time `json:"createdAt" gorm:"column:created_at;autoCreateTime"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (FeatureSnapshot) TableName() string {
	return "sec_feature_snapshot"
}
