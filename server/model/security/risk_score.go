package security

import "time"

// RiskScore 用于映射风险评分数据库记录。
type RiskScore struct {
	ID                  uint64    `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	TaskID              uint64    `json:"taskId" gorm:"column:task_id;uniqueIndex"`
	IP                  string    `json:"ip" gorm:"column:ip;size:64;index"`
	BaseScore           float64   `json:"baseScore" gorm:"column:base_score;type:decimal(10,2)"`
	ReputationScore     float64   `json:"reputationScore" gorm:"column:reputation_score;type:decimal(10,2)"`
	AttackSurfaceScore  float64   `json:"attackSurfaceScore" gorm:"column:attack_surface_score;type:decimal(10,2)"`
	BehaviorScore       float64   `json:"behaviorScore" gorm:"column:behavior_score;type:decimal(10,2)"`
	RuleAdjustmentValue float64   `json:"ruleAdjustmentValue" gorm:"column:rule_adjustment_value;type:decimal(10,2)"`
	ScoreValue          float64   `json:"scoreValue" gorm:"column:score_value;type:decimal(10,2);index"`
	RiskLevel           string    `json:"riskLevel" gorm:"column:risk_level;size:32;index"`
	ScoreReason         string    `json:"scoreReason" gorm:"column:score_reason;size:500"`
	RuleAdjustment      string    `json:"ruleAdjustment" gorm:"column:rule_adjustment;size:255"`
	AlgorithmVersion    string    `json:"algorithmVersion" gorm:"column:algorithm_version;size:128"`
	WeightProfile       string    `json:"weightProfile" gorm:"column:weight_profile;type:json"`
	IsAlertTriggered    bool      `json:"isAlertTriggered" gorm:"column:is_alert_triggered;index"`
	CreatedAt           time.Time `json:"createdAt" gorm:"column:created_at;autoCreateTime"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (RiskScore) TableName() string {
	return "sec_risk_score"
}
