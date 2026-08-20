package security

import (
	"time"

	securityModel "lightweight-ip-traffic-sa/server/model/security"

	"gorm.io/gorm"
)

// FlowFeatureSnapshotRepository 用于封装安全态势模块的数据持久化访问。
type FlowFeatureSnapshotRepository struct{}

// FlowBehaviorTrendRow 用于承载流量BehaviorTrend数据库查询行。
type FlowBehaviorTrendRow struct {
	Date                   string
	HighBehaviorRiskCount  int64
	AverageBehaviorRisk    float64
	TrackedConversationSum int64
	HighEntropyPacketCount int64
	AveragePortDensity     float64
	DirectionalBiasCount   int64
}

// Create 用于写入流量特征快照记录。
func (r *FlowFeatureSnapshotRepository) Create(db *gorm.DB, snapshot *securityModel.FlowFeatureSnapshot) error {
	return db.Create(snapshot).Error
}

// FindByCollectionID 用于查询流量特征快照记录。
func (r *FlowFeatureSnapshotRepository) FindByCollectionID(db *gorm.DB, collectionID uint64) (*securityModel.FlowFeatureSnapshot, error) {
	var snapshot securityModel.FlowFeatureSnapshot
	err := db.Where("collection_id = ?", collectionID).First(&snapshot).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &snapshot, nil
}

// FindLatestByTaskID 用于查询流量特征快照记录。
func (r *FlowFeatureSnapshotRepository) FindLatestByTaskID(db *gorm.DB, taskID uint64) (*securityModel.FlowFeatureSnapshot, error) {
	var snapshot securityModel.FlowFeatureSnapshot
	err := db.Where("task_id = ?", taskID).
		Order("created_at DESC").
		First(&snapshot).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &snapshot, nil
}

// CountBehaviorTrend 用于统计流量特征快照数据。
func (r *FlowFeatureSnapshotRepository) CountBehaviorTrend(db *gorm.DB, start time.Time) ([]FlowBehaviorTrendRow, error) {
	var rows []FlowBehaviorTrendRow
	highEntropyExpr := "0"
	if db.Migrator().HasColumn(&securityModel.FlowFeatureSnapshot{}, "high_entropy_packet_count") {
		highEntropyExpr = "COALESCE(SUM(high_entropy_packet_count), 0)"
	}
	portDensityExpr := "0"
	if db.Migrator().HasColumn(&securityModel.FlowFeatureSnapshot{}, "target_port_density") {
		portDensityExpr = "COALESCE(AVG(target_port_density), 0)"
	}
	directionalBiasExpr := "0"
	if db.Migrator().HasColumn(&securityModel.FlowFeatureSnapshot{}, "dominant_direction") {
		directionalBiasExpr = "COALESCE(SUM(CASE WHEN dominant_direction IS NOT NULL AND dominant_direction <> '' AND dominant_direction <> 'balanced' THEN 1 ELSE 0 END), 0)"
	}
	err := db.Model(&securityModel.FlowFeatureSnapshot{}).
		Select(`
			DATE_FORMAT(created_at, '%Y-%m-%d') AS date,
			COALESCE(SUM(CASE WHEN behavior_risk_score >= 60 THEN 1 ELSE 0 END), 0) AS high_behavior_risk_count,
			COALESCE(AVG(behavior_risk_score), 0) AS average_behavior_risk,
			COALESCE(SUM(conversation_count), 0) AS tracked_conversation_sum,
			`+highEntropyExpr+` AS high_entropy_packet_count,
			`+portDensityExpr+` AS average_port_density,
			`+directionalBiasExpr+` AS directional_bias_count
		`).
		Where("created_at >= ?", start).
		Group("DATE_FORMAT(created_at, '%Y-%m-%d')").
		Order("date ASC").
		Scan(&rows).Error
	return rows, err
}

// DeleteByTaskID 用于删除流量特征快照记录。
func (r *FlowFeatureSnapshotRepository) DeleteByTaskID(db *gorm.DB, taskID uint64) error {
	return db.Where("task_id = ?", taskID).Delete(&securityModel.FlowFeatureSnapshot{}).Error
}
