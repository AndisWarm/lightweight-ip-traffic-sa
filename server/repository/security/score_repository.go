package security

import (
	"time"

	securityModel "lightweight-ip-traffic-sa/server/model/security"

	"gorm.io/gorm"
)

// ScoreRepository 用于封装安全态势模块的数据持久化访问。
type ScoreRepository struct{}

// RiskLevelCountRow 用于承载风险LevelCount数据库查询行。
type RiskLevelCountRow struct {
	RiskLevel string
	Count     int64
}

// RiskTrendCountRow 用于承载风险TrendCount数据库查询行。
type RiskTrendCountRow struct {
	Date              string
	HighRiskTaskCount int64
	CriticalTaskCount int64
}

// Create 用于写入评分记录。
func (r *ScoreRepository) Create(db *gorm.DB, score *securityModel.RiskScore) error {
	return db.Create(score).Error
}

// FindByTaskID 用于查询评分记录。
func (r *ScoreRepository) FindByTaskID(db *gorm.DB, taskID uint64) (*securityModel.RiskScore, error) {
	var score securityModel.RiskScore
	err := db.Where("task_id = ?", taskID).First(&score).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &score, nil
}

// CountByRiskLevel 用于统计评分数据。
func (r *ScoreRepository) CountByRiskLevel(db *gorm.DB, riskLevels ...string) (int64, error) {
	var count int64
	if err := db.Model(&securityModel.RiskScore{}).
		Where("risk_level IN ?", riskLevels).
		Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// CountRiskDistribution 用于统计评分数据。
func (r *ScoreRepository) CountRiskDistribution(db *gorm.DB) ([]RiskLevelCountRow, error) {
	var rows []RiskLevelCountRow
	err := db.Model(&securityModel.RiskScore{}).
		Select("risk_level, COUNT(*) AS count").
		Group("risk_level").
		Scan(&rows).Error
	return rows, err
}

// CountRiskTrend 用于统计评分数据。
func (r *ScoreRepository) CountRiskTrend(db *gorm.DB, start time.Time) ([]RiskTrendCountRow, error) {
	var rows []RiskTrendCountRow
	err := db.Model(&securityModel.RiskScore{}).
		Select(`
			DATE_FORMAT(created_at, '%Y-%m-%d') AS date,
			SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) AS high_risk_task_count,
			SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_task_count
		`).
		Where("created_at >= ?", start).
		Group("DATE_FORMAT(created_at, '%Y-%m-%d')").
		Order("date ASC").
		Scan(&rows).Error
	return rows, err
}

// DeleteByTaskID 用于删除评分记录。
func (r *ScoreRepository) DeleteByTaskID(db *gorm.DB, taskID uint64) error {
	return db.Where("task_id = ?", taskID).Delete(&securityModel.RiskScore{}).Error
}
