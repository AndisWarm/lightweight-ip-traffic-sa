package security

import (
	"time"

	securityModel "lightweight-ip-traffic-sa/server/model/security"

	"gorm.io/gorm"
)

// FlowWindowAggregateRepository 用于封装安全态势模块的数据持久化访问。
type FlowWindowAggregateRepository struct{}

// FlowWindowTrendRow 用于承载流量WindowTrend数据库查询行。
type FlowWindowTrendRow struct {
	Date              string
	PacketCount       int64
	ByteCount         int64
	ConversationCount int64
}

// FlowWindowSummaryRow 用于承载流量Window摘要数据库查询行。
type FlowWindowSummaryRow struct {
	Date                 string
	PacketCount          int64
	ByteCount            int64
	ConversationCount    int64
	HighRiskPortHitCount int64
	DNSEventCount        int64
	HTTPEventCount       int64
	TLSEventCount        int64
}

// CreateInBatches 用于写入流量WindowAggregate记录。
func (r *FlowWindowAggregateRepository) CreateInBatches(db *gorm.DB, rows []securityModel.FlowWindowAggregate, batchSize int) error {
	if len(rows) == 0 {
		return nil
	}
	if batchSize <= 0 {
		batchSize = 200
	}
	return db.CreateInBatches(rows, batchSize).Error
}

// ListByTaskID 用于查询流量WindowAggregate列表。
func (r *FlowWindowAggregateRepository) ListByTaskID(db *gorm.DB, taskID uint64, limit int) ([]securityModel.FlowWindowAggregate, error) {
	var rows []securityModel.FlowWindowAggregate
	query := db.Where("task_id = ?", taskID).
		Order("window_start DESC").
		Order("id DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	err := query.Find(&rows).Error
	return rows, err
}

// ListByCollectionID 用于查询流量WindowAggregate列表。
func (r *FlowWindowAggregateRepository) ListByCollectionID(db *gorm.DB, collectionID uint64, limit int) ([]securityModel.FlowWindowAggregate, error) {
	var rows []securityModel.FlowWindowAggregate
	query := db.Where("collection_id = ?", collectionID).
		Order("window_start DESC").
		Order("id DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	err := query.Find(&rows).Error
	return rows, err
}

// CountDailyTrend 用于统计流量WindowAggregate数据。
func (r *FlowWindowAggregateRepository) CountDailyTrend(db *gorm.DB, start time.Time) ([]FlowWindowTrendRow, error) {
	var rows []FlowWindowTrendRow
	err := db.Model(&securityModel.FlowWindowAggregate{}).
		Select(`
			DATE_FORMAT(window_start, '%Y-%m-%d') AS date,
			COALESCE(SUM(packet_count), 0) AS packet_count,
			COALESCE(SUM(byte_count), 0) AS byte_count,
			COALESCE(SUM(conversation_count), 0) AS conversation_count
		`).
		Where("window_start >= ?", start).
		Group("DATE_FORMAT(window_start, '%Y-%m-%d')").
		Order("date ASC").
		Scan(&rows).Error
	return rows, err
}

// CountDailySummary 用于统计流量WindowAggregate数据。
func (r *FlowWindowAggregateRepository) CountDailySummary(db *gorm.DB, start time.Time) ([]FlowWindowSummaryRow, error) {
	var rows []FlowWindowSummaryRow
	err := db.Model(&securityModel.FlowWindowAggregate{}).
		Select(`
			DATE_FORMAT(window_start, '%Y-%m-%d') AS date,
			COALESCE(SUM(packet_count), 0) AS packet_count,
			COALESCE(SUM(byte_count), 0) AS byte_count,
			COALESCE(SUM(conversation_count), 0) AS conversation_count,
			COALESCE(SUM(high_risk_port_hit_count), 0) AS high_risk_port_hit_count,
			COALESCE(SUM(dns_event_count), 0) AS dns_event_count,
			COALESCE(SUM(http_event_count), 0) AS http_event_count,
			COALESCE(SUM(tls_event_count), 0) AS tls_event_count
		`).
		Where("window_start >= ?", start).
		Group("DATE_FORMAT(window_start, '%Y-%m-%d')").
		Order("date ASC").
		Scan(&rows).Error
	return rows, err
}

// DeleteByTaskID 用于删除流量WindowAggregate记录。
func (r *FlowWindowAggregateRepository) DeleteByTaskID(db *gorm.DB, taskID uint64) error {
	return db.Where("task_id = ?", taskID).Delete(&securityModel.FlowWindowAggregate{}).Error
}
