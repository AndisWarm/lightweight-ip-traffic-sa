package security

import (
	"time"

	securityModel "lightweight-ip-traffic-sa/server/model/security"

	"gorm.io/gorm"
)

// FlowCollectionRepository 用于封装安全态势模块的数据持久化访问。
type FlowCollectionRepository struct{}

// FlowModeCountRow 用于承载流量ModeCount数据库查询行。
type FlowModeCountRow struct {
	CollectionMode string
	Count          int64
}

// FlowCollectionTrendRow 用于承载流量CollectionTrend数据库查询行。
type FlowCollectionTrendRow struct {
	Date              string
	CollectionCount   int64
	PacketCount       int64
	ByteCount         int64
	ConversationCount int64
}

// FlowHistoryRow 用于承载流量History数据库查询行。
type FlowHistoryRow struct {
	CollectionID      uint64
	TaskID            uint64
	IP                string
	CollectionMode    string
	CollectionStatus  string
	SourceName        string
	ParserName        string
	PacketCount       uint64
	ByteCount         uint64
	ConversationCount uint32
	Summary           string
	StartedAt         time.Time
	FinishedAt        time.Time
	CreatedAt         time.Time
}

// Create 用于写入流量Collection记录。
func (r *FlowCollectionRepository) Create(db *gorm.DB, collection *securityModel.FlowCollection) error {
	return db.Create(collection).Error
}

// CreateInBatches 用于写入流量Collection记录。
func (r *FlowCollectionRepository) CreateInBatches(db *gorm.DB, collections []securityModel.FlowCollection, batchSize int) error {
	if len(collections) == 0 {
		return nil
	}
	if batchSize <= 0 {
		batchSize = 100
	}
	return db.CreateInBatches(collections, batchSize).Error
}

// FindLatestByTaskID 用于查询流量Collection记录。
func (r *FlowCollectionRepository) FindLatestByTaskID(db *gorm.DB, taskID uint64) (*securityModel.FlowCollection, error) {
	var collection securityModel.FlowCollection
	err := db.Where("task_id = ?", taskID).
		Order("created_at DESC").
		First(&collection).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &collection, nil
}

// ListByTaskID 用于查询流量Collection列表。
func (r *FlowCollectionRepository) ListByTaskID(db *gorm.DB, taskID uint64) ([]securityModel.FlowCollection, error) {
	var rows []securityModel.FlowCollection
	err := db.Where("task_id = ?", taskID).
		Order("created_at DESC").
		Find(&rows).Error
	return rows, err
}

// ListRecentHistory 用于查询流量Collection列表。
func (r *FlowCollectionRepository) ListRecentHistory(db *gorm.DB, limit int) ([]FlowHistoryRow, error) {
	var rows []FlowHistoryRow
	query := db.Model(&securityModel.FlowCollection{}).
		Select("id AS collection_id, task_id, ip, collection_mode, collection_status, source_name, parser_name, packet_count, byte_count, conversation_count, summary, started_at, finished_at, created_at").
		Order("created_at DESC").
		Order("id DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	err := query.Scan(&rows).Error
	return rows, err
}

// CountModeDistribution 用于统计流量Collection数据。
func (r *FlowCollectionRepository) CountModeDistribution(db *gorm.DB, start time.Time) ([]FlowModeCountRow, error) {
	var rows []FlowModeCountRow
	err := db.Model(&securityModel.FlowCollection{}).
		Select("collection_mode, COUNT(*) AS count").
		Where("created_at >= ?", start).
		Group("collection_mode").
		Order("count DESC, collection_mode ASC").
		Scan(&rows).Error
	return rows, err
}

// CountDailyTrend 用于统计流量Collection数据。
func (r *FlowCollectionRepository) CountDailyTrend(db *gorm.DB, start time.Time) ([]FlowCollectionTrendRow, error) {
	var rows []FlowCollectionTrendRow
	err := db.Model(&securityModel.FlowCollection{}).
		Select(`
			DATE_FORMAT(COALESCE(started_at, created_at), '%Y-%m-%d') AS date,
			COUNT(*) AS collection_count,
			COALESCE(SUM(packet_count), 0) AS packet_count,
			COALESCE(SUM(byte_count), 0) AS byte_count,
			COALESCE(SUM(conversation_count), 0) AS conversation_count
		`).
		Where("COALESCE(started_at, created_at) >= ?", start).
		Group("DATE_FORMAT(COALESCE(started_at, created_at), '%Y-%m-%d')").
		Order("date ASC").
		Scan(&rows).Error
	return rows, err
}

// DeleteByTaskID 用于删除流量Collection记录。
func (r *FlowCollectionRepository) DeleteByTaskID(db *gorm.DB, taskID uint64) error {
	return db.Where("task_id = ?", taskID).Delete(&securityModel.FlowCollection{}).Error
}
