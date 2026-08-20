package security

import (
	"strings"
	"time"

	"gorm.io/gorm"
)

// RecordRepository 用于封装安全态势模块的数据持久化访问。
type RecordRepository struct{}

// TaskRecordRow 用于承载任务记录数据库查询行。
type TaskRecordRow struct {
	ID                          uint64
	TaskNo                      string
	TargetIP                    string
	OriginalTarget              string
	TaskStatus                  string
	RiskLevel                   string
	BaseInfoRawPayload          string
	NormalizedFeatures          string
	FlowCollectionID            uint64
	FlowCollectionMode          string
	FlowCollectionStatus        string
	FlowCollectionSummary       string
	FlowSourceName              string
	FlowParserName              string
	FlowPacketCount             uint64
	FlowConversationCount       uint32
	FlowWindowCount             int64
	FlowHighRiskPortHits        int64
	FlowDNSEventCount           int64
	FlowHTTPEventCount          int64
	FlowTLSEventCount           int64
	FlowBehaviorRiskScore       float64
	FlowHighEntropyPacketCount  int64
	FlowUniqueTargetPortCount   int64
	FlowHighRiskTargetPortCount int64
	FlowTargetPortDensity       float64
	FlowDominantDirection       string
	FlowFeatureDigest           string
	CreatedAt                   time.Time
}

// AlertRecordRow 用于承载预警记录数据库查询行。
type AlertRecordRow struct {
	ID                          uint64
	TaskNo                      string
	TargetIP                    string
	OriginalTarget              string
	MonitorSessionID            string
	AlertLevel                  string
	SendStatus                  string
	BaseInfoRawPayload          string
	NormalizedFeatures          string
	FlowCollectionID            uint64
	FlowCollectionMode          string
	FlowCollectionStatus        string
	FlowCollectionSummary       string
	FlowSourceName              string
	FlowParserName              string
	FlowPacketCount             uint64
	FlowConversationCount       uint32
	FlowWindowCount             int64
	FlowHighRiskPortHits        int64
	FlowDNSEventCount           int64
	FlowHTTPEventCount          int64
	FlowTLSEventCount           int64
	FlowBehaviorRiskScore       float64
	FlowHighEntropyPacketCount  int64
	FlowUniqueTargetPortCount   int64
	FlowHighRiskTargetPortCount int64
	FlowTargetPortDensity       float64
	FlowDominantDirection       string
	FlowFeatureDigest           string
	CreatedAt                   time.Time
}

// ListTaskRecords 用于查询记录列表。
func (r *RecordRepository) ListTaskRecords(db *gorm.DB, keyword string, createdBy string) ([]TaskRecordRow, error) {
	base := db.Table("sec_ip_task AS t").
		Joins("LEFT JOIN sec_risk_score AS r ON r.task_id = t.id").
		Joins("LEFT JOIN sec_ip_base_info AS b ON b.task_id = t.id").
		Joins("LEFT JOIN sec_feature_snapshot AS f ON f.task_id = t.id").
		Joins("LEFT JOIN sec_flow_collection AS fc ON fc.id = (SELECT id FROM sec_flow_collection WHERE task_id = t.id ORDER BY created_at DESC, id DESC LIMIT 1)").
		Joins(`LEFT JOIN (
			SELECT
				collection_id,
				COUNT(*) AS flow_window_count,
				COALESCE(SUM(high_risk_port_hit_count), 0) AS flow_high_risk_port_hits,
				COALESCE(SUM(dns_event_count), 0) AS flow_dns_event_count,
				COALESCE(SUM(http_event_count), 0) AS flow_http_event_count,
				COALESCE(SUM(tls_event_count), 0) AS flow_tls_event_count
			FROM sec_flow_window_aggregate
			GROUP BY collection_id
		) AS fw ON fw.collection_id = fc.id`).
		Joins("LEFT JOIN sec_flow_feature_snapshot AS ff ON ff.collection_id = fc.id")

	if createdBy != "" {
		base = base.Where("t.created_by = ?", strings.TrimSpace(createdBy))
	}
	if keyword != "" {
		keyword = strings.TrimSpace(keyword)
		base = base.Where("t.target_ip LIKE ? OR t.task_no LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}

	var rows []TaskRecordRow
	err := base.Select("t.id, t.task_no, t.target_ip, COALESCE(t.input_value, '') AS original_target, t.task_status, COALESCE(r.risk_level, 'LOW') AS risk_level, COALESCE(b.raw_payload, '{}') AS base_info_raw_payload, COALESCE(f.normalized_features, '{}') AS normalized_features, COALESCE(fc.id, 0) AS flow_collection_id, COALESCE(fc.collection_mode, '') AS flow_collection_mode, COALESCE(fc.collection_status, '') AS flow_collection_status, COALESCE(fc.summary, '') AS flow_collection_summary, COALESCE(fc.source_name, '') AS flow_source_name, COALESCE(fc.parser_name, '') AS flow_parser_name, COALESCE(fc.packet_count, 0) AS flow_packet_count, COALESCE(fc.conversation_count, 0) AS flow_conversation_count, COALESCE(fw.flow_window_count, 0) AS flow_window_count, COALESCE(fw.flow_high_risk_port_hits, 0) AS flow_high_risk_port_hits, COALESCE(fw.flow_dns_event_count, 0) AS flow_dns_event_count, COALESCE(fw.flow_http_event_count, 0) AS flow_http_event_count, COALESCE(fw.flow_tls_event_count, 0) AS flow_tls_event_count, COALESCE(ff.behavior_risk_score, 0) AS flow_behavior_risk_score, COALESCE(ff.high_entropy_packet_count, 0) AS flow_high_entropy_packet_count, COALESCE(ff.unique_target_port_count, 0) AS flow_unique_target_port_count, COALESCE(ff.high_risk_target_port_count, 0) AS flow_high_risk_target_port_count, COALESCE(ff.target_port_density, 0) AS flow_target_port_density, COALESCE(ff.dominant_direction, '') AS flow_dominant_direction, COALESCE(ff.feature_digest, '') AS flow_feature_digest, t.created_at").
		Order("t.created_at DESC").
		Scan(&rows).Error
	return rows, err
}

// ListAlertRecords 用于查询记录列表。
func (r *RecordRepository) ListAlertRecords(db *gorm.DB, keyword string, createdBy string) ([]AlertRecordRow, error) {
	base := db.Table("sec_alert_record AS a").
		Joins("LEFT JOIN sec_ip_task AS t ON t.id = a.task_id").
		Joins("LEFT JOIN sec_ip_base_info AS b ON b.task_id = t.id").
		Joins("LEFT JOIN sec_feature_snapshot AS f ON f.task_id = t.id").
		Joins("LEFT JOIN sec_flow_collection AS fc ON fc.id = (SELECT id FROM sec_flow_collection WHERE task_id = t.id ORDER BY created_at DESC, id DESC LIMIT 1)").
		Joins(`LEFT JOIN (
			SELECT
				collection_id,
				COUNT(*) AS flow_window_count,
				COALESCE(SUM(high_risk_port_hit_count), 0) AS flow_high_risk_port_hits,
				COALESCE(SUM(dns_event_count), 0) AS flow_dns_event_count,
				COALESCE(SUM(http_event_count), 0) AS flow_http_event_count,
				COALESCE(SUM(tls_event_count), 0) AS flow_tls_event_count
			FROM sec_flow_window_aggregate
			GROUP BY collection_id
		) AS fw ON fw.collection_id = fc.id`).
		Joins("LEFT JOIN sec_flow_feature_snapshot AS ff ON ff.collection_id = fc.id")

	if createdBy != "" {
		base = base.Where("t.created_by = ?", strings.TrimSpace(createdBy))
	}
	if keyword != "" {
		keyword = strings.TrimSpace(keyword)
		base = base.Where("a.ip LIKE ? OR t.task_no LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}

	var rows []AlertRecordRow
	err := base.Select("a.id, t.task_no, a.ip AS target_ip, COALESCE(t.input_value, '') AS original_target, COALESCE(a.monitor_session_id, '') AS monitor_session_id, a.alert_level, a.send_status, COALESCE(b.raw_payload, '{}') AS base_info_raw_payload, COALESCE(f.normalized_features, '{}') AS normalized_features, COALESCE(fc.id, 0) AS flow_collection_id, COALESCE(fc.collection_mode, '') AS flow_collection_mode, COALESCE(fc.collection_status, '') AS flow_collection_status, COALESCE(fc.summary, '') AS flow_collection_summary, COALESCE(fc.source_name, '') AS flow_source_name, COALESCE(fc.parser_name, '') AS flow_parser_name, COALESCE(fc.packet_count, 0) AS flow_packet_count, COALESCE(fc.conversation_count, 0) AS flow_conversation_count, COALESCE(fw.flow_window_count, 0) AS flow_window_count, COALESCE(fw.flow_high_risk_port_hits, 0) AS flow_high_risk_port_hits, COALESCE(fw.flow_dns_event_count, 0) AS flow_dns_event_count, COALESCE(fw.flow_http_event_count, 0) AS flow_http_event_count, COALESCE(fw.flow_tls_event_count, 0) AS flow_tls_event_count, COALESCE(ff.behavior_risk_score, 0) AS flow_behavior_risk_score, COALESCE(ff.high_entropy_packet_count, 0) AS flow_high_entropy_packet_count, COALESCE(ff.unique_target_port_count, 0) AS flow_unique_target_port_count, COALESCE(ff.high_risk_target_port_count, 0) AS flow_high_risk_target_port_count, COALESCE(ff.target_port_density, 0) AS flow_target_port_density, COALESCE(ff.dominant_direction, '') AS flow_dominant_direction, COALESCE(ff.feature_digest, '') AS flow_feature_digest, a.created_at").
		Order("a.created_at DESC").
		Scan(&rows).Error
	return rows, err
}
