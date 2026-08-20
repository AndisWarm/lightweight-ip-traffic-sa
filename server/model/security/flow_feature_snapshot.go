package security

import "time"

// FlowFeatureSnapshot 对应 sec_flow_feature_snapshot 表，保存流量行为维度的特征快照
// （行为风险分/突发/扫描/协议分布等），collection_id 唯一索引即一次采集只有一份行为特征。
// FlowFeatureSnapshot 用于映射流量特征快照数据库记录。
type FlowFeatureSnapshot struct {
	ID                       uint64    `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	CollectionID             uint64    `json:"collectionId" gorm:"column:collection_id;uniqueIndex"`
	TaskID                   uint64    `json:"taskId" gorm:"column:task_id;index"`
	IP                       string    `json:"ip" gorm:"column:ip;size:64;index"`
	ParserName               string    `json:"parserName" gorm:"column:parser_name;size:128"`
	BehaviorRiskScore        float64   `json:"behaviorRiskScore" gorm:"column:behavior_risk_score;type:decimal(10,2);index"`
	PacketCount              uint64    `json:"packetCount" gorm:"column:packet_count"`
	ByteCount                uint64    `json:"byteCount" gorm:"column:byte_count"`
	ConversationCount        uint32    `json:"conversationCount" gorm:"column:conversation_count"`
	PeakPPS                  float64   `json:"peakPps" gorm:"column:peak_pps;type:decimal(12,2)"`
	BurstScore               float64   `json:"burstScore" gorm:"column:burst_score;type:decimal(10,2)"`
	ScanScore                float64   `json:"scanScore" gorm:"column:scan_score;type:decimal(10,2)"`
	HighEntropyPacketCount   uint32    `json:"highEntropyPacketCount" gorm:"column:high_entropy_packet_count"`
	UniqueTargetPortCount    uint32    `json:"uniqueTargetPortCount" gorm:"column:unique_target_port_count"`
	HighRiskTargetPortCount  uint32    `json:"highRiskTargetPortCount" gorm:"column:high_risk_target_port_count"`
	TargetPortDensity        float64   `json:"targetPortDensity" gorm:"column:target_port_density;type:decimal(10,4)"`
	DominantDirection        string    `json:"dominantDirection" gorm:"column:dominant_direction;size:32"`
	ProtocolDistribution     string    `json:"protocolDistribution" gorm:"column:protocol_distribution;type:json"`
	DNSTopQuestions          string    `json:"dnsTopQuestions" gorm:"column:dns_top_questions;type:json"`
	DNSQueryTypeHints        string    `json:"dnsQueryTypeHints" gorm:"column:dns_query_type_hints;type:json"`
	HTTPHostHints            string    `json:"httpHostHints" gorm:"column:http_host_hints;type:json"`
	HTTPMethodHints          string    `json:"httpMethodHints" gorm:"column:http_method_hints;type:json"`
	HTTPStatusHints          string    `json:"httpStatusHints" gorm:"column:http_status_hints;type:json"`
	TLSHandshakeHints        string    `json:"tlsHandshakeHints" gorm:"column:tls_handshake_hints;type:json"`
	TLSVersionHints          string    `json:"tlsVersionHints" gorm:"column:tls_version_hints;type:json"`
	ApplicationSignals       string    `json:"applicationSignals" gorm:"column:application_signals;type:json"`
	DirectionalityIndicators string    `json:"directionalityIndicators" gorm:"column:directionality_indicators;type:json"`
	PortDensityIndicators    string    `json:"portDensityIndicators" gorm:"column:port_density_indicators;type:json"`
	PayloadEntropyIndicators string    `json:"payloadEntropyIndicators" gorm:"column:payload_entropy_indicators;type:json"`
	TopPorts                 string    `json:"topPorts" gorm:"column:top_ports;type:json"`
	PeerEndpoints            string    `json:"peerEndpoints" gorm:"column:peer_endpoints;type:json"`
	EvidencePayload          string    `json:"evidencePayload" gorm:"column:evidence_payload;type:json"`
	FeatureDigest            string    `json:"featureDigest" gorm:"column:feature_digest;size:128"`
	CreatedAt                time.Time `json:"createdAt" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt                time.Time `json:"updatedAt" gorm:"column:updated_at;autoUpdateTime"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (FlowFeatureSnapshot) TableName() string {
	return "sec_flow_feature_snapshot"
}
