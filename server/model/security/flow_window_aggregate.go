package security

import "time"

// FlowWindowAggregate 用于映射流量WindowAggregate数据库记录。
type FlowWindowAggregate struct {
	ID                   uint64    `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	CollectionID         uint64    `json:"collectionId" gorm:"column:collection_id;uniqueIndex:uk_sec_flow_window_collection_window,priority:1;index:idx_sec_flow_window_collection_window_start,priority:1"`
	TaskID               uint64    `json:"taskId" gorm:"column:task_id;index:idx_sec_flow_window_task_window_start,priority:1"`
	IP                   string    `json:"ip" gorm:"column:ip;size:64;index:idx_sec_flow_window_ip_window_start,priority:1"`
	WindowNo             uint32    `json:"windowNo" gorm:"column:window_no;uniqueIndex:uk_sec_flow_window_collection_window,priority:2"`
	WindowStart          time.Time `json:"windowStart" gorm:"column:window_start;index:idx_sec_flow_window_task_window_start,priority:2;index:idx_sec_flow_window_collection_window_start,priority:2;index:idx_sec_flow_window_ip_window_start,priority:2"`
	WindowEnd            time.Time `json:"windowEnd" gorm:"column:window_end"`
	PacketCount          uint64    `json:"packetCount" gorm:"column:packet_count"`
	ByteCount            uint64    `json:"byteCount" gorm:"column:byte_count"`
	ConversationCount    uint32    `json:"conversationCount" gorm:"column:conversation_count"`
	InboundPacketCount   uint64    `json:"inboundPacketCount" gorm:"column:inbound_packet_count"`
	OutboundPacketCount  uint64    `json:"outboundPacketCount" gorm:"column:outbound_packet_count"`
	InboundByteCount     uint64    `json:"inboundByteCount" gorm:"column:inbound_byte_count"`
	OutboundByteCount    uint64    `json:"outboundByteCount" gorm:"column:outbound_byte_count"`
	TCPPacketCount       uint64    `json:"tcpPacketCount" gorm:"column:tcp_packet_count"`
	UDPPacketCount       uint64    `json:"udpPacketCount" gorm:"column:udp_packet_count"`
	ICMPPacketCount      uint64    `json:"icmpPacketCount" gorm:"column:icmp_packet_count"`
	DNSEventCount        uint32    `json:"dnsEventCount" gorm:"column:dns_event_count"`
	HTTPEventCount       uint32    `json:"httpEventCount" gorm:"column:http_event_count"`
	TLSEventCount        uint32    `json:"tlsEventCount" gorm:"column:tls_event_count"`
	HighRiskPortHitCount uint32    `json:"highRiskPortHitCount" gorm:"column:high_risk_port_hit_count"`
	EvidencePayload      string    `json:"evidencePayload" gorm:"column:evidence_payload;type:json"`
	CreatedAt            time.Time `json:"createdAt" gorm:"column:created_at;autoCreateTime"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (FlowWindowAggregate) TableName() string {
	return "sec_flow_window_aggregate"
}
