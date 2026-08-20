package security

import "time"

// FlowCollection 对应 sec_flow_collection 表，记录一次流量采集的元数据（模式/解析器/包量/字节量），
// 一个任务可对应多次采集（1:N），evidence_payload 存采集证据 JSON。
// FlowCollection 用于映射流量Collection数据库记录。
type FlowCollection struct {
	ID                uint64    `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	TaskID            uint64    `json:"taskId" gorm:"column:task_id;index"`
	IP                string    `json:"ip" gorm:"column:ip;size:64;index"`
	CollectionMode    string    `json:"collectionMode" gorm:"column:collection_mode;size:32;index:idx_sec_flow_collection_mode_status,priority:1"`
	CollectionStatus  string    `json:"collectionStatus" gorm:"column:collection_status;size:32;index:idx_sec_flow_collection_mode_status,priority:2"`
	ParserName        string    `json:"parserName" gorm:"column:parser_name;size:128"`
	SourceName        string    `json:"sourceName" gorm:"column:source_name;size:128"`
	WindowSeconds     int       `json:"windowSeconds" gorm:"column:window_seconds"`
	SampleProfile     string    `json:"sampleProfile" gorm:"column:sample_profile;size:128"`
	InterfaceName     string    `json:"interfaceName" gorm:"column:interface_name;size:128"`
	PcapFilePath      string    `json:"pcapFilePath" gorm:"column:pcap_file_path;size:255"`
	PacketCount       uint64    `json:"packetCount" gorm:"column:packet_count"`
	ByteCount         uint64    `json:"byteCount" gorm:"column:byte_count"`
	ConversationCount uint32    `json:"conversationCount" gorm:"column:conversation_count"`
	Summary           string    `json:"summary" gorm:"column:summary;size:500"`
	ErrorMessage      string    `json:"errorMessage" gorm:"column:error_message;size:500"`
	EvidencePayload   string    `json:"evidencePayload" gorm:"column:evidence_payload;type:json"`
	StartedAt         time.Time `json:"startedAt" gorm:"column:started_at"`
	FinishedAt        time.Time `json:"finishedAt" gorm:"column:finished_at"`
	CreatedAt         time.Time `json:"createdAt" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt         time.Time `json:"updatedAt" gorm:"column:updated_at;autoUpdateTime"`
}

// TableName 用于指定当前模型绑定的数据库表名。
func (FlowCollection) TableName() string {
	return "sec_flow_collection"
}
