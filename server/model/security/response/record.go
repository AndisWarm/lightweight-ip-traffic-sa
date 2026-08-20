package response

// RecordListItem 用于承载记录List列表展示条目。
type RecordListItem struct {
	ID                          uint64  `json:"id"`
	EventType                   string  `json:"eventType"`
	Title                       string  `json:"title"`
	Description                 string  `json:"description"`
	TargetIP                    string  `json:"targetIp"`
	OriginalTarget              string  `json:"originalTarget"`
	TaskNo                      string  `json:"taskNo"`
	SourceSummary               string  `json:"sourceSummary"`
	FlowSummary                 string  `json:"flowSummary"`
	FlowHistorySourceTable      string  `json:"flowHistorySourceTable"`
	FlowTrendSourceTable        string  `json:"flowTrendSourceTable"`
	FlowEvidenceSourceTable     string  `json:"flowEvidenceSourceTable"`
	FlowCollectionMode          string  `json:"flowCollectionMode"`
	FlowCollectionStatus        string  `json:"flowCollectionStatus"`
	FlowSourceName              string  `json:"flowSourceName"`
	FlowParserName              string  `json:"flowParserName"`
	FlowPacketCount             uint64  `json:"flowPacketCount"`
	FlowConversationCount       uint32  `json:"flowConversationCount"`
	FlowWindowCount             int64   `json:"flowWindowCount"`
	FlowHighRiskPortHits        int64   `json:"flowHighRiskPortHits"`
	FlowDNSEventCount           int64   `json:"flowDnsEventCount"`
	FlowHTTPEventCount          int64   `json:"flowHttpEventCount"`
	FlowTLSEventCount           int64   `json:"flowTlsEventCount"`
	FlowBehaviorRiskScore       float64 `json:"flowBehaviorRiskScore"`
	FlowHighEntropyPacketCount  int64   `json:"flowHighEntropyPacketCount"`
	FlowUniqueTargetPortCount   int64   `json:"flowUniqueTargetPortCount"`
	FlowHighRiskTargetPortCount int64   `json:"flowHighRiskTargetPortCount"`
	FlowTargetPortDensity       float64 `json:"flowTargetPortDensity"`
	FlowDominantDirection       string  `json:"flowDominantDirection"`
	FlowFeatureDigest           string  `json:"flowFeatureDigest"`
	FlowHasRealMetrics          bool    `json:"flowHasRealMetrics"`
	FlowIsTraceable             bool    `json:"flowIsTraceable"`
	Level                       string  `json:"level"`
	Status                      string  `json:"status"`
	Time                        string  `json:"time"`
	DetailRoute                 string  `json:"detailRoute"`
}

// PagedRecordResponse 用于承载Paged记录接口的响应数据。
type PagedRecordResponse struct {
	Page     int              `json:"page"`
	PageSize int              `json:"pageSize"`
	Total    int              `json:"total"`
	Items    []RecordListItem `json:"items"`
}
