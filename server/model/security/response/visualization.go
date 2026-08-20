package response

// DashboardGeoRiskItem 用于承载总览地理风险列表展示条目。
type DashboardGeoRiskItem struct {
	TargetIP      string  `json:"targetIp"`
	Country       string  `json:"country"`
	Region        string  `json:"region"`
	City          string  `json:"city"`
	RiskLevel     string  `json:"riskLevel"`
	TaskCount     int64   `json:"taskCount"`
	AlertCount    int64   `json:"alertCount"`
	Latitude      float64 `json:"latitude"`
	Longitude     float64 `json:"longitude"`
	HasCoordinate bool    `json:"hasCoordinate"`
}

// DashboardGeoRiskResponse 是总览地理风险分布接口的出参，Items 附带经纬度（HasCoordinate 标记是否有坐标），
// 供地图散点渲染。
// DashboardGeoRiskResponse 用于承载总览地理风险接口的响应数据。
type DashboardGeoRiskResponse struct {
	Items []DashboardGeoRiskItem `json:"items"`
}

// RelationGraphNode 是关系图中的一个节点，Value 表示权重/大小，Meta 携带额外的展示元数据。
// RelationGraphNode 用于映射RelationGraphNode数据库记录。
type RelationGraphNode struct {
	ID       string         `json:"id"`
	Label    string         `json:"label"`
	Category string         `json:"category"`
	Value    float64        `json:"value"`
	Meta     map[string]any `json:"meta"`
}

// RelationGraphEdge 用于映射RelationGraphEdge数据库记录。
type RelationGraphEdge struct {
	Source string         `json:"source"`
	Target string         `json:"target"`
	Label  string         `json:"label"`
	Value  float64        `json:"value"`
	Meta   map[string]any `json:"meta"`
}

// TaskRelationGraphResponse 是任务关系图接口的出参，Nodes/Edges 描述 IP 与画像/评分/预警等实体间的关联，
// 供前端力导向图渲染。
// TaskRelationGraphResponse 用于承载任务RelationGraph接口的响应数据。
type TaskRelationGraphResponse struct {
	TaskID uint64              `json:"taskId"`
	Nodes  []RelationGraphNode `json:"nodes"`
	Edges  []RelationGraphEdge `json:"edges"`
}
