package request

// StartFlowMonitorSessionRequest 用于承载Start流量监控Session接口的请求参数。
type StartFlowMonitorSessionRequest struct {
	InterfaceName string `json:"interfaceName" binding:"required"`
}
