package request

// StartFlowMonitorSessionRequest 是启动实时流量监控会话的入参，InterfaceName 指定要抓包的网卡，必填。
// StartFlowMonitorSessionRequest 用于承载Start流量监控Session接口的请求参数。
type StartFlowMonitorSessionRequest struct {
	InterfaceName string `json:"interfaceName" binding:"required"`
}
