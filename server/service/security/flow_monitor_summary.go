package security

import "fmt"

// buildOnlineCaptureSessionSummary 用于构建OnlineCaptureSession摘要。
// 实时监控每 5 秒采样一轮，这里生成供前端展示的本轮采样摘要；
// 未命中本机相关报文时明确提示“无数据”，避免让用户误以为抓包失败
func buildOnlineCaptureSessionSummary(metrics flowParseMetrics, iface string) string {
	if metrics.MatchedPacketCount == 0 {
		return fmt.Sprintf("网卡 %s 已完成 5 秒采样，本轮未发现可用于分析的本机相关报文。", iface)
	}
	return fmt.Sprintf(
		"网卡 %s 已完成 5 秒采样：报文 %d 个，会话 %d 个，字节 %d，DNS/HTTP/TLS=%d/%d/%d。",
		iface,
		metrics.MatchedPacketCount,
		metrics.SessionCount,
		metrics.ByteCount,
		metrics.DNSEventCount,
		metrics.HTTPEventCount,
		metrics.TLSEventCount,
	)
}
