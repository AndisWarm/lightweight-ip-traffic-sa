package security

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const pcapngMagicNumber = 0x0A0D0D0A

// flowAnomalyCandidate 用于承载flowAnomalyCandidate候选项。
type flowAnomalyCandidate struct {
	Name     string  `json:"name"`
	Score    float64 `json:"score"`
	RiskHint string  `json:"riskHint"`
	Summary  string  `json:"summary"`
}

// flowStringCount 用于承载flowStringCount数据。
type flowStringCount struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// flowHTTPMethodHint 用于承载flowHTTPMethodHint提示信息。
type flowHTTPMethodHint struct {
	Method string            `json:"method"`
	Count  int               `json:"count"`
	Hosts  []flowStringCount `json:"hosts,omitempty"`
}

// flowTLSHandshakeHint 用于承载flowTLSHandshakeHint提示信息。
type flowTLSHandshakeHint struct {
	ServerName string `json:"serverName"`
	Count      int    `json:"count"`
}

// flowWindowMetric 用于承载flowWindowMetric指标。
type flowWindowMetric struct {
	WindowNo             uint32         `json:"windowNo"`
	WindowStart          string         `json:"windowStart"`
	WindowEnd            string         `json:"windowEnd"`
	PacketCount          uint64         `json:"packetCount"`
	ByteCount            uint64         `json:"byteCount"`
	ConversationCount    uint32         `json:"conversationCount"`
	InboundPacketCount   uint64         `json:"inboundPacketCount"`
	OutboundPacketCount  uint64         `json:"outboundPacketCount"`
	InboundByteCount     uint64         `json:"inboundByteCount"`
	OutboundByteCount    uint64         `json:"outboundByteCount"`
	TCPPacketCount       uint64         `json:"tcpPacketCount"`
	UDPPacketCount       uint64         `json:"udpPacketCount"`
	ICMPPacketCount      uint64         `json:"icmpPacketCount"`
	DNSEventCount        uint32         `json:"dnsEventCount"`
	HTTPEventCount       uint32         `json:"httpEventCount"`
	TLSEventCount        uint32         `json:"tlsEventCount"`
	HighRiskPortHitCount uint32         `json:"highRiskPortHitCount"`
	EvidencePayload      map[string]any `json:"evidencePayload"`
}

// flowParseMetrics 用于承载flowParseMetrics指标。
type flowParseMetrics struct {
	CaptureFormat            string
	PacketCount              int
	MatchedPacketCount       int
	ByteCount                int64
	SessionCount             int
	ProtocolCounts           map[string]int
	PortCounts               map[string]int
	PeerCounts               map[string]int
	AnomalyCandidates        []flowAnomalyCandidate
	FirstSeenAt              time.Time
	LastSeenAt               time.Time
	PeakPPS                  float64
	BurstScore               float64
	ScanScore                float64
	DNSEventCount            int
	HTTPEventCount           int
	TLSEventCount            int
	Windows                  []flowWindowMetric
	DNSTopQuestions          []flowStringCount
	DNSQueryTypeHints        []flowStringCount
	HTTPMethodHints          []flowHTTPMethodHint
	HTTPHostHints            []flowStringCount
	HTTPStatusHints          []flowStringCount
	TLSHandshakeHints        []flowTLSHandshakeHint
	TLSVersionHints          []flowStringCount
	ApplicationSignals       []string
	DirectionalityIndicators map[string]any
	PortDensityIndicators    map[string]any
	PayloadEntropyIndicators map[string]any
}

// flowMetricsAccumulator 用于承载flowMetricsAccumulator指标。
type flowMetricsAccumulator struct {
	targetIP              string
	focusIPs              map[string]struct{}
	windowSeconds         int
	packetCount           int
	matchedPacketCount    int
	byteCount             int64
	protocolCounts        map[string]int
	portCounts            map[string]int
	peerCounts            map[string]int
	sessionKeys           map[string]struct{}
	synProbeCount         int
	dnsCount              int
	httpCount             int
	tlsCount              int
	icmpCount             int
	tcpResetCount         int
	uniqueTargetPorts     map[string]struct{}
	httpMethodCounts      map[string]int
	httpHostCounts        map[string]int
	httpStatusCounts      map[string]int
	tlsServerNames        map[string]int
	tlsVersionCounts      map[string]int
	dnsQuestionCounts     map[string]int
	dnsQuestionTypeCounts map[string]int
	highEntropyCount      int
	totalEntropy          float64
	entropySamples        int
	entropyPeerCounts     map[string]int
	windowBaseStart       time.Time
	windows               map[int]*flowWindowAccumulator
	firstSeenAt           time.Time
	lastSeenAt            time.Time
}

// flowWindowAccumulator 用于承载flowWindowAccumulator数据。
type flowWindowAccumulator struct {
	WindowNo             uint32
	WindowStart          time.Time
	WindowEnd            time.Time
	PacketCount          uint64
	ByteCount            uint64
	ConversationKeys     map[string]struct{}
	InboundPacketCount   uint64
	OutboundPacketCount  uint64
	InboundByteCount     uint64
	OutboundByteCount    uint64
	TCPPacketCount       uint64
	UDPPacketCount       uint64
	ICMPPacketCount      uint64
	DNSEventCount        uint32
	HTTPEventCount       uint32
	TLSEventCount        uint32
	HighRiskPortHitCount uint32
	ProtocolCounts       map[string]int
}

// newFlowMetricsAccumulator 用于创建并返回新的业务实例。
func newFlowMetricsAccumulator(targetIP string, localIPs []string, windowSeconds int) *flowMetricsAccumulator {
	// 窗口秒数未配置时回退到 60 秒，保证后续 PPS 与趋势聚合有合理的时间粒度
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	// focusIPs 包含目标 IP 与所有本机 IP，用于把“与本机/目标相关的流量”从背景流量中筛出
	focusIPs := buildFlowFocusIPs(targetIP, localIPs)
	return &flowMetricsAccumulator{
		targetIP:              strings.TrimSpace(targetIP),
		focusIPs:              focusIPs,
		windowSeconds:         windowSeconds,
		protocolCounts:        make(map[string]int),
		portCounts:            make(map[string]int),
		peerCounts:            make(map[string]int),
		sessionKeys:           make(map[string]struct{}),
		uniqueTargetPorts:     make(map[string]struct{}),
		httpMethodCounts:      make(map[string]int),
		httpHostCounts:        make(map[string]int),
		httpStatusCounts:      make(map[string]int),
		tlsServerNames:        make(map[string]int),
		tlsVersionCounts:      make(map[string]int),
		dnsQuestionCounts:     make(map[string]int),
		dnsQuestionTypeCounts: make(map[string]int),
		entropyPeerCounts:     make(map[string]int),
		windows:               make(map[int]*flowWindowAccumulator),
	}
}

// observe 用于累计单条流量报文指标。
func (a *flowMetricsAccumulator) observe(packet gopacket.Packet) {
	// 无论是否命中目标，先累计总报文数，用于反映 pcap 文件整体规模
	a.packetCount++

	// 从以太网帧解析出网络层源/目的 IP；非 IPv4/IPv6 的报文（如纯 ARP）直接跳过
	srcIP, dstIP, ok := extractPacketIPs(packet)
	if !ok {
		return
	}
	srcFocus := a.isFocusIP(srcIP)
	dstFocus := a.isFocusIP(dstIP)
	// 只统计与目标 IP / 本机 IP 相关的报文，过滤无关背景流量，避免其干扰行为风险分
	if len(a.focusIPs) > 0 && !srcFocus && !dstFocus {
		return
	}

	// 通过过滤的报文才计入“命中数”，它是行为风险分里“命中目标流量”加分项的依据
	a.matchedPacketCount++
	captureInfo := packet.Metadata().CaptureInfo
	packetBytes := len(packet.Data())
	// 优先用抓包时记录的真实帧长（captureInfo.Length），因为它包含可能被截断的原始帧字节
	if captureInfo.Length > 0 {
		packetBytes = captureInfo.Length
	}
	packetTimestamp := captureInfo.Timestamp
	if !packetTimestamp.IsZero() {
		if a.firstSeenAt.IsZero() || packetTimestamp.Before(a.firstSeenAt) {
			a.firstSeenAt = packetTimestamp
		}
		if a.lastSeenAt.IsZero() || packetTimestamp.After(a.lastSeenAt) {
			a.lastSeenAt = packetTimestamp
		}
		// 以首个报文的抓包时间作为窗口基准，后续窗口按 windowSeconds 对齐切分
		if a.windowBaseStart.IsZero() {
			a.windowBaseStart = packetTimestamp
		}
	}
	a.byteCount += int64(packetBytes)

	// 一步完成传输层/协议识别、目标端口判定、对端 IP 解析与双向会话 key 构造
	proto, targetPort, peerIP, sessionKey := classifyPacketFlow(packet, srcIP, dstIP, a.targetIP, a.focusIPs)
	inbound := dstFocus && !srcFocus
	a.protocolCounts[proto]++
	if targetPort != "" {
		portKey := normalizeFlowPortKey(proto, targetPort)
		a.portCounts[portKey]++
		a.uniqueTargetPorts[portKey] = struct{}{}
	}
	if peerIP != "" {
		a.peerCounts[peerIP]++
	}
	if sessionKey != "" {
		// 用 map 去重，最终 len(sessionKeys) 即为双向会话数
		a.sessionKeys[sessionKey] = struct{}{}
	}

	if tcpLayer, ok := packet.TransportLayer().(*layers.TCP); ok {
		// 只有入站方向的新建连接（SYN 且非 ACK）才算“被探测”，避免把正常握手的 ACK 也算进去
		if inbound && tcpLayer.SYN && !tcpLayer.ACK {
			a.synProbeCount++
		}
		if tcpLayer.RST {
			a.tcpResetCount++
		}
		// HTTP / TLS 没有独立 gopacket 层，需从 TCP 载荷里按特征字节识别
		if method, host, statusCode, isHTTP := extractHTTPHint(tcpLayer.Payload); isHTTP {
			a.httpCount++
			a.httpMethodCounts[method]++
			if host != "" {
				a.httpHostCounts[host]++
			}
			if statusCode != "" {
				a.httpStatusCounts[statusCode]++
			}
		}
		if serverName, tlsVersion, isTLS := extractTLSServerName(tcpLayer.Payload); isTLS {
			a.tlsCount++
			if serverName == "" {
				serverName = "unknown-sni"
			}
			a.tlsServerNames[serverName]++
			if tlsVersion != "" {
				a.tlsVersionCounts[tlsVersion]++
			}
		}
		recordPayloadEntropy(a, tcpLayer.Payload, peerIP)
	}
	if udpLayer, ok := packet.TransportLayer().(*layers.UDP); ok {
		recordPayloadEntropy(a, udpLayer.Payload, peerIP)
	}
	if dnsLayer, ok := packet.Layer(layers.LayerTypeDNS).(*layers.DNS); ok {
		a.dnsCount++
		recordDNSHints(a, dnsLayer)
	}
	if packet.Layer(layers.LayerTypeICMPv4) != nil || packet.Layer(layers.LayerTypeICMPv6) != nil {
		a.icmpCount++
	}

	a.observeWindow(packetTimestamp, proto, targetPort, sessionKey, packetBytes, inbound)
}

// isFocusIP 用于判断FocusIP是否成立。
func (a *flowMetricsAccumulator) isFocusIP(ip string) bool {
	if strings.TrimSpace(ip) == "" {
		return false
	}
	if len(a.focusIPs) == 0 {
		return true
	}
	_, ok := a.focusIPs[strings.TrimSpace(ip)]
	return ok
}

// observeWindow 用于累计时间窗口内的流量指标。
func (a *flowMetricsAccumulator) observeWindow(timestamp time.Time, proto string, targetPort string, sessionKey string, packetBytes int, inbound bool) {
	if timestamp.IsZero() {
		return
	}
	window := a.resolveWindow(timestamp)
	window.PacketCount++
	window.ByteCount += uint64(packetBytes)
	if sessionKey != "" {
		window.ConversationKeys[sessionKey] = struct{}{}
	}
	if inbound {
		window.InboundPacketCount++
		window.InboundByteCount += uint64(packetBytes)
	} else {
		window.OutboundPacketCount++
		window.OutboundByteCount += uint64(packetBytes)
	}
	window.ProtocolCounts[proto]++
	switch {
	case strings.HasPrefix(proto, "TCP"), strings.Contains(proto, "HTTP"), strings.Contains(proto, "HTTPS"), strings.Contains(proto, "SSH"), strings.Contains(proto, "RDP"):
		window.TCPPacketCount++
	case strings.HasPrefix(proto, "UDP"), proto == "DNS":
		window.UDPPacketCount++
	case strings.HasPrefix(proto, "ICMP"):
		window.ICMPPacketCount++
	}
	if proto == "DNS" {
		window.DNSEventCount++
	}
	if strings.Contains(proto, "HTTP") {
		window.HTTPEventCount++
	}
	if strings.Contains(proto, "HTTPS") || strings.Contains(proto, "TLS") {
		window.TLSEventCount++
	}
	if isHighRiskFlowPort(normalizeFlowPortKey(proto, targetPort)) {
		window.HighRiskPortHitCount++
	}
}

// resolveWindow 用于解析Window。
func (a *flowMetricsAccumulator) resolveWindow(timestamp time.Time) *flowWindowAccumulator {
	index := 0
	if !a.windowBaseStart.IsZero() && a.windowSeconds > 0 {
		offset := timestamp.Sub(a.windowBaseStart)
		if offset > 0 {
			index = int(offset / (time.Duration(a.windowSeconds) * time.Second))
		}
	}
	if window, ok := a.windows[index]; ok {
		if timestamp.After(window.WindowEnd) {
			window.WindowEnd = timestamp
		}
		if timestamp.Before(window.WindowStart) {
			window.WindowStart = timestamp
		}
		return window
	}
	windowStart := a.windowBaseStart
	if windowStart.IsZero() {
		windowStart = timestamp
	}
	if a.windowSeconds > 0 {
		windowStart = windowStart.Add(time.Duration(index*a.windowSeconds) * time.Second)
	}
	window := &flowWindowAccumulator{
		WindowNo:         uint32(index + 1),
		WindowStart:      windowStart,
		WindowEnd:        timestamp,
		ConversationKeys: make(map[string]struct{}),
		ProtocolCounts:   make(map[string]int),
	}
	a.windows[index] = window
	return window
}

// finalize 用于生成最终流量解析指标。
func (a *flowMetricsAccumulator) finalize(format string) flowParseMetrics {
	anomalies := buildFlowAnomalyCandidates(a)
	peakPPS := computePeakPPS(a.windows, a.windowSeconds)
	burstScore := computeBurstScore(peakPPS)
	scanScore := computeScanScore(a)
	return flowParseMetrics{
		CaptureFormat:            format,
		PacketCount:              a.packetCount,
		MatchedPacketCount:       a.matchedPacketCount,
		ByteCount:                a.byteCount,
		SessionCount:             len(a.sessionKeys),
		ProtocolCounts:           a.protocolCounts,
		PortCounts:               a.portCounts,
		PeerCounts:               a.peerCounts,
		AnomalyCandidates:        anomalies,
		FirstSeenAt:              a.firstSeenAt,
		LastSeenAt:               a.lastSeenAt,
		PeakPPS:                  peakPPS,
		BurstScore:               burstScore,
		ScanScore:                scanScore,
		DNSEventCount:            a.dnsCount,
		HTTPEventCount:           a.httpCount,
		TLSEventCount:            a.tlsCount,
		Windows:                  buildFlowWindows(a.windows),
		DNSTopQuestions:          buildTopCounts(a.dnsQuestionCounts, 5),
		DNSQueryTypeHints:        buildTopCounts(a.dnsQuestionTypeCounts, 5),
		HTTPMethodHints:          buildHTTPMethodHints(a.httpMethodCounts, a.httpHostCounts),
		HTTPHostHints:            buildTopCounts(a.httpHostCounts, 5),
		HTTPStatusHints:          buildTopCounts(a.httpStatusCounts, 5),
		TLSHandshakeHints:        buildTLSHandshakeHints(a.tlsServerNames),
		TLSVersionHints:          buildTopCounts(a.tlsVersionCounts, 5),
		ApplicationSignals:       buildApplicationSignals(a, anomalies),
		DirectionalityIndicators: buildDirectionalityIndicators(a),
		PortDensityIndicators:    buildPortDensityIndicators(a),
		PayloadEntropyIndicators: buildPayloadEntropyIndicators(a),
	}
}

// normalizeFlowPortKey 用于归一化输入参数或业务指标。
func normalizeFlowPortKey(proto string, targetPort string) string {
	proto = strings.ToLower(strings.TrimSpace(proto))
	targetPort = strings.TrimSpace(targetPort)
	switch {
	case targetPort == "":
		return ""
	case strings.Contains(proto, "udp"), proto == "dns":
		return "udp:" + targetPort
	default:
		return "tcp:" + targetPort
	}
}

// isHighRiskFlowPort 用于判断输入是否满足指定条件。
func isHighRiskFlowPort(portKey string) bool {
	switch strings.ToLower(strings.TrimSpace(portKey)) {
	case "tcp:22", "tcp:445", "tcp:3389", "tcp:8080", "udp:53":
		return true
	default:
		return false
	}
}

// recordDNSHints 用于记录DNSHints。
func recordDNSHints(a *flowMetricsAccumulator, dnsLayer *layers.DNS) {
	if a == nil || dnsLayer == nil {
		return
	}
	for _, question := range dnsLayer.Questions {
		name := strings.TrimSuffix(strings.TrimSpace(string(question.Name)), ".")
		if name == "" {
			continue
		}
		a.dnsQuestionCounts[name]++
		queryType := strings.TrimSpace(question.Type.String())
		if queryType == "" {
			queryType = fmt.Sprintf("%d", question.Type)
		}
		a.dnsQuestionTypeCounts[queryType]++
	}
}

// extractHTTPHint 用于提取请求、令牌或流量中的关键信息。
func extractHTTPHint(payload []byte) (string, string, string, bool) {
	if len(payload) == 0 {
		return "", "", "", false
	}
	text := string(payload)
	method := ""
	statusCode := ""
	for _, candidate := range []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"} {
		if strings.HasPrefix(text, candidate+" ") {
			method = candidate
			break
		}
	}
	if method == "" {
		for _, versionPrefix := range []string{"HTTP/1.0 ", "HTTP/1.1 ", "HTTP/2 "} {
			if strings.HasPrefix(text, versionPrefix) {
				method = "RESPONSE"
				remainder := strings.TrimPrefix(text, versionPrefix)
				if fields := strings.Fields(remainder); len(fields) > 0 {
					statusCode = fields[0]
				}
				break
			}
		}
	}
	if method == "" {
		return "", "", "", false
	}
	host := ""
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), "host:") {
			host = strings.TrimSpace(strings.TrimPrefix(trimmed, "Host:"))
			host = strings.TrimSpace(strings.TrimPrefix(host, "host:"))
			break
		}
	}
	return method, host, statusCode, true
}

// extractTLSServerName 用于提取请求、令牌或流量中的关键信息。
// TLS 握手明文阶段的 ClientHello 会携带 SNI，可用来识别加密流量真正访问的域名（否则只剩端口号）
func extractTLSServerName(payload []byte) (string, string, bool) {
	if len(payload) < 9 {
		return "", "", false
	}
	// 0x16 = Handshake 记录类型，0x03 0x01~0x04 = TLS 1.0~1.3 版本号
	if payload[0] != 0x16 || payload[1] != 0x03 {
		return "", "", false
	}
	tlsVersion := formatTLSVersion(payload[1], payload[2])
	// payload[5] == 0x01 表示 ClientHello 握手消息类型
	if payload[5] != 0x01 {
		return "", tlsVersion, true
	}
	serverName, err := parseTLSClientHelloSNI(payload)
	if err != nil {
		return "", tlsVersion, true
	}
	return serverName, tlsVersion, true
}

// formatTLSVersion 用于格式化TLSVersion展示文本。
func formatTLSVersion(major byte, minor byte) string {
	switch {
	case major == 0x03 && minor == 0x01:
		return "TLS1.0"
	case major == 0x03 && minor == 0x02:
		return "TLS1.1"
	case major == 0x03 && minor == 0x03:
		return "TLS1.2"
	case major == 0x03 && minor == 0x04:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%02x%02x", major, minor)
	}
}

// parseTLSClientHelloSNI 用于解析输入数据并转换为内部模型。
// 按 TLS ClientHello 的定长结构逐段跳过：随机数、会话 ID、密码套件、压缩方法，最终定位到扩展区
// 再从扩展区里找 type=0x0000 的 SNI 扩展，取出其中的服务器名（域名）
func parseTLSClientHelloSNI(payload []byte) (string, error) {
	if len(payload) < 43 {
		return "", fmt.Errorf("tls payload too short")
	}
	offset := 5
	if len(payload) < offset+4 {
		return "", fmt.Errorf("tls handshake header too short")
	}
	offset += 4
	if len(payload) < offset+2+32+1 {
		return "", fmt.Errorf("tls client hello too short")
	}
	offset += 2 + 32
	sessionLen := int(payload[offset])
	offset++
	if len(payload) < offset+sessionLen+2 {
		return "", fmt.Errorf("tls session id overflow")
	}
	offset += sessionLen
	cipherLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	if len(payload) < offset+cipherLen+1 {
		return "", fmt.Errorf("tls cipher suites overflow")
	}
	offset += cipherLen
	compressionLen := int(payload[offset])
	offset++
	if len(payload) < offset+compressionLen+2 {
		return "", fmt.Errorf("tls compression overflow")
	}
	offset += compressionLen
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	limit := offset + extensionsLen
	if len(payload) < limit {
		return "", fmt.Errorf("tls extensions overflow")
	}
	// 遍历所有扩展，只有 type=0x0000（SNI）才需要解析
	for offset+4 <= limit {
		extensionType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extensionLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4
		if offset+extensionLen > limit {
			return "", fmt.Errorf("tls extension overflow")
		}
		if extensionType != 0x0000 {
			offset += extensionLen
			continue
		}
		if extensionLen < 5 {
			return "", fmt.Errorf("tls sni extension too short")
		}
		serverNameListLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
		offset += 2
		if serverNameListLen <= 0 || offset+serverNameListLen > limit {
			return "", fmt.Errorf("tls sni list overflow")
		}
		// SNI 名称类型 0x00 表示 host_name（域名）
		nameType := payload[offset]
		if nameType != 0x00 {
			return "", fmt.Errorf("unsupported tls sni type")
		}
		offset++
		nameLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
		offset += 2
		if nameLen <= 0 || offset+nameLen > limit {
			return "", fmt.Errorf("tls sni name overflow")
		}
		return strings.TrimSpace(string(payload[offset : offset+nameLen])), nil
	}
	return "", fmt.Errorf("tls sni not found")
}

// recordPayloadEntropy 用于记录载荷Entropy。
func recordPayloadEntropy(a *flowMetricsAccumulator, payload []byte, peerIP string) {
	// 小于 64 字节的载荷样本太少，熵值不稳定，跳过以免误判
	if a == nil || len(payload) < 64 {
		return
	}
	entropy := estimatePayloadEntropy(payload)
	a.totalEntropy += entropy
	a.entropySamples++
	// 熵越接近 8 越接近随机分布，通常意味着加密、压缩或隧道混淆
	if entropy >= 7.2 {
		a.highEntropyCount++
		if peerIP != "" {
			a.entropyPeerCounts[peerIP]++
		}
	}
}

// estimatePayloadEntropy 用于执行estimate载荷Entropy流程。
func estimatePayloadEntropy(payload []byte) float64 {
	if len(payload) == 0 {
		return 0
	}
	// Shannon 熵：H = -Σ p(x)·log2(p(x))，按字节频次分布度量载荷的随机程度，取值范围 0~8
	var counts [256]int
	for _, item := range payload {
		counts[int(item)]++
	}
	entropy := 0.0
	total := float64(len(payload))
	for _, count := range counts {
		if count == 0 {
			continue
		}
		probability := float64(count) / total
		entropy -= probability * math.Log2(probability)
	}
	return round2(entropy)
}

// computePeakPPS 用于计算PeakPPS指标。
func computePeakPPS(windows map[int]*flowWindowAccumulator, windowSeconds int) float64 {
	if len(windows) == 0 {
		return 0
	}
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	peak := 0.0
	for _, item := range windows {
		durationSeconds := float64(windowSeconds)
		// 首/末窗口可能不满一个完整窗口，用实际跨度计算 PPS，避免用满窗口时长拉低峰值
		if !item.WindowStart.IsZero() && !item.WindowEnd.IsZero() {
			actual := item.WindowEnd.Sub(item.WindowStart).Seconds()
			if actual > 0 && actual < durationSeconds {
				durationSeconds = actual
			}
		}
		if durationSeconds <= 0 {
			durationSeconds = 1
		}
		pps := float64(item.PacketCount) / durationSeconds
		if pps > peak {
			peak = pps
		}
	}
	return round2(peak)
}

// computeBurstScore 用于计算Burst评分指标。
// 公式：min(PeakPPS * 2, 100)，用于把峰值包速率放大映射到 0~100 的突发分
func computeBurstScore(peakPPS float64) float64 {
	score := peakPPS * 2
	if score > 100 {
		score = 100
	}
	return round2(score)
}

// computeScanScore 用于计算Scan评分指标。
// 公式：min(唯一目标端口数*2.5 + SYN探测数*1.2 + RST数*0.2, 100)
// 端口数与 SYN 探测是端口扫描的直接证据，RST 往往来自大量被拒绝的连接，作为弱信号补充
func computeScanScore(a *flowMetricsAccumulator) float64 {
	if a == nil {
		return 0
	}
	score := float64(len(a.uniqueTargetPorts))*2.5 + float64(a.synProbeCount)*1.2 + float64(a.tcpResetCount)*0.2
	if score > 100 {
		score = 100
	}
	return round2(score)
}

// buildHTTPMethodHints 用于构建HTTPMethodHints。
func buildHTTPMethodHints(methodCounts map[string]int, hostCounts map[string]int) []flowHTTPMethodHint {
	if len(methodCounts) == 0 {
		return nil
	}
	methods := sortStringIntMap(methodCounts)
	result := make([]flowHTTPMethodHint, 0, len(methods))
	hosts := sortStringIntMap(hostCounts)
	if len(hosts) > 3 {
		hosts = hosts[:3]
	}
	for _, item := range methods {
		result = append(result, flowHTTPMethodHint{
			Method: item.Key,
			Count:  item.Count,
			Hosts:  hosts,
		})
	}
	return result
}

// buildTLSHandshakeHints 用于构建TLSHandshakeHints。
func buildTLSHandshakeHints(serverNames map[string]int) []flowTLSHandshakeHint {
	if len(serverNames) == 0 {
		return nil
	}
	items := sortStringIntMap(serverNames)
	if len(items) > 5 {
		items = items[:5]
	}
	result := make([]flowTLSHandshakeHint, 0, len(items))
	for _, item := range items {
		result = append(result, flowTLSHandshakeHint{
			ServerName: item.Key,
			Count:      item.Count,
		})
	}
	return result
}

// buildPayloadEntropyIndicators 用于构建载荷EntropyIndicators。
func buildPayloadEntropyIndicators(a *flowMetricsAccumulator) map[string]any {
	if a == nil || a.entropySamples == 0 {
		return nil
	}
	return map[string]any{
		"highEntropyPacketCount": a.highEntropyCount,
		"averagePayloadEntropy":  round2(a.totalEntropy / float64(a.entropySamples)),
		"topPeers":               sortStringIntMap(a.entropyPeerCounts),
	}
}

// buildDirectionalityIndicators 用于构建DirectionalityIndicators。
// 统计入站/出站的报文与字节占比，方向性偏置（packetBias/byteBias 接近 1）暗示流量几乎单向
// 单向流量常见于扫描、单向攻击或数据外传，是行为风险分中的加分依据
func buildDirectionalityIndicators(a *flowMetricsAccumulator) map[string]any {
	if a == nil || len(a.windows) == 0 {
		return nil
	}
	var inboundPackets uint64
	var outboundPackets uint64
	var inboundBytes uint64
	var outboundBytes uint64
	for _, window := range a.windows {
		inboundPackets += window.InboundPacketCount
		outboundPackets += window.OutboundPacketCount
		inboundBytes += window.InboundByteCount
		outboundBytes += window.OutboundByteCount
	}
	totalPackets := inboundPackets + outboundPackets
	totalBytes := inboundBytes + outboundBytes
	packetBias := 0.0
	byteBias := 0.0
	dominantDirection := "balanced"
	if totalPackets > 0 {
		// packetBias = 占比大的一侧 / 总包数，越接近 1 表示越单向
		packetBias = round2(float64(maxUint64(inboundPackets, outboundPackets)) / float64(totalPackets))
		switch {
		case inboundPackets > outboundPackets:
			dominantDirection = "inbound"
		case outboundPackets > inboundPackets:
			dominantDirection = "outbound"
		}
	}
	if totalBytes > 0 {
		byteBias = round2(float64(maxUint64(inboundBytes, outboundBytes)) / float64(totalBytes))
	}
	return map[string]any{
		"inboundPacketCount":  inboundPackets,
		"outboundPacketCount": outboundPackets,
		"inboundByteCount":    inboundBytes,
		"outboundByteCount":   outboundBytes,
		"packetBias":          packetBias,
		"byteBias":            byteBias,
		"dominantDirection":   dominantDirection,
	}
}

// buildPortDensityIndicators 用于构建PortDensityIndicators。
// 端口密度 = 唯一目标端口数 / 会话数，衡量“单位会话接触了多少端口”，数值越大越像扫描
func buildPortDensityIndicators(a *flowMetricsAccumulator) map[string]any {
	if a == nil {
		return nil
	}
	uniquePortCount := len(a.uniqueTargetPorts)
	if uniquePortCount == 0 {
		return nil
	}
	highRiskCount := 0
	for portKey := range a.uniqueTargetPorts {
		if isHighRiskFlowPort(portKey) {
			highRiskCount++
		}
	}
	sessionCount := len(a.sessionKeys)
	portDensity := round2(float64(uniquePortCount) / float64(maxInt(sessionCount, 1)))
	return map[string]any{
		"uniqueTargetPortCount":   uniquePortCount,
		"highRiskTargetPortCount": highRiskCount,
		"sessionCount":            sessionCount,
		"targetPortDensity":       portDensity,
	}
}

// buildApplicationSignals 用于构建ApplicationSignals。
func buildApplicationSignals(a *flowMetricsAccumulator, anomalies []flowAnomalyCandidate) []string {
	if a == nil {
		return nil
	}
	signals := make([]string, 0, 8)
	if a.dnsCount > 0 {
		signals = append(signals, fmt.Sprintf("DNS事件=%d, 域名Top=%s", a.dnsCount, formatTopCounts(a.dnsQuestionCounts)))
	}
	if len(a.dnsQuestionTypeCounts) > 0 {
		signals = append(signals, fmt.Sprintf("DNS类型=%s", formatTopCounts(a.dnsQuestionTypeCounts)))
	}
	if a.httpCount > 0 {
		signals = append(signals, fmt.Sprintf("HTTP事件=%d, 方法=%s", a.httpCount, formatTopCounts(a.httpMethodCounts)))
	}
	if len(a.httpStatusCounts) > 0 {
		signals = append(signals, fmt.Sprintf("HTTP状态=%s", formatTopCounts(a.httpStatusCounts)))
	}
	if a.tlsCount > 0 {
		signals = append(signals, fmt.Sprintf("TLS握手=%d, SNI=%s", a.tlsCount, formatTopCounts(a.tlsServerNames)))
	}
	if len(a.tlsVersionCounts) > 0 {
		signals = append(signals, fmt.Sprintf("TLS版本=%s", formatTopCounts(a.tlsVersionCounts)))
	}
	if a.highEntropyCount > 0 {
		signals = append(signals, fmt.Sprintf("高熵负载=%d, 平均熵=%.2f", a.highEntropyCount, round2(a.totalEntropy/float64(maxInt(a.entropySamples, 1)))))
	}
	if directionality := buildDirectionalityIndicators(a); len(directionality) > 0 {
		packetBias := toFloat64(directionality["packetBias"])
		dominantDirection := fmt.Sprintf("%v", directionality["dominantDirection"])
		if dominantDirection != "balanced" && packetBias >= 0.75 {
			signals = append(signals, fmt.Sprintf("方向性偏置=%s(%.2f)", dominantDirection, packetBias))
		}
	}
	if portDensity := buildPortDensityIndicators(a); len(portDensity) > 0 {
		density := toFloat64(portDensity["targetPortDensity"])
		uniquePorts := toInt(portDensity["uniqueTargetPortCount"])
		if uniquePorts >= 6 || density >= 2 {
			signals = append(signals, fmt.Sprintf("端口密度=%d端口/%.2f", uniquePorts, density))
		}
	}
	if len(anomalies) > 0 {
		signals = append(signals, "异常候选="+joinAnomalyNames(anomalies))
	}
	return signals
}

// buildTopCounts 用于构建TopCounts。
func buildTopCounts(values map[string]int, limit int) []flowStringCount {
	items := sortStringIntMap(values)
	if len(items) == 0 {
		return nil
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return items
}

// buildFlowWindows 用于构建流量Windows。
func buildFlowWindows(windows map[int]*flowWindowAccumulator) []flowWindowMetric {
	if len(windows) == 0 {
		return nil
	}
	indexes := make([]int, 0, len(windows))
	for index := range windows {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	result := make([]flowWindowMetric, 0, len(indexes))
	for _, index := range indexes {
		item := windows[index]
		result = append(result, flowWindowMetric{
			WindowNo:             item.WindowNo,
			WindowStart:          item.WindowStart.Format(time.RFC3339),
			WindowEnd:            item.WindowEnd.Format(time.RFC3339),
			PacketCount:          item.PacketCount,
			ByteCount:            item.ByteCount,
			ConversationCount:    uint32(len(item.ConversationKeys)),
			InboundPacketCount:   item.InboundPacketCount,
			OutboundPacketCount:  item.OutboundPacketCount,
			InboundByteCount:     item.InboundByteCount,
			OutboundByteCount:    item.OutboundByteCount,
			TCPPacketCount:       item.TCPPacketCount,
			UDPPacketCount:       item.UDPPacketCount,
			ICMPPacketCount:      item.ICMPPacketCount,
			DNSEventCount:        item.DNSEventCount,
			HTTPEventCount:       item.HTTPEventCount,
			TLSEventCount:        item.TLSEventCount,
			HighRiskPortHitCount: item.HighRiskPortHitCount,
			EvidencePayload: map[string]any{
				"summary":   buildWindowEvidenceSummary(item),
				"protocols": item.ProtocolCounts,
			},
		})
	}
	return result
}

// buildWindowEvidenceSummary 用于构建WindowEvidence摘要。
func buildWindowEvidenceSummary(window *flowWindowAccumulator) string {
	if window == nil {
		return ""
	}
	return fmt.Sprintf(
		"窗口报文=%d，入/出=%d/%d，DNS/HTTP/TLS=%d/%d/%d，高危端口命中=%d。",
		window.PacketCount,
		window.InboundPacketCount,
		window.OutboundPacketCount,
		window.DNSEventCount,
		window.HTTPEventCount,
		window.TLSEventCount,
		window.HighRiskPortHitCount,
	)
}

// joinAnomalyNames 用于拼接AnomalyNames。
func joinAnomalyNames(items []flowAnomalyCandidate) string {
	if len(items) == 0 {
		return "-"
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, item.Name)
	}
	return strings.Join(names, ", ")
}

// maxInt 用于执行maxInt流程。
func maxInt(primary int, fallback int) int {
	if primary > fallback {
		return primary
	}
	return fallback
}

// maxUint64 用于执行maxUint64流程。
func maxUint64(left uint64, right uint64) uint64 {
	if left > right {
		return left
	}
	return right
}

// extractPacketIPs 用于提取请求、令牌或流量中的关键信息。
func extractPacketIPs(packet gopacket.Packet) (string, string, bool) {
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		return ipv4.SrcIP.String(), ipv4.DstIP.String(), true
	}
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ipv6 := ipv6Layer.(*layers.IPv6)
		return ipv6.SrcIP.String(), ipv6.DstIP.String(), true
	}
	return "", "", false
}

// classifyPacketFlow 用于执行classifyPacket流量流程。
// 按传输层协议分别归类：TCP/UDP 下再识别应用协议并解析端口/对端/会话 key，ICMP 与其它网络层协议单独处理
func classifyPacketFlow(packet gopacket.Packet, srcIP string, dstIP string, targetIP string, focusIPs map[string]struct{}) (string, string, string, string) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return classifyApplicationProtocol(packet, "TCP", int(tcp.SrcPort), int(tcp.DstPort)),
			formatObservedPort(resolveObservedPort(int(tcp.SrcPort), int(tcp.DstPort), srcIP, dstIP, targetIP, focusIPs)),
			resolvePeerIP(srcIP, dstIP, focusIPs),
			buildBidirectionalSessionKey("tcp", srcIP, dstIP, int(tcp.SrcPort), int(tcp.DstPort))
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		return classifyApplicationProtocol(packet, "UDP", int(udp.SrcPort), int(udp.DstPort)),
			formatObservedPort(resolveObservedPort(int(udp.SrcPort), int(udp.DstPort), srcIP, dstIP, targetIP, focusIPs)),
			resolvePeerIP(srcIP, dstIP, focusIPs),
			buildBidirectionalSessionKey("udp", srcIP, dstIP, int(udp.SrcPort), int(udp.DstPort))
	}
	if packet.Layer(layers.LayerTypeICMPv4) != nil {
		return "ICMPv4", "", resolvePeerIP(srcIP, dstIP, focusIPs), buildBidirectionalSessionKey("icmpv4", srcIP, dstIP, 0, 0)
	}
	if packet.Layer(layers.LayerTypeICMPv6) != nil {
		return "ICMPv6", "", resolvePeerIP(srcIP, dstIP, focusIPs), buildBidirectionalSessionKey("icmpv6", srcIP, dstIP, 0, 0)
	}
	return fallbackNetworkProtocol(packet), "", resolvePeerIP(srcIP, dstIP, focusIPs), buildBidirectionalSessionKey("network", srcIP, dstIP, 0, 0)
}

// fallbackNetworkProtocol 用于执行fallbackNetworkProtocol流程。
func fallbackNetworkProtocol(packet gopacket.Packet) string {
	switch {
	case packet.Layer(layers.LayerTypeARP) != nil:
		return "ARP"
	case packet.Layer(layers.LayerTypeIPv6) != nil:
		return "IPv6"
	default:
		return "IPv4"
	}
}

// formatObservedPort 用于格式化ObservedPort展示文本。
func formatObservedPort(port int) string {
	if port <= 0 {
		return ""
	}
	return strconv.Itoa(port)
}

// resolveObservedPort 用于解析ObservedPort。
// 目标端口的选择是启发式：优先以目标 IP / 关注 IP 所在的一侧为基准取“对端端口”，
// 否则用临时端口(49152~65535)排除法和服务端口(<=1024 或 8080/8443/3389)判定服务端口
func resolveObservedPort(srcPort int, dstPort int, srcIP string, dstIP string, targetIP string, focusIPs map[string]struct{}) int {
	targetIP = strings.TrimSpace(targetIP)
	srcIP = strings.TrimSpace(srcIP)
	dstIP = strings.TrimSpace(dstIP)
	// 明确命中目标 IP 时，取目标 IP 那侧的端口
	switch {
	case targetIP != "" && srcIP == targetIP:
		return normalizeObservedPort(srcPort)
	case targetIP != "" && dstIP == targetIP:
		return normalizeObservedPort(dstPort)
	}

	srcFocus := isIPInSet(srcIP, focusIPs)
	dstFocus := isIPInSet(dstIP, focusIPs)
	switch {
	// 只一侧是关注 IP 时，服务端口在对端，取对端端口
	case srcFocus && !dstFocus:
		return normalizeObservedPort(dstPort)
	case dstFocus && !srcFocus:
		return normalizeObservedPort(srcPort)
	// 无明确方向时，临时端口大概率是客户端源端口，排除它得到服务端口
	case isLikelyEphemeralPort(srcPort) && !isLikelyEphemeralPort(dstPort):
		return normalizeObservedPort(dstPort)
	case isLikelyEphemeralPort(dstPort) && !isLikelyEphemeralPort(srcPort):
		return normalizeObservedPort(srcPort)
	// 用服务端口特征做兜底判断
	case isPreferredServicePort(srcPort) && !isPreferredServicePort(dstPort):
		return normalizeObservedPort(srcPort)
	case isPreferredServicePort(dstPort) && !isPreferredServicePort(srcPort):
		return normalizeObservedPort(dstPort)
	case dstPort > 0:
		return normalizeObservedPort(dstPort)
	default:
		return normalizeObservedPort(srcPort)
	}
}

// normalizeObservedPort 用于归一化输入参数或业务指标。
func normalizeObservedPort(port int) int {
	if port <= 0 {
		return 0
	}
	return port
}

// isLikelyEphemeralPort 用于判断输入是否满足指定条件。
func isLikelyEphemeralPort(port int) bool {
	return port >= 49152 && port <= 65535
}

// isPreferredServicePort 用于判断输入是否满足指定条件。
func isPreferredServicePort(port int) bool {
	switch {
	case port <= 0:
		return false
	case port <= 1024:
		return true
	case port == 8080 || port == 8443 || port == 3389:
		return true
	default:
		return false
	}
}

// resolvePeerIP 用于解析PeerIP。
func resolvePeerIP(srcIP string, dstIP string, focusIPs map[string]struct{}) string {
	srcFocus := isIPInSet(srcIP, focusIPs)
	dstFocus := isIPInSet(dstIP, focusIPs)
	switch {
	case srcFocus && !dstFocus:
		return dstIP
	case dstFocus && !srcFocus:
		return srcIP
	case srcFocus && dstFocus:
		return dstIP
	default:
		return ""
	}
}

// buildFlowFocusIPs 用于构建流量FocusIPs。
func buildFlowFocusIPs(targetIP string, localIPs []string) map[string]struct{} {
	result := make(map[string]struct{})
	if trimmed := strings.TrimSpace(targetIP); trimmed != "" {
		result[trimmed] = struct{}{}
	}
	for _, item := range localIPs {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			result[trimmed] = struct{}{}
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// isIPInSet 用于判断输入是否满足指定条件。
func isIPInSet(ip string, values map[string]struct{}) bool {
	if len(values) == 0 {
		return false
	}
	_, ok := values[strings.TrimSpace(ip)]
	return ok
}

// classifyApplicationProtocol 用于执行classifyApplicationProtocol流程。
// 基于端口号先做应用协议候选判断（DNS 有独立层直接命中），后续再结合载荷字节进一步确认
func classifyApplicationProtocol(packet gopacket.Packet, fallback string, srcPort int, dstPort int) string {
	switch {
	case packet.Layer(layers.LayerTypeDNS) != nil:
		return "DNS"
	case srcPort == 80 || dstPort == 80 || srcPort == 8080 || dstPort == 8080:
		return "HTTP-CANDIDATE"
	case srcPort == 443 || dstPort == 443:
		return "HTTPS-CANDIDATE"
	case srcPort == 22 || dstPort == 22:
		return "SSH-CANDIDATE"
	case srcPort == 3389 || dstPort == 3389:
		return "RDP-CANDIDATE"
	default:
		return fallback
	}
}

// buildBidirectionalSessionKey 用于构建BidirectionalSessionKey。
// 双向会话 key：把源/目的端点字典序排序后再拼接，使“A→B”与“B→A”的两个方向归一化为同一个 key
// 这样用 map 去重后，正反两个方向的包只会被统计成同一条会话
func buildBidirectionalSessionKey(proto string, srcIP string, dstIP string, srcPort int, dstPort int) string {
	left := fmt.Sprintf("%s:%d", srcIP, srcPort)
	right := fmt.Sprintf("%s:%d", dstIP, dstPort)
	if left > right {
		left, right = right, left
	}
	return proto + "|" + left + "|" + right
}

// buildFlowAnomalyCandidates 用于构建流量AnomalyCandidates。
// 四类异常候选是行为风险分的“大额加分项”，分别对应端口扫描、DNS 突增、ICMP 探测、TCP RST 突增
func buildFlowAnomalyCandidates(a *flowMetricsAccumulator) []flowAnomalyCandidate {
	items := make([]flowAnomalyCandidate, 0, 4)
	if len(a.uniqueTargetPorts) >= 8 && a.synProbeCount >= 8 {
		items = append(items, flowAnomalyCandidate{
			Name:     "port-scan-candidate",
			Score:    42,
			RiskHint: "HIGH",
			Summary:  fmt.Sprintf("检测到面向目标的 SYN 探测 %d 次，涉及 %d 个目标端口，存在端口扫描候选特征。", a.synProbeCount, len(a.uniqueTargetPorts)),
		})
	}
	if a.dnsCount >= 60 && len(a.uniqueTargetPorts) >= 4 {
		items = append(items, flowAnomalyCandidate{
			Name:     "dns-spike-candidate",
			Score:    14,
			RiskHint: "MEDIUM",
			Summary:  fmt.Sprintf("检测到 DNS 相关报文 %d 个，存在解析请求突增候选特征。", a.dnsCount),
		})
	}
	if a.icmpCount >= 30 {
		items = append(items, flowAnomalyCandidate{
			Name:     "icmp-probe-candidate",
			Score:    20,
			RiskHint: "MEDIUM",
			Summary:  fmt.Sprintf("检测到 ICMP 相关报文 %d 个，存在探测或连通性扫描候选特征。", a.icmpCount),
		})
	}
	if a.tcpResetCount >= 40 {
		items = append(items, flowAnomalyCandidate{
			Name:     "tcp-reset-burst-candidate",
			Score:    8,
			RiskHint: "LOW",
			Summary:  fmt.Sprintf("检测到 TCP RST 报文 %d 个，可能存在大量失败连接或快速拒绝。", a.tcpResetCount),
		})
	}
	return items
}

// buildFlowBehaviorRiskScore 用于构建流量Behavior风险评分。
// 行为风险分 = 4(命中目标流量) + Σ异常候选分 + 突发分*0.08 + 扫描分*0.12
//            + DNS/HTTP/TLS 事件阈值分 + 高熵载荷阈值分 + 方向性偏置分 + 端口密度/高危端口分，上限 100
func buildFlowBehaviorRiskScore(metrics flowParseMetrics) float64 {
	score := 0.0
	// 命中目标流量就给 4 分基础分，表示“确实存在与目标相关的动态行为”
	if metrics.MatchedPacketCount > 0 {
		score += 4
	}
	// 异常候选分值较大（42/20/14/8），是行为风险的主要来源
	for _, item := range metrics.AnomalyCandidates {
		score += item.Score
	}
	// 突发与扫描按系数折算成小幅加分，避免单一指标压过候选规则
	score += metrics.BurstScore * 0.08
	score += metrics.ScanScore * 0.12
	// 以下为应用层事件数量的阈值加分，超过阈值说明存在明显协议活动
	if metrics.DNSEventCount >= 40 {
		score += 3
	}
	if metrics.HTTPEventCount >= 20 {
		score += 2
	}
	if metrics.TLSEventCount >= 20 {
		score += 2
	}
	// 高熵载荷达到 24 个，暗示存在较多加密/混淆流量
	if entropyIndicators := metrics.PayloadEntropyIndicators; len(entropyIndicators) != 0 && toInt(entropyIndicators["highEntropyPacketCount"]) >= 24 {
		score += 4
	}
	// 方向性偏置 >= 0.92 表示流量几乎单向，符合扫描/单向攻击的形态
	if directionality := metrics.DirectionalityIndicators; len(directionality) != 0 {
		if dominantDirection := fmt.Sprintf("%v", directionality["dominantDirection"]); dominantDirection != "balanced" && toFloat64(directionality["packetBias"]) >= 0.92 {
			score += 4
		}
	}
	if portDensity := metrics.PortDensityIndicators; len(portDensity) != 0 {
		// 目标端口越多、端口密度越高、高危端口越多，越像端口扫描/爆破
		if toInt(portDensity["uniqueTargetPortCount"]) >= 10 {
			score += 4
		}
		if toFloat64(portDensity["targetPortDensity"]) >= 3 {
			score += 3
		}
		if toInt(portDensity["highRiskTargetPortCount"]) >= 2 {
			score += 6
		}
	}
	if score > 100 {
		return 100
	}
	return round2(score)
}

// buildOfflinePCAPSummary 用于构建OfflinePCAP摘要。
func buildOfflinePCAPSummary(metrics flowParseMetrics, resolvedPath string) string {
	if metrics.MatchedPacketCount == 0 {
		return fmt.Sprintf("离线文件 %s 已解析，但未发现与目标 IP 相关的报文。", resolvedPath)
	}
	return fmt.Sprintf(
		"离线文件 %s 解析完成：目标相关报文 %d 个，会话 %d 个，字节 %d，协议分布 %s。",
		resolvedPath,
		metrics.MatchedPacketCount,
		metrics.SessionCount,
		metrics.ByteCount,
		formatProtocolDistribution(metrics.ProtocolCounts),
	)
}

// buildOfflinePCAPEvidenceItems 用于构建OfflinePCAPEvidenceItems。
func buildOfflinePCAPEvidenceItems(metrics flowParseMetrics, resolvedPath string) []securityEvidenceItem {
	items := []securityEvidenceItem{
		{
			Source:   resolveFlowCollectorSourceName(FlowParseModeOfflinePCAP),
			Title:    "离线 pcap 解析完成",
			Summary:  buildOfflinePCAPSummary(metrics, resolvedPath),
			RiskHint: selectFlowRiskHint(buildFlowBehaviorRiskScore(metrics)),
		},
	}
	if metrics.MatchedPacketCount > 0 {
		items = append(items, securityEvidenceItem{
			Source:   resolveFlowCollectorSourceName(FlowParseModeOfflinePCAP),
			Title:    "协议与会话统计",
			Summary:  fmt.Sprintf("协议分布=%s；高频端口=%s；高频对端=%s。", formatProtocolDistribution(metrics.ProtocolCounts), formatTopCounts(metrics.PortCounts), formatTopCounts(metrics.PeerCounts)),
			RiskHint: "INFO",
		})
	}
	if len(metrics.AnomalyCandidates) > 0 {
		items = append(items, securityEvidenceItem{
			Source:   resolveFlowCollectorSourceName(FlowParseModeOfflinePCAP),
			Title:    "基础异常特征候选",
			Summary:  joinAnomalySummaries(metrics.AnomalyCandidates),
			RiskHint: selectAnomalyRiskHint(metrics.AnomalyCandidates),
		})
	}
	return items
}

// formatProtocolDistribution 用于格式化ProtocolDistribution展示文本。
func formatProtocolDistribution(counts map[string]int) string {
	items := sortStringIntMap(counts)
	if len(items) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("%s=%d", item.Key, item.Count))
	}
	return strings.Join(parts, ", ")
}

// formatTopCounts 用于格式化TopCounts展示文本。
func formatTopCounts(counts map[string]int) string {
	items := sortStringIntMap(counts)
	if len(items) == 0 {
		return "-"
	}
	if len(items) > 3 {
		items = items[:3]
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("%s=%d", item.Key, item.Count))
	}
	return strings.Join(parts, ", ")
}

// joinAnomalySummaries 用于拼接AnomalySummaries。
func joinAnomalySummaries(items []flowAnomalyCandidate) string {
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, item.Summary)
	}
	return strings.Join(parts, "；")
}

// selectAnomalyRiskHint 用于执行selectAnomaly风险Hint流程。
func selectAnomalyRiskHint(items []flowAnomalyCandidate) string {
	level := "LOW"
	for _, item := range items {
		switch item.RiskHint {
		case "HIGH":
			return "HIGH"
		case "MEDIUM":
			level = "MEDIUM"
		}
	}
	return level
}

// selectFlowRiskHint 用于执行select流量风险Hint流程。
func selectFlowRiskHint(score float64) string {
	switch {
	case score >= 70:
		return "HIGH"
	case score >= 35:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// sortStringIntMap 用于排序StringIntMap。
func sortStringIntMap(values map[string]int) []flowStringCount {
	items := make([]flowStringCount, 0, len(values))
	for key, count := range values {
		items = append(items, flowStringCount{Key: key, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Key < items[j].Key
		}
		return items[i].Count > items[j].Count
	})
	return items
}

// parseOfflinePCAPWithGopacket 用于解析输入数据并转换为内部模型。
// 离线解析主流程：打开文件 → 逐包读取 → 累计指标，读到 EOF 才视为解析完成
func parseOfflinePCAPWithGopacket(ctx context.Context, req FlowParseRequest, resolvedPath string) (flowParseMetrics, error) {
	format, packetSource, closer, err := openOfflinePacketSource(resolvedPath)
	if err != nil {
		return flowParseMetrics{}, err
	}
	defer closer()

	accumulator := newFlowMetricsAccumulator(req.TargetIP, req.LocalIPs, req.WindowSeconds)
	for {
		// 每读一包前先检查上下文是否被取消，保证大文件解析能被外部超时/停止及时打断
		select {
		case <-ctx.Done():
			return flowParseMetrics{}, ctx.Err()
		default:
		}

		packet, err := packetSource.NextPacket()
		if err != nil {
			// io.EOF 表示文件正常读完，属于预期结束，不是错误
			if err == io.EOF {
				break
			}
			return flowParseMetrics{}, fmt.Errorf("读取 pcap 报文失败: %w", err)
		}
		accumulator.observe(packet)
	}
	return accumulator.finalize(format), nil
}

// openOfflinePacketSource 用于执行openOfflinePacket来源流程。
func openOfflinePacketSource(path string) (string, *gopacket.PacketSource, func() error, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", nil, nil, fmt.Errorf("打开 pcap 文件失败: %w", err)
	}

	format, source, err := buildOfflinePacketSource(file)
	if err != nil {
		_ = file.Close()
		return "", nil, nil, err
	}
	return format, source, file.Close, nil
}

// buildOfflinePacketSource 用于构建OfflinePacket来源。
// 通过文件头魔数区分 pcapng（0x0A0D0D0A）与传统 pcap，选择对应读取器，二者后续解析逻辑一致
func buildOfflinePacketSource(file *os.File) (string, *gopacket.PacketSource, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(file, header); err != nil {
		return "", nil, fmt.Errorf("读取 pcap 文件头失败: %w", err)
	}
	// 读完 4 字节后把文件指针拨回开头，让下游读取器从完整文件头开始解析
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", nil, fmt.Errorf("重置 pcap 文件指针失败: %w", err)
	}

	if binary.BigEndian.Uint32(header) == pcapngMagicNumber {
		reader, err := pcapgo.NewNgReader(file, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return "", nil, fmt.Errorf("初始化 pcapng 读取器失败: %w", err)
		}
		return "pcapng", gopacket.NewPacketSource(reader, reader.LinkType()), nil
	}

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		return "", nil, fmt.Errorf("初始化 pcap 读取器失败: %w", err)
	}
	return "pcap", gopacket.NewPacketSource(reader, reader.LinkType()), nil
}
