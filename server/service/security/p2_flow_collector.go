package security

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"lightweight-ip-traffic-sa/server/config"
)

// RealFlowCollector 用于采集Real流量特征数据。
type RealFlowCollector struct{}

// Collect 用于执行Collect流程。
func (c RealFlowCollector) Collect(targetIP string, cfg config.SecurityConfig) (FlowCollectedData, error) {
	parseRequest := buildFlowParseRequest(targetIP, cfg)
	sourceName := resolveFlowCollectorSourceName(parseRequest.Mode)
	configVersion := buildCollectorConfigVersion(cfg)
	return runCollectorStep(
		"flow",
		targetIP,
		sourceName,
		configVersion,
		parseRequest.Timeout,
		resolveSourceTTL(cfg.Source.Flow.CacheTTLSeconds, 15*time.Minute),
		func() (FlowCollectedData, error) {
			parser := resolveFlowParser(parseRequest.Mode)
			parserCtx, cancel := context.WithTimeout(context.Background(), parseRequest.Timeout)
			defer cancel()

			result, err := parser.Parse(parserCtx, parseRequest)
			if err != nil {
				return FlowCollectedData{}, err
			}
			return mapFlowParseResultToCollectedData(targetIP, result), nil
		},
		validateFlowCollectedData,
	)
}

// resolveFlowParser 用于解析流量Parser。
func resolveFlowParser(mode FlowParseMode) FlowParser {
	switch mode {
	case FlowParseModeOfflinePCAP:
		return offlinePCAPFlowParser{}
	case FlowParseModeOnlineCapture:
		return realOnlineCaptureFlowParser{}
	case FlowParseModeDisabled:
		return disabledFlowParser{}
	default:
		return sampleFlowParser{}
	}
}

// normalizeFlowMode 用于归一化输入参数或业务指标。
func normalizeFlowMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "offline_pcap":
		return "offline_pcap"
	case "online_capture":
		return "online_capture"
	default:
		return "sample"
	}
}

// buildOfflinePCAPFailureResult 用于构建OfflinePCAPFailureResult。
func buildOfflinePCAPFailureResult(req FlowParseRequest, parserName string, status string, summary string, errorModel *FlowParseErrorModel, debugPayload map[string]any, evidenceTitle string, evidenceSummary string) FlowParseResult {
	return FlowParseResult{
		Mode:                   FlowParseModeOfflinePCAP,
		Status:                 status,
		Summary:                summary,
		BehaviorRiskScore:      0,
		SourceName:             resolveFlowCollectorSourceName(FlowParseModeOfflinePCAP),
		SourceChain:            []string{resolveFlowCollectorSourceName(FlowParseModeOfflinePCAP)},
		ParserName:             parserName,
		ParserReady:            false,
		IntegrationStage:       "offline-entry-only",
		PrototypeBoundary:      "independent-orchestration-entry",
		InputKind:              "pcap-file",
		InputSnapshot:          map[string]any{"pcapFilePath": strings.TrimSpace(req.PcapFilePath), "windowSeconds": req.WindowSeconds, "targetIP": req.TargetIP},
		ErrorModel:             errorModel,
		DebugPayload:           debugPayload,
		CollectedStableFields:  defaultFlowCollectedStableFields(FlowParseModeOfflinePCAP, false),
		NormalizedStableFields: defaultFlowNormalizedStableFields(),
		FutureStableFields:     defaultFlowFutureStableFields(),
		PrototypeOnlyFields:    defaultFlowPrototypeOnlyFields(FlowParseModeOfflinePCAP),
		DebugOnlyFields:        defaultFlowDebugOnlyFields(FlowParseModeOfflinePCAP),
		EvidenceItems: []securityEvidenceItem{
			{
				Source:   resolveFlowCollectorSourceName(FlowParseModeOfflinePCAP),
				Title:    evidenceTitle,
				Summary:  evidenceSummary,
				RiskHint: "INFO",
			},
		},
	}
}

// buildOnlineCaptureResult 用于构建OnlineCaptureResult。
func buildOnlineCaptureResult(req FlowParseRequest, parserName string, status string, summary string, errorModel *FlowParseErrorModel, debugPayload map[string]any, evidenceTitle string) FlowParseResult {
	return FlowParseResult{
		Mode:                   FlowParseModeOnlineCapture,
		Status:                 status,
		Summary:                summary,
		BehaviorRiskScore:      0,
		SourceName:             resolveFlowCollectorSourceName(FlowParseModeOnlineCapture),
		SourceChain:            []string{resolveFlowCollectorSourceName(FlowParseModeOnlineCapture), "gopacket-live-entry"},
		ParserName:             parserName,
		ParserReady:            false,
		IntegrationStage:       "online-capture-entry-ready",
		PrototypeBoundary:      "independent-orchestration-entry",
		InputKind:              "network-interface",
		InputSnapshot:          map[string]any{"interfaceName": strings.TrimSpace(req.InterfaceName), "windowSeconds": req.WindowSeconds, "targetIP": req.TargetIP},
		ErrorModel:             errorModel,
		DebugPayload:           debugPayload,
		CollectedStableFields:  defaultFlowCollectedStableFields(FlowParseModeOnlineCapture, false),
		NormalizedStableFields: defaultFlowNormalizedStableFields(),
		FutureStableFields:     defaultFlowFutureStableFields(),
		PrototypeOnlyFields:    defaultFlowPrototypeOnlyFields(FlowParseModeOnlineCapture),
		DebugOnlyFields:        defaultFlowDebugOnlyFields(FlowParseModeOnlineCapture),
		EvidenceItems: []securityEvidenceItem{
			{
				Source:   resolveFlowCollectorSourceName(FlowParseModeOnlineCapture),
				Title:    evidenceTitle,
				Summary:  summary,
				RiskHint: "INFO",
			},
		},
	}
}

// disabledFlowParser 用于解析disabled流量输入并输出标准结果。
type disabledFlowParser struct{}

// Name 用于返回流量解析器名称。
func (p disabledFlowParser) Name() string {
	return "prototype-flow-disabled-parser"
}

// Parse 用于解析流量输入并生成标准流量结果。
func (p disabledFlowParser) Parse(ctx context.Context, req FlowParseRequest) (FlowParseResult, error) {
	return FlowParseResult{
		Mode:                   FlowParseModeDisabled,
		Status:                 FlowStatusDisabled,
		Summary:                "流量维能力未启用，当前仍以 IP 多特征链路为主。",
		BehaviorRiskScore:      0,
		SourceName:             resolveFlowCollectorSourceName(FlowParseModeDisabled),
		SourceChain:            []string{resolveFlowCollectorSourceName(FlowParseModeDisabled)},
		ParserName:             p.Name(),
		ParserReady:            false,
		IntegrationStage:       "default-off",
		PrototypeBoundary:      "default-off",
		InputKind:              "disabled",
		InputSnapshot:          map[string]any{"mode": string(req.Mode)},
		DebugPayload:           map[string]any{"reason": "flow disabled by configuration"},
		CollectedStableFields:  defaultFlowCollectedStableFields(FlowParseModeDisabled, false),
		NormalizedStableFields: defaultFlowNormalizedStableFields(),
		FutureStableFields:     defaultFlowFutureStableFields(),
		PrototypeOnlyFields:    defaultFlowPrototypeOnlyFields(FlowParseModeDisabled),
		DebugOnlyFields:        defaultFlowDebugOnlyFields(FlowParseModeDisabled),
		EvidenceItems: []securityEvidenceItem{
			{
				Source:   resolveFlowCollectorSourceName(FlowParseModeDisabled),
				Title:    "流量维已关闭",
				Summary:  "当前未启用流量动态特征采集，不影响 IP 主链路，也不会进入默认来源链。",
				RiskHint: "LOW",
			},
		},
	}, nil
}

// sampleFlowParser 用于解析sample流量输入并输出标准结果。
type sampleFlowParser struct{}

// Name 用于返回流量解析器名称。
func (p sampleFlowParser) Name() string {
	return "prototype-flow-sample-parser"
}

// Parse 用于解析流量输入并生成标准流量结果。
func (p sampleFlowParser) Parse(ctx context.Context, req FlowParseRequest) (FlowParseResult, error) {
	profile := strings.TrimSpace(req.SampleProfile)
	if profile == "" {
		profile = "baseline-web"
	}

	score := 12.0
	summary := "伪实时样本驱动：普通 Web 会话占主导，未发现明显异常。"
	switch profile {
	case "dns-spike":
		score = 46
		summary = "伪实时样本驱动：DNS 请求激增，存在异常解析放大迹象。"
	case "scan-burst":
		score = 68
		summary = "伪实时样本驱动：短时端口探测突发，存在横向扫描特征。"
	}

	return FlowParseResult{
		Mode:                   FlowParseModeSample,
		Status:                 FlowStatusSampleOnly,
		Summary:                summary + " 当前仅作为流量样本原型展示，不进入默认来源链。",
		BehaviorRiskScore:      score,
		SourceName:             resolveFlowCollectorSourceName(FlowParseModeSample),
		SourceChain:            []string{resolveFlowCollectorSourceName(FlowParseModeSample), "gopacket-sample-placeholder"},
		ParserName:             p.Name(),
		ParserReady:            false,
		IntegrationStage:       "sample-only",
		PrototypeBoundary:      "sample-only",
		InputKind:              "sample-profile",
		InputSnapshot:          map[string]any{"sampleProfile": profile, "windowSeconds": req.WindowSeconds},
		DebugPayload:           map[string]any{"sampleProfile": profile},
		CollectedStableFields:  defaultFlowCollectedStableFields(FlowParseModeSample, false),
		NormalizedStableFields: defaultFlowNormalizedStableFields(),
		FutureStableFields:     defaultFlowFutureStableFields(),
		PrototypeOnlyFields:    defaultFlowPrototypeOnlyFields(FlowParseModeSample),
		DebugOnlyFields:        defaultFlowDebugOnlyFields(FlowParseModeSample),
		EvidenceItems: []securityEvidenceItem{
			{
				Source:   resolveFlowCollectorSourceName(FlowParseModeSample),
				Title:    "样本流量驱动",
				Summary:  summary + " 当前仅用于样本原型展示。",
				RiskHint: abuseRiskHint(score),
			},
		},
	}, nil
}

// offlinePCAPFlowParser 用于解析offlinePCAP流量输入并输出标准结果。
type offlinePCAPFlowParser struct{}

// Name 用于返回流量解析器名称。
func (p offlinePCAPFlowParser) Name() string {
	return "prototype-flow-offline-pcap-parser"
}

// Parse 用于解析流量输入并生成标准流量结果。
func (p offlinePCAPFlowParser) Parse(ctx context.Context, req FlowParseRequest) (FlowParseResult, error) {
	path := strings.TrimSpace(req.PcapFilePath)
	if path == "" {
		return FlowParseResult{
			Mode:                   FlowParseModeOfflinePCAP,
			Status:                 FlowStatusConfigRequired,
			Summary:                "离线 pcap 回放模式已预留，但尚未配置 pcap 文件路径。",
			BehaviorRiskScore:      0,
			SourceName:             resolveFlowCollectorSourceName(FlowParseModeOfflinePCAP),
			SourceChain:            []string{resolveFlowCollectorSourceName(FlowParseModeOfflinePCAP)},
			ParserName:             p.Name(),
			ParserReady:            false,
			IntegrationStage:       "offline-entry-only",
			PrototypeBoundary:      "independent-orchestration-entry",
			InputKind:              "pcap-file",
			InputSnapshot:          map[string]any{"pcapFilePath": "", "windowSeconds": req.WindowSeconds, "targetIP": req.TargetIP},
			ErrorModel:             newFlowParseErrorModel(FlowErrorCodePcapPathRequired, FlowErrorCategoryConfig, "未配置离线 pcap 文件路径。", false),
			DebugPayload:           map[string]any{"failureCause": "pcap path missing"},
			CollectedStableFields:  defaultFlowCollectedStableFields(FlowParseModeOfflinePCAP, false),
			NormalizedStableFields: defaultFlowNormalizedStableFields(),
			FutureStableFields:     defaultFlowFutureStableFields(),
			PrototypeOnlyFields:    defaultFlowPrototypeOnlyFields(FlowParseModeOfflinePCAP),
			DebugOnlyFields:        defaultFlowDebugOnlyFields(FlowParseModeOfflinePCAP),
			EvidenceItems: []securityEvidenceItem{
				{
					Source:   resolveFlowCollectorSourceName(FlowParseModeOfflinePCAP),
					Title:    "离线 pcap 待配置",
					Summary:  "独立流量编排入口已建立，待提供 pcap 文件并接入解析器后才能形成真实能力。",
					RiskHint: "INFO",
				},
			},
		}, nil
	}

	resolved, err := resolveConfigPath(path)
	if err != nil {
		return buildOfflinePCAPFailureResult(
			req,
			p.Name(),
			FlowStatusInputInvalid,
			"离线 pcap 路径解析失败，当前仅保留独立入口信息。",
			newFlowParseErrorModel(FlowErrorCodePcapPathInvalid, FlowErrorCategoryInput, "pcap 配置路径无效。", false),
			map[string]any{"configuredPcapPath": path, "failureCause": err.Error()},
			"离线 pcap 路径无效",
			"当前提供的 pcap 路径无法解析，仅保留离线入口状态，不影响默认主链路。",
		), nil
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return buildOfflinePCAPFailureResult(
			FlowParseRequest{TargetIP: req.TargetIP, Mode: req.Mode, Timeout: req.Timeout, WindowSeconds: req.WindowSeconds, SampleProfile: req.SampleProfile, PcapFilePath: resolved, InterfaceName: req.InterfaceName},
			p.Name(),
			FlowStatusEntryUnavailable,
			"离线 pcap 文件不可用，当前仅保留独立入口状态。",
			newFlowParseErrorModel(FlowErrorCodePcapFileUnavailable, FlowErrorCategoryDependency, "pcap 文件不存在或当前进程无权读取。", true),
			map[string]any{"resolvedPcapPath": resolved, "failureCause": err.Error()},
			"离线 pcap 文件不可用",
			"当前 pcap 文件无法读取，仅保留离线入口状态，不影响默认主链路。",
		), nil
	}
	if info.IsDir() {
		return buildOfflinePCAPFailureResult(
			FlowParseRequest{TargetIP: req.TargetIP, Mode: req.Mode, Timeout: req.Timeout, WindowSeconds: req.WindowSeconds, SampleProfile: req.SampleProfile, PcapFilePath: resolved, InterfaceName: req.InterfaceName},
			p.Name(),
			FlowStatusInputInvalid,
			"离线 pcap 路径指向目录，无法作为解析输入。",
			newFlowParseErrorModel(FlowErrorCodePcapPathInvalid, FlowErrorCategoryInput, "pcap 路径指向目录，不是可解析文件。", false),
			map[string]any{"resolvedPcapPath": resolved, "failureCause": "path points to directory"},
			"离线 pcap 输入无效",
			"当前路径不是 pcap 文件，仅保留离线入口状态，不影响默认主链路。",
		), nil
	}

	metrics, err := parseOfflinePCAPWithGopacket(ctx, req, resolved)
	if err != nil {
		errorCode := FlowErrorCodePcapParseFailed
		retryable := false
		if err == context.DeadlineExceeded || err == context.Canceled {
			errorCode = FlowErrorCodePcapParseTimeout
			retryable = true
		}
		return buildOfflinePCAPFailureResult(
			FlowParseRequest{TargetIP: req.TargetIP, Mode: req.Mode, Timeout: req.Timeout, WindowSeconds: req.WindowSeconds, SampleProfile: req.SampleProfile, PcapFilePath: resolved, InterfaceName: req.InterfaceName},
			p.Name(),
			FlowStatusParseFailed,
			"离线 pcap 解析失败，当前仅保留独立入口与失败说明。",
			newFlowParseErrorModel(errorCode, FlowErrorCategoryRuntime, "pcap 解析过程失败，请检查输入文件与运行环境。", retryable),
			map[string]any{"resolvedPcapPath": resolved, "fileSize": info.Size(), "failureCause": err.Error()},
			"离线 pcap 解析失败",
			"gopacket 未能完成当前文件解析，仅保留失败说明，不影响默认主链路。",
		), nil
	}
	score := buildFlowBehaviorRiskScore(metrics)
	status := FlowStatusParsed
	if metrics.MatchedPacketCount == 0 {
		status = FlowStatusNoTargetTraffic
	}

	parsedMetrics := buildFlowParsedMetricsMap(metrics)

	return FlowParseResult{
		Mode:                   FlowParseModeOfflinePCAP,
		Status:                 status,
		Summary:                buildOfflinePCAPSummary(metrics, resolved),
		BehaviorRiskScore:      score,
		SourceName:             resolveFlowCollectorSourceName(FlowParseModeOfflinePCAP),
		SourceChain:            []string{resolveFlowCollectorSourceName(FlowParseModeOfflinePCAP), "gopacket-offline-parser"},
		ParserName:             p.Name(),
		ParserReady:            true,
		IntegrationStage:       "offline-pcap-gopacket",
		PrototypeBoundary:      "independent-orchestration-entry",
		InputKind:              "pcap-file",
		InputSnapshot:          map[string]any{"pcapFilePath": resolved, "windowSeconds": req.WindowSeconds, "targetIP": req.TargetIP},
		ParsedMetrics:          parsedMetrics,
		CollectedStableFields:  offlinePCAPCollectedStableFields(),
		NormalizedStableFields: defaultFlowNormalizedStableFields(),
		FutureStableFields:     defaultFlowFutureStableFields(),
		PrototypeOnlyFields:    defaultFlowPrototypeOnlyFields(FlowParseModeOfflinePCAP),
		DebugOnlyFields:        defaultFlowDebugOnlyFields(FlowParseModeOfflinePCAP),
		DebugPayload:           map[string]any{"resolvedPcapPath": resolved, "fileSize": info.Size()},
		EvidenceItems:          buildFlowAnalysisEvidenceItems(FlowParseModeOfflinePCAP, metrics, resolved),
	}, nil
}

// onlineCaptureFlowParser 用于解析onlineCapture流量输入并输出标准结果。
type onlineCaptureFlowParser struct{}

// Name 用于返回流量解析器名称。
func (p onlineCaptureFlowParser) Name() string {
	return "prototype-flow-online-capture-parser"
}

// Parse 用于解析流量输入并生成标准流量结果。
func (p onlineCaptureFlowParser) Parse(ctx context.Context, req FlowParseRequest) (FlowParseResult, error) {
	iface := strings.TrimSpace(req.InterfaceName)
	status := FlowStatusWaitingPermission
	summary := "在线抓包入口待授权，需提供可授权网卡后才能接入持续采集调度。"
	debugPayload := map[string]any{"configuredInterfaceName": iface}
	var errorModel *FlowParseErrorModel
	if iface == "" {
		errorModel = newFlowParseErrorModel(FlowErrorCodeCapturePermissionNeeded, FlowErrorCategoryPermission, "未提供可授权的抓包网卡，在线抓包入口仍处于待授权状态。", false)
	}

	if iface != "" {
		ifaceInfo, err := net.InterfaceByName(iface)
		if err != nil {
			return buildOnlineCaptureResult(
				req,
				p.Name(),
				FlowStatusEntryUnavailable,
				"在线抓包网卡不可用，当前仅保留独立入口状态。",
				newFlowParseErrorModel(FlowErrorCodeCaptureInterfaceInvalid, FlowErrorCategoryDependency, "指定网卡不存在或当前进程无法访问。", true),
				map[string]any{"configuredInterfaceName": iface, "failureCause": err.Error()},
				"在线抓包网卡不可用",
			), nil
		}
		status = FlowStatusEntryReady
		summary = fmt.Sprintf("在线抓包入口已绑定网卡 %s，当前默认仍保持关闭，待后续接入持续采集调度。", ifaceInfo.Name)
		debugPayload["interfaceIndex"] = ifaceInfo.Index
		debugPayload["mtu"] = ifaceInfo.MTU
		debugPayload["flags"] = ifaceInfo.Flags.String()
		errorModel = nil
	}

	return FlowParseResult{
		Mode:                   FlowParseModeOnlineCapture,
		Status:                 status,
		Summary:                summary,
		BehaviorRiskScore:      0,
		SourceName:             resolveFlowCollectorSourceName(FlowParseModeOnlineCapture),
		SourceChain:            []string{resolveFlowCollectorSourceName(FlowParseModeOnlineCapture), "gopacket-live-entry"},
		ParserName:             p.Name(),
		ParserReady:            false,
		IntegrationStage:       "online-capture-entry-ready",
		PrototypeBoundary:      "independent-orchestration-entry",
		InputKind:              "network-interface",
		InputSnapshot:          map[string]any{"interfaceName": iface, "windowSeconds": req.WindowSeconds, "targetIP": req.TargetIP},
		ErrorModel:             errorModel,
		DebugPayload:           debugPayload,
		CollectedStableFields:  onlineCaptureCollectedStableFields(),
		NormalizedStableFields: defaultFlowNormalizedStableFields(),
		FutureStableFields:     defaultFlowFutureStableFields(),
		PrototypeOnlyFields:    defaultFlowPrototypeOnlyFields(FlowParseModeOnlineCapture),
		DebugOnlyFields:        defaultFlowDebugOnlyFields(FlowParseModeOnlineCapture),
		EvidenceItems: []securityEvidenceItem{
			{
				Source:   resolveFlowCollectorSourceName(FlowParseModeOnlineCapture),
				Title:    "在线抓包入口已预留",
				Summary:  summary,
				RiskHint: "INFO",
			},
		},
	}, nil
}
