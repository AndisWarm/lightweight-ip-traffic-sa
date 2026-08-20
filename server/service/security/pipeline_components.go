package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"strings"
	"time"

	"lightweight-ip-traffic-sa/server/config"
	"lightweight-ip-traffic-sa/server/global"
	securityModel "lightweight-ip-traffic-sa/server/model/security"
	"lightweight-ip-traffic-sa/server/utils"
)

// collectorTimeout 是单个采集步骤的硬超时。设为 2 秒是为了让整条异步任务链路
// 不会因为某个外部数据源（GeoLite2/RDAP/端口探测/抓包）长时间无响应而卡死。
const collectorTimeout = 2 * time.Second

// CollectorErrorKind 用于限定采集器错误分类取值。
type CollectorErrorKind string

// 四类错误把"超时、外部源不可用、返回数据不合法、程序内部异常"区分开，
// 上层据此决定是否降级、是否重试、审计里记什么类别，而不是拿到一个笼统的 error。
const (
	CollectorErrorTimeout     CollectorErrorKind = "TIMEOUT"
	CollectorErrorUnavailable CollectorErrorKind = "UNAVAILABLE"
	CollectorErrorInvalidData CollectorErrorKind = "INVALID_DATA"
	CollectorErrorInternal    CollectorErrorKind = "INTERNAL"
)

// CollectorError 用于表达Collector错误信息。
type CollectorError struct {
	StepName string
	Source   string
	TargetIP string
	Kind     CollectorErrorKind
	Cause    error
}

// Error 用于返回当前错误的可读描述。
func (e *CollectorError) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("collector[%s] step=%s kind=%s target=%s", e.Source, e.StepName, e.Kind, e.TargetIP)
	}
	return fmt.Sprintf("collector[%s] step=%s kind=%s target=%s: %v", e.Source, e.StepName, e.Kind, e.TargetIP, e.Cause)
}

// Unwrap 用于暴露底层错误以支持 errors 包判定。
func (e *CollectorError) Unwrap() error {
	return e.Cause
}

// BaseInfoCollectedData 用于承载基础画像采集结果。
type BaseInfoCollectedData struct {
	IP           string         `json:"ip"`
	Country      string         `json:"country"`
	Region       string         `json:"region"`
	City         string         `json:"city"`
	ISP          string         `json:"isp"`
	WhoisOrg     string         `json:"whoisOrg"`
	WhoisContact string         `json:"whoisContact"`
	RawPayload   map[string]any `json:"rawPayload"`
	SourceName   string         `json:"sourceName"`
}

// ReputationCollectedData 用于承载信誉风险采集结果。
type ReputationCollectedData struct {
	IP              string         `json:"ip"`
	ReputationScore float64        `json:"reputationScore"`
	SourceName      string         `json:"sourceName"`
	RawPayload      map[string]any `json:"rawPayload"`
}

// AttackSurfaceCollectedData 用于承载攻击面采集结果。
type AttackSurfaceCollectedData struct {
	IP                string         `json:"ip"`
	OpenPortCount     int            `json:"openPortCount"`
	HighRiskPortCount int            `json:"highRiskPortCount"`
	GeoRiskFlag       bool           `json:"geoRiskFlag"`
	SourceName        string         `json:"sourceName"`
	RawPayload        map[string]any `json:"rawPayload"`
}

// FlowCollectedData 用于承载流量采集与解析结果。
type FlowCollectedData struct {
	IP                     string                 `json:"ip"`
	Mode                   string                 `json:"mode"`
	Status                 string                 `json:"status"`
	BehaviorRiskScore      float64                `json:"behaviorRiskScore"`
	Summary                string                 `json:"summary"`
	SourceName             string                 `json:"sourceName"`
	SourceChain            []string               `json:"sourceChain"`
	EvidenceItems          []securityEvidenceItem `json:"evidenceItems"`
	ParserName             string                 `json:"parserName"`
	ParserReady            bool                   `json:"parserReady"`
	IntegrationStage       string                 `json:"integrationStage"`
	PrototypeBoundary      string                 `json:"prototypeBoundary"`
	InputKind              string                 `json:"inputKind"`
	InputSnapshot          map[string]any         `json:"inputSnapshot"`
	ParsedMetrics          map[string]any         `json:"parsedMetrics"`
	CollectedStableFields  []string               `json:"collectedStableFields"`
	NormalizedStableFields []string               `json:"normalizedStableFields"`
	FutureStableFields     []string               `json:"futureStableFields"`
	PrototypeOnlyFields    []string               `json:"prototypeOnlyFields"`
	DebugOnlyFields        []string               `json:"debugOnlyFields"`
	RawPayload             map[string]any         `json:"rawPayload"`
}

// TaskCollectedData 用于汇总单次安全任务的多源采集结果。
type TaskCollectedData struct {
	BaseInfo      BaseInfoCollectedData      `json:"baseInfo"`
	Reputation    ReputationCollectedData    `json:"reputation"`
	AttackSurface AttackSurfaceCollectedData `json:"attackSurface"`
	Flow          FlowCollectedData          `json:"flow"`
}

// NormalizedFeatureSet 用于承载融合评分前的归一化特征集合。
type NormalizedFeatureSet struct {
	TargetIP                   string                 `json:"targetIp"`
	SourceName                 string                 `json:"sourceName"`
	WhoisRiskScore             float64                `json:"whoisRiskScore"`
	ReputationScore            float64                `json:"reputationScore"`
	AttackSurfaceRisk          float64                `json:"attackSurfaceRisk"`
	BehaviorRisk               float64                `json:"behaviorRisk"`
	OpenPortCount              int                    `json:"openPortCount"`
	HighRiskPortCount          int                    `json:"highRiskPortCount"`
	GeoRiskFlag                bool                   `json:"geoRiskFlag"`
	FeatureDigest              string                 `json:"featureDigest"`
	ConfigVersion              string                 `json:"configVersion"`
	DataSources                []string               `json:"dataSources"`
	DataSourceChains           map[string][]string    `json:"dataSourceChains"`
	SourceSummary              string                 `json:"sourceSummary"`
	SourceGroups               []canonicalSourceGroup `json:"sourceGroups"`
	FlowSourceChain            []string               `json:"flowSourceChain"`
	EvidenceItems              []securityEvidenceItem `json:"evidenceItems"`
	FlowPrototypeItems         []securityEvidenceItem `json:"flowPrototypeItems"`
	ScoreFactors               []securityScoreFactor  `json:"scoreFactors"`
	FlowMode                   string                 `json:"flowMode"`
	FlowStatus                 string                 `json:"flowStatus"`
	FlowSummary                string                 `json:"flowSummary"`
	FlowParserName             string                 `json:"flowParserName"`
	FlowParserReady            bool                   `json:"flowParserReady"`
	FlowIntegrationStage       string                 `json:"flowIntegrationStage"`
	FlowPrototypeBoundary      string                 `json:"flowPrototypeBoundary"`
	FlowInputKind              string                 `json:"flowInputKind"`
	FlowInputSnapshot          map[string]any         `json:"flowInputSnapshot"`
	FlowParsedMetrics          map[string]any         `json:"flowParsedMetrics"`
	FlowCollectedStableFields  []string               `json:"flowCollectedStableFields"`
	FlowNormalizedStableFields []string               `json:"flowNormalizedStableFields"`
	FlowFutureStableFields     []string               `json:"flowFutureStableFields"`
	FlowPrototypeOnlyFields    []string               `json:"flowPrototypeOnlyFields"`
}

// ScoreResult 用于承载融合评分计算结果。
type ScoreResult struct {
	BaseScore           float64            `json:"baseScore"`
	ReputationScore     float64            `json:"reputationScore"`
	AttackSurfaceScore  float64            `json:"attackSurfaceScore"`
	BehaviorScore       float64            `json:"behaviorScore"`
	RuleAdjustmentValue float64            `json:"ruleAdjustmentValue"`
	ScoreValue          float64            `json:"scoreValue"`
	RiskLevel           string             `json:"riskLevel"`
	ScoreReason         string             `json:"scoreReason"`
	RuleAdjustment      string             `json:"ruleAdjustment"`
	AlgorithmVersion    string             `json:"algorithmVersion"`
	WeightProfile       map[string]float64 `json:"weightProfile"`
	IsAlertTriggered    bool               `json:"isAlertTriggered"`
}

// AlertDecision 用于承载预警Decision数据。
type AlertDecision struct {
	ShouldAlert bool   `json:"shouldAlert"`
	AlertLevel  string `json:"alertLevel"`
	Channel     string `json:"channel"`
	Title       string `json:"title"`
	Content     string `json:"content"`
}

// TaskPipelineResult 用于承载任务采集、评分、预警和流量落库产物。
type TaskPipelineResult struct {
	BaseInfo          securityModel.IPBaseInfo
	FeatureSnapshot   securityModel.FeatureSnapshot
	RiskScore         securityModel.RiskScore
	AlertRecord       *securityModel.AlertRecord
	FlowCollection    *securityModel.FlowCollection
	FlowWindows       []securityModel.FlowWindowAggregate
	FlowFeature       *securityModel.FlowFeatureSnapshot
	NormalizedFeature NormalizedFeatureSet
}

// BaseInfoCollector 用于采集基础信息特征数据。
type BaseInfoCollector interface {
	Collect(taskID uint64, targetIP string, cfg config.SecurityConfig) (BaseInfoCollectedData, error)
}

// ReputationCollector 用于抽象信誉风险采集能力。
type ReputationCollector interface {
	Collect(targetIP string, cfg config.SecurityConfig) (ReputationCollectedData, error)
}

// AttackSurfaceCollector 用于抽象攻击面采集能力。
type AttackSurfaceCollector interface {
	Collect(targetIP string, baseInfo BaseInfoCollectedData, cfg config.SecurityConfig) (AttackSurfaceCollectedData, error)
}

// FlowCollector 用于采集流量特征数据。
type FlowCollector interface {
	Collect(targetIP string, cfg config.SecurityConfig) (FlowCollectedData, error)
}

// FeatureNormalizer 用于归一化特征输入特征。
type FeatureNormalizer interface {
	Normalize(targetIP string, collected TaskCollectedData, cfg config.SecurityConfig) (NormalizedFeatureSet, error)
}

// ScoreCalculator 用于计算评分结果。
type ScoreCalculator interface {
	Calculate(taskID uint64, targetIP string, normalized NormalizedFeatureSet, cfg config.SecurityConfig) (ScoreResult, error)
}

// AlertDecider 用于判定预警结果。
type AlertDecider interface {
	Decide(taskID uint64, taskNo string, targetIP string, score ScoreResult, cfg config.SecurityConfig) (*AlertDecision, error)
}

// DemoBaseInfoCollector 用于采集Demo基础信息特征数据。
type DemoBaseInfoCollector struct{}

// DemoReputationCollector 用于提供演示模式的信誉风险采集结果。
type DemoReputationCollector struct{}

// DemoAttackSurfaceCollector 用于提供演示模式的攻击面采集结果。
type DemoAttackSurfaceCollector struct{}

// DemoFlowCollector 用于采集Demo流量特征数据。
type DemoFlowCollector struct{}

// DefaultFeatureNormalizer 用于归一化Default特征输入特征。
type DefaultFeatureNormalizer struct{}

// WeightedScoreCalculator 用于计算Weighted评分结果。
type WeightedScoreCalculator struct{}

// ThresholdAlertDecider 用于判定Threshold预警结果。
type ThresholdAlertDecider struct{}

// Collect 用于执行Collect流程。
func (c DemoBaseInfoCollector) Collect(taskID uint64, targetIP string, cfg config.SecurityConfig) (BaseInfoCollectedData, error) {
	configVersion := buildCollectorConfigVersion(cfg)
	return runCollectorStep(
		"base_info",
		targetIP,
		cfg.Source.WhoisEndpoint,
		configVersion,
		collectorTimeout,
		utils.CollectorCacheTTL(),
		func() (BaseInfoCollectedData, error) {
			first := firstOctet(targetIP)
			country, region := locate(first)
			isp := inferISP(first)

			return BaseInfoCollectedData{
				IP:           targetIP,
				Country:      country,
				Region:       region,
				City:         fmt.Sprintf("%s-CITY", region),
				ISP:          isp,
				WhoisOrg:     fmt.Sprintf("%s Network", strings.ToUpper(country)),
				WhoisContact: fmt.Sprintf("noc@%s.example", strings.ToLower(country)),
				RawPayload: map[string]any{
					"country":     country,
					"region":      region,
					"isp":         isp,
					"sourceChain": []string{cfg.Source.WhoisEndpoint},
					"evidenceItems": []securityEvidenceItem{
						{
							Source:   cfg.Source.WhoisEndpoint,
							Title:    "演示基础画像",
							Summary:  fmt.Sprintf("国家=%s，地区=%s，运营商=%s。", country, region, isp),
							RiskHint: "INFO",
						},
					},
				},
				SourceName: cfg.Source.WhoisEndpoint,
			}, nil
		},
		validateBaseInfoCollectedData,
	)
}

// Collect 用于执行Collect流程。
func (c DemoReputationCollector) Collect(targetIP string, cfg config.SecurityConfig) (ReputationCollectedData, error) {
	configVersion := buildCollectorConfigVersion(cfg)
	return runCollectorStep(
		"reputation",
		targetIP,
		cfg.Source.ReputationEndpoint,
		configVersion,
		collectorTimeout,
		utils.CollectorCacheTTL(),
		func() (ReputationCollectedData, error) {
			// 用目标 IP 的稳定哈希生成 30~84 之间的确定性分数：
			// 同一 IP 每次演示结果一致，便于演示与测试断言，而不是随机抖动。
			hashValue := stableHash(targetIP)
			return ReputationCollectedData{
				IP:              targetIP,
				ReputationScore: float64(30 + int(hashValue%55)),
				SourceName:      cfg.Source.ReputationEndpoint,
				RawPayload: map[string]any{
					"sourceChain": []string{cfg.Source.ReputationEndpoint},
					"evidenceItems": []securityEvidenceItem{
						{
							Source:   cfg.Source.ReputationEndpoint,
							Title:    "演示信誉评分",
							Summary:  "当前为演示模式生成的信誉评分。",
							RiskHint: "INFO",
						},
					},
				},
			}, nil
		},
		validateReputationCollectedData,
	)
}

// Collect 用于执行Collect流程。
func (c DemoAttackSurfaceCollector) Collect(targetIP string, baseInfo BaseInfoCollectedData, cfg config.SecurityConfig) (AttackSurfaceCollectedData, error) {
	sourceName := "demo-attack-surface"
	configVersion := buildCollectorConfigVersion(cfg)
	return runCollectorStep(
		"attack_surface",
		targetIP,
		sourceName,
		configVersion,
		collectorTimeout,
		utils.CollectorCacheTTL(),
		func() (AttackSurfaceCollectedData, error) {
			hashValue := stableHash(targetIP)
			return AttackSurfaceCollectedData{
				IP:                targetIP,
				OpenPortCount:     int(hashValue%12) + 1,
				HighRiskPortCount: int((hashValue / 13) % 4),
				// 演示模式用国家简写近似表达地理风险（RU/KP 命中高风险），
				// 真实链路会由攻击面采集器根据 GeoLite2 结果回填该标记。
				GeoRiskFlag:       strings.EqualFold(baseInfo.Country, "RU") || strings.EqualFold(baseInfo.Country, "KP"),
				SourceName:        sourceName,
				RawPayload: map[string]any{
					"sourceChain": []string{sourceName},
					"evidenceItems": []securityEvidenceItem{
						{
							Source:   sourceName,
							Title:    "演示攻击面画像",
							Summary:  "当前为演示模式生成的攻击面统计。",
							RiskHint: "INFO",
						},
					},
				},
			}, nil
		},
		validateAttackSurfaceCollectedData,
	)
}

// Collect 用于执行Collect流程。
func (c DemoFlowCollector) Collect(targetIP string, cfg config.SecurityConfig) (FlowCollectedData, error) {
	configVersion := buildCollectorConfigVersion(cfg)
	sourceName := resolveFlowCollectorSourceName(FlowParseModeSample)
	return runCollectorStep(
		"flow",
		targetIP,
		sourceName,
		configVersion,
		collectorTimeout,
		utils.CollectorCacheTTL(),
		func() (FlowCollectedData, error) {
			parseRequest := buildFlowParseRequest(targetIP, cfg)
			if parseRequest.Mode == FlowParseModeDisabled {
				result, err := disabledFlowParser{}.Parse(context.Background(), parseRequest)
				if err != nil {
					return FlowCollectedData{}, err
				}
				return mapFlowParseResultToCollectedData(targetIP, result), nil
			}

			result, err := sampleFlowParser{}.Parse(context.Background(), parseRequest)
			if err != nil {
				return FlowCollectedData{}, err
			}
			return mapFlowParseResultToCollectedData(targetIP, result), nil
		},
		validateFlowCollectedData,
	)
}

// Normalize 用于规范化当前。
func (n DefaultFeatureNormalizer) Normalize(targetIP string, collected TaskCollectedData, cfg config.SecurityConfig) (NormalizedFeatureSet, error) {
	// 归一化这一步把采集到的"原始事实"（国家/ISP/端口/流量指标）折算成四个 0~100 的风险分：
	// 基础属性、信誉、攻击面、行为。其中信誉分直接来自采集器，其余三个在这里用公式计算。
	baseInfoRisk := computeWhoisRiskFromCollected(collected.BaseInfo)
	attackRisk := computeAttackSurfaceRiskFromCollected(collected.AttackSurface)
	behaviorRisk := computeBehaviorRisk(collected.Flow)
	baseSourceChain := extractSourceChain(collected.BaseInfo.RawPayload, collected.BaseInfo.SourceName)
	sourceChains := buildCollectedSourceChains(collected)
	dataSources := flattenSourceChains(sourceChains)
	flowMode, flowStatus, flowSummary := buildFlowDisplayFields(collected.Flow)
	flowSourceChain := buildFlowPrototypeSourceChain(collected.Flow)
	sourceSummary := buildCanonicalSourceSummary(baseSourceChain, sourceChains, flowMode, flowStatus, flowSourceChain)
	scoreFactors := decorateScoreFactorsWithDisplayBasis(
		buildEnhancedScoreFactors(collected, cfg, baseInfoRisk, attackRisk, behaviorRisk),
		sourceSummary,
		flowMode,
		flowStatus,
		flowSummary,
	)

	return NormalizedFeatureSet{
		TargetIP:          targetIP,
		SourceName:        joinOrFallback(dataSources, "security-pipeline"),
		WhoisRiskScore:    baseInfoRisk,
		ReputationScore:   collected.Reputation.ReputationScore,
		AttackSurfaceRisk: attackRisk,
		BehaviorRisk:      behaviorRisk,
		OpenPortCount:     collected.AttackSurface.OpenPortCount,
		HighRiskPortCount: collected.AttackSurface.HighRiskPortCount,
		GeoRiskFlag:       collected.AttackSurface.GeoRiskFlag,
		FeatureDigest:     buildNormalizedFeatureDigest(targetIP, collected, baseInfoRisk, attackRisk, behaviorRisk),
		ConfigVersion: fmt.Sprintf(
			"wh=%.2f|rep=%.2f|atk=%.2f|beh=%.2f|high=%.2f|critical=%.2f",
			cfg.Weights.WhoisWeight,
			cfg.Weights.ReputationWeight,
			cfg.Weights.AttackSurfaceWeight,
			cfg.Weights.BehaviorWeight,
			cfg.HighRiskThreshold,
			cfg.CriticalRiskThreshold,
		),
		DataSources:                dataSources,
		DataSourceChains:           sourceChains,
		SourceSummary:              sourceSummary.Summary,
		SourceGroups:               sourceSummary.Groups,
		FlowSourceChain:            sourceSummary.FlowSourceChain,
		EvidenceItems:              buildCollectedEvidenceItemsV2(collected),
		FlowPrototypeItems:         buildCollectedFlowPrototypeItems(collected.Flow),
		ScoreFactors:               scoreFactors,
		FlowMode:                   flowMode,
		FlowStatus:                 flowStatus,
		FlowSummary:                flowSummary,
		FlowParserName:             resolveFlowParserName(collected.Flow),
		FlowParserReady:            resolveFlowParserReady(collected.Flow),
		FlowIntegrationStage:       strings.TrimSpace(collected.Flow.IntegrationStage),
		FlowPrototypeBoundary:      strings.TrimSpace(collected.Flow.PrototypeBoundary),
		FlowInputKind:              strings.TrimSpace(collected.Flow.InputKind),
		FlowInputSnapshot:          cloneMap(collected.Flow.InputSnapshot),
		FlowParsedMetrics:          cloneMap(collected.Flow.ParsedMetrics),
		FlowCollectedStableFields:  cloneStringList(collected.Flow.CollectedStableFields),
		FlowNormalizedStableFields: cloneStringList(collected.Flow.NormalizedStableFields),
		FlowFutureStableFields:     cloneStringList(collected.Flow.FutureStableFields),
		FlowPrototypeOnlyFields:    cloneStringList(collected.Flow.PrototypeOnlyFields),
	}, nil
}

// Calculate 用于执行Calculate流程。
func (s WeightedScoreCalculator) Calculate(taskID uint64, targetIP string, normalized NormalizedFeatureSet, cfg config.SecurityConfig) (ScoreResult, error) {
	// 加权融合：四个维度的贡献值已在 Normalize 阶段按权重算好（Contribution = RawScore × Weight），
	// 这里直接求和得到核心分 CoreScore，再叠加非线性规则修正得到最终分 FinalScore。
	baseScore := 0.0
	reputationScore := 0.0
	attackSurfaceScore := 0.0
	behaviorScore := 0.0
	for _, factor := range normalized.ScoreFactors {
		switch factor.Key {
		case "whois":
			baseScore += factor.Contribution
		case "reputation":
			reputationScore += factor.Contribution
		case "attack_surface":
			attackSurfaceScore += factor.Contribution
		case "behavior":
			behaviorScore += factor.Contribution
		}
	}
	// 规则修正是在线性加权之外对"组合危险信号"的额外加减分，并限制在 [-5, +15] 区间，
	// 避免经验规则压过权重模型，保证评分稳定可解释。
	ruleAdjustmentValue := calculateRuleAdjustmentValue(normalized, cfg)
	scoreValue := baseScore + reputationScore + attackSurfaceScore + behaviorScore + ruleAdjustmentValue

	riskLevel := mapRiskLevel(scoreValue, cfg)

	return ScoreResult{
		BaseScore:           round2(baseScore),
		ReputationScore:     round2(reputationScore),
		AttackSurfaceScore:  round2(attackSurfaceScore),
		BehaviorScore:       round2(behaviorScore),
		RuleAdjustmentValue: round2(ruleAdjustmentValue),
		ScoreValue:          round2(scoreValue),
		RiskLevel:           riskLevel,
		ScoreReason:         buildScoreReason(normalized),
		RuleAdjustment:      buildRuleAdjustmentSummary(normalized, ruleAdjustmentValue),
		AlgorithmVersion:    buildAlgorithmVersion(cfg),
		WeightProfile: map[string]float64{
			"base":          round2(cfg.Weights.WhoisWeight),
			"reputation":    round2(cfg.Weights.ReputationWeight),
			"attackSurface": round2(cfg.Weights.AttackSurfaceWeight),
			"behavior":      round2(cfg.Weights.BehaviorWeight),
		},
		// 预警判定直接复用高风险阈值：最终分达到 highRiskThreshold（默认 75）即触发预警。
		IsAlertTriggered: scoreValue >= cfg.HighRiskThreshold,
	}, nil
}

// Decide 用于执行Decide流程。
func (d ThresholdAlertDecider) Decide(taskID uint64, taskNo string, targetIP string, score ScoreResult, cfg config.SecurityConfig) (*AlertDecision, error) {
	// 未触发预警时返回 nil，调用方据此跳过预警记录落库；只有真正达到阈值才生成预警内容。
	if !score.IsAlertTriggered {
		return nil, nil
	}

	return &AlertDecision{
		ShouldAlert: true,
		AlertLevel:  score.RiskLevel,
		Channel:     cfg.Alert.NotifyChannel,
		Title:       fmt.Sprintf("%s 风险预警", targetIP),
		Content:     fmt.Sprintf("任务 %s 风险评分为 %.2f，超过高风险阈值。%s", taskNo, score.ScoreValue, strings.TrimSpace(score.ScoreReason)),
	}, nil
}

// computeWhoisRiskFromCollected 用于从基础画像采集结果计算 WHOIS 风险。
func computeWhoisRiskFromCollected(baseInfo BaseInfoCollectedData) float64 {
	// 基础属性风险 = 25（基础不确定性：仅凭 IP 归属无法证明安全）
	//               + 30（命中地理风险国家）
	//               + 15（ISP 含 "hosting"，云主机/VPS 等托管基础设施更易被滥用）。
	score := 25.0
	if isGeoRiskCountry(baseInfo.Country) {
		score += 30
	}
	// 大小写不敏感匹配 "hosting"，避免不同数据源大小写不一致导致漏判。
	if strings.Contains(strings.ToLower(baseInfo.ISP), "hosting") {
		score += 15
	}
	return score
}

// computeAttackSurfaceRiskFromCollected 用于从攻击面采集结果计算攻击面风险。
func computeAttackSurfaceRiskFromCollected(attack AttackSurfaceCollectedData) float64 {
	// 攻击面风险 = 开放端口数 × 4 + 高危端口数 × 15 + 地理风险标记 ? 10 : 0。
	// 高危端口（22/445/3389 等远程管理与横向移动入口）权重远高于普通端口；
	// 地理风险只做小幅修正，避免地理属性压过真实可达服务。
	score := float64(attack.OpenPortCount*4 + attack.HighRiskPortCount*15)
	if attack.GeoRiskFlag {
		score += 10
	}
	// 封顶 100，避免端口爆炸导致分数失真。
	if score > 100 {
		return 100
	}
	return score
}

// buildScoreReason 用于构建评分Reason。
func buildScoreReason(normalized NormalizedFeatureSet) string {
	// 评分说明把四个维度的原始风险分串成一句话，前端直接展示，是评分可解释性的落点。
	parts := []string{
		fmt.Sprintf("基础属性风险 %.2f", round2(normalized.WhoisRiskScore)),
		fmt.Sprintf("信誉风险 %.2f", round2(normalized.ReputationScore)),
		fmt.Sprintf("攻击面风险 %.2f", round2(normalized.AttackSurfaceRisk)),
		fmt.Sprintf("行为风险 %.2f", round2(normalized.BehaviorRisk)),
	}
	if strings.TrimSpace(normalized.SourceSummary) != "" {
		parts = append(parts, "默认来源="+strings.TrimSpace(normalized.SourceSummary))
	}
	if normalizeFlowBoundaryMode(normalized.FlowMode) != "" && strings.TrimSpace(normalized.FlowStatus) != "" {
		parts = append(parts, fmt.Sprintf("流量增强=%s:%s", normalizeFlowBoundaryMode(normalized.FlowMode), strings.ToUpper(strings.TrimSpace(normalized.FlowStatus))))
		if flowExplain := buildFlowBehaviorExplainSegment(normalized.FlowParsedMetrics); flowExplain != "" {
			parts = append(parts, flowExplain)
		}
	}
	return strings.Join(parts, "；")
}

// calculateRuleAdjustmentValue 用于计算RuleAdjustmentValue数值。
func calculateRuleAdjustmentValue(normalized NormalizedFeatureSet, cfg config.SecurityConfig) float64 {
	// 规则修正表达的是线性加权表达不出来的"组合危险信号"：
	//   +6  地理风险标记
	//   +5  高危端口数 >= 3
	//   +8  行为风险 >= 70（动态证据强烈指向恶意）
	//   -2  行为风险 <= 10 且流量禁用（说明缺少动态证据，做小幅减分）。
	adjustment := 0.0
	if normalized.GeoRiskFlag {
		adjustment += 6
	}
	if normalized.HighRiskPortCount >= 3 {
		adjustment += 5
	}
	if normalized.BehaviorRisk >= 70 {
		adjustment += 8
	}
	if normalized.BehaviorRisk <= 10 && normalizeFlowBoundaryMode(normalized.FlowMode) == "disabled" {
		adjustment -= 2
	}
	// 修正值限制在 [-5, +15]，防止经验规则压过加权分数、破坏评分模型的稳定性。
	if adjustment > 15 {
		return 15
	}
	if adjustment < -5 {
		return -5
	}
	_ = cfg
	return adjustment
}

// buildRuleAdjustmentSummary 用于构建RuleAdjustment摘要。
func buildRuleAdjustmentSummary(normalized NormalizedFeatureSet, adjustment float64) string {
	if adjustment == 0 {
		return "weighted-score-with-threshold-mapping;no-extra-adjustment"
	}
	// 把命中的修正规则编码成人类可读的标签串并持久化，审计时能还原"为什么加/减了多少分"。
	parts := []string{"weighted-score-with-threshold-mapping"}
	if normalized.GeoRiskFlag {
		parts = append(parts, "geo-risk-flag")
	}
	if normalized.HighRiskPortCount >= 3 {
		parts = append(parts, "high-risk-port-bias")
	}
	if normalized.BehaviorRisk >= 70 {
		parts = append(parts, "flow-behavior-escalation")
	}
	if normalized.BehaviorRisk <= 10 && normalizeFlowBoundaryMode(normalized.FlowMode) == "disabled" {
		parts = append(parts, "flow-disabled-small-relief")
	}
	parts = append(parts, fmt.Sprintf("delta=%.2f", round2(adjustment)))
	return strings.Join(parts, ";")
}

// buildAlgorithmVersion 用于构建AlgorithmVersion。
func buildAlgorithmVersion(cfg config.SecurityConfig) string {
	// 算法版本号把当前四个权重一并编码进去，评分记录里存下这串版本，
	// 即使日后调整权重，历史评分也能还原出"当时用的是哪套权重"，保证可追溯。
	return fmt.Sprintf(
		"ahp-entropy-v1|base=%.2f|rep=%.2f|atk=%.2f|beh=%.2f",
		round2(cfg.Weights.WhoisWeight),
		round2(cfg.Weights.ReputationWeight),
		round2(cfg.Weights.AttackSurfaceWeight),
		round2(cfg.Weights.BehaviorWeight),
	)
}

// buildFlowBehaviorExplainSegment 用于构建流量BehaviorExplainSegment。
func buildFlowBehaviorExplainSegment(metrics map[string]any) string {
	if len(metrics) == 0 {
		return ""
	}
	parts := make([]string, 0, 6)
	if packets := readFlowMetricUint64(metrics, "packetCount"); packets > 0 {
		parts = append(parts, fmt.Sprintf("报文=%d", packets))
	}
	if sessions := readFlowMetricUint64(metrics, "sessionCount"); sessions > 0 {
		parts = append(parts, fmt.Sprintf("会话=%d", sessions))
	}
	if dnsEvents := readFlowMetricUint64(metrics, "dnsEventCount"); dnsEvents > 0 {
		parts = append(parts, fmt.Sprintf("DNS=%d", dnsEvents))
	}
	if httpEvents := readFlowMetricUint64(metrics, "httpEventCount"); httpEvents > 0 {
		parts = append(parts, fmt.Sprintf("HTTP=%d", httpEvents))
	}
	if tlsEvents := readFlowMetricUint64(metrics, "tlsEventCount"); tlsEvents > 0 {
		parts = append(parts, fmt.Sprintf("TLS=%d", tlsEvents))
	}
	if directionality := stringifyDirectionalityMetrics(metrics["directionalityIndicators"]); directionality != "" {
		parts = append(parts, directionality)
	}
	if portDensity := stringifyPortDensityMetrics(metrics["portDensityIndicators"]); portDensity != "" {
		parts = append(parts, portDensity)
	}
	if entropy := stringifyEntropyMetrics(metrics["payloadEntropyIndicators"]); entropy != "" {
		parts = append(parts, entropy)
	}
	if dnsTop := stringifyTopCountMetrics(metrics["dnsTopQuestions"]); dnsTop != "" {
		parts = append(parts, "DNS Top="+dnsTop)
	}
	if httpHost := stringifyTopCountMetrics(metrics["httpHostHints"]); httpHost != "" {
		parts = append(parts, "HTTP Host="+httpHost)
	}
	if tlsSNI := stringifyTLSHints(metrics["tlsHandshakeHints"]); tlsSNI != "" {
		parts = append(parts, "TLS SNI="+tlsSNI)
	}
	if len(parts) == 0 {
		return ""
	}
	return "动态流量特征=" + strings.Join(parts, ", ")
}

// stableHash 用于执行stableHash流程。
func stableHash(input string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(input))
	return h.Sum32()
}

// firstOctet 用于选取首个可用的Octet。
func firstOctet(targetIP string) int {
	parsed := net.ParseIP(targetIP)
	if parsed == nil {
		return 0
	}
	v4 := parsed.To4()
	if v4 == nil {
		return 0
	}
	return int(v4[0])
}

// locate 用于执行locate流程。
func locate(first int) (string, string) {
	// 演示模式按 IP 首字节粗略映射国家/地区，仅用于本地无外部数据源时的占位画像。
	switch {
	case first < 32:
		return "US", "California"
	case first < 64:
		return "DE", "Frankfurt"
	case first < 96:
		return "SG", "Singapore"
	case first < 128:
		return "JP", "Tokyo"
	case first < 160:
		return "RU", "Moscow"
	case first < 192:
		return "CN", "Beijing"
	case first < 224:
		return "BR", "SaoPaulo"
	default:
		return "KP", "Pyongyang"
	}
}

// inferISP 用于执行inferISP流程。
func inferISP(first int) string {
	switch {
	case first%5 == 0:
		return "Cloud Hosting"
	case first%3 == 0:
		return "Regional Backbone"
	default:
		return "Demo ISP"
	}
}

// computeBehaviorRisk 用于计算Behavior风险指标。
func computeBehaviorRisk(flow FlowCollectedData) float64 {
	if flow.BehaviorRiskScore < 0 {
		return 0
	}
	if flow.BehaviorRiskScore > 100 {
		return 100
	}
	return round2(flow.BehaviorRiskScore)
}

// mapRiskLevel 用于映射风险Level。
func mapRiskLevel(score float64, runtimeConfig config.SecurityConfig) string {
	// 等级映射按阈值从高到低依次判断：CRITICAL >= critical(90) >= HIGH >= high(75) >= MEDIUM >= 45 > LOW。
	// switch 无表达式时按 case 顺序短路判断，所以顺序本身即优先级，不能颠倒。
	switch {
	case score >= runtimeConfig.CriticalRiskThreshold:
		return "CRITICAL"
	case score >= runtimeConfig.HighRiskThreshold:
		return "HIGH"
	case score >= 45:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// loadRuntimeSecurityConfig 用于加载配置、缓存或外部资源。
func loadRuntimeSecurityConfig() config.SecurityConfig {
	// 运行时配置以静态 config.yaml 为底，再用数据库里保存的最新安全配置覆盖，
	// 这样安全配置页改阈值/权重/数据源开关后无需重启服务即可生效。
	current := global.AppConfig.Security
	// DB 未初始化（例如启动早期或测试环境）时直接退回静态配置，保证任务链路可跑。
	if global.DB == nil {
		return current
	}

	var dbConfig securityModel.SecurityConfig
	// 取 id 最小的那条作为运行时配置；查不到（首次未配置）时也退回静态配置。
	if err := global.DB.Order("id ASC").First(&dbConfig).Error; err != nil {
		return current
	}

	current.Source.WhoisEndpoint = dbConfig.WhoisEndpoint
	current.Source.ReputationEndpoint = dbConfig.ReputationEndpoint
	current.Source.Flow.Enabled = dbConfig.FlowEnabled
	current.Source.Flow.Mode = dbConfig.FlowMode
	current.Source.Flow.InterfaceName = dbConfig.FlowInterfaceName
	current.Source.Flow.PcapFilePath = dbConfig.FlowPcapFilePath
	current.Source.Flow.SampleProfile = dbConfig.FlowSampleProfile
	current.Source.Flow.WindowSeconds = dbConfig.FlowWindowSeconds
	current.Source.Flow.TimeoutSeconds = dbConfig.FlowTimeoutSeconds
	current.Alert.NotifyChannel = dbConfig.NotifyChannel
	current.HighRiskThreshold = dbConfig.HighRiskThreshold
	current.CriticalRiskThreshold = dbConfig.CriticalRiskThreshold
	current.Weights.WhoisWeight = dbConfig.WhoisWeight
	current.Weights.ReputationWeight = dbConfig.ReputationWeight
	current.Weights.AttackSurfaceWeight = dbConfig.AttackSurfaceWeight
	current.Weights.BehaviorWeight = dbConfig.BehaviorWeight
	applyPersistedFeatureSourceSelectionV2(&current)
	return current
}

// round2 用于执行round2流程。
func round2(value float64) float64 {
	// 先放大 100 倍、加 0.5 再截断，实现"四舍五入保留两位小数"；
	// 全部评分与贡献值都经过这一步，保证展示与落库的小数位数一致。
	return float64(int(value*100+0.5)) / 100
}

// buildCollectorConfigVersion 用于构建Collector配置Version。
func buildCollectorConfigVersion(cfg config.SecurityConfig) string {
	// 配置版本串会参与采集结果缓存 key 的构成：任何数据源开关/参数/文件版本变化都会改变这串，
	// 从而让旧缓存自动失效，避免"改了配置却拿到旧采集结果"。
	return fmt.Sprintf(
		"whois=%s|reputation=%s|notify=%s|high=%.2f|critical=%.2f|wh=%.2f|rep=%.2f|atk=%.2f|beh=%.2f|geo=%t:%s:%s:%s:%s:%s:%s:%d|rdap=%t:%s:%s:%d:%d|blacklist=%t:%s:%s:%d:%.2f:%.2f|abuse=%t:%s:%t:%d:%d:%d|attackSurface=%t:%v:%d:%d:%d:%t:%s:%d|flow=%t:%s:%s:%s:%s:%d:%d:%d",
		resolveWhoisEndpointContractKey(cfg),
		resolveReputationEndpointContractKey(cfg),
		cfg.Alert.NotifyChannel,
		cfg.HighRiskThreshold,
		cfg.CriticalRiskThreshold,
		cfg.Weights.WhoisWeight,
		cfg.Weights.ReputationWeight,
		cfg.Weights.AttackSurfaceWeight,
		cfg.Weights.BehaviorWeight,
		cfg.Source.GeoLite2.Enabled,
		cfg.Source.GeoLite2.CountryDBPath,
		cfg.Source.GeoLite2.CityDBPath,
		cfg.Source.GeoLite2.ASNDBPath,
		resolveFileVersionToken(cfg.Source.GeoLite2.CountryDBPath),
		resolveFileVersionToken(cfg.Source.GeoLite2.CityDBPath),
		resolveFileVersionToken(cfg.Source.GeoLite2.ASNDBPath),
		cfg.Source.GeoLite2.CacheTTLSeconds,
		cfg.Source.RDAP.Enabled,
		cfg.Source.RDAP.BaseURL,
		strings.Join(cfg.Source.RDAP.BackupBaseURLs, ","),
		cfg.Source.RDAP.TimeoutSeconds,
		cfg.Source.RDAP.CacheTTLSeconds,
		cfg.Source.LocalBlacklist.Enabled,
		cfg.Source.LocalBlacklist.FilePath,
		resolveFileVersionToken(cfg.Source.LocalBlacklist.FilePath),
		cfg.Source.LocalBlacklist.ReloadIntervalSeconds,
		cfg.Source.LocalBlacklist.MatchScore,
		cfg.Source.LocalBlacklist.DefaultScore,
		cfg.Source.AbuseIPDB.Enabled,
		cfg.Source.AbuseIPDB.BaseURL,
		strings.TrimSpace(cfg.Source.AbuseIPDB.APIKey) != "",
		cfg.Source.AbuseIPDB.TimeoutSeconds,
		cfg.Source.AbuseIPDB.CacheTTLSeconds,
		cfg.Source.AbuseIPDB.MaxAgeInDays,
		cfg.Source.AttackSurface.Enabled,
		cfg.Source.AttackSurface.Ports,
		cfg.Source.AttackSurface.TimeoutMilliseconds,
		cfg.Source.AttackSurface.CacheTTLSeconds,
		cfg.Source.AttackSurface.MaxConcurrency,
		cfg.Source.AttackSurface.NmapEnabled,
		cfg.Source.AttackSurface.NmapPath,
		cfg.Source.AttackSurface.NmapTimeoutSeconds,
		cfg.Source.Flow.Enabled,
		cfg.Source.Flow.Mode,
		cfg.Source.Flow.InterfaceName,
		cfg.Source.Flow.PcapFilePath,
		cfg.Source.Flow.SampleProfile,
		cfg.Source.Flow.WindowSeconds,
		cfg.Source.Flow.TimeoutSeconds,
		cfg.Source.Flow.CacheTTLSeconds,
	)
}

// resolveWhoisEndpointContractKey 用于解析WHOISEndpointContractKey。
func resolveWhoisEndpointContractKey(cfg config.SecurityConfig) string {
	if cfg.DemoMode {
		return fallbackString(strings.TrimSpace(cfg.Source.WhoisEndpoint), "rdap")
	}
	items := make([]string, 0, 2)
	if cfg.Source.GeoLite2.Enabled {
		items = append(items, "geolite2")
	}
	if cfg.Source.RDAP.Enabled {
		items = append(items, "rdap")
	}
	return joinOrFallback(items, "disabled")
}

// resolveReputationEndpointContractKey 用于解析ReputationEndpointContractKey。
func resolveReputationEndpointContractKey(cfg config.SecurityConfig) string {
	if cfg.DemoMode {
		return fallbackString(strings.TrimSpace(cfg.Source.ReputationEndpoint), "local-blacklist")
	}
	items := make([]string, 0, 2)
	if cfg.Source.LocalBlacklist.Enabled {
		items = append(items, "local-blacklist")
	}
	if cfg.Source.AbuseIPDB.Enabled {
		items = append(items, "abuseipdb-enabled")
	}
	return joinOrFallback(items, "disabled")
}

// resolveAttackSurfaceEndpointContractKey 用于解析AttackSurfaceEndpointContractKey。
func resolveAttackSurfaceEndpointContractKey(cfg config.SecurityConfig) string {
	if !cfg.Source.AttackSurface.Enabled {
		return fallbackString(strings.TrimSpace(cfg.Source.AttackSurfaceEndpoint), "disabled")
	}
	items := make([]string, 0, 2)
	items = append(items, "limited-port-scan")
	if cfg.Source.AttackSurface.NmapEnabled {
		items = append(items, "nmap-enhanced")
	}
	return joinOrFallback(items, "disabled")
}

// applyPersistedFeatureSourceSelectionV2 用于执行applyPersisted特征来源SelectionV2流程。
func applyPersistedFeatureSourceSelectionV2(cfg *config.SecurityConfig) {
	if cfg == nil {
		return
	}

	switch strings.ToLower(strings.TrimSpace(cfg.Source.WhoisEndpoint)) {
	case "local-demo":
		// demoMode 下保留原样
	case "disabled":
		cfg.Source.GeoLite2.Enabled = false
		cfg.Source.RDAP.Enabled = false
	case "geolite2":
		cfg.Source.GeoLite2.Enabled = true
		cfg.Source.RDAP.Enabled = false
	case "rdap":
		cfg.Source.GeoLite2.Enabled = false
		cfg.Source.RDAP.Enabled = true
	case "geolite2+rdap":
		cfg.Source.GeoLite2.Enabled = true
		cfg.Source.RDAP.Enabled = true
	}

	switch strings.ToLower(strings.TrimSpace(cfg.Source.ReputationEndpoint)) {
	case "local-demo":
		// demoMode 下保留原样
	case "disabled":
		cfg.Source.LocalBlacklist.Enabled = false
		cfg.Source.AbuseIPDB.Enabled = false
	case "abuseipdb":
		cfg.Source.LocalBlacklist.Enabled = false
		cfg.Source.AbuseIPDB.Enabled = true
	case "local-blacklist+abuseipdb":
		cfg.Source.LocalBlacklist.Enabled = true
		cfg.Source.AbuseIPDB.Enabled = true
	case "local-blacklist":
		cfg.Source.LocalBlacklist.Enabled = true
		cfg.Source.AbuseIPDB.Enabled = false
	}

	switch strings.ToLower(strings.TrimSpace(cfg.Source.AttackSurfaceEndpoint)) {
	case "disabled":
		cfg.Source.AttackSurface.Enabled = false
		cfg.Source.AttackSurface.NmapEnabled = false
	case "nmap-enhanced", "limited-port-scan+nmap-enhanced":
		cfg.Source.AttackSurface.Enabled = true
		cfg.Source.AttackSurface.NmapEnabled = true
	case "limited-port-scan":
		cfg.Source.AttackSurface.Enabled = true
		cfg.Source.AttackSurface.NmapEnabled = false
	}
}

// applyPersistedFeatureSourceSelection 用于执行applyPersisted特征来源Selection流程。
func applyPersistedFeatureSourceSelection(cfg *config.SecurityConfig) {
	if cfg == nil {
		return
	}

	switch strings.ToLower(strings.TrimSpace(cfg.Source.WhoisEndpoint)) {
	case "local-demo":
		// demoMode 下保留原样
	case "geolite2":
		cfg.Source.GeoLite2.Enabled = true
		cfg.Source.RDAP.Enabled = false
	case "rdap":
		cfg.Source.GeoLite2.Enabled = false
		cfg.Source.RDAP.Enabled = true
	case "geolite2+rdap":
		cfg.Source.GeoLite2.Enabled = true
		cfg.Source.RDAP.Enabled = true
	}

	switch strings.ToLower(strings.TrimSpace(cfg.Source.ReputationEndpoint)) {
	case "local-demo":
		// demoMode 下保留原样
	case "abuseipdb":
		cfg.Source.LocalBlacklist.Enabled = false
		cfg.Source.AbuseIPDB.Enabled = true
	case "local-blacklist+abuseipdb":
		cfg.Source.LocalBlacklist.Enabled = true
		cfg.Source.AbuseIPDB.Enabled = true
	case "local-blacklist":
		cfg.Source.LocalBlacklist.Enabled = true
		cfg.Source.AbuseIPDB.Enabled = false
	}

	switch strings.ToLower(strings.TrimSpace(cfg.Source.AttackSurfaceEndpoint)) {
	case "disabled":
		cfg.Source.AttackSurface.Enabled = false
		cfg.Source.AttackSurface.NmapEnabled = false
	case "nmap-enhanced", "limited-port-scan+nmap-enhanced":
		cfg.Source.AttackSurface.Enabled = true
		cfg.Source.AttackSurface.NmapEnabled = true
	case "limited-port-scan":
		cfg.Source.AttackSurface.Enabled = true
		cfg.Source.AttackSurface.NmapEnabled = false
	}
}

// validateBaseInfoCollectedData 用于校验基础画像采集结果。
func validateBaseInfoCollectedData(result BaseInfoCollectedData) error {
	if result.IP == "" || result.SourceName == "" {
		return errors.New("base info collected data is incomplete")
	}
	return nil
}

// validateReputationCollectedData 用于校验信誉风险采集结果。
func validateReputationCollectedData(result ReputationCollectedData) error {
	if result.IP == "" || result.SourceName == "" {
		return errors.New("reputation collected data is incomplete")
	}
	if result.ReputationScore < 0 || result.ReputationScore > 100 {
		return errors.New("reputation score out of range")
	}
	return nil
}

// validateAttackSurfaceCollectedData 用于校验攻击面采集结果。
func validateAttackSurfaceCollectedData(result AttackSurfaceCollectedData) error {
	if result.IP == "" || result.SourceName == "" {
		return errors.New("attack surface collected data is incomplete")
	}
	if result.OpenPortCount < 0 || result.HighRiskPortCount < 0 {
		return errors.New("attack surface counts are invalid")
	}
	return nil
}

// validateFlowCollectedData 用于校验流量增强采集结果。
func validateFlowCollectedData(result FlowCollectedData) error {
	if result.IP == "" || result.SourceName == "" || strings.TrimSpace(result.Status) == "" || strings.TrimSpace(result.Summary) == "" {
		return errors.New("flow collected data is incomplete")
	}
	if normalizeFlowBoundaryMode(result.Mode) == "" {
		return errors.New("flow mode is invalid")
	}
	if !isAllowedFlowStatusForMode(result.Mode, result.Status) {
		return errors.New("flow status is invalid for mode")
	}
	if result.BehaviorRiskScore < 0 || result.BehaviorRiskScore > 100 {
		return errors.New("flow behavior risk score out of range")
	}
	if len(result.ParsedMetrics) != 0 && !resolveFlowParserReady(result) {
		return errors.New("flow parsed metrics require parser-ready state")
	}
	if isFlowFailureStatus(result.Status) {
		errorModel := extractMap(result.RawPayload, "errorModel")
		if len(errorModel) == 0 {
			return errors.New("flow failure result requires error model")
		}
		degraded, ok := readFlowPayloadBool(result.RawPayload, "degraded")
		if !ok || !degraded {
			return errors.New("flow failure result requires degraded flag")
		}
	}
	return nil
}

// classifyCollectorError 用于执行classifyCollectorError流程。
func classifyCollectorError(stepName, sourceName, targetIP string, err error) error {
	// 错误分类：优先用 errors.Is 精确匹配超时，其余按错误文本关键词归类。
	// 关键词匹配是兜底手段——外部库未必规范地包装错误类型，只能靠文案特征判断。
	kind := CollectorErrorInternal
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		kind = CollectorErrorTimeout
	case strings.Contains(strings.ToLower(err.Error()), "invalid"):
		kind = CollectorErrorInvalidData
	case strings.Contains(strings.ToLower(err.Error()), "incomplete"):
		kind = CollectorErrorInvalidData
	case strings.Contains(strings.ToLower(err.Error()), "unavailable"):
		kind = CollectorErrorUnavailable
	case strings.Contains(strings.ToLower(err.Error()), "refused"):
		kind = CollectorErrorUnavailable
	}

	return &CollectorError{
		StepName: stepName,
		Source:   sourceName,
		TargetIP: targetIP,
		Kind:     kind,
		Cause:    err,
	}
}

// runCollectorStep 用于运行服务启动或业务执行流程。
func runCollectorStep[T any](
	stepName string,
	targetIP string,
	sourceName string,
	configVersion string,
	timeout time.Duration,
	cacheTTL time.Duration,
	execute func() (T, error),
	validate func(T) error,
) (T, error) {
	var zero T
	if timeout <= 0 {
		timeout = collectorTimeout
	}
	if cacheTTL <= 0 {
		cacheTTL = utils.CollectorCacheTTL()
	}

	// 缓存 key = 目标 IP + 来源名 + 配置版本，三者任一变化都会命中不同的 key。
	// 读缓存失败不中断，降级为实时采集，保证主链路可用性优先于性能。
	cacheKey := utils.BuildCollectorCacheKey(targetIP, sourceName, configVersion)
	var cached T
	if hit, err := utils.CacheGetJSON(cacheKey, &cached); err == nil && hit {
		return cached, nil
	} else if err != nil {
		log.Printf("采集步骤缓存读取失败，继续实时采集，step=%s source=%s key=%s err=%v", stepName, sourceName, cacheKey, err)
	}

	// collectorResult 承载异步采集协程返回的数据和错误。
	type collectorResult[T any] struct {
		value T
		err   error
	}

	// 用带缓冲(1)的 channel + goroutine 实现超时控制：采集协程无论如何都能写入结果，
	// 不会因为调用方超时返回而把 goroutine 阻塞在发送上造成泄漏。
	resultCh := make(chan collectorResult[T], 1)
	go func() {
		value, err := execute()
		resultCh <- collectorResult[T]{value: value, err: err}
	}()

	select {
	case result := <-resultCh:
		if result.err != nil {
			return zero, classifyCollectorError(stepName, sourceName, targetIP, result.err)
		}
		if validate != nil {
			if err := validate(result.value); err != nil {
				return zero, classifyCollectorError(stepName, sourceName, targetIP, err)
			}
		}
		// 只有"非降级"的成功结果才写缓存：失败/降级结果不缓存，避免把不可信数据当成长期缓存复用。
		if shouldCacheCollectorValue(result.value) {
			if err := utils.CacheSetJSON(cacheKey, result.value, cacheTTL); err != nil {
				log.Printf("采集步骤缓存写入失败，已返回实时采集结果，step=%s source=%s key=%s err=%v", stepName, sourceName, cacheKey, err)
			}
		} else {
			log.Printf("采集步骤命中降级结果，按失败不缓存处理，step=%s source=%s key=%s", stepName, sourceName, cacheKey)
		}
		return result.value, nil
	case <-time.After(timeout):
		// 超时统一归类为 TIMEOUT，走 CollectorError 的错误分类，便于上层按类别处理。
		return zero, classifyCollectorError(stepName, sourceName, targetIP, context.DeadlineExceeded)
	}
}

// shouldCacheCollectorValue 用于执行should缓存CollectorValue流程。
func shouldCacheCollectorValue(value any) bool {
	switch typed := value.(type) {
	case BaseInfoCollectedData:
		return !isDegradedPayload(typed.RawPayload)
	case ReputationCollectedData:
		return !isDegradedPayload(typed.RawPayload)
	case AttackSurfaceCollectedData:
		return !isDegradedPayload(typed.RawPayload)
	case FlowCollectedData:
		return !isDegradedPayload(typed.RawPayload)
	default:
		return true
	}
}

// isDegradedPayload 用于判断输入是否满足指定条件。
func isDegradedPayload(payload map[string]any) bool {
	if len(payload) == 0 {
		return false
	}
	value, ok := payload["degraded"]
	if !ok {
		return false
	}
	flag, ok := value.(bool)
	return ok && flag
}

// buildCollectedSourceChains 用于构建任务采集来源链路。
func buildCollectedSourceChains(collected TaskCollectedData) map[string][]string {
	chains := map[string][]string{
		"base_info":      extractSourceChain(collected.BaseInfo.RawPayload, collected.BaseInfo.SourceName),
		"reputation":     extractSourceChain(collected.Reputation.RawPayload, collected.Reputation.SourceName),
		"attack_surface": extractSourceChain(collected.AttackSurface.RawPayload, collected.AttackSurface.SourceName),
	}
	if shouldIncludeFlowSource(collected.Flow) {
		chains["flow"] = extractSourceChain(collected.Flow.RawPayload, collected.Flow.SourceName)
	}
	return pruneEmptySourceChains(chains)
}

// pruneEmptySourceChains 用于执行pruneEmpty来源Chains流程。
func pruneEmptySourceChains(chains map[string][]string) map[string][]string {
	result := make(map[string][]string, len(chains))
	for key, items := range chains {
		filtered := filterEffectiveSourceChain(items)
		if len(filtered) == 0 {
			continue
		}
		result[key] = filtered
	}
	return result
}

// flattenSourceChains 用于执行flatten来源Chains流程。
func flattenSourceChains(chains map[string][]string) []string {
	items := make([]string, 0, len(chains)*2)
	for _, chain := range chains {
		items = append(items, chain...)
	}
	return dedupeStrings(items)
}

// extractSourceChain 用于提取请求、令牌或流量中的关键信息。
func extractSourceChain(payload map[string]any, fallback string) []string {
	if len(payload) != 0 {
		if raw, ok := payload["sourceChain"]; ok {
			bytes, err := json.Marshal(raw)
			if err == nil {
				var items []string
				if err := json.Unmarshal(bytes, &items); err == nil {
					filtered := filterEffectiveSourceChain(items)
					if len(filtered) > 0 {
						return filtered
					}
				}
			}
		}
	}
	if !isEffectiveSourceName(fallback) {
		return nil
	}
	return []string{strings.TrimSpace(fallback)}
}

// filterEffectiveSourceChain 用于执行filterEffective来源链路流程。
func filterEffectiveSourceChain(items []string) []string {
	filtered := make([]string, 0, len(items))
	for _, item := range dedupeStrings(items) {
		if !isEffectiveSourceName(item) {
			continue
		}
		filtered = append(filtered, strings.TrimSpace(item))
	}
	return filtered
}

// isEffectiveSourceName 用于判断输入是否满足指定条件。
func isEffectiveSourceName(source string) bool {
	trimmed := strings.TrimSpace(source)
	if trimmed == "" {
		return false
	}
	// 过滤掉 disabled/degraded/neutral 等"未真正生效"的来源标记，
	// 保证来源链里只保留真正参与了采集的数据源，避免总览统计虚高。
	lower := strings.ToLower(trimmed)
	switch {
	case lower == "flow-disabled":
		return false
	case lower == "attack-surface-disabled":
		return false
	case strings.Contains(lower, ":disabled"):
		return false
	case strings.Contains(lower, ":degraded"):
		return false
	case strings.Contains(lower, ":neutral"):
		return false
	default:
		return true
	}
}

// toBaseInfoModel 用于转换并生成基础信息模型。
func toBaseInfoModel(taskID uint64, collected BaseInfoCollectedData) securityModel.IPBaseInfo {
	rawPayload, _ := json.Marshal(collected.RawPayload)
	now := time.Now()
	return securityModel.IPBaseInfo{
		TaskID:       taskID,
		IP:           collected.IP,
		Country:      collected.Country,
		Region:       collected.Region,
		City:         collected.City,
		ISP:          collected.ISP,
		WhoisOrg:     collected.WhoisOrg,
		WhoisContact: collected.WhoisContact,
		RawPayload:   string(rawPayload),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// toFeatureSnapshotModel 用于转换并生成特征快照模型。
func toFeatureSnapshotModel(taskID uint64, normalized NormalizedFeatureSet) securityModel.FeatureSnapshot {
	payload, _ := json.Marshal(buildPersistedFeaturePayload(normalized))
	return securityModel.FeatureSnapshot{
		TaskID:             taskID,
		IP:                 normalized.TargetIP,
		ReputationScore:    normalized.ReputationScore,
		OpenPortCount:      normalized.OpenPortCount,
		HighRiskPortCount:  normalized.HighRiskPortCount,
		GeoRiskFlag:        normalized.GeoRiskFlag,
		NormalizedFeatures: string(payload),
		FeatureDigest:      normalized.FeatureDigest,
		CreatedAt:          time.Now(),
	}
}

// toFlowCollectionModel 用于转换并生成流量Collection模型。
func toFlowCollectionModel(taskID uint64, cfg config.SecurityConfig, collected FlowCollectedData) *securityModel.FlowCollection {
	if isFlowDisabled(collected) {
		return nil
	}

	evidencePayload, _ := json.Marshal(resolveFlowEvidencePayload(collected))
	now := time.Now()
	return &securityModel.FlowCollection{
		TaskID:            taskID,
		IP:                collected.IP,
		CollectionMode:    normalizeFlowBoundaryMode(collected.Mode),
		CollectionStatus:  strings.ToUpper(strings.TrimSpace(collected.Status)),
		ParserName:        resolveFlowParserName(collected),
		SourceName:        strings.TrimSpace(collected.SourceName),
		WindowSeconds:     resolveFlowWindowSeconds(cfg, collected),
		SampleProfile:     resolveFlowSampleProfile(cfg, collected),
		InterfaceName:     resolveFlowInterfaceName(cfg, collected),
		PcapFilePath:      resolveFlowPcapFilePath(cfg, collected),
		PacketCount:       readFlowMetricUint64(resolveFlowParsedMetrics(collected), "packetCount"),
		ByteCount:         readFlowMetricUint64(resolveFlowParsedMetrics(collected), "byteCount"),
		ConversationCount: uint32(readFlowMetricUint64(resolveFlowParsedMetrics(collected), "sessionCount")),
		Summary:           strings.TrimSpace(collected.Summary),
		ErrorMessage:      resolveFlowCollectionErrorMessage(collected),
		EvidencePayload:   string(evidencePayload),
		StartedAt:         now,
		FinishedAt:        now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
}

// toFlowFeatureSnapshotModel 用于转换并生成流量特征快照模型。
func toFlowFeatureSnapshotModel(taskID uint64, collected FlowCollectedData, normalized NormalizedFeatureSet) *securityModel.FlowFeatureSnapshot {
	if isFlowDisabled(collected) {
		return nil
	}

	parsedMetrics := resolveFlowParsedMetrics(collected)
	protocolDistribution, _ := json.Marshal(readFlowMetricValue(parsedMetrics, "protocolDistribution"))
	dnsTopQuestions, _ := json.Marshal(readFlowMetricValue(parsedMetrics, "dnsTopQuestions"))
	dnsQueryTypeHints, _ := json.Marshal(readFlowMetricValue(parsedMetrics, "dnsQueryTypeHints"))
	httpHostHints, _ := json.Marshal(readFlowMetricValue(parsedMetrics, "httpHostHints"))
	httpMethodHints, _ := json.Marshal(readFlowMetricValue(parsedMetrics, "httpMethodHints"))
	httpStatusHints, _ := json.Marshal(readFlowMetricValue(parsedMetrics, "httpStatusHints"))
	tlsHandshakeHints, _ := json.Marshal(readFlowMetricValue(parsedMetrics, "tlsHandshakeHints"))
	tlsVersionHints, _ := json.Marshal(readFlowMetricValue(parsedMetrics, "tlsVersionHints"))
	applicationSignals, _ := json.Marshal(readFlowMetricValue(parsedMetrics, "applicationSignals"))
	directionalityIndicators, _ := json.Marshal(readFlowMetricValue(parsedMetrics, "directionalityIndicators"))
	portDensityIndicators, _ := json.Marshal(readFlowMetricValue(parsedMetrics, "portDensityIndicators"))
	payloadEntropyIndicators, _ := json.Marshal(readFlowMetricValue(parsedMetrics, "payloadEntropyIndicators"))
	topPorts, _ := json.Marshal(readFlowMetricValue(parsedMetrics, "topPorts"))
	peerEndpoints, _ := json.Marshal(readFlowMetricValue(parsedMetrics, "peerEndpoints"))
	evidencePayload, _ := json.Marshal(resolveFlowEvidencePayload(collected))

	return &securityModel.FlowFeatureSnapshot{
		TaskID:                   taskID,
		IP:                       collected.IP,
		ParserName:               resolveFlowParserName(collected),
		BehaviorRiskScore:        normalized.BehaviorRisk,
		PacketCount:              readFlowMetricUint64(parsedMetrics, "packetCount"),
		ByteCount:                readFlowMetricUint64(parsedMetrics, "byteCount"),
		ConversationCount:        uint32(readFlowMetricUint64(parsedMetrics, "sessionCount")),
		PeakPPS:                  readFlowMetricFloat64(parsedMetrics, "peakPps"),
		BurstScore:               readFlowMetricFloat64(parsedMetrics, "burstScore"),
		ScanScore:                readFlowMetricFloat64(parsedMetrics, "scanScore"),
		HighEntropyPacketCount:   uint32(readFlowMetricNestedUint64(parsedMetrics, "payloadEntropyIndicators", "highEntropyPacketCount")),
		UniqueTargetPortCount:    uint32(readFlowMetricNestedUint64(parsedMetrics, "portDensityIndicators", "uniqueTargetPortCount")),
		HighRiskTargetPortCount:  uint32(readFlowMetricNestedUint64(parsedMetrics, "portDensityIndicators", "highRiskTargetPortCount")),
		TargetPortDensity:        readFlowMetricNestedFloat64(parsedMetrics, "portDensityIndicators", "targetPortDensity"),
		DominantDirection:        readFlowMetricNestedString(parsedMetrics, "directionalityIndicators", "dominantDirection"),
		ProtocolDistribution:     string(protocolDistribution),
		DNSTopQuestions:          string(dnsTopQuestions),
		DNSQueryTypeHints:        string(dnsQueryTypeHints),
		HTTPHostHints:            string(httpHostHints),
		HTTPMethodHints:          string(httpMethodHints),
		HTTPStatusHints:          string(httpStatusHints),
		TLSHandshakeHints:        string(tlsHandshakeHints),
		TLSVersionHints:          string(tlsVersionHints),
		ApplicationSignals:       string(applicationSignals),
		DirectionalityIndicators: string(directionalityIndicators),
		PortDensityIndicators:    string(portDensityIndicators),
		PayloadEntropyIndicators: string(payloadEntropyIndicators),
		TopPorts:                 string(topPorts),
		PeerEndpoints:            string(peerEndpoints),
		EvidencePayload:          string(evidencePayload),
		FeatureDigest:            buildFlowFeatureDigest(collected, normalized),
	}
}

// toFlowWindowAggregateModels 用于转换并生成流量WindowAggregateModels。
func toFlowWindowAggregateModels(taskID uint64, cfg config.SecurityConfig, collected FlowCollectedData) []securityModel.FlowWindowAggregate {
	if isFlowDisabled(collected) {
		return nil
	}
	windows := extractFlowWindowRows(collected)
	if len(windows) == 0 {
		windows = buildFallbackFlowWindowRows(cfg, collected)
	}
	if len(windows) == 0 {
		return nil
	}
	result := make([]securityModel.FlowWindowAggregate, 0, len(windows))
	for _, item := range windows {
		result = append(result, securityModel.FlowWindowAggregate{
			TaskID:               taskID,
			IP:                   collected.IP,
			WindowNo:             item.WindowNo,
			WindowStart:          item.WindowStart,
			WindowEnd:            item.WindowEnd,
			PacketCount:          item.PacketCount,
			ByteCount:            item.ByteCount,
			ConversationCount:    item.ConversationCount,
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
			EvidencePayload:      item.EvidencePayload,
			CreatedAt:            time.Now(),
		})
	}
	return result
}

// flowWindowAggregateDraft 用于承载flowWindowAggregateDraft数据。
type flowWindowAggregateDraft struct {
	WindowNo             uint32
	WindowStart          time.Time
	WindowEnd            time.Time
	PacketCount          uint64
	ByteCount            uint64
	ConversationCount    uint32
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
	EvidencePayload      string
}

// extractFlowWindowRows 用于提取请求、令牌或流量中的关键信息。
func extractFlowWindowRows(collected FlowCollectedData) []flowWindowAggregateDraft {
	raw := resolveFlowParsedMetrics(collected)
	windowValues, ok := raw["windows"]
	if !ok {
		windowValues, ok = collected.RawPayload["windows"]
	}
	if !ok {
		return nil
	}
	bytes, err := json.Marshal(windowValues)
	if err != nil {
		return nil
	}
	var items []map[string]any
	if err := json.Unmarshal(bytes, &items); err != nil {
		return nil
	}
	result := make([]flowWindowAggregateDraft, 0, len(items))
	for index, item := range items {
		draft := flowWindowAggregateDraft{
			WindowNo:             uint32(nonZeroInt64(toInt64(item["windowNo"]), int64(index+1))),
			WindowStart:          parseFlowWindowTime(item["windowStart"]),
			WindowEnd:            parseFlowWindowTime(item["windowEnd"]),
			PacketCount:          uint64(toInt64(item["packetCount"])),
			ByteCount:            uint64(toInt64(item["byteCount"])),
			ConversationCount:    uint32(toInt64(item["conversationCount"])),
			InboundPacketCount:   uint64(toInt64(item["inboundPacketCount"])),
			OutboundPacketCount:  uint64(toInt64(item["outboundPacketCount"])),
			InboundByteCount:     uint64(toInt64(item["inboundByteCount"])),
			OutboundByteCount:    uint64(toInt64(item["outboundByteCount"])),
			TCPPacketCount:       uint64(toInt64(item["tcpPacketCount"])),
			UDPPacketCount:       uint64(toInt64(item["udpPacketCount"])),
			ICMPPacketCount:      uint64(toInt64(item["icmpPacketCount"])),
			DNSEventCount:        uint32(toInt64(item["dnsEventCount"])),
			HTTPEventCount:       uint32(toInt64(item["httpEventCount"])),
			TLSEventCount:        uint32(toInt64(item["tlsEventCount"])),
			HighRiskPortHitCount: uint32(toInt64(item["highRiskPortHitCount"])),
			EvidencePayload:      mustJSON(item["evidencePayload"]),
		}
		if draft.WindowStart.IsZero() && draft.WindowEnd.IsZero() {
			continue
		}
		if draft.WindowEnd.IsZero() {
			draft.WindowEnd = draft.WindowStart
		}
		result = append(result, draft)
	}
	return result
}

// buildFallbackFlowWindowRows 用于构建Fallback流量WindowRows。
func buildFallbackFlowWindowRows(cfg config.SecurityConfig, collected FlowCollectedData) []flowWindowAggregateDraft {
	// 当解析器没有给出分窗明细（windows 为空）但又有整体指标时，
	// 用整体指标合成一条单窗口记录，保证流量趋势/证据时间线仍有内容可展示。
	metrics := resolveFlowParsedMetrics(collected)
	packetCount := readFlowMetricUint64(metrics, "packetCount")
	byteCount := readFlowMetricUint64(metrics, "byteCount")
	conversationCount := uint32(readFlowMetricUint64(metrics, "sessionCount"))
	if packetCount == 0 && byteCount == 0 && conversationCount == 0 {
		return nil
	}
	startAt := parseFlowWindowTime(metrics["firstSeenAt"])
	endAt := parseFlowWindowTime(metrics["lastSeenAt"])
	if startAt.IsZero() {
		startAt = time.Now()
	}
	if endAt.IsZero() {
		windowSeconds := resolveFlowWindowSeconds(cfg, collected)
		if windowSeconds <= 0 {
			windowSeconds = 60
		}
		endAt = startAt.Add(time.Duration(windowSeconds) * time.Second)
	}
	protocolCounts := decodeFlowStringCountMap(metrics["protocolDistribution"])
	topPorts := decodeFlowTopPortItems(metrics["topPorts"])
	highRiskHits := countHighRiskPortHits(topPorts)
	evidencePayload := mustJSON(map[string]any{
		"summary":  strings.TrimSpace(collected.Summary),
		"fallback": true,
	})
	return []flowWindowAggregateDraft{
		{
			WindowNo:             1,
			WindowStart:          startAt,
			WindowEnd:            endAt,
			PacketCount:          packetCount,
			ByteCount:            byteCount,
			ConversationCount:    conversationCount,
			TCPPacketCount:       uint64(protocolCounts["TCP"]) + uint64(protocolCounts["HTTP-CANDIDATE"]) + uint64(protocolCounts["HTTPS-CANDIDATE"]) + uint64(protocolCounts["SSH-CANDIDATE"]) + uint64(protocolCounts["RDP-CANDIDATE"]),
			UDPPacketCount:       uint64(protocolCounts["UDP"]) + uint64(protocolCounts["DNS"]),
			ICMPPacketCount:      uint64(protocolCounts["ICMPv4"]) + uint64(protocolCounts["ICMPv6"]),
			DNSEventCount:        uint32(protocolCounts["DNS"]),
			HTTPEventCount:       uint32(protocolCounts["HTTP-CANDIDATE"]),
			TLSEventCount:        uint32(protocolCounts["HTTPS-CANDIDATE"]),
			HighRiskPortHitCount: highRiskHits,
			EvidencePayload:      evidencePayload,
		},
	}
}

// parseFlowWindowTime 用于解析输入数据并转换为内部模型。
func parseFlowWindowTime(value any) time.Time {
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, text); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

// mustJSON 用于执行mustJSON流程。
func mustJSON(value any) string {
	if value == nil {
		return ""
	}
	bytes, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(bytes)
}

// nonZeroInt64 用于执行nonZeroInt64流程。
func nonZeroInt64(primary int64, fallback int64) int64 {
	if primary != 0 {
		return primary
	}
	return fallback
}

// decodeFlowStringCountMap 用于反序列化流量StringCountMap。
func decodeFlowStringCountMap(value any) map[string]int {
	result := make(map[string]int)
	if value == nil {
		return result
	}
	bytes, err := json.Marshal(value)
	if err != nil {
		return result
	}
	var direct map[string]int
	if err := json.Unmarshal(bytes, &direct); err == nil {
		return direct
	}
	var mixed map[string]any
	if err := json.Unmarshal(bytes, &mixed); err != nil {
		return result
	}
	for key, raw := range mixed {
		result[key] = int(toInt64(raw))
	}
	return result
}

// flowTopPortItem 用于承载flowTopPort列表展示条目。
type flowTopPortItem struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// decodeFlowTopPortItems 用于反序列化流量TopPortItems。
func decodeFlowTopPortItems(value any) []flowTopPortItem {
	if value == nil {
		return nil
	}
	bytes, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var items []flowTopPortItem
	if err := json.Unmarshal(bytes, &items); err != nil {
		return nil
	}
	return items
}

// countHighRiskPortHits 用于统计符合条件的数据数量。
func countHighRiskPortHits(items []flowTopPortItem) uint32 {
	if len(items) == 0 {
		return 0
	}
	// 高危端口集合：SSH/RDP/SMB 等远程管理入口 + 常见代理端口 8080 + DNS 53，
	// 与攻击面维度的高危端口口径保持一致，用于回退窗口里统计高危端口命中数。
	highRiskPorts := map[string]struct{}{
		"tcp:22":   {},
		"tcp:445":  {},
		"tcp:3389": {},
		"tcp:8080": {},
		"udp:53":   {},
	}
	var total uint32
	for _, item := range items {
		key := strings.ToLower(strings.TrimSpace(item.Key))
		if _, ok := highRiskPorts[key]; ok {
			total += uint32(item.Count)
		}
	}
	return total
}

// resolveFlowEvidencePayload 用于解析流量Evidence载荷。
func resolveFlowEvidencePayload(collected FlowCollectedData) map[string]any {
	if len(collected.RawPayload) != 0 {
		return cloneMap(collected.RawPayload)
	}
	return map[string]any{
		"sourceChain":                cloneStringList(collected.SourceChain),
		"evidenceItems":              cloneEvidenceItems(collected.EvidenceItems),
		"parserName":                 resolveFlowParserName(collected),
		"parserReady":                resolveFlowParserReady(collected),
		"integrationStage":           strings.TrimSpace(collected.IntegrationStage),
		"prototypeBoundary":          strings.TrimSpace(collected.PrototypeBoundary),
		"inputKind":                  strings.TrimSpace(collected.InputKind),
		"inputSnapshot":              cloneMap(collected.InputSnapshot),
		"parsedMetrics":              cloneMap(collected.ParsedMetrics),
		"flowCollectedStableFields":  cloneStringList(collected.CollectedStableFields),
		"flowNormalizedStableFields": cloneStringList(collected.NormalizedStableFields),
	}
}

// resolveFlowParserName 用于解析流量Parser名称。
func resolveFlowParserName(flow FlowCollectedData) string {
	if strings.TrimSpace(flow.ParserName) != "" {
		return strings.TrimSpace(flow.ParserName)
	}
	if value, ok := flow.RawPayload["parserName"].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

// resolveFlowParserReady 用于解析流量ParserReady。
func resolveFlowParserReady(flow FlowCollectedData) bool {
	if flow.ParserReady {
		return true
	}
	if value, ok := readFlowPayloadBool(flow.RawPayload, "parserReady"); ok {
		return value
	}
	return false
}

// resolveFlowParsedMetrics 用于解析流量ParsedMetrics。
func resolveFlowParsedMetrics(flow FlowCollectedData) map[string]any {
	if len(flow.ParsedMetrics) != 0 {
		return cloneMap(flow.ParsedMetrics)
	}
	if metrics, ok := flow.RawPayload["parsedMetrics"].(map[string]any); ok {
		return cloneMap(metrics)
	}
	return map[string]any{}
}

// resolveFlowWindowSeconds 用于解析流量WindowSeconds。
func resolveFlowWindowSeconds(cfg config.SecurityConfig, flow FlowCollectedData) int {
	if inputSnapshot, ok := flow.InputSnapshot["windowSeconds"]; ok {
		if value := toInt(inputSnapshot); value > 0 {
			return value
		}
	}
	return cfg.Source.Flow.WindowSeconds
}

// resolveFlowSampleProfile 用于解析流量SampleProfile。
func resolveFlowSampleProfile(cfg config.SecurityConfig, flow FlowCollectedData) string {
	if inputSnapshot, ok := flow.InputSnapshot["sampleProfile"].(string); ok {
		return strings.TrimSpace(inputSnapshot)
	}
	return strings.TrimSpace(cfg.Source.Flow.SampleProfile)
}

// resolveFlowInterfaceName 用于解析流量Interface名称。
func resolveFlowInterfaceName(cfg config.SecurityConfig, flow FlowCollectedData) string {
	if inputSnapshot, ok := flow.InputSnapshot["interfaceName"].(string); ok {
		return strings.TrimSpace(inputSnapshot)
	}
	return strings.TrimSpace(cfg.Source.Flow.InterfaceName)
}

// resolveFlowPcapFilePath 用于解析流量PCAPFilePath。
func resolveFlowPcapFilePath(cfg config.SecurityConfig, flow FlowCollectedData) string {
	if inputSnapshot, ok := flow.InputSnapshot["pcapFilePath"].(string); ok {
		return strings.TrimSpace(inputSnapshot)
	}
	return strings.TrimSpace(cfg.Source.Flow.PcapFilePath)
}

// resolveFlowCollectionErrorMessage 用于解析流量CollectionErrorMessage。
func resolveFlowCollectionErrorMessage(flow FlowCollectedData) string {
	// 只有失败类状态才提取错误信息；成功/降级/解析完成等状态一律返回空，
	// 避免任务详情页把正常的降级提示误当成错误展示。
	status := strings.ToUpper(strings.TrimSpace(flow.Status))
	if strings.Contains(status, "ERROR") || strings.Contains(status, "FAILED") {
		return strings.TrimSpace(flow.Summary)
	}
	switch status {
	case FlowStatusConfigRequired, FlowStatusInputInvalid, FlowStatusEntryUnavailable, FlowStatusParseFailed, FlowStatusWaitingPermission:
		if payload, ok := flow.RawPayload["errorModel"].(map[string]any); ok {
			if message, ok := payload["message"].(string); ok && strings.TrimSpace(message) != "" {
				return strings.TrimSpace(message)
			}
		}
		return strings.TrimSpace(flow.Summary)
	}
	return ""
}

// buildFlowFeatureDigest 用于构建流量特征Digest。
func buildFlowFeatureDigest(collected FlowCollectedData, normalized NormalizedFeatureSet) string {
	metrics := resolveFlowParsedMetrics(collected)
	parts := []string{
		normalizeFlowBoundaryMode(collected.Mode),
		strings.ToUpper(strings.TrimSpace(collected.Status)),
		fmt.Sprintf("behavior=%.2f", normalized.BehaviorRisk),
	}
	if packets := readFlowMetricUint64(metrics, "packetCount"); packets > 0 {
		parts = append(parts, fmt.Sprintf("packets=%d", packets))
	}
	if sessions := readFlowMetricUint64(metrics, "sessionCount"); sessions > 0 {
		parts = append(parts, fmt.Sprintf("sessions=%d", sessions))
	}
	if dnsEvents := readFlowMetricUint64(metrics, "dnsEventCount"); dnsEvents > 0 {
		parts = append(parts, fmt.Sprintf("dns=%d", dnsEvents))
	}
	if httpEvents := readFlowMetricUint64(metrics, "httpEventCount"); httpEvents > 0 {
		parts = append(parts, fmt.Sprintf("http=%d", httpEvents))
	}
	if tlsEvents := readFlowMetricUint64(metrics, "tlsEventCount"); tlsEvents > 0 {
		parts = append(parts, fmt.Sprintf("tls=%d", tlsEvents))
	}
	if directionality := stringifyDirectionalityMetrics(metrics["directionalityIndicators"]); directionality != "" {
		parts = append(parts, directionality)
	}
	if portDensity := stringifyPortDensityMetrics(metrics["portDensityIndicators"]); portDensity != "" {
		parts = append(parts, portDensity)
	}
	return truncateFeatureDigest(strings.Join(parts, " | "))
}

// buildNormalizedFeatureDigest 用于构建Normalized特征Digest。
func buildNormalizedFeatureDigest(targetIP string, collected TaskCollectedData, baseInfoRisk float64, attackRisk float64, behaviorRisk float64) string {
	parts := []string{
		fmt.Sprintf("ip=%s", strings.TrimSpace(targetIP)),
		fmt.Sprintf("geo=%s/%s", fallbackString(collected.BaseInfo.Country, "UNKNOWN"), fallbackString(collected.BaseInfo.WhoisOrg, "UNKNOWN")),
		fmt.Sprintf("rep=%.2f", round2(collected.Reputation.ReputationScore)),
		fmt.Sprintf("attack=%d/%d", collected.AttackSurface.OpenPortCount, collected.AttackSurface.HighRiskPortCount),
		fmt.Sprintf("staticRisk=%.2f/%.2f", round2(baseInfoRisk), round2(attackRisk)),
	}
	if hasFlowRealMetrics(collected.Flow) {
		metrics := resolveFlowParsedMetrics(collected.Flow)
		parts = append(parts,
			fmt.Sprintf("flow=%s:%s", normalizeFlowBoundaryMode(collected.Flow.Mode), strings.ToUpper(strings.TrimSpace(collected.Flow.Status))),
			fmt.Sprintf("behavior=%.2f", round2(behaviorRisk)),
		)
		if packets := readFlowMetricUint64(metrics, "packetCount"); packets > 0 {
			parts = append(parts, fmt.Sprintf("packets=%d", packets))
		}
		if signals, ok := metrics["applicationSignals"].([]string); ok && len(signals) > 0 {
			parts = append(parts, "signals="+strings.Join(signals, " / "))
		}
		if dnsTop := stringifyTopCountMetrics(metrics["dnsTopQuestions"]); dnsTop != "" {
			parts = append(parts, "dnsTop="+dnsTop)
		}
		if httpHosts := stringifyTopCountMetrics(metrics["httpHostHints"]); httpHosts != "" {
			parts = append(parts, "httpHost="+httpHosts)
		}
	}
	return truncateFeatureDigest(strings.Join(parts, " | "))
}

// truncateFeatureDigest 用于执行truncate特征Digest流程。
func truncateFeatureDigest(input string) string {
	trimmed := strings.TrimSpace(input)
	if len(trimmed) <= 120 {
		return trimmed
	}
	return strings.TrimSpace(trimmed[:117]) + "..."
}

// readFlowMetricValue 用于读取流量MetricValue。
func readFlowMetricValue(metrics map[string]any, key string) any {
	if len(metrics) == 0 {
		return nil
	}
	return metrics[key]
}

// readFlowMetricUint64 用于读取流量MetricUint64。
func readFlowMetricUint64(metrics map[string]any, key string) uint64 {
	return uint64(toInt64(readFlowMetricValue(metrics, key)))
}

// readFlowMetricFloat64 用于读取流量MetricFloat64。
func readFlowMetricFloat64(metrics map[string]any, key string) float64 {
	return toFloat64(readFlowMetricValue(metrics, key))
}

// readFlowMetricNestedUint64 用于读取流量MetricNestedUint64。
func readFlowMetricNestedUint64(metrics map[string]any, key string, nestedKey string) uint64 {
	nested, ok := readFlowMetricValue(metrics, key).(map[string]any)
	if !ok || len(nested) == 0 {
		return 0
	}
	return uint64(toInt64(nested[nestedKey]))
}

// readFlowMetricNestedFloat64 用于读取流量MetricNestedFloat64。
func readFlowMetricNestedFloat64(metrics map[string]any, key string, nestedKey string) float64 {
	nested, ok := readFlowMetricValue(metrics, key).(map[string]any)
	if !ok || len(nested) == 0 {
		return 0
	}
	return toFloat64(nested[nestedKey])
}

// readFlowMetricNestedString 用于读取流量MetricNestedString。
func readFlowMetricNestedString(metrics map[string]any, key string, nestedKey string) string {
	nested, ok := readFlowMetricValue(metrics, key).(map[string]any)
	if !ok || len(nested) == 0 {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", nested[nestedKey]))
}

// cloneMap 用于复制Map。
func cloneMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	result := make(map[string]any, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

// cloneStringList 用于复制StringList。
func cloneStringList(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	return append([]string(nil), items...)
}

// cloneEvidenceItems 用于复制EvidenceItems。
func cloneEvidenceItems(items []securityEvidenceItem) []securityEvidenceItem {
	if len(items) == 0 {
		return nil
	}
	return append([]securityEvidenceItem(nil), items...)
}

// toInt 用于转换并生成Int。
func toInt(value any) int {
	return int(toInt64(value))
}

// toInt64 用于转换并生成Int64。
func toInt64(value any) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int32:
		return int64(typed)
	case int64:
		return typed
	case uint:
		return int64(typed)
	case uint32:
		return int64(typed)
	case uint64:
		return int64(typed)
	case float32:
		return int64(typed)
	case float64:
		return int64(typed)
	default:
		return 0
	}
}

// toFloat64 用于转换并生成Float64。
func toFloat64(value any) float64 {
	switch typed := value.(type) {
	case float32:
		return float64(typed)
	case float64:
		return typed
	case int:
		return float64(typed)
	case int32:
		return float64(typed)
	case int64:
		return float64(typed)
	case uint:
		return float64(typed)
	case uint32:
		return float64(typed)
	case uint64:
		return float64(typed)
	default:
		return 0
	}
}

// toRiskScoreModel 用于转换并生成风险评分模型。
func toRiskScoreModel(taskID uint64, targetIP string, score ScoreResult) securityModel.RiskScore {
	weightProfile, _ := json.Marshal(score.WeightProfile)
	return securityModel.RiskScore{
		TaskID:              taskID,
		IP:                  targetIP,
		BaseScore:           score.BaseScore,
		ReputationScore:     score.ReputationScore,
		AttackSurfaceScore:  score.AttackSurfaceScore,
		BehaviorScore:       score.BehaviorScore,
		RuleAdjustmentValue: score.RuleAdjustmentValue,
		ScoreValue:          score.ScoreValue,
		RiskLevel:           score.RiskLevel,
		ScoreReason:         score.ScoreReason,
		RuleAdjustment:      score.RuleAdjustment,
		AlgorithmVersion:    score.AlgorithmVersion,
		WeightProfile:       string(weightProfile),
		IsAlertTriggered:    score.IsAlertTriggered,
		CreatedAt:           time.Now(),
	}
}

// toAlertRecordModel 用于转换并生成预警记录模型。
func toAlertRecordModel(taskID uint64, targetIP string, scoreID uint64, decision *AlertDecision) *securityModel.AlertRecord {
	if decision == nil || !decision.ShouldAlert {
		return nil
	}
	// 预警发送在评分落库前同步执行：拿到发送状态后一并写入预警记录，
	// 这样任务详情能直接展示"已发送/失败"，无需再异步查询发送结果。
	cfg := loadRuntimeSecurityConfig()
	sendStatus, sendTime, err := sendAlertByConfiguredChannel(decision, cfg)
	now := time.Now()
	if err != nil {
		sendStatus = "FAILED"
	}
	taskIDValue := taskID
	scoreIDValue := scoreID
	return &securityModel.AlertRecord{
		TaskID:       &taskIDValue,
		ScoreID:      &scoreIDValue,
		IP:           targetIP,
		SourceType:   "TASK",
		SourceLabel:  targetIP,
		AlertLevel:   decision.AlertLevel,
		AlertTitle:   decision.Title,
		AlertContent: decision.Content,
		Channel:      decision.Channel,
		SendStatus:   sendStatus,
		SendTime:     sendTime,
		CreatedAt:    now,
	}
}
