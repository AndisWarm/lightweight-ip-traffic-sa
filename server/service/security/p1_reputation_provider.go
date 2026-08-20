package security

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"lightweight-ip-traffic-sa/server/config"
)

// enhancedReputationSourceProvider 用于封装enhancedReputation来源数据源访问能力。
type enhancedReputationSourceProvider struct{}

// abuseIPDBCheckResponse 用于承载abuseIPDBCheck接口的响应数据。
type abuseIPDBCheckResponse struct {
	Data abuseIPDBCheckData `json:"data"`
}

// abuseIPDBCheckData 用于承载abuseIPDBCheck采集阶段输出。
type abuseIPDBCheckData struct {
	IPAddress            string `json:"ipAddress"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	CountryCode          string `json:"countryCode"`
	UsageType            string `json:"usageType"`
	ISP                  string `json:"isp"`
	Domain               string `json:"domain"`
	TotalReports         int    `json:"totalReports"`
	LastReportedAt       string `json:"lastReportedAt"`
	IsWhitelisted        bool   `json:"isWhitelisted"`
}

// Name 用于返回数据源名称。
func (p enhancedReputationSourceProvider) Name() string {
	return "p1-reputation"
}

// CollectReputation 用于采集目标 IP 的信誉风险信息。
func (p enhancedReputationSourceProvider) CollectReputation(ctx context.Context, targetIP string, cfg config.SecurityConfig) (ReputationCollectedData, error) {
	defaultScore := cfg.Source.LocalBlacklist.DefaultScore
	if defaultScore <= 0 || defaultScore > 100 {
		defaultScore = 20
	}

	result := ReputationCollectedData{
		IP:              targetIP,
		ReputationScore: round2(defaultScore),
		SourceName:      "local-blacklist:neutral",
		RawPayload: map[string]any{
			"sourceName":       "local-blacklist:neutral",
			"sourceChain":      []string{},
			"attemptedSources": []string{},
			"match":            false,
			"defaultScore":     round2(defaultScore),
			"listFile":         cfg.Source.LocalBlacklist.FilePath,
			"abuseEnabled":     cfg.Source.AbuseIPDB.Enabled,
			"evidenceItems":    []securityEvidenceItem{},
			"degraded":         false,
			"degradeReasons":   []string{},
		},
	}

	evidenceItems := make([]securityEvidenceItem, 0, 3)
	attemptedSources := make([]string, 0, 2)
	sourceChain := make([]string, 0, 2)

	if cfg.Source.LocalBlacklist.Enabled {
		attemptedSources = append(attemptedSources, "local-blacklist")
		entry, matchType, err := loadAndMatchBlacklist(targetIP, cfg.Source.LocalBlacklist)
		if err != nil {
			result.SourceName = "local-blacklist:degraded"
			appendReputationDegradeReason(&result, err.Error())
			evidenceItems = append(evidenceItems, securityEvidenceItem{
				Source:   "local-blacklist",
				Title:    "本地黑名单加载失败",
				Summary:  fmt.Sprintf("名单读取异常，信誉评分先回退到 %.2f，并继续尝试外部信誉源。", round2(defaultScore)),
				RiskHint: "LOW",
			})
			log.Printf("基础信誉降级，source=local-blacklist target=%s err=%v", targetIP, err)
		} else if entry != nil {
			sourceChain = append(sourceChain, "local-blacklist")
			matchScore := entry.Score
			if matchScore <= 0 || matchScore > 100 {
				matchScore = cfg.Source.LocalBlacklist.MatchScore
			}
			if matchScore <= 0 || matchScore > 100 {
				matchScore = 92
			}

			result.ReputationScore = round2(matchScore)
			result.SourceName = "local-blacklist:matched"
			result.RawPayload["sourceName"] = result.SourceName
			result.RawPayload["match"] = true
			result.RawPayload["matchType"] = matchType
			result.RawPayload["matchedEntry"] = map[string]any{
				"value":  entry.Value,
				"label":  entry.Label,
				"reason": entry.Reason,
				"score":  round2(matchScore),
			}
			evidenceItems = append(evidenceItems, securityEvidenceItem{
				Source:   "local-blacklist",
				Title:    "本地黑名单命中",
				Summary:  fmt.Sprintf("命中 %s 条目 %s，原因：%s。", matchType, entry.Value, fallbackString(entry.Reason, "未填写")),
				RiskHint: "HIGH",
			})
			result.RawPayload["attemptedSources"] = attemptedSources
			result.RawPayload["sourceChain"] = sourceChain
			result.RawPayload["evidenceItems"] = evidenceItems
			return result, nil
		} else {
			sourceChain = append(sourceChain, "local-blacklist")
			evidenceItems = append(evidenceItems, securityEvidenceItem{
				Source:   "local-blacklist",
				Title:    "本地黑名单未命中",
				Summary:  fmt.Sprintf("目标 IP 未命中本地黑名单 / CIDR，保持中性信誉分 %.2f。", round2(defaultScore)),
				RiskHint: "LOW",
			})
		}
	} else {
		result.SourceName = "local-blacklist:disabled"
		appendReputationDegradeReason(&result, "local blacklist disabled")
		evidenceItems = append(evidenceItems, securityEvidenceItem{
			Source:   "local-blacklist",
			Title:    "本地黑名单已关闭",
			Summary:  fmt.Sprintf("未启用本地黑名单能力，信誉评分先回退到 %.2f。", round2(defaultScore)),
			RiskHint: "LOW",
		})
	}

	select {
	case <-ctx.Done():
		return result, ctx.Err()
	default:
	}

	if cfg.Source.AbuseIPDB.Enabled {
		attemptedSources = append(attemptedSources, "abuseipdb")
		rawPayload, evidence, score, err := collectAbuseIPDBReputation(ctx, targetIP, cfg)
		if err != nil {
			appendReputationDegradeReason(&result, "abuseipdb:"+err.Error())
			evidenceItems = append(evidenceItems, securityEvidenceItem{
				Source:   "abuseipdb",
				Title:    "AbuseIPDB 查询失败",
				Summary:  fmt.Sprintf("外部信誉源不可用，维持当前信誉分 %.2f，不阻断任务主链路。", result.ReputationScore),
				RiskHint: "LOW",
			})
			log.Printf("信誉增强降级，source=abuseipdb target=%s err=%v", targetIP, err)
		} else {
			sourceChain = append(sourceChain, "abuseipdb")
			result.ReputationScore = score
			result.SourceName = "abuseipdb"
			result.RawPayload["sourceName"] = result.SourceName
			result.RawPayload["abuseipdb"] = rawPayload
			evidenceItems = append(evidenceItems, evidence)
		}
	}

	result.RawPayload["attemptedSources"] = attemptedSources
	result.RawPayload["sourceChain"] = sourceChain
	result.RawPayload["sourceName"] = result.SourceName
	result.RawPayload["evidenceItems"] = evidenceItems
	return result, nil
}

// collectAbuseIPDBReputation 用于采集AbuseIPDBReputation。
func collectAbuseIPDBReputation(ctx context.Context, targetIP string, cfg config.SecurityConfig) (map[string]any, securityEvidenceItem, float64, error) {
	baseURL := strings.TrimSpace(cfg.Source.AbuseIPDB.BaseURL)
	apiKey := strings.TrimSpace(cfg.Source.AbuseIPDB.APIKey)
	if baseURL == "" || apiKey == "" {
		return nil, securityEvidenceItem{}, 0, fmt.Errorf("abuseipdb config incomplete")
	}

	queryURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, securityEvidenceItem{}, 0, err
	}
	params := queryURL.Query()
	params.Set("ipAddress", targetIP)
	params.Set("maxAgeInDays", strconv.Itoa(cfg.Source.AbuseIPDB.MaxAgeInDays))
	queryURL.RawQuery = params.Encode()

	timeout := resolveSourceTTL(cfg.Source.AbuseIPDB.TimeoutSeconds, 2*time.Second)
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL.String(), nil)
	if err != nil {
		return nil, securityEvidenceItem{}, 0, err
	}
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, securityEvidenceItem{}, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, securityEvidenceItem{}, 0, fmt.Errorf("abuseipdb status=%d", resp.StatusCode)
	}

	var payload abuseIPDBCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, securityEvidenceItem{}, 0, fmt.Errorf("invalid abuseipdb payload: %w", err)
	}

	score := float64(payload.Data.AbuseConfidenceScore)
	if payload.Data.IsWhitelisted && score > 20 {
		score = 20
	}
	score = round2(score)

	rawPayload := map[string]any{
		"ipAddress":            payload.Data.IPAddress,
		"abuseConfidenceScore": payload.Data.AbuseConfidenceScore,
		"countryCode":          payload.Data.CountryCode,
		"usageType":            payload.Data.UsageType,
		"isp":                  payload.Data.ISP,
		"domain":               payload.Data.Domain,
		"totalReports":         payload.Data.TotalReports,
		"lastReportedAt":       payload.Data.LastReportedAt,
		"isWhitelisted":        payload.Data.IsWhitelisted,
	}

	evidence := securityEvidenceItem{
		Source:   "abuseipdb",
		Title:    "AbuseIPDB 信誉查询",
		Summary:  fmt.Sprintf("置信分=%.2f，报告数=%d，使用类型=%s，最近上报=%s。", score, payload.Data.TotalReports, fallbackString(payload.Data.UsageType, "未知"), fallbackString(payload.Data.LastReportedAt, "无")),
		RiskHint: abuseRiskHint(score),
	}

	return rawPayload, evidence, score, nil
}

// abuseRiskHint 用于执行abuse风险Hint流程。
func abuseRiskHint(score float64) string {
	switch {
	case score >= 75:
		return "HIGH"
	case score >= 40:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// appendReputationDegradeReason 用于追加业务明细或展示条目。
func appendReputationDegradeReason(result *ReputationCollectedData, reason string) {
	reasons, _ := result.RawPayload["degradeReasons"].([]string)
	reasons = append(reasons, reason)
	result.RawPayload["degradeReasons"] = reasons
	result.RawPayload["degraded"] = true
}
