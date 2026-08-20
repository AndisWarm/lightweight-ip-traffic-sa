package security

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"lightweight-ip-traffic-sa/server/config"
	"lightweight-ip-traffic-sa/server/utils"
)

// realBaseInfoSourceProvider 用于封装real基础信息来源数据源访问能力。
type realBaseInfoSourceProvider struct{}

// realReputationSourceProvider 用于封装realReputation来源数据源访问能力。
type realReputationSourceProvider struct{}

// noopAttackSurfaceProvider 用于封装noopAttackSurface数据源访问能力。
type noopAttackSurfaceProvider struct{}

// securityEvidenceItem 用于承载securityEvidence列表展示条目。
type securityEvidenceItem struct {
	Source   string `json:"source"`
	Title    string `json:"title"`
	Summary  string `json:"summary"`
	RiskHint string `json:"riskHint"`
}

// securityScoreFactor 用于承载security评分Factor数据。
type securityScoreFactor struct {
	Key          string  `json:"key"`
	Label        string  `json:"label"`
	RawScore     float64 `json:"rawScore"`
	Weight       float64 `json:"weight"`
	Contribution float64 `json:"contribution"`
	Basis        string  `json:"basis"`
	DisplayBasis string  `json:"displayBasis"`
}

// geoLite2LookupResult 用于承载 GeoLite2 离线库查询结果。
type geoLite2LookupResult struct {
	Country        string
	Region         string
	City           string
	ISP            string
	ASN            uint
	Latitude       float64
	Longitude      float64
	TimeZone       string
	AccuracyRadius int
}

// geoLite2ReaderEntry 用于承载geoLite2ReaderEntry配置条目。
type geoLite2ReaderEntry struct {
	path    string
	version string
	reader  *maxminddb.Reader
}

// geoLite2ReaderState 用于保存geoLite2ReaderState运行状态。
type geoLite2ReaderState struct {
	mu      sync.Mutex
	country geoLite2ReaderEntry
	city    geoLite2ReaderEntry
	asn     geoLite2ReaderEntry
}

// blacklistState 用于保存blacklistState运行状态。
type blacklistState struct {
	mu         sync.RWMutex
	path       string
	lastCheck  time.Time
	singleIPs  map[string]blacklistEntry
	cidrBlocks []blacklistCIDREntry
}

// blacklistEntry 用于承载blacklistEntry配置条目。
type blacklistEntry struct {
	Value  string
	Label  string
	Reason string
	Score  float64
}

// blacklistCIDREntry 用于承载blacklistCIDREntry配置条目。
type blacklistCIDREntry struct {
	Entry blacklistEntry
	Net   *net.IPNet
}

// rdapResponse 用于承载rdap接口的响应数据。
type rdapResponse struct {
	Name         string       `json:"name"`
	Handle       string       `json:"handle"`
	Country      string       `json:"country"`
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	Status       []string     `json:"status"`
	Entities     []rdapEntity `json:"entities"`
}

// rdapEntity 用于承载rdapEntity数据。
type rdapEntity struct {
	VCardArray []interface{} `json:"vcardArray"`
}

// geoLite2CityRecord 用于承载geoLite2City记录数据。
type geoLite2CityRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		AccuracyRadius uint16  `maxminddb:"accuracy_radius"`
		Latitude       float64 `maxminddb:"latitude"`
		Longitude      float64 `maxminddb:"longitude"`
		TimeZone       string  `maxminddb:"time_zone"`
	} `maxminddb:"location"`
}

// geoLite2CountryRecord 用于承载geoLite2Country记录数据。
type geoLite2CountryRecord struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
}

// geoLite2ASNRecord 用于承载geoLite2ASN记录数据。
type geoLite2ASNRecord struct {
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

var (
	geoLite2Readers = &geoLite2ReaderState{}
	blacklistCache  = &blacklistState{}
)

// Name 用于返回数据源名称。
func (p realBaseInfoSourceProvider) Name() string {
	return "p0-base-info"
}

// CollectBaseInfo 用于采集目标 IP 的基础画像信息。
func (p realBaseInfoSourceProvider) CollectBaseInfo(ctx context.Context, targetIP string, cfg config.SecurityConfig) (BaseInfoCollectedData, error) {
	result := BaseInfoCollectedData{
		IP:         targetIP,
		RawPayload: map[string]any{},
		SourceName: p.Name(),
	}

	fieldSources := map[string]string{}
	sourceChain := make([]string, 0, 2)
	evidenceItems := make([]securityEvidenceItem, 0, 2)
	degradeReasons := make([]string, 0, 2)

	// 基础画像采用"离线优先、在线补充"策略：先用本地 GeoLite2 拿地理/ASN 画像（不依赖网络、可重复演示），
	// 再用 RDAP 补充注册组织与网段信息；两个源各自失败都不阻断任务，只把原因记进 degradeReasons 做降级。
	if cfg.Source.GeoLite2.Enabled {
		geoResult, evidence, err := collectGeoLite2Data(ctx, targetIP, cfg)
		if err != nil {
			degradeReasons = append(degradeReasons, "GeoLite2:"+err.Error())
			log.Printf("基础画像降级，source=GeoLite2 target=%s err=%v", targetIP, err)
		} else {
			mergeBaseInfoResult(&result, geoResult, fieldSources)
			sourceChain = append(sourceChain, "GeoLite2")
			evidenceItems = append(evidenceItems, evidence)
			result.RawPayload["geoLite2"] = geoResult.RawPayload["geoLite2"]
		}
	}

	if cfg.Source.RDAP.Enabled {
		rdapResult, evidence, err := collectRDAPData(ctx, targetIP, cfg)
		if err != nil {
			degradeReasons = append(degradeReasons, "RDAP:"+err.Error())
			log.Printf("基础画像降级，source=RDAP target=%s err=%v", targetIP, err)
		} else {
			mergeBaseInfoResult(&result, rdapResult, fieldSources)
			sourceChain = append(sourceChain, "RDAP")
			evidenceItems = append(evidenceItems, evidence)
			result.RawPayload["rdap"] = rdapResult.RawPayload["rdap"]
		}
	}

	if result.Country == "" {
		result.Country = "UNKNOWN"
	}
	if result.Region == "" {
		result.Region = "UNKNOWN"
	}
	if result.City == "" {
		result.City = "UNKNOWN"
	}
	if result.ISP == "" {
		result.ISP = "UNKNOWN"
	}

	result.SourceName = joinOrFallback(sourceChain, "p0-base-info:degraded")
	result.RawPayload["sourceName"] = result.SourceName
	result.RawPayload["sourceChain"] = dedupeStrings(sourceChain)
	result.RawPayload["fieldSources"] = fieldSources
	result.RawPayload["evidenceItems"] = evidenceItems
	if len(degradeReasons) > 0 {
		result.RawPayload["degraded"] = true
		result.RawPayload["degradeReasons"] = degradeReasons
	}

	return result, nil
}

// Name 用于返回数据源名称。
func (p realReputationSourceProvider) Name() string {
	return "p0-reputation"
}

// CollectReputation 用于采集目标 IP 的信誉风险信息。
func (p realReputationSourceProvider) CollectReputation(ctx context.Context, targetIP string, cfg config.SecurityConfig) (ReputationCollectedData, error) {
	// defaultScore 是未命中黑名单时的中性分：既不为 0（避免彻底忽略信誉维度），也不虚高，作为未命中目标的兜底。
	// 配置越界（<=0 或 >100）时强制回到 20，防止错误配置直接污染信誉评分。
	defaultScore := cfg.Source.LocalBlacklist.DefaultScore
	if defaultScore <= 0 || defaultScore > 100 {
		defaultScore = 20
	}

	result := ReputationCollectedData{
		IP:              targetIP,
		ReputationScore: round2(defaultScore),
		SourceName:      "local-blacklist:neutral",
		RawPayload: map[string]any{
			"sourceName":    "local-blacklist",
			"sourceChain":   []string{"local-blacklist"},
			"match":         false,
			"defaultScore":  round2(defaultScore),
			"listFile":      cfg.Source.LocalBlacklist.FilePath,
			"evidenceItems": []securityEvidenceItem{},
			"degraded":      false,
		},
	}

	if !cfg.Source.LocalBlacklist.Enabled {
		result.SourceName = "local-blacklist:disabled"
		result.RawPayload["degraded"] = true
		result.RawPayload["degradeReasons"] = []string{"local blacklist disabled"}
		result.RawPayload["evidenceItems"] = []securityEvidenceItem{
			{
				Source:   "local-blacklist",
				Title:    "本地黑名单已关闭",
				Summary:  fmt.Sprintf("未启用本地黑名单能力，信誉评分回退到 %.2f。", round2(defaultScore)),
				RiskHint: "LOW",
			},
		}
		return result, nil
	}

	entry, matchType, err := loadAndMatchBlacklist(targetIP, cfg.Source.LocalBlacklist)
	if err != nil {
		result.SourceName = "local-blacklist:degraded"
		result.RawPayload["degraded"] = true
		result.RawPayload["degradeReasons"] = []string{err.Error()}
		result.RawPayload["evidenceItems"] = []securityEvidenceItem{
			{
				Source:   "local-blacklist",
				Title:    "本地黑名单加载失败",
				Summary:  fmt.Sprintf("名单读取异常，信誉评分降级为 %.2f。", round2(defaultScore)),
				RiskHint: "LOW",
			},
		}
		log.Printf("基础信誉降级，source=local-blacklist target=%s err=%v", targetIP, err)
		return result, nil
	}

	select {
	case <-ctx.Done():
		return result, ctx.Err()
	default:
	}

	if entry == nil {
		result.RawPayload["evidenceItems"] = []securityEvidenceItem{
			{
				Source:   "local-blacklist",
				Title:    "本地黑名单未命中",
				Summary:  fmt.Sprintf("目标 IP 未命中本地黑名单 / CIDR，保持中性信誉分 %.2f。", round2(defaultScore)),
				RiskHint: "LOW",
			},
		}
		return result, nil
	}

	// 命中条目优先用条目自带分数（支持逐条精细控制）；条目未配分或越界时回退到配置 matchScore，再兜底到 92。
	// 命中即是最强信誉证据，直接采用条目分，解释力最强。
	matchScore := entry.Score
	if matchScore <= 0 || matchScore > 100 {
		matchScore = cfg.Source.LocalBlacklist.MatchScore
	}
	if matchScore <= 0 || matchScore > 100 {
		matchScore = 92
	}

	result.ReputationScore = round2(matchScore)
	result.SourceName = "local-blacklist:matched"
	result.RawPayload["match"] = true
	result.RawPayload["matchType"] = matchType
	result.RawPayload["matchedEntry"] = map[string]any{
		"value":  entry.Value,
		"label":  entry.Label,
		"reason": entry.Reason,
		"score":  round2(matchScore),
	}
	result.RawPayload["evidenceItems"] = []securityEvidenceItem{
		{
			Source:   "local-blacklist",
			Title:    "本地黑名单命中",
			Summary:  fmt.Sprintf("命中 %s 条目 %s，原因：%s。", matchType, entry.Value, fallbackString(entry.Reason, "未填写")),
			RiskHint: "HIGH",
		},
	}
	return result, nil
}

// Name 用于返回数据源名称。
func (p noopAttackSurfaceProvider) Name() string {
	return "attack-surface-disabled"
}

// CollectAttackSurface 用于采集目标 IP 的攻击面信息。
func (p noopAttackSurfaceProvider) CollectAttackSurface(ctx context.Context, targetIP string, baseInfo BaseInfoCollectedData, cfg config.SecurityConfig) (AttackSurfaceCollectedData, error) {
	return AttackSurfaceCollectedData{
		IP:                targetIP,
		OpenPortCount:     0,
		HighRiskPortCount: 0,
		GeoRiskFlag:       isGeoRiskCountry(baseInfo.Country),
		SourceName:        p.Name(),
		RawPayload: map[string]any{
			"sourceName":  p.Name(),
			"sourceChain": []string{p.Name()},
			"enabled":     false,
			"evidenceItems": []securityEvidenceItem{
				{
					Source:   p.Name(),
					Title:    "攻击面采集未启用",
					Summary:  "有限端口探测尚未接入，当前按 0 端口暴露处理，不阻断主链路。",
					RiskHint: "LOW",
				},
			},
		},
	}, nil
}

// collectGeoLite2Data 用于采集地理Lite2Data。
func collectGeoLite2Data(ctx context.Context, targetIP string, cfg config.SecurityConfig) (BaseInfoCollectedData, securityEvidenceItem, error) {
	cacheKey := utils.BuildCollectorCacheKey(targetIP, "geolite2", buildCollectorConfigVersion(cfg))
	var cached BaseInfoCollectedData
	if hit, err := utils.CacheGetJSON(cacheKey, &cached); err == nil && hit {
		return cached, buildBaseInfoEvidenceFromCache("GeoLite2", cached), nil
	}

	lookup, err := queryGeoLite2(targetIP, cfg.Source.GeoLite2)
	if err != nil {
		return BaseInfoCollectedData{}, securityEvidenceItem{}, err
	}

	select {
	case <-ctx.Done():
		return BaseInfoCollectedData{}, securityEvidenceItem{}, ctx.Err()
	default:
	}

	result := BaseInfoCollectedData{
		IP:      targetIP,
		Country: lookup.Country,
		Region:  lookup.Region,
		City:    lookup.City,
		ISP:     lookup.ISP,
		RawPayload: map[string]any{
			"geoLite2": map[string]any{
				"country":        lookup.Country,
				"region":         lookup.Region,
				"city":           lookup.City,
				"isp":            lookup.ISP,
				"asn":            lookup.ASN,
				"latitude":       lookup.Latitude,
				"longitude":      lookup.Longitude,
				"timeZone":       lookup.TimeZone,
				"accuracyRadius": lookup.AccuracyRadius,
			},
		},
		SourceName: "GeoLite2",
	}

	if err := utils.CacheSetJSON(cacheKey, result, resolveSourceTTL(cfg.Source.GeoLite2.CacheTTLSeconds, 24*time.Hour)); err != nil {
		log.Printf("GeoLite2 缓存写入失败，target=%s err=%v", targetIP, err)
	}

	return result, securityEvidenceItem{
		Source:   "GeoLite2",
		Title:    "GeoLite2 离线画像",
		Summary:  fmt.Sprintf("国家=%s，地区=%s，城市=%s，ISP=%s。", fallbackString(lookup.Country, "UNKNOWN"), fallbackString(lookup.Region, "UNKNOWN"), fallbackString(lookup.City, "UNKNOWN"), fallbackString(lookup.ISP, "UNKNOWN")),
		RiskHint: "INFO",
	}, nil
}

// collectRDAPData 用于采集RDAPData。
func collectRDAPData(ctx context.Context, targetIP string, cfg config.SecurityConfig) (BaseInfoCollectedData, securityEvidenceItem, error) {
	cacheKey := utils.BuildCollectorCacheKey(targetIP, "rdap", buildCollectorConfigVersion(cfg))
	var cached BaseInfoCollectedData
	if hit, err := utils.CacheGetJSON(cacheKey, &cached); err == nil && hit {
		return cached, buildBaseInfoEvidenceFromCache("RDAP", cached), nil
	}

	timeout := resolveSourceTTL(cfg.Source.RDAP.TimeoutSeconds, 2*time.Second)
	payload, endpoint, err := queryRDAPWithFallback(ctx, targetIP, timeout, cfg.Source.RDAP)
	if err != nil {
		return BaseInfoCollectedData{}, securityEvidenceItem{}, err
	}

	org, contact := extractRDAPOrgAndContact(payload)
	result := BaseInfoCollectedData{
		IP:           targetIP,
		Country:      strings.TrimSpace(payload.Country),
		WhoisOrg:     org,
		WhoisContact: contact,
		RawPayload: map[string]any{
			"rdap": map[string]any{
				"endpoint":     endpoint,
				"name":         payload.Name,
				"handle":       payload.Handle,
				"country":      payload.Country,
				"startAddress": payload.StartAddress,
				"endAddress":   payload.EndAddress,
				"status":       payload.Status,
			},
		},
		SourceName: "RDAP",
	}

	if err := utils.CacheSetJSON(cacheKey, result, resolveSourceTTL(cfg.Source.RDAP.CacheTTLSeconds, 24*time.Hour)); err != nil {
		log.Printf("RDAP 缓存写入失败，target=%s err=%v", targetIP, err)
	}

	return result, securityEvidenceItem{
		Source:   "RDAP",
		Title:    "RDAP 注册信息",
		Summary:  fmt.Sprintf("组织=%s，联系人=%s，网段=%s-%s，端点=%s。", fallbackString(org, "UNKNOWN"), fallbackString(contact, "UNKNOWN"), fallbackString(payload.StartAddress, "-"), fallbackString(payload.EndAddress, "-"), fallbackString(endpoint, "default")),
		RiskHint: "INFO",
	}, nil
}

// queryGeoLite2 用于查询地理Lite2。
func queryGeoLite2(targetIP string, cfg config.GeoLite2SourceConfig) (geoLite2LookupResult, error) {
	parsed := net.ParseIP(strings.TrimSpace(targetIP))
	if parsed == nil {
		return geoLite2LookupResult{}, fmt.Errorf("invalid ip for geolite2")
	}

	result := geoLite2LookupResult{}
	found := false

	// GeoLite2 是本地 mmdb 离线库，查询走内存映射文件、微秒级返回且不依赖公网，因此作为基础画像的稳定首选。
	// 优先查信息更全的 City 库，缺国家字段时再回退到更小的 Country 库。
	var cityRecord geoLite2CityRecord
	if err := geoLite2Readers.lookup(cfg.CityDBPath, "city", parsed, &cityRecord); err == nil {
		result.Country = pickLocalizedName(cityRecord.Country.Names, cityRecord.Country.ISOCode)
		if len(cityRecord.Subdivisions) > 0 {
			result.Region = pickLocalizedName(cityRecord.Subdivisions[0].Names, "")
		}
		result.City = pickLocalizedName(cityRecord.City.Names, "")
		result.AccuracyRadius = int(cityRecord.Location.AccuracyRadius)
		result.Latitude = cityRecord.Location.Latitude
		result.Longitude = cityRecord.Location.Longitude
		result.TimeZone = strings.TrimSpace(cityRecord.Location.TimeZone)
		found = found || result.Country != "" || result.Region != "" || result.City != ""
		found = found || result.AccuracyRadius > 0 || result.Latitude != 0 || result.Longitude != 0 || result.TimeZone != ""
	}

	// City 库可能缺失或未解析出国家码，此时回退到更小的 Country 库补国家信息，避免画像缺位。
	if result.Country == "" {
		var countryRecord geoLite2CountryRecord
		if err := geoLite2Readers.lookup(cfg.CountryDBPath, "country", parsed, &countryRecord); err == nil {
			result.Country = pickLocalizedName(countryRecord.Country.Names, countryRecord.Country.ISOCode)
			found = found || result.Country != ""
		}
	}

	var asnRecord geoLite2ASNRecord
	if err := geoLite2Readers.lookup(cfg.ASNDBPath, "asn", parsed, &asnRecord); err == nil {
		result.ISP = strings.TrimSpace(asnRecord.AutonomousSystemOrganization)
		result.ASN = asnRecord.AutonomousSystemNumber
		found = found || result.ISP != "" || result.ASN > 0
	}

	if !found {
		return geoLite2LookupResult{}, fmt.Errorf("geolite2 unavailable or empty")
	}
	return result, nil
}

// lookup 用于执行lookup流程。
func (s *geoLite2ReaderState) lookup(path string, dbType string, ip net.IP, result any) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return fmt.Errorf("geolite2 db path empty")
	}

	resolved, err := resolveConfigPath(trimmed)
	if err != nil {
		return err
	}

	version, err := resolveFileVersionTokenByResolvedPath(resolved)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	entry, err := s.entry(dbType)
	if err != nil {
		return err
	}
	if err := s.ensureReaderLocked(entry, resolved, version, dbType); err != nil {
		return err
	}
	return entry.reader.Lookup(ip, result)
}

// entry 用于执行entry流程。
func (s *geoLite2ReaderState) entry(dbType string) (*geoLite2ReaderEntry, error) {
	switch dbType {
	case "country":
		return &s.country, nil
	case "city":
		return &s.city, nil
	case "asn":
		return &s.asn, nil
	default:
		return nil, fmt.Errorf("unsupported geolite2 db type: %s", dbType)
	}
}

// ensureReaderLocked 用于执行ensureReaderLocked流程。
func (s *geoLite2ReaderState) ensureReaderLocked(entry *geoLite2ReaderEntry, resolved string, version string, dbType string) error {
	if entry.reader != nil && entry.path == resolved && entry.version == version {
		return nil
	}

	reader, err := maxminddb.Open(resolved)
	if err != nil {
		return err
	}

	// 版本令牌 = 文件大小 + 修改时间：文件内容或版本变化后令牌不一致，会自动关闭旧 reader 并重新打开实现热重载，
	// 避免长期运行后仍使用过期的 mmdb 数据。
	action := "加载"
	if entry.reader != nil {
		action = "热重载"
		_ = entry.reader.Close()
	}

	entry.reader = reader
	entry.path = resolved
	entry.version = version
	log.Printf("GeoLite2 数据库已%s，type=%s path=%s version=%s", action, dbType, resolved, version)
	return nil
}

// queryRDAPWithFallback 用于查询RDAPWithFallback。
func queryRDAPWithFallback(ctx context.Context, targetIP string, timeout time.Duration, cfg config.RDAPSourceConfig) (rdapResponse, string, error) {
	client := &http.Client{Timeout: timeout}
	endpoints := buildRDAPEndpoints(cfg)
	errorsSeen := make([]string, 0, len(endpoints))

	// 主端点失败后按顺序轮询备用端点（默认 ARIN/RIPE/APNIC/AFRINIC/LACNIC），任一成功即返回；
	// 每个端点独立设置超时并记录失败原因，避免单个注册局挂起拖死整个基础画像采集。
	for _, endpoint := range endpoints {
		if err := ctx.Err(); err != nil {
			errorsSeen = append(errorsSeen, fmt.Sprintf("parent_context=%v", err))
			break
		}
		requestCtx, cancel := context.WithTimeout(ctx, timeout)
		payload, err := querySingleRDAPEndpoint(requestCtx, client, endpoint, targetIP)
		cancel()
		if err == nil {
			return payload, endpoint, nil
		}
		errorsSeen = append(errorsSeen, fmt.Sprintf("%s=%v", endpoint, err))
	}

	return rdapResponse{}, "", fmt.Errorf("rdap fallback exhausted: %s", strings.Join(errorsSeen, "; "))
}

// buildRDAPEndpoints 用于构建RDAPEndpoints。
func buildRDAPEndpoints(cfg config.RDAPSourceConfig) []string {
	// 主端点在前、备用端点在后：rdap.org 会按 IP 归属自动跳转到正确注册局，备用端点兜底覆盖各区域注册局；
	// 去重后保证同一端点不会被重复轮询。
	items := make([]string, 0, 1+len(cfg.BackupBaseURLs))
	if base := normalizeRDAPEndpoint(cfg.BaseURL); base != "" {
		items = append(items, base)
	}
	for _, base := range cfg.BackupBaseURLs {
		if normalized := normalizeRDAPEndpoint(base); normalized != "" {
			items = append(items, normalized)
		}
	}
	return dedupeStrings(items)
}

// normalizeRDAPEndpoint 用于归一化输入参数或业务指标。
func normalizeRDAPEndpoint(baseURL string) string {
	trimmed := strings.TrimSpace(baseURL)
	if trimmed == "" {
		return ""
	}
	if !strings.HasSuffix(trimmed, "/") {
		trimmed += "/"
	}
	return trimmed
}

// querySingleRDAPEndpoint 用于查询SingleRDAPEndpoint。
func querySingleRDAPEndpoint(ctx context.Context, client *http.Client, endpoint string, targetIP string) (rdapResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+targetIP, nil)
	if err != nil {
		return rdapResponse{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return rdapResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return rdapResponse{}, fmt.Errorf("rdap status=%d", resp.StatusCode)
	}

	var payload rdapResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return rdapResponse{}, fmt.Errorf("invalid rdap payload: %w", err)
	}
	return payload, nil
}

// loadAndMatchBlacklist 用于加载配置、缓存或外部资源。
func loadAndMatchBlacklist(targetIP string, cfg config.LocalBlacklistConfig) (*blacklistEntry, string, error) {
	if err := blacklistCache.ensureLoaded(cfg); err != nil {
		return nil, "", err
	}
	return blacklistCache.match(targetIP)
}

// ensureLoaded 用于执行ensureLoaded流程。
func (s *blacklistState) ensureLoaded(cfg config.LocalBlacklistConfig) error {
	resolved, err := resolveConfigPath(cfg.FilePath)
	if err != nil {
		return err
	}

	checkInterval := resolveSourceTTL(cfg.ReloadIntervalSeconds, 5*time.Minute)

	s.mu.RLock()
	sameFile := s.path == resolved
	needsReload := s.singleIPs == nil || time.Since(s.lastCheck) >= checkInterval
	s.mu.RUnlock()
	if sameFile && !needsReload {
		return nil
	}

	file, err := os.Open(resolved)
	if err != nil {
		return err
	}
	defer file.Close()

	nextIPs := make(map[string]blacklistEntry)
	nextCIDRs := make([]blacklistCIDREntry, 0)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entry, err := parseBlacklistLine(line)
		if err != nil {
			log.Printf("跳过非法黑名单条目，line=%s err=%v", line, err)
			continue
		}

		if strings.Contains(entry.Value, "/") {
			_, network, err := net.ParseCIDR(entry.Value)
			if err != nil {
				log.Printf("跳过非法 CIDR 黑名单条目，value=%s err=%v", entry.Value, err)
				continue
			}
			nextCIDRs = append(nextCIDRs, blacklistCIDREntry{Entry: entry, Net: network})
			continue
		}

		nextIPs[entry.Value] = entry
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = resolved
	s.singleIPs = nextIPs
	s.cidrBlocks = nextCIDRs
	s.lastCheck = time.Now()
	return nil
}

// match 用于执行match流程。
func (s *blacklistState) match(targetIP string) (*blacklistEntry, string, error) {
	parsed := net.ParseIP(targetIP)
	if parsed == nil {
		return nil, "", fmt.Errorf("invalid ip for blacklist")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if entry, ok := s.singleIPs[targetIP]; ok {
		entryCopy := entry
		return &entryCopy, "IP", nil
	}

	for _, item := range s.cidrBlocks {
		if item.Net.Contains(parsed) {
			entryCopy := item.Entry
			return &entryCopy, "CIDR", nil
		}
	}

	return nil, "", nil
}

// parseBlacklistLine 用于解析输入数据并转换为内部模型。
func parseBlacklistLine(line string) (blacklistEntry, error) {
	parts := strings.Split(line, ",")
	if len(parts) == 0 {
		return blacklistEntry{}, fmt.Errorf("empty blacklist line")
	}

	entry := blacklistEntry{
		Value: strings.TrimSpace(parts[0]),
		Label: "本地名单",
	}
	if entry.Value == "" {
		return blacklistEntry{}, fmt.Errorf("empty blacklist target")
	}
	if len(parts) > 1 && strings.TrimSpace(parts[1]) != "" {
		entry.Label = strings.TrimSpace(parts[1])
	}
	if len(parts) > 2 {
		entry.Reason = strings.TrimSpace(parts[2])
	}
	if len(parts) > 3 && strings.TrimSpace(parts[3]) != "" {
		score, err := strconv.ParseFloat(strings.TrimSpace(parts[3]), 64)
		if err != nil {
			return blacklistEntry{}, fmt.Errorf("invalid blacklist score")
		}
		entry.Score = score
	}
	return entry, nil
}

// extractRDAPOrgAndContact 用于提取请求、令牌或流量中的关键信息。
func extractRDAPOrgAndContact(payload rdapResponse) (string, string) {
	org := strings.TrimSpace(payload.Name)
	contact := ""

	for _, entity := range payload.Entities {
		currentOrg, currentContact := parseEntityVCard(entity)
		if org == "" && currentOrg != "" {
			org = currentOrg
		}
		if contact == "" && currentContact != "" {
			contact = currentContact
		}
		if org != "" && contact != "" {
			break
		}
	}

	return org, contact
}

// parseEntityVCard 用于解析输入数据并转换为内部模型。
func parseEntityVCard(entity rdapEntity) (string, string) {
	if len(entity.VCardArray) != 2 {
		return "", ""
	}
	rows, ok := entity.VCardArray[1].([]interface{})
	if !ok {
		return "", ""
	}

	org := ""
	contact := ""
	for _, row := range rows {
		values, ok := row.([]interface{})
		if !ok || len(values) < 4 {
			continue
		}
		name, _ := values[0].(string)
		value := fmt.Sprintf("%v", values[3])
		switch strings.ToLower(name) {
		case "fn", "org":
			if org == "" {
				org = strings.TrimSpace(value)
			}
		case "email", "tel":
			if contact == "" {
				contact = strings.TrimSpace(value)
			}
		}
	}
	return org, contact
}

// mergeBaseInfoResult 用于合并基础信息Result。
func mergeBaseInfoResult(target *BaseInfoCollectedData, incoming BaseInfoCollectedData, fieldSources map[string]string) {
	assignIfEmpty(&target.Country, incoming.Country, "country", incoming.SourceName, fieldSources)
	assignIfEmpty(&target.Region, incoming.Region, "region", incoming.SourceName, fieldSources)
	assignIfEmpty(&target.City, incoming.City, "city", incoming.SourceName, fieldSources)
	assignIfEmpty(&target.ISP, incoming.ISP, "isp", incoming.SourceName, fieldSources)
	assignIfEmpty(&target.WhoisOrg, incoming.WhoisOrg, "whoisOrg", incoming.SourceName, fieldSources)
	assignIfEmpty(&target.WhoisContact, incoming.WhoisContact, "whoisContact", incoming.SourceName, fieldSources)
}

// assignIfEmpty 用于执行assignIfEmpty流程。
func assignIfEmpty(target *string, value string, field string, source string, fieldSources map[string]string) {
	if strings.TrimSpace(*target) != "" || strings.TrimSpace(value) == "" {
		return
	}
	*target = strings.TrimSpace(value)
	fieldSources[field] = source
}

// buildBaseInfoEvidenceFromCache 用于构建基础信息EvidenceFrom缓存。
func buildBaseInfoEvidenceFromCache(source string, result BaseInfoCollectedData) securityEvidenceItem {
	return securityEvidenceItem{
		Source:   source,
		Title:    source + " 缓存命中",
		Summary:  fmt.Sprintf("国家=%s，地区=%s，城市=%s，组织=%s。", fallbackString(result.Country, "UNKNOWN"), fallbackString(result.Region, "UNKNOWN"), fallbackString(result.City, "UNKNOWN"), fallbackString(result.WhoisOrg, "UNKNOWN")),
		RiskHint: "INFO",
	}
}

// resolveConfigPath 用于解析配置Path。
func resolveConfigPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", fmt.Errorf("config path empty")
	}
	if filepath.IsAbs(trimmed) {
		return trimmed, nil
	}

	candidates := []string{
		filepath.Clean(trimmed),
		filepath.Join("server", trimmed),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return filepath.Clean(candidate), nil
		}
	}
	return filepath.Clean(candidates[0]), nil
}

// resolveFileVersionToken 用于解析FileVersionToken。
func resolveFileVersionToken(path string) string {
	resolved, err := resolveConfigPath(path)
	if err != nil {
		return "path-error"
	}
	version, err := resolveFileVersionTokenByResolvedPath(resolved)
	if err != nil {
		return "missing"
	}
	return version
}

// resolveFileVersionTokenByResolvedPath 用于解析FileVersionTokenByResolvedPath。
func resolveFileVersionTokenByResolvedPath(resolved string) (string, error) {
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%d", info.Size(), info.ModTime().Unix()), nil
}

// resolveSourceTTL 用于解析来源TTL。
func resolveSourceTTL(seconds int, fallback time.Duration) time.Duration {
	if seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

// joinOrFallback 用于拼接OrFallback。
func joinOrFallback(values []string, fallback string) string {
	unique := dedupeStrings(values)
	if len(unique) == 0 {
		return fallback
	}
	return strings.Join(unique, "+")
}

// dedupeStrings 用于执行dedupeStrings流程。
func dedupeStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

// fallbackString 用于执行fallbackString流程。
func fallbackString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

// pickLocalizedName 用于选取Localized名称。
func pickLocalizedName(names map[string]string, fallback string) string {
	for _, key := range []string{"zh-CN", "en"} {
		if names != nil {
			if value := strings.TrimSpace(names[key]); value != "" {
				return value
			}
		}
	}
	if names != nil {
		for _, value := range names {
			if strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		}
	}
	return fallback
}

// isGeoRiskCountry 用于判断输入是否满足指定条件。
func isGeoRiskCountry(country string) bool {
	switch strings.ToUpper(strings.TrimSpace(country)) {
	case "RU", "KP":
		return true
	default:
		return false
	}
}

// buildScoreFactors 用于构建评分Factors。
func buildScoreFactors(collected TaskCollectedData, cfg config.SecurityConfig, baseInfoRisk float64, attackRisk float64, behaviorRisk float64) []securityScoreFactor {
	reputationChain := strings.Join(extractSourceChain(collected.Reputation.RawPayload, collected.Reputation.SourceName), " -> ")
	attackChain := strings.Join(extractSourceChain(collected.AttackSurface.RawPayload, collected.AttackSurface.SourceName), " -> ")
	return []securityScoreFactor{
		{
			Key:          "whois",
			Label:        "基础属性风险",
			RawScore:     round2(baseInfoRisk),
			Weight:       cfg.Weights.WhoisWeight,
			Contribution: round2(baseInfoRisk * cfg.Weights.WhoisWeight),
			Basis:        fmt.Sprintf("country=%s, isp=%s, org=%s", collected.BaseInfo.Country, collected.BaseInfo.ISP, collected.BaseInfo.WhoisOrg),
		},
		{
			Key:          "reputation",
			Label:        "信誉风险",
			RawScore:     round2(collected.Reputation.ReputationScore),
			Weight:       cfg.Weights.ReputationWeight,
			Contribution: round2(collected.Reputation.ReputationScore * cfg.Weights.ReputationWeight),
			Basis:        "sourceChain=" + fallbackString(reputationChain, collected.Reputation.SourceName),
		},
		{
			Key:          "attack_surface",
			Label:        "攻击面风险",
			RawScore:     round2(attackRisk),
			Weight:       cfg.Weights.AttackSurfaceWeight,
			Contribution: round2(attackRisk * cfg.Weights.AttackSurfaceWeight),
			Basis:        fmt.Sprintf("sourceChain=%s; openPorts=%d, highRiskPorts=%d", fallbackString(attackChain, collected.AttackSurface.SourceName), collected.AttackSurface.OpenPortCount, collected.AttackSurface.HighRiskPortCount),
		},
		{
			Key:          "behavior",
			Label:        "行为风险",
			RawScore:     round2(behaviorRisk),
			Weight:       cfg.Weights.BehaviorWeight,
			Contribution: round2(behaviorRisk * cfg.Weights.BehaviorWeight),
			Basis:        "基础主链路未启用流量行为采集，固定按 0 分处理",
		},
	}
}

// buildCollectedEvidenceItems 用于构建任务详情中的多源证据条目。
func buildCollectedEvidenceItems(collected TaskCollectedData) []securityEvidenceItem {
	items := make([]securityEvidenceItem, 0, 6)
	items = append(items, extractEvidenceItems(collected.BaseInfo.RawPayload)...)
	items = append(items, extractEvidenceItems(collected.Reputation.RawPayload)...)
	items = append(items, extractEvidenceItems(collected.AttackSurface.RawPayload)...)
	return items
}

// extractEvidenceItems 用于提取请求、令牌或流量中的关键信息。
func extractEvidenceItems(payload map[string]any) []securityEvidenceItem {
	if len(payload) == 0 {
		return nil
	}
	raw, ok := payload["evidenceItems"]
	if !ok {
		return nil
	}
	bytes, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var items []securityEvidenceItem
	if err := json.Unmarshal(bytes, &items); err != nil {
		return nil
	}
	return items
}
