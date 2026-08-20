package security

import (
	"context"
	"fmt"
	"log"
	"math"
	"sort"
	"strings"
	"time"

	"lightweight-ip-traffic-sa/server/config"
	"lightweight-ip-traffic-sa/server/global"
	securityModel "lightweight-ip-traffic-sa/server/model/security"
	requestModel "lightweight-ip-traffic-sa/server/model/security/request"
	responseModel "lightweight-ip-traffic-sa/server/model/security/response"
	"lightweight-ip-traffic-sa/server/repository"
	"lightweight-ip-traffic-sa/server/utils"
)

// ConfigService 用于编排安全态势模块的业务流程。
type ConfigService struct{}

var (
	allowedWhoisEndpoints = map[string]struct{}{
		"geolite2+rdap": {},
		"geolite2":      {},
		"rdap":          {},
		"disabled":      {},
		"local-demo":    {},
	}
	allowedReputationEndpoints = map[string]struct{}{
		"local-blacklist":           {},
		"local-blacklist+abuseipdb": {},
		"abuseipdb":                 {},
		"disabled":                  {},
		"local-demo":                {},
	}
	allowedAttackSurfaceEndpoints = map[string]struct{}{
		"limited-port-scan":               {},
		"nmap-enhanced":                   {},
		"limited-port-scan+nmap-enhanced": {},
		"disabled":                        {},
	}
	allowedFlowModes = map[string]struct{}{
		"sample":         {},
		"offline_pcap":   {},
		"online_capture": {},
	}
)

// GetSecurityConfig 用于查询配置详情并组装响应。
// 三级读取策略：先读缓存 → 未命中再读数据库 → 都无则返回默认配置；读到结果后回填缓存
func (s *ConfigService) GetSecurityConfig() (responseModel.ConfigResponse, error) {
	var cached responseModel.ConfigResponse
	if hit, err := utils.CacheGetJSON(utils.SecurityConfigCacheKey, &cached); err == nil && hit {
		return cached, nil
	} else if err != nil {
		// 缓存异常不阻断主流程，降级回源数据库即可
		log.Printf("安全配置缓存读取失败，继续读取数据库，key=%s err=%v", utils.SecurityConfigCacheKey, err)
	}

	config, err := repository.RepositoryGroupApp.SecurityRepositoryGroup.ConfigRepository.Get(global.DB)
	if err != nil {
		return responseModel.ConfigResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "获取安全配置失败，请稍后重试", err)
	}

	if config == nil {
		// 数据库还没有配置记录时，按启动配置生成默认值返回，并尝试写入缓存
		resp := buildDefaultSecurityConfigResponse()
		if err := utils.CacheSetJSON(utils.SecurityConfigCacheKey, resp, utils.SecurityConfigCacheTTL()); err != nil {
			log.Printf("默认安全配置缓存写入失败，已返回默认配置，key=%s err=%v", utils.SecurityConfigCacheKey, err)
		}
		return resp, nil
	}

	resp := mapSecurityConfigToResponse(*config)
	if err := utils.CacheSetJSON(utils.SecurityConfigCacheKey, resp, utils.SecurityConfigCacheTTL()); err != nil {
		log.Printf("安全配置缓存写入失败，已返回实时配置，key=%s err=%v", utils.SecurityConfigCacheKey, err)
	}
	return resp, nil
}

// UpdateSecurityConfig 用于编排配置服务流程。
func (s *ConfigService) UpdateSecurityConfig(req requestModel.UpdateConfigRequest) (responseModel.ConfigResponse, error) {
	if err := validateConfigRequest(req); err != nil {
		return responseModel.ConfigResponse{}, err
	}
	repo := repository.RepositoryGroupApp.SecurityRepositoryGroup.ConfigRepository
	config, err := repo.Get(global.DB)
	if err != nil {
		return responseModel.ConfigResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "更新安全配置失败，请稍后重试", err)
	}

	if config == nil {
		config = &securityModel.SecurityConfig{}
	}

	config.WhoisEndpoint = req.WhoisEndpoint
	config.ReputationEndpoint = req.ReputationEndpoint
	config.AttackSurfaceEndpoint = req.AttackSurfaceEndpoint
	config.FlowEnabled = req.FlowEnabled
	config.FlowMode = normalizeResponseFlowMode(req.FlowMode)
	config.FlowInterfaceName = strings.TrimSpace(req.FlowInterfaceName)
	config.FlowPcapFilePath = strings.TrimSpace(req.FlowPcapFilePath)
	config.FlowSampleProfile = normalizeResponseFlowSampleProfile(req.FlowSampleProfile)
	config.FlowWindowSeconds = normalizeResponseFlowWindowSeconds(req.FlowWindowSeconds)
	config.FlowTimeoutSeconds = normalizeResponseFlowTimeoutSeconds(req.FlowTimeoutSeconds)
	config.NotifyChannel = req.NotifyChannel
	config.MailEnabled = req.MailEnabled
	config.MailSender = strings.TrimSpace(req.MailSender)
	config.MailRecipient = strings.TrimSpace(req.MailRecipient)
	config.SMTPHost = strings.TrimSpace(req.SMTPHost)
	config.SMTPPort = normalizeSMTPPort(req.SMTPPort)
	config.SMTPUsername = strings.TrimSpace(req.SMTPUsername)
	if strings.TrimSpace(req.SMTPPassword) != "" {
		config.SMTPPassword = strings.TrimSpace(req.SMTPPassword)
	}
	config.SMTPUseTLS = req.SMTPUseTLS
	config.HighRiskThreshold = req.HighRiskThreshold
	config.CriticalRiskThreshold = req.CriticalRiskThreshold
	config.WhoisWeight = req.Weights.WhoisWeight
	config.ReputationWeight = req.Weights.ReputationWeight
	config.AttackSurfaceWeight = req.Weights.AttackSurfaceWeight
	config.BehaviorWeight = req.Weights.BehaviorWeight

	if err := repo.Save(global.DB, config); err != nil {
		return responseModel.ConfigResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "更新安全配置失败，请稍后重试", err)
	}

	// 关键点：保存到数据库后立即同步内存里的运行时配置（global.AppConfig），
	// 使“运行时配置”覆盖“启动配置”，后续评分/采集链路无需重启即生效
	global.AppConfig.Security.Source.WhoisEndpoint = config.WhoisEndpoint
	global.AppConfig.Security.Source.ReputationEndpoint = config.ReputationEndpoint
	global.AppConfig.Security.Source.AttackSurfaceEndpoint = config.AttackSurfaceEndpoint
	global.AppConfig.Security.Source.Flow.Enabled = config.FlowEnabled
	global.AppConfig.Security.Source.Flow.Mode = config.FlowMode
	global.AppConfig.Security.Source.Flow.InterfaceName = config.FlowInterfaceName
	global.AppConfig.Security.Source.Flow.PcapFilePath = config.FlowPcapFilePath
	global.AppConfig.Security.Source.Flow.SampleProfile = config.FlowSampleProfile
	global.AppConfig.Security.Source.Flow.WindowSeconds = config.FlowWindowSeconds
	global.AppConfig.Security.Source.Flow.TimeoutSeconds = config.FlowTimeoutSeconds
	global.AppConfig.Security.Alert.NotifyChannel = config.NotifyChannel
	global.AppConfig.Security.Alert.Mail.Enabled = config.MailEnabled
	global.AppConfig.Security.Alert.Mail.Sender = config.MailSender
	global.AppConfig.Security.Alert.Mail.Recipient = config.MailRecipient
	global.AppConfig.Security.Alert.Mail.SMTPHost = config.SMTPHost
	global.AppConfig.Security.Alert.Mail.SMTPPort = config.SMTPPort
	global.AppConfig.Security.Alert.Mail.Username = config.SMTPUsername
	global.AppConfig.Security.Alert.Mail.Password = config.SMTPPassword
	global.AppConfig.Security.Alert.Mail.UseTLS = config.SMTPUseTLS
	global.AppConfig.Security.HighRiskThreshold = config.HighRiskThreshold
	global.AppConfig.Security.CriticalRiskThreshold = config.CriticalRiskThreshold
	global.AppConfig.Security.Weights.WhoisWeight = config.WhoisWeight
	global.AppConfig.Security.Weights.ReputationWeight = config.ReputationWeight
	global.AppConfig.Security.Weights.AttackSurfaceWeight = config.AttackSurfaceWeight
	global.AppConfig.Security.Weights.BehaviorWeight = config.BehaviorWeight
	applyPersistedFeatureSourceSelectionV2(&global.AppConfig.Security)

	resp := mapSecurityConfigToResponse(*config)
	// 先删除旧缓存再写新缓存，保证配置变更后缓存与数据库一致；同时清掉总览缓存
	_ = utils.CacheDelete(utils.SecurityConfigCacheKey, utils.SecurityDashboardSummaryCacheKey)
	if err := utils.CacheSetJSON(utils.SecurityConfigCacheKey, resp, utils.SecurityConfigCacheTTL()); err != nil {
		log.Printf("更新后的安全配置缓存写入失败，后续请求将回源数据库，key=%s err=%v", utils.SecurityConfigCacheKey, err)
	}
	recordSecurityAuditLog(AuditLogEntry{
		Category:    "CONFIG",
		Action:      "UPDATE_SECURITY_CONFIG",
		TargetType:  "security-config",
		TargetID:    "default",
		TargetLabel: config.NotifyChannel,
		Status:      "SUCCESS",
		Summary:     "安全配置已更新",
	})

	return resp, nil
}

// UpdateFlowToggle 用于编排配置服务流程。
func (s *ConfigService) UpdateFlowToggle(req requestModel.UpdateFlowToggleRequest) (responseModel.ConfigResponse, error) {
	if req.Enabled == nil {
		return responseModel.ConfigResponse{}, NewServiceError(ServiceErrorCategoryInvalidArgument, "流量开关参数不能为空")
	}

	repo := repository.RepositoryGroupApp.SecurityRepositoryGroup.ConfigRepository
	config, err := repo.Get(global.DB)
	if err != nil {
		return responseModel.ConfigResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "更新流量开关失败，请稍后重试", err)
	}
	if config == nil {
		config = &securityModel.SecurityConfig{
			WhoisEndpoint:         resolvePersistedWhoisEndpoint(global.AppConfig.Security),
			ReputationEndpoint:    resolvePersistedReputationEndpoint(global.AppConfig.Security),
			AttackSurfaceEndpoint: resolvePersistedAttackSurfaceEndpoint(global.AppConfig.Security),
			NotifyChannel:         global.AppConfig.Security.Alert.NotifyChannel,
			HighRiskThreshold:     global.AppConfig.Security.HighRiskThreshold,
			CriticalRiskThreshold: global.AppConfig.Security.CriticalRiskThreshold,
			WhoisWeight:           global.AppConfig.Security.Weights.WhoisWeight,
			ReputationWeight:      global.AppConfig.Security.Weights.ReputationWeight,
			AttackSurfaceWeight:   global.AppConfig.Security.Weights.AttackSurfaceWeight,
			BehaviorWeight:        global.AppConfig.Security.Weights.BehaviorWeight,
		}
	}

	config.FlowEnabled = *req.Enabled
	if err := repo.Save(global.DB, config); err != nil {
		return responseModel.ConfigResponse{}, WrapServiceError(ServiceErrorCategoryInternal, "更新流量开关失败，请稍后重试", err)
	}

	// 与全量更新一致：落库后同步内存运行时配置，让流量开关即时生效
	global.AppConfig.Security.Source.Flow.Enabled = config.FlowEnabled
	global.AppConfig.Security.Source.Flow.Mode = config.FlowMode
	global.AppConfig.Security.Source.Flow.InterfaceName = config.FlowInterfaceName
	global.AppConfig.Security.Source.Flow.PcapFilePath = config.FlowPcapFilePath
	global.AppConfig.Security.Source.Flow.SampleProfile = config.FlowSampleProfile
	global.AppConfig.Security.Source.Flow.WindowSeconds = config.FlowWindowSeconds
	global.AppConfig.Security.Source.Flow.TimeoutSeconds = config.FlowTimeoutSeconds
	global.AppConfig.Security.Source.WhoisEndpoint = config.WhoisEndpoint
	global.AppConfig.Security.Source.ReputationEndpoint = config.ReputationEndpoint
	global.AppConfig.Security.Source.AttackSurfaceEndpoint = config.AttackSurfaceEndpoint
	applyPersistedFeatureSourceSelectionV2(&global.AppConfig.Security)

	resp := mapSecurityConfigToResponse(*config)
	_ = utils.CacheDelete(utils.SecurityConfigCacheKey, utils.SecurityDashboardSummaryCacheKey)
	if err := utils.CacheSetJSON(utils.SecurityConfigCacheKey, resp, utils.SecurityConfigCacheTTL()); err != nil {
		log.Printf("流量开关更新后的安全配置缓存写入失败，key=%s err=%v", utils.SecurityConfigCacheKey, err)
	}
	recordSecurityAuditLog(AuditLogEntry{
		Category:    "CONFIG",
		Action:      "UPDATE_FLOW_TOGGLE",
		TargetType:  "security-config",
		TargetID:    "default",
		TargetLabel: config.FlowMode,
		Status:      "SUCCESS",
		Summary:     fmt.Sprintf("流量增强开关已切换为 %t", config.FlowEnabled),
	})
	return resp, nil
}

// ListFlowInterfaces 用于查询配置列表并组装响应。
// 枚举本机可抓包网卡，供实时监控/在线抓包页选择；带 5 秒超时防止底层枚举卡死
func (s *ConfigService) ListFlowInterfaces() ([]responseModel.FlowInterfaceOption, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	interfaces, err := enumerateLiveCaptureInterfaces(ctx)
	if err != nil {
		return nil, WrapServiceError(ServiceErrorCategoryInternal, "获取在线抓包网卡列表失败，请稍后重试", err)
	}
	// 按网卡索引排序（索引为 0 的排最后），让用户看到稳定有序的列表
	sort.Slice(interfaces, func(i, j int) bool {
		if interfaces[i].IfIndex == interfaces[j].IfIndex {
			return interfaces[i].Name < interfaces[j].Name
		}
		if interfaces[i].IfIndex == 0 {
			return false
		}
		if interfaces[j].IfIndex == 0 {
			return true
		}
		return interfaces[i].IfIndex < interfaces[j].IfIndex
	})
	return interfaces, nil
}

// buildDefaultSecurityConfigResponse 用于构建Default安全配置响应。
func buildDefaultSecurityConfigResponse() responseModel.ConfigResponse {
	return responseModel.ConfigResponse{
		DemoMode:              global.AppConfig.Security.DemoMode,
		WhoisEndpoint:         resolvePersistedWhoisEndpoint(global.AppConfig.Security),
		ReputationEndpoint:    resolvePersistedReputationEndpoint(global.AppConfig.Security),
		AttackSurfaceEndpoint: resolvePersistedAttackSurfaceEndpoint(global.AppConfig.Security),
		FlowEnabled:           global.AppConfig.Security.Source.Flow.Enabled,
		FlowMode:              global.AppConfig.Security.Source.Flow.Mode,
		FlowInterfaceName:     global.AppConfig.Security.Source.Flow.InterfaceName,
		FlowPcapFilePath:      global.AppConfig.Security.Source.Flow.PcapFilePath,
		FlowSampleProfile:     global.AppConfig.Security.Source.Flow.SampleProfile,
		FlowWindowSeconds:     global.AppConfig.Security.Source.Flow.WindowSeconds,
		FlowTimeoutSeconds:    global.AppConfig.Security.Source.Flow.TimeoutSeconds,
		NotifyChannel:         global.AppConfig.Security.Alert.NotifyChannel,
		MailEnabled:           global.AppConfig.Security.Alert.Mail.Enabled,
		MailSender:            global.AppConfig.Security.Alert.Mail.Sender,
		MailRecipient:         global.AppConfig.Security.Alert.Mail.Recipient,
		SMTPHost:              global.AppConfig.Security.Alert.Mail.SMTPHost,
		SMTPPort:              global.AppConfig.Security.Alert.Mail.SMTPPort,
		SMTPUsername:          global.AppConfig.Security.Alert.Mail.Username,
		SMTPUseTLS:            global.AppConfig.Security.Alert.Mail.UseTLS,
		HighRiskThreshold:     global.AppConfig.Security.HighRiskThreshold,
		CriticalRiskThreshold: global.AppConfig.Security.CriticalRiskThreshold,
		Weights: responseModel.ConfigWeightResponse{
			WhoisWeight:         global.AppConfig.Security.Weights.WhoisWeight,
			ReputationWeight:    global.AppConfig.Security.Weights.ReputationWeight,
			AttackSurfaceWeight: global.AppConfig.Security.Weights.AttackSurfaceWeight,
			BehaviorWeight:      global.AppConfig.Security.Weights.BehaviorWeight,
		},
	}
}

// mapSecurityConfigToResponse 用于映射安全配置To响应。
func mapSecurityConfigToResponse(config securityModel.SecurityConfig) responseModel.ConfigResponse {
	return responseModel.ConfigResponse{
		DemoMode:              global.AppConfig.Security.DemoMode,
		WhoisEndpoint:         normalizeResponseWhoisEndpoint(config.WhoisEndpoint),
		ReputationEndpoint:    normalizeResponseReputationEndpoint(config.ReputationEndpoint),
		AttackSurfaceEndpoint: normalizeResponseAttackSurfaceEndpoint(config.AttackSurfaceEndpoint),
		FlowEnabled:           config.FlowEnabled,
		FlowMode:              normalizeResponseFlowMode(config.FlowMode),
		FlowInterfaceName:     strings.TrimSpace(config.FlowInterfaceName),
		FlowPcapFilePath:      strings.TrimSpace(config.FlowPcapFilePath),
		FlowSampleProfile:     normalizeResponseFlowSampleProfile(config.FlowSampleProfile),
		FlowWindowSeconds:     normalizeResponseFlowWindowSeconds(config.FlowWindowSeconds),
		FlowTimeoutSeconds:    normalizeResponseFlowTimeoutSeconds(config.FlowTimeoutSeconds),
		NotifyChannel:         config.NotifyChannel,
		MailEnabled:           config.MailEnabled,
		MailSender:            strings.TrimSpace(config.MailSender),
		MailRecipient:         strings.TrimSpace(config.MailRecipient),
		SMTPHost:              strings.TrimSpace(config.SMTPHost),
		SMTPPort:              normalizeSMTPPort(config.SMTPPort),
		SMTPUsername:          strings.TrimSpace(config.SMTPUsername),
		SMTPUseTLS:            config.SMTPUseTLS,
		HighRiskThreshold:     config.HighRiskThreshold,
		CriticalRiskThreshold: config.CriticalRiskThreshold,
		Weights: responseModel.ConfigWeightResponse{
			WhoisWeight:         config.WhoisWeight,
			ReputationWeight:    config.ReputationWeight,
			AttackSurfaceWeight: config.AttackSurfaceWeight,
			BehaviorWeight:      config.BehaviorWeight,
		},
	}
}

// normalizeResponseWhoisEndpoint 用于归一化输入参数或业务指标。
func normalizeResponseWhoisEndpoint(value string) string {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if global.AppConfig.Security.DemoMode {
		if trimmed == "" {
			return "local-demo"
		}
		return trimmed
	}
	switch trimmed {
	case "", "local-demo":
		return resolvePersistedWhoisEndpoint(global.AppConfig.Security)
	case "geolite2", "rdap", "geolite2+rdap", "disabled":
		return trimmed
	default:
		if strings.Contains(trimmed, "geolite2") && strings.Contains(trimmed, "rdap") {
			return "geolite2+rdap"
		}
		if strings.Contains(trimmed, "geolite2") {
			return "geolite2"
		}
		if strings.Contains(trimmed, "rdap") {
			return "rdap"
		}
		return resolvePersistedWhoisEndpoint(global.AppConfig.Security)
	}
}

// normalizeResponseReputationEndpoint 用于归一化输入参数或业务指标。
func normalizeResponseReputationEndpoint(value string) string {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if global.AppConfig.Security.DemoMode {
		if trimmed == "" {
			return "local-demo"
		}
		return trimmed
	}
	switch trimmed {
	case "", "local-demo":
		return resolvePersistedReputationEndpoint(global.AppConfig.Security)
	case "local-blacklist", "local-blacklist+abuseipdb", "abuseipdb":
		return trimmed
	default:
		if strings.Contains(trimmed, "local-blacklist") && strings.Contains(trimmed, "abuseipdb") {
			return "local-blacklist+abuseipdb"
		}
		if strings.Contains(trimmed, "abuseipdb") {
			return "abuseipdb"
		}
		if strings.Contains(trimmed, "local-blacklist") {
			return "local-blacklist"
		}
		return resolvePersistedReputationEndpoint(global.AppConfig.Security)
	}
}

// normalizeResponseAttackSurfaceEndpoint 用于归一化输入参数或业务指标。
func normalizeResponseAttackSurfaceEndpoint(value string) string {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	switch trimmed {
	case "":
		return resolvePersistedAttackSurfaceEndpoint(global.AppConfig.Security)
	case "disabled", "limited-port-scan", "nmap-enhanced", "limited-port-scan+nmap-enhanced":
		return trimmed
	default:
		if strings.Contains(trimmed, "limited-port-scan") && strings.Contains(trimmed, "nmap") {
			return "limited-port-scan+nmap-enhanced"
		}
		if strings.Contains(trimmed, "nmap") {
			return "nmap-enhanced"
		}
		if strings.Contains(trimmed, "limited-port-scan") {
			return "limited-port-scan"
		}
		return resolvePersistedAttackSurfaceEndpoint(global.AppConfig.Security)
	}
}

// validateConfigRequest 用于校验输入参数和业务约束。
func validateConfigRequest(req requestModel.UpdateConfigRequest) error {
	whoisEndpoint := strings.TrimSpace(req.WhoisEndpoint)
	if _, ok := allowedWhoisEndpoints[whoisEndpoint]; !ok {
		return NewServiceError(ServiceErrorCategoryInvalidArgument, "基础画像来源配置不支持")
	}

	reputationEndpoint := strings.TrimSpace(req.ReputationEndpoint)
	if _, ok := allowedReputationEndpoints[reputationEndpoint]; !ok {
		return NewServiceError(ServiceErrorCategoryInvalidArgument, "信誉来源配置不支持")
	}

	attackSurfaceEndpoint := strings.TrimSpace(req.AttackSurfaceEndpoint)
	if _, ok := allowedAttackSurfaceEndpoints[attackSurfaceEndpoint]; !ok {
		return NewServiceError(ServiceErrorCategoryInvalidArgument, "attack surface source config is unsupported")
	}

	flowMode := normalizeResponseFlowMode(req.FlowMode)
	if _, ok := allowedFlowModes[flowMode]; !ok {
		return NewServiceError(ServiceErrorCategoryInvalidArgument, "流量模式配置不支持")
	}
	if normalizeResponseFlowWindowSeconds(req.FlowWindowSeconds) <= 0 {
		return NewServiceError(ServiceErrorCategoryInvalidArgument, "流量窗口秒数必须大于 0")
	}
	if normalizeResponseFlowTimeoutSeconds(req.FlowTimeoutSeconds) <= 0 {
		return NewServiceError(ServiceErrorCategoryInvalidArgument, "流量超时秒数必须大于 0")
	}
	if req.MailEnabled {
		if strings.TrimSpace(req.SMTPHost) == "" {
			return NewServiceError(ServiceErrorCategoryInvalidArgument, "已开启邮件预警时必须提供 SMTP 主机")
		}
		if strings.TrimSpace(req.MailRecipient) == "" {
			return NewServiceError(ServiceErrorCategoryInvalidArgument, "已开启邮件预警时必须提供收件人")
		}
	}

	if err := validateWeightSum(req.Weights); err != nil {
		return err
	}
	return nil
}

// validateWeightSum 用于校验输入参数和业务约束。
// 四维权重之和必须严格等于 1.0000；用基点（×10000 取整）比较，规避浮点累加误差导致的误判
func validateWeightSum(weights requestModel.ConfigWeightRequest) error {
	total := weightToBasisPoint(weights.WhoisWeight) +
		weightToBasisPoint(weights.ReputationWeight) +
		weightToBasisPoint(weights.AttackSurfaceWeight) +
		weightToBasisPoint(weights.BehaviorWeight)
	if total != 10000 {
		return NewServiceError(ServiceErrorCategoryInvalidArgument, "评分权重总和必须严格等于 1.0000")
	}
	return nil
}

// weightToBasisPoint 用于执行weightToBasisPoint流程。
// 把权重（0~1）转成万分位整数（基点），避免直接比较 float 时因精度导致 0.2+0.35+0.3+0.15 != 1.0
func weightToBasisPoint(value float64) int {
	return int(math.Round(value * 10000))
}

// resolvePersistedWhoisEndpoint 用于解析PersistedWHOISEndpoint。
func resolvePersistedWhoisEndpoint(cfg config.SecurityConfig) string {
	if cfg.DemoMode {
		return "local-demo"
	}
	if cfg.Source.GeoLite2.Enabled && cfg.Source.RDAP.Enabled {
		return "geolite2+rdap"
	}
	if cfg.Source.GeoLite2.Enabled {
		return "geolite2"
	}
	if cfg.Source.RDAP.Enabled {
		return "rdap"
	}
	return "rdap"
}

// resolvePersistedReputationEndpoint 用于解析PersistedReputationEndpoint。
func resolvePersistedReputationEndpoint(cfg config.SecurityConfig) string {
	if cfg.DemoMode {
		return "local-demo"
	}
	if !cfg.Source.LocalBlacklist.Enabled && !cfg.Source.AbuseIPDB.Enabled {
		return "disabled"
	}
	if cfg.Source.LocalBlacklist.Enabled && cfg.Source.AbuseIPDB.Enabled {
		return "local-blacklist+abuseipdb"
	}
	if cfg.Source.AbuseIPDB.Enabled {
		return "abuseipdb"
	}
	return "local-blacklist"
}

// resolvePersistedAttackSurfaceEndpoint 用于解析PersistedAttackSurfaceEndpoint。
func resolvePersistedAttackSurfaceEndpoint(cfg config.SecurityConfig) string {
	if !cfg.Source.AttackSurface.Enabled {
		return "disabled"
	}
	if cfg.Source.AttackSurface.NmapEnabled {
		return "limited-port-scan+nmap-enhanced"
	}
	return "limited-port-scan"
}

// normalizeResponseFlowMode 用于归一化输入参数或业务指标。
func normalizeResponseFlowMode(value string) string {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	switch trimmed {
	case "offline_pcap", "online_capture":
		return trimmed
	default:
		return "sample"
	}
}

// normalizeResponseFlowSampleProfile 用于归一化输入参数或业务指标。
func normalizeResponseFlowSampleProfile(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "baseline-web"
	}
	return trimmed
}

// normalizeResponseFlowWindowSeconds 用于归一化输入参数或业务指标。
func normalizeResponseFlowWindowSeconds(value int) int {
	if value <= 0 {
		return 60
	}
	return value
}

// normalizeResponseFlowTimeoutSeconds 用于归一化输入参数或业务指标。
func normalizeResponseFlowTimeoutSeconds(value int) int {
	if value <= 0 {
		return 5
	}
	return value
}

// normalizeSMTPPort 用于归一化输入参数或业务指标。
func normalizeSMTPPort(value int) int {
	if value <= 0 {
		return 25
	}
	return value
}
