package config

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ServerConfig 用于承载Server运行配置。
// 根节点，直接对应 config.yaml 的顶层结构，四个子块分别管：端口/密钥、数据库、缓存、安全业务。
type ServerConfig struct {
	App      AppConfig      `yaml:"app"`
	Database DatabaseConfig `yaml:"database"`
	Redis    RedisConfig    `yaml:"redis"`
	Security SecurityConfig `yaml:"security"`
}

// AppConfig 用于承载App运行配置。
type AppConfig struct {
	// HTTP 监听端口，默认 8080
	Port      string `yaml:"port"`
	// JWT 签名密钥，必须保密
	JWTSecret string `yaml:"jwtSecret"`
}

// DatabaseConfig 用于承载Database运行配置。
type DatabaseConfig struct {
	// MySQL 连接串（含用户/密码/库名/字符集等）
	DSN          string `yaml:"dsn"`
	// 连接池最大空闲连接数
	MaxIdleConns int    `yaml:"maxIdleConns"`
	// 连接池最大打开连接数
	MaxOpenConns int    `yaml:"maxOpenConns"`
}

// RedisConfig 用于承载Redis运行配置。
type RedisConfig struct {
	// 是否启用 Redis；关闭则进入无缓存降级模式
	Enabled  bool   `yaml:"enabled"`
	// Redis 地址 host:port
	Addr     string `yaml:"addr"`
	// Redis 密码
	Password string `yaml:"password"`
	// 逻辑库编号
	DB       int    `yaml:"db"`
	// 连接池大小上限
	PoolSize int    `yaml:"poolSize"`
}

// SecurityConfig 用于承载安全运行配置。
type SecurityConfig struct {
	// 演示模式：用本地模拟数据，不依赖外部 API
	DemoMode              bool         `yaml:"demoMode"`
	// 系统自动建记录时归属的操作人
	DefaultCreatedBy      string       `yaml:"defaultCreatedBy"`
	// 高危评分阈值
	HighRiskThreshold     float64      `yaml:"highRiskThreshold"`
	// 严重风险评分阈值
	CriticalRiskThreshold float64      `yaml:"criticalRiskThreshold"`
	// 各数据源开关与参数
	Source                SourceConfig `yaml:"source"`
	// 预警通知配置
	Alert                 AlertConfig  `yaml:"alert"`
	// 各类缓存 TTL
	Cache                 CacheConfig  `yaml:"cache"`
	// 四个数据源的评分权重
	Weights               WeightConfig `yaml:"weights"`
}

// SourceConfig 用于承载来源运行配置。
// 汇聚五类数据源（IP 归属/RDAP、黑名单/AbuseIPDB、攻击面扫描、流量采集），
// 三个 endpoint 字段是种子数据推导"当前生效数据源组合"的依据。
type SourceConfig struct {
	WhoisEndpoint         string                    `yaml:"whoisEndpoint"`
	ReputationEndpoint    string                    `yaml:"reputationEndpoint"`
	AttackSurfaceEndpoint string                    `yaml:"attackSurfaceEndpoint"`
	// 本地 GeoLite2 离线库
	GeoLite2              GeoLite2SourceConfig      `yaml:"geoLite2"`
	// RDAP 协议查询
	RDAP                  RDAPSourceConfig          `yaml:"rdap"`
	// 本地黑名单文件
	LocalBlacklist        LocalBlacklistConfig      `yaml:"localBlacklist"`
	// AbuseIPDB 在线查询
	AbuseIPDB             AbuseIPDBSourceConfig     `yaml:"abuseIPDB"`
	// 端口/攻击面扫描
	AttackSurface         AttackSurfaceSourceConfig `yaml:"attackSurface"`
	// 实时流量采集
	Flow                  FlowSourceConfig          `yaml:"flow"`
}

// GeoLite2SourceConfig 用于承载地理Lite2来源运行配置。
// 基于 MaxMind 的离线 mmdb 库解析 IP 归属地/城市/ASN，无需联网、查询快，但需要定期更新库文件。
type GeoLite2SourceConfig struct {
	Enabled         bool   `yaml:"enabled"`
	// 国家库路径
	CountryDBPath   string `yaml:"countryDBPath"`
	// 城市库路径
	CityDBPath      string `yaml:"cityDBPath"`
	// ASN 库路径
	ASNDBPath       string `yaml:"asnDBPath"`
	// 查询结果缓存秒数
	CacheTTLSeconds int    `yaml:"cacheTTLSeconds"`
}

// RDAPSourceConfig 用于承载RDAP来源运行配置。
// RDAP 是 WHOIS 的现代替代协议，走 HTTPS 查 IP 注册信息；BackupBaseURLs 用于主节点不可用时故障转移。
type RDAPSourceConfig struct {
	Enabled         bool     `yaml:"enabled"`
	// 主查询节点
	BaseURL         string   `yaml:"baseURL"`
	// 备用节点列表
	BackupBaseURLs  []string `yaml:"backupBaseURLs"`
	// 单次请求超时
	TimeoutSeconds  int      `yaml:"timeoutSeconds"`
	// 结果缓存秒数
	CacheTTLSeconds int      `yaml:"cacheTTLSeconds"`
}

var DefaultRDAPBackupBaseURLs = []string{
	"https://rdap.arin.net/registry/ip/",
	"https://rdap.db.ripe.net/ip/",
	"https://rdap.apnic.net/ip/",
	"https://rdap.afrinic.net/rdap/ip/",
	"https://rdap.lacnic.net/rdap/ip/",
}

// LocalBlacklistConfig 用于承载LocalBlacklist运行配置。
// 从本地文件加载恶意 IP 名单，定时热重载；命中给 MatchScore，未命中给 DefaultScore 作为声誉子分。
type LocalBlacklistConfig struct {
	Enabled               bool    `yaml:"enabled"`
	// 黑名单文件路径
	FilePath              string  `yaml:"filePath"`
	// 热重载间隔秒数
	ReloadIntervalSeconds int     `yaml:"reloadIntervalSeconds"`
	// 命中时的声誉得分
	MatchScore            float64 `yaml:"matchScore"`
	// 未命中时的兜底得分
	DefaultScore          float64 `yaml:"defaultScore"`
}

// AbuseIPDBSourceConfig 用于承载AbuseIPDB来源运行配置。
// 调用 AbuseIPDB 在线 API 查 IP 的历史滥用记录；APIKey 属敏感凭证，不要提交到版本库。
type AbuseIPDBSourceConfig struct {
	Enabled         bool   `yaml:"enabled"`
	// API 地址
	BaseURL         string `yaml:"baseURL"`
	// 调用凭证（敏感）
	APIKey          string `yaml:"apiKey"`
	// 请求超时
	TimeoutSeconds  int    `yaml:"timeoutSeconds"`
	// 结果缓存秒数
	CacheTTLSeconds int    `yaml:"cacheTTLSeconds"`
	// 回溯最近 N 天滥用记录
	MaxAgeInDays    int    `yaml:"maxAgeInDays"`
}

// AttackSurfaceSourceConfig 用于承载AttackSurface来源运行配置。
// 对目标 IP 做端口存活探测（可选叠加 nmap 增强），MaxConcurrency 限制并发避免打爆目标与自身资源。
type AttackSurfaceSourceConfig struct {
	Enabled             bool   `yaml:"enabled"`
	// 要探测的端口列表
	Ports               []int  `yaml:"ports"`
	// 单端口探测超时（毫秒）
	TimeoutMilliseconds int    `yaml:"timeoutMilliseconds"`
	// 结果缓存秒数
	CacheTTLSeconds     int    `yaml:"cacheTTLSeconds"`
	// 并发扫描上限
	MaxConcurrency      int    `yaml:"maxConcurrency"`
	// 是否叠加 nmap
	NmapEnabled         bool   `yaml:"nmapEnabled"`
	// nmap 可执行文件路径
	NmapPath            string `yaml:"nmapPath"`
	// nmap 扫描超时
	NmapTimeoutSeconds  int    `yaml:"nmapTimeoutSeconds"`
}

// FlowSourceConfig 用于承载流量来源运行配置。
// 实时流量采集：可从网卡抓包或回放 pcap 文件，按时间窗口聚合流特征。
type FlowSourceConfig struct {
	Enabled         bool   `yaml:"enabled"`
	// 采集模式（sample 等）
	Mode            string `yaml:"mode"`
	// 网卡名（实时抓包时用）
	InterfaceName   string `yaml:"interfaceName"`
	// pcap 文件路径（回放时用）
	PcapFilePath    string `yaml:"pcapFilePath"`
	// 采样画像
	SampleProfile   string `yaml:"sampleProfile"`
	// 聚合窗口秒数
	WindowSeconds   int    `yaml:"windowSeconds"`
	// 采集超时
	TimeoutSeconds  int    `yaml:"timeoutSeconds"`
	// 结果缓存秒数
	CacheTTLSeconds int    `yaml:"cacheTTLSeconds"`
}

// AlertConfig 用于承载预警运行配置。
type AlertConfig struct {
	// 通知渠道（SYSTEM/邮件等）
	NotifyChannel string     `yaml:"notifyChannel"`
	// 邮件告警配置
	Mail          MailConfig `yaml:"mail"`
}

// MailConfig 用于承载Mail运行配置。
type MailConfig struct {
	// 是否启用邮件告警
	Enabled   bool   `yaml:"enabled"`
	// 发件人
	Sender    string `yaml:"sender"`
	// 收件人
	Recipient string `yaml:"recipient"`
	// SMTP 服务器地址
	SMTPHost  string `yaml:"smtpHost"`
	// SMTP 端口
	SMTPPort  int    `yaml:"smtpPort"`
	// SMTP 账号
	Username  string `yaml:"username"`
	// SMTP 密码（敏感）
	Password  string `yaml:"password"`
	// 是否走 TLS
	UseTLS    bool   `yaml:"useTLS"`
}

// CacheConfig 用于承载缓存运行配置。
// 按业务场景拆成四类 TTL：总览摘要最短（实时性要求高）、详情/采集较长（计算代价高）。
type CacheConfig struct {
	// 总览摘要缓存秒数
	DashboardSummaryTTLSeconds int `yaml:"dashboardSummaryTTLSeconds"`
	// 安全配置缓存秒数
	SecurityConfigTTLSeconds   int `yaml:"securityConfigTTLSeconds"`
	// 详情查询缓存秒数
	DetailQueryTTLSeconds      int `yaml:"detailQueryTTLSeconds"`
	// 采集结果缓存秒数
	CollectorTTLSeconds        int `yaml:"collectorTTLSeconds"`
}

// WeightConfig 用于承载Weight运行配置。
// 四个数据源的评分权重，用于把各源子分加权求和成最终风险分；四个值应合计约等于 1。
type WeightConfig struct {
	// IP 归属数据源权重
	WhoisWeight         float64 `yaml:"whoisWeight"`
	// 声誉数据源权重
	ReputationWeight    float64 `yaml:"reputationWeight"`
	// 攻击面数据源权重
	AttackSurfaceWeight float64 `yaml:"attackSurfaceWeight"`
	// 行为数据源权重
	BehaviorWeight      float64 `yaml:"behaviorWeight"`
}

// LoadConfig 用于加载配置、缓存或外部资源。
func LoadConfig() (ServerConfig, error) {
	// 依次尝试两个相对路径：先在进程工作目录找 config.yaml，再退到 server/ 子目录，
	// 这样无论从项目根还是 server/ 目录启动都能读到配置文件。
	paths := []string{
		"config.yaml",
		filepath.Join("server", "config.yaml"),
	}

	var cfg ServerConfig
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			// 某个路径读不到就试下一个，而不是立刻报错。
			continue
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			// 文件读到了但 YAML 语法错误是硬错误，必须停下来暴露问题。
			return ServerConfig{}, err
		}
		cfg.applyDefaults()
		cfg.applyEnvOverrides()
		return cfg, nil
	}

	// 走到这说明 config.yaml 不存在，直接用全默认配置 + 环境变量覆盖来启动。
	cfg.applyDefaults()
	cfg.applyEnvOverrides()
	return cfg, nil
}

// applyDefaults 用于执行applyDefaults流程。
func (c *ServerConfig) applyDefaults() {
	// 用"零值即视为未配置"的策略批量填默认值，让 config.yaml 只需写要覆盖的项。
	if c.App.Port == "" {
		c.App.Port = "8080"
	}
	if c.App.JWTSecret == "" {
		c.App.JWTSecret = "lightweight-ip-traffic-sa-dev-secret"
	}
	if c.Database.MaxIdleConns == 0 {
		c.Database.MaxIdleConns = 5
	}
	if c.Database.MaxOpenConns == 0 {
		c.Database.MaxOpenConns = 10
	}
	if c.Redis.Addr == "" {
		c.Redis.Addr = "127.0.0.1:6379"
	}
	if c.Redis.PoolSize == 0 {
		c.Redis.PoolSize = 10
	}
	if c.Security.HighRiskThreshold == 0 {
		c.Security.HighRiskThreshold = 75
	}
	if c.Security.CriticalRiskThreshold == 0 {
		c.Security.CriticalRiskThreshold = 90
	}
	if c.Security.Alert.NotifyChannel == "" {
		c.Security.Alert.NotifyChannel = "SYSTEM"
	}
	if c.Security.Alert.Mail.SMTPPort == 0 {
		c.Security.Alert.Mail.SMTPPort = 25
	}
	if c.Security.Source.WhoisEndpoint == "" {
		c.Security.Source.WhoisEndpoint = "rdap"
	}
	if c.Security.Source.ReputationEndpoint == "" {
		c.Security.Source.ReputationEndpoint = "local-blacklist"
	}
	if c.Security.Source.AttackSurfaceEndpoint == "" {
		c.Security.Source.AttackSurfaceEndpoint = "limited-port-scan"
	}
	if !c.Security.Source.GeoLite2.Enabled && c.Security.Source.GeoLite2.CityDBPath == "" && c.Security.Source.GeoLite2.ASNDBPath == "" {
		c.Security.Source.GeoLite2.Enabled = true
	}
	if c.Security.Source.GeoLite2.CountryDBPath == "" {
		c.Security.Source.GeoLite2.CountryDBPath = "data/geoip/GeoLite2-Country.mmdb"
	}
	if c.Security.Source.GeoLite2.CityDBPath == "" {
		c.Security.Source.GeoLite2.CityDBPath = "data/geoip/GeoLite2-City.mmdb"
	}
	if c.Security.Source.GeoLite2.ASNDBPath == "" {
		c.Security.Source.GeoLite2.ASNDBPath = "data/geoip/GeoLite2-ASN.mmdb"
	}
	if c.Security.Source.GeoLite2.CacheTTLSeconds == 0 {
		c.Security.Source.GeoLite2.CacheTTLSeconds = 86400
	}
	if !c.Security.Source.RDAP.Enabled && c.Security.Source.RDAP.BaseURL == "" && c.Security.Source.RDAP.TimeoutSeconds == 0 && c.Security.Source.RDAP.CacheTTLSeconds == 0 {
		c.Security.Source.RDAP.Enabled = true
	}
	if c.Security.Source.RDAP.BaseURL == "" {
		c.Security.Source.RDAP.BaseURL = "https://rdap.org/ip/"
	}
	if len(c.Security.Source.RDAP.BackupBaseURLs) == 0 {
		c.Security.Source.RDAP.BackupBaseURLs = append([]string(nil), DefaultRDAPBackupBaseURLs...)
	}
	if c.Security.Source.RDAP.TimeoutSeconds == 0 {
		c.Security.Source.RDAP.TimeoutSeconds = 3
	}
	if c.Security.Source.RDAP.CacheTTLSeconds == 0 {
		c.Security.Source.RDAP.CacheTTLSeconds = 86400
	}
	if !c.Security.Source.LocalBlacklist.Enabled && c.Security.Source.LocalBlacklist.FilePath == "" {
		c.Security.Source.LocalBlacklist.Enabled = true
	}
	if c.Security.Source.LocalBlacklist.ReloadIntervalSeconds == 0 {
		c.Security.Source.LocalBlacklist.ReloadIntervalSeconds = 300
	}
	if c.Security.Source.LocalBlacklist.MatchScore == 0 {
		c.Security.Source.LocalBlacklist.MatchScore = 92
	}
	if c.Security.Source.LocalBlacklist.DefaultScore == 0 {
		c.Security.Source.LocalBlacklist.DefaultScore = 20
	}
	if c.Security.Source.AbuseIPDB.BaseURL == "" {
		c.Security.Source.AbuseIPDB.BaseURL = "https://api.abuseipdb.com/api/v2/check"
	}
	if c.Security.Source.AbuseIPDB.TimeoutSeconds == 0 {
		c.Security.Source.AbuseIPDB.TimeoutSeconds = 2
	}
	if c.Security.Source.AbuseIPDB.CacheTTLSeconds == 0 {
		c.Security.Source.AbuseIPDB.CacheTTLSeconds = 3600
	}
	if c.Security.Source.AbuseIPDB.MaxAgeInDays == 0 {
		c.Security.Source.AbuseIPDB.MaxAgeInDays = 30
	}
	if len(c.Security.Source.AttackSurface.Ports) == 0 {
		c.Security.Source.AttackSurface.Ports = []int{22, 80, 443, 445, 3389, 8080}
	}
	if c.Security.Source.AttackSurface.TimeoutMilliseconds == 0 {
		c.Security.Source.AttackSurface.TimeoutMilliseconds = 800
	}
	if c.Security.Source.AttackSurface.CacheTTLSeconds == 0 {
		c.Security.Source.AttackSurface.CacheTTLSeconds = 43200
	}
	if c.Security.Source.AttackSurface.MaxConcurrency == 0 {
		c.Security.Source.AttackSurface.MaxConcurrency = 3
	}
	if c.Security.Source.AttackSurface.NmapPath == "" {
		c.Security.Source.AttackSurface.NmapPath = "nmap"
	}
	if c.Security.Source.AttackSurface.NmapTimeoutSeconds == 0 {
		c.Security.Source.AttackSurface.NmapTimeoutSeconds = 8
	}
	if c.Security.Source.Flow.Mode == "" {
		c.Security.Source.Flow.Mode = "sample"
	}
	if c.Security.Source.Flow.SampleProfile == "" {
		c.Security.Source.Flow.SampleProfile = "baseline-web"
	}
	if c.Security.Source.Flow.WindowSeconds == 0 {
		c.Security.Source.Flow.WindowSeconds = 60
	}
	if c.Security.Source.Flow.TimeoutSeconds == 0 {
		c.Security.Source.Flow.TimeoutSeconds = 5
	}
	if c.Security.Source.Flow.CacheTTLSeconds == 0 {
		c.Security.Source.Flow.CacheTTLSeconds = 900
	}
	if c.Security.Cache.DashboardSummaryTTLSeconds == 0 {
		c.Security.Cache.DashboardSummaryTTLSeconds = 30
	}
	if c.Security.Cache.SecurityConfigTTLSeconds == 0 {
		c.Security.Cache.SecurityConfigTTLSeconds = 300
	}
	if c.Security.Cache.DetailQueryTTLSeconds == 0 {
		c.Security.Cache.DetailQueryTTLSeconds = 120
	}
	if c.Security.Cache.CollectorTTLSeconds == 0 {
		c.Security.Cache.CollectorTTLSeconds = 1800
	}
	if c.Security.DefaultCreatedBy == "" {
		c.Security.DefaultCreatedBy = "admin"
	}
	if c.Security.Weights.WhoisWeight == 0 {
		c.Security.Weights.WhoisWeight = 0.20
	}
	if c.Security.Weights.ReputationWeight == 0 {
		c.Security.Weights.ReputationWeight = 0.35
	}
	if c.Security.Weights.AttackSurfaceWeight == 0 {
		c.Security.Weights.AttackSurfaceWeight = 0.30
	}
	if c.Security.Weights.BehaviorWeight == 0 {
		c.Security.Weights.BehaviorWeight = 0.15
	}
}

// applyEnvOverrides 用于执行applyEnvOverrides流程。
func (c *ServerConfig) applyEnvOverrides() {
	// 环境变量优先级最高：APP_PORT 优先于 PORT，便于容器化/CI 注入端口而不改配置文件。
	if port := strings.TrimSpace(os.Getenv("APP_PORT")); port != "" {
		c.App.Port = port
		return
	}
	if port := strings.TrimSpace(os.Getenv("PORT")); port != "" {
		c.App.Port = port
	}
}
