package config

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ServerConfig 用于承载Server运行配置。
type ServerConfig struct {
	App      AppConfig      `yaml:"app"`
	Database DatabaseConfig `yaml:"database"`
	Redis    RedisConfig    `yaml:"redis"`
	Security SecurityConfig `yaml:"security"`
}

// AppConfig 用于承载App运行配置。
type AppConfig struct {
	Port      string `yaml:"port"`
	JWTSecret string `yaml:"jwtSecret"`
}

// DatabaseConfig 用于承载Database运行配置。
type DatabaseConfig struct {
	DSN          string `yaml:"dsn"`
	MaxIdleConns int    `yaml:"maxIdleConns"`
	MaxOpenConns int    `yaml:"maxOpenConns"`
}

// RedisConfig 用于承载Redis运行配置。
type RedisConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
	PoolSize int    `yaml:"poolSize"`
}

// SecurityConfig 用于承载安全运行配置。
type SecurityConfig struct {
	DemoMode              bool         `yaml:"demoMode"`
	DefaultCreatedBy      string       `yaml:"defaultCreatedBy"`
	HighRiskThreshold     float64      `yaml:"highRiskThreshold"`
	CriticalRiskThreshold float64      `yaml:"criticalRiskThreshold"`
	Source                SourceConfig `yaml:"source"`
	Alert                 AlertConfig  `yaml:"alert"`
	Cache                 CacheConfig  `yaml:"cache"`
	Weights               WeightConfig `yaml:"weights"`
}

// SourceConfig 用于承载来源运行配置。
type SourceConfig struct {
	WhoisEndpoint         string                    `yaml:"whoisEndpoint"`
	ReputationEndpoint    string                    `yaml:"reputationEndpoint"`
	AttackSurfaceEndpoint string                    `yaml:"attackSurfaceEndpoint"`
	GeoLite2              GeoLite2SourceConfig      `yaml:"geoLite2"`
	RDAP                  RDAPSourceConfig          `yaml:"rdap"`
	LocalBlacklist        LocalBlacklistConfig      `yaml:"localBlacklist"`
	AbuseIPDB             AbuseIPDBSourceConfig     `yaml:"abuseIPDB"`
	AttackSurface         AttackSurfaceSourceConfig `yaml:"attackSurface"`
	Flow                  FlowSourceConfig          `yaml:"flow"`
}

// GeoLite2SourceConfig 用于承载地理Lite2来源运行配置。
type GeoLite2SourceConfig struct {
	Enabled         bool   `yaml:"enabled"`
	CountryDBPath   string `yaml:"countryDBPath"`
	CityDBPath      string `yaml:"cityDBPath"`
	ASNDBPath       string `yaml:"asnDBPath"`
	CacheTTLSeconds int    `yaml:"cacheTTLSeconds"`
}

// RDAPSourceConfig 用于承载RDAP来源运行配置。
type RDAPSourceConfig struct {
	Enabled         bool     `yaml:"enabled"`
	BaseURL         string   `yaml:"baseURL"`
	BackupBaseURLs  []string `yaml:"backupBaseURLs"`
	TimeoutSeconds  int      `yaml:"timeoutSeconds"`
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
type LocalBlacklistConfig struct {
	Enabled               bool    `yaml:"enabled"`
	FilePath              string  `yaml:"filePath"`
	ReloadIntervalSeconds int     `yaml:"reloadIntervalSeconds"`
	MatchScore            float64 `yaml:"matchScore"`
	DefaultScore          float64 `yaml:"defaultScore"`
}

// AbuseIPDBSourceConfig 用于承载AbuseIPDB来源运行配置。
type AbuseIPDBSourceConfig struct {
	Enabled         bool   `yaml:"enabled"`
	BaseURL         string `yaml:"baseURL"`
	APIKey          string `yaml:"apiKey"`
	TimeoutSeconds  int    `yaml:"timeoutSeconds"`
	CacheTTLSeconds int    `yaml:"cacheTTLSeconds"`
	MaxAgeInDays    int    `yaml:"maxAgeInDays"`
}

// AttackSurfaceSourceConfig 用于承载AttackSurface来源运行配置。
type AttackSurfaceSourceConfig struct {
	Enabled             bool   `yaml:"enabled"`
	Ports               []int  `yaml:"ports"`
	TimeoutMilliseconds int    `yaml:"timeoutMilliseconds"`
	CacheTTLSeconds     int    `yaml:"cacheTTLSeconds"`
	MaxConcurrency      int    `yaml:"maxConcurrency"`
	NmapEnabled         bool   `yaml:"nmapEnabled"`
	NmapPath            string `yaml:"nmapPath"`
	NmapTimeoutSeconds  int    `yaml:"nmapTimeoutSeconds"`
}

// FlowSourceConfig 用于承载流量来源运行配置。
type FlowSourceConfig struct {
	Enabled         bool   `yaml:"enabled"`
	Mode            string `yaml:"mode"`
	InterfaceName   string `yaml:"interfaceName"`
	PcapFilePath    string `yaml:"pcapFilePath"`
	SampleProfile   string `yaml:"sampleProfile"`
	WindowSeconds   int    `yaml:"windowSeconds"`
	TimeoutSeconds  int    `yaml:"timeoutSeconds"`
	CacheTTLSeconds int    `yaml:"cacheTTLSeconds"`
}

// AlertConfig 用于承载预警运行配置。
type AlertConfig struct {
	NotifyChannel string     `yaml:"notifyChannel"`
	Mail          MailConfig `yaml:"mail"`
}

// MailConfig 用于承载Mail运行配置。
type MailConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Sender    string `yaml:"sender"`
	Recipient string `yaml:"recipient"`
	SMTPHost  string `yaml:"smtpHost"`
	SMTPPort  int    `yaml:"smtpPort"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	UseTLS    bool   `yaml:"useTLS"`
}

// CacheConfig 用于承载缓存运行配置。
type CacheConfig struct {
	DashboardSummaryTTLSeconds int `yaml:"dashboardSummaryTTLSeconds"`
	SecurityConfigTTLSeconds   int `yaml:"securityConfigTTLSeconds"`
	DetailQueryTTLSeconds      int `yaml:"detailQueryTTLSeconds"`
	CollectorTTLSeconds        int `yaml:"collectorTTLSeconds"`
}

// WeightConfig 用于承载Weight运行配置。
type WeightConfig struct {
	WhoisWeight         float64 `yaml:"whoisWeight"`
	ReputationWeight    float64 `yaml:"reputationWeight"`
	AttackSurfaceWeight float64 `yaml:"attackSurfaceWeight"`
	BehaviorWeight      float64 `yaml:"behaviorWeight"`
}

// LoadConfig 用于加载配置、缓存或外部资源。
func LoadConfig() (ServerConfig, error) {
	paths := []string{
		"config.yaml",
		filepath.Join("server", "config.yaml"),
	}

	var cfg ServerConfig
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return ServerConfig{}, err
		}
		cfg.applyDefaults()
		cfg.applyEnvOverrides()
		return cfg, nil
	}

	cfg.applyDefaults()
	cfg.applyEnvOverrides()
	return cfg, nil
}

// applyDefaults 用于执行applyDefaults流程。
func (c *ServerConfig) applyDefaults() {
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
	if port := strings.TrimSpace(os.Getenv("APP_PORT")); port != "" {
		c.App.Port = port
		return
	}
	if port := strings.TrimSpace(os.Getenv("PORT")); port != "" {
		c.App.Port = port
	}
}
