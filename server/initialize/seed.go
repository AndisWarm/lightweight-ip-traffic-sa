package initialize

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	appConfig "lightweight-ip-traffic-sa/server/config"
	"lightweight-ip-traffic-sa/server/global"
	securityModel "lightweight-ip-traffic-sa/server/model/security"
	systemModel "lightweight-ip-traffic-sa/server/model/system"
	"lightweight-ip-traffic-sa/server/utils"
)

// demoUserSeed 用于承载demo用户Seed数据。
type demoUserSeed struct {
	Username    string
	DisplayName string
	RoleCode    string
}

// InitDemoUsers 用于初始化运行时依赖或基础数据。
func InitDemoUsers() error {
	users := []demoUserSeed{
		{Username: "admin", DisplayName: "Admin", RoleCode: utils.RoleAdmin},
		{Username: "manager", DisplayName: "Manager", RoleCode: utils.RoleManager},
		{Username: "user", DisplayName: "User", RoleCode: utils.RoleUser},
	}

	for _, user := range users {
		if err := ensureUser(user); err != nil {
			return err
		}
	}

	return ensureSecurityConfig()
}

// ensureUser 用于确保基础数据或配置满足运行要求。
func ensureUser(seed demoUserSeed) error {
	var user systemModel.SysUser
	err := global.DB.Where("username = ?", seed.Username).First(&user).Error
	if err == nil {
		return global.DB.Model(&user).Updates(map[string]interface{}{
			"display_name": seed.DisplayName,
			"role_code":    seed.RoleCode,
			"enable":       true,
		}).Error
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte("Admin123!"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user = systemModel.SysUser{
		Username:     seed.Username,
		PasswordHash: string(passwordHash),
		DisplayName:  seed.DisplayName,
		RoleCode:     seed.RoleCode,
		Enable:       true,
	}

	return global.DB.Create(&user).Error
}

// ensureSecurityConfig 用于确保基础数据或配置满足运行要求。
func ensureSecurityConfig() error {
	var config securityModel.SecurityConfig
	err := global.DB.Order("id ASC").First(&config).Error
	if err == nil {
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	return global.DB.Create(&securityModel.SecurityConfig{
		WhoisEndpoint:         deriveSeedWhoisEndpoint(global.AppConfig.Security),
		ReputationEndpoint:    deriveSeedReputationEndpoint(global.AppConfig.Security),
		AttackSurfaceEndpoint: deriveSeedAttackSurfaceEndpoint(global.AppConfig.Security),
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
		SMTPPassword:          global.AppConfig.Security.Alert.Mail.Password,
		SMTPUseTLS:            global.AppConfig.Security.Alert.Mail.UseTLS,
		HighRiskThreshold:     global.AppConfig.Security.HighRiskThreshold,
		CriticalRiskThreshold: global.AppConfig.Security.CriticalRiskThreshold,
		WhoisWeight:           global.AppConfig.Security.Weights.WhoisWeight,
		ReputationWeight:      global.AppConfig.Security.Weights.ReputationWeight,
		AttackSurfaceWeight:   global.AppConfig.Security.Weights.AttackSurfaceWeight,
		BehaviorWeight:        global.AppConfig.Security.Weights.BehaviorWeight,
	}).Error
}

// deriveSeedWhoisEndpoint 用于根据配置推导默认参数。
func deriveSeedWhoisEndpoint(cfg appConfig.SecurityConfig) string {
	if cfg.DemoMode {
		return "local-demo"
	}
	if cfg.Source.GeoLite2.Enabled && cfg.Source.RDAP.Enabled {
		return "geolite2+rdap"
	}
	if cfg.Source.GeoLite2.Enabled {
		return "geolite2"
	}
	return "rdap"
}

// deriveSeedReputationEndpoint 用于根据配置推导默认参数。
func deriveSeedReputationEndpoint(cfg appConfig.SecurityConfig) string {
	if cfg.DemoMode {
		return "local-demo"
	}
	if cfg.Source.LocalBlacklist.Enabled && cfg.Source.AbuseIPDB.Enabled {
		return "local-blacklist+abuseipdb"
	}
	if cfg.Source.AbuseIPDB.Enabled {
		return "abuseipdb"
	}
	return "local-blacklist"
}

// deriveSeedAttackSurfaceEndpoint 用于根据配置推导默认参数。
func deriveSeedAttackSurfaceEndpoint(cfg appConfig.SecurityConfig) string {
	if !cfg.Source.AttackSurface.Enabled {
		return "disabled"
	}
	if cfg.Source.AttackSurface.NmapEnabled {
		return "limited-port-scan+nmap-enhanced"
	}
	return "limited-port-scan"
}
