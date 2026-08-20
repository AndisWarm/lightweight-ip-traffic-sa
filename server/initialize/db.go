package initialize

import (
	"lightweight-ip-traffic-sa/server/global"
	securityModel "lightweight-ip-traffic-sa/server/model/security"
	systemModel "lightweight-ip-traffic-sa/server/model/system"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// InitDB 用于初始化运行时依赖或基础数据。
func InitDB() (*gorm.DB, error) {
	db, err := gorm.Open(mysql.Open(global.AppConfig.Database.DSN), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxIdleConns(global.AppConfig.Database.MaxIdleConns)
	sqlDB.SetMaxOpenConns(global.AppConfig.Database.MaxOpenConns)

	models := []interface{}{
		&systemModel.SysUser{},
		&systemModel.SysJWTBlacklist{},
		&systemModel.SysLoginLog{},
		&securityModel.IPTask{},
		&securityModel.IPBaseInfo{},
		&securityModel.FeatureSnapshot{},
		&securityModel.FlowCollection{},
		&securityModel.FlowWindowAggregate{},
		&securityModel.FlowFeatureSnapshot{},
		&securityModel.RiskScore{},
		&securityModel.AlertRecord{},
		&securityModel.SecurityConfig{},
		&securityModel.AuditLog{},
	}

	for _, model := range models {
		if !db.Migrator().HasTable(model) {
			if err := db.AutoMigrate(model); err != nil {
				return nil, err
			}
		}
	}

	if db.Migrator().HasTable(&systemModel.SysJWTBlacklist{}) {
		if !db.Migrator().HasColumn(&systemModel.SysJWTBlacklist{}, "token_hash") {
			if err := db.Exec("ALTER TABLE sys_jwt_blacklist ADD COLUMN token_hash VARCHAR(64) NOT NULL DEFAULT ''").Error; err != nil {
				return nil, err
			}
			if err := db.Exec("UPDATE sys_jwt_blacklist SET token_hash = SHA2(token, 256) WHERE token_hash = ''").Error; err != nil {
				return nil, err
			}
			if err := db.Exec("CREATE UNIQUE INDEX idx_sys_jwt_blacklist_token_hash ON sys_jwt_blacklist (token_hash)").Error; err != nil {
				return nil, err
			}
		}
	}

	if db.Migrator().HasTable(&securityModel.IPTask{}) {
		if !db.Migrator().HasColumn(&securityModel.IPTask{}, "input_type") {
			if err := db.Exec("ALTER TABLE sec_ip_task ADD COLUMN input_type VARCHAR(16) NOT NULL DEFAULT 'IP' AFTER task_no").Error; err != nil {
				return nil, err
			}
		}
		if !db.Migrator().HasColumn(&securityModel.IPTask{}, "input_value") {
			if err := db.Exec("ALTER TABLE sec_ip_task ADD COLUMN input_value VARCHAR(255) DEFAULT NULL AFTER input_type").Error; err != nil {
				return nil, err
			}
			if err := db.Exec("UPDATE sec_ip_task SET input_value = target_ip WHERE input_value IS NULL OR input_value = ''").Error; err != nil {
				return nil, err
			}
		}
		if err := db.Exec("UPDATE sec_ip_task SET input_type = 'IP' WHERE input_type IS NULL OR input_type = ''").Error; err != nil {
			return nil, err
		}
	}

	if db.Migrator().HasTable(&securityModel.SecurityConfig{}) {
		if !db.Migrator().HasColumn(&securityModel.SecurityConfig{}, "attack_surface_endpoint") {
			if err := db.Exec("ALTER TABLE sec_security_config ADD COLUMN attack_surface_endpoint VARCHAR(255) NOT NULL DEFAULT 'limited-port-scan' AFTER reputation_endpoint").Error; err != nil {
				return nil, err
			}
			if err := db.Exec("UPDATE sec_security_config SET attack_surface_endpoint = 'limited-port-scan' WHERE attack_surface_endpoint IS NULL OR attack_surface_endpoint = ''").Error; err != nil {
				return nil, err
			}
		}
		if !db.Migrator().HasColumn(&securityModel.SecurityConfig{}, "flow_enabled") {
			if err := db.Exec("ALTER TABLE sec_security_config ADD COLUMN flow_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER reputation_endpoint").Error; err != nil {
				return nil, err
			}
			if err := db.Exec("UPDATE sec_security_config SET flow_enabled = 0 WHERE flow_enabled IS NULL").Error; err != nil {
				return nil, err
			}
		}
		if !db.Migrator().HasColumn(&securityModel.SecurityConfig{}, "flow_mode") {
			if err := db.Exec("ALTER TABLE sec_security_config ADD COLUMN flow_mode VARCHAR(32) NOT NULL DEFAULT 'sample' AFTER flow_enabled").Error; err != nil {
				return nil, err
			}
		}
		if !db.Migrator().HasColumn(&securityModel.SecurityConfig{}, "flow_interface_name") {
			if err := db.Exec("ALTER TABLE sec_security_config ADD COLUMN flow_interface_name VARCHAR(128) NULL AFTER flow_mode").Error; err != nil {
				return nil, err
			}
		}
		if !db.Migrator().HasColumn(&securityModel.SecurityConfig{}, "flow_pcap_file_path") {
			if err := db.Exec("ALTER TABLE sec_security_config ADD COLUMN flow_pcap_file_path VARCHAR(255) NULL AFTER flow_interface_name").Error; err != nil {
				return nil, err
			}
		}
		if !db.Migrator().HasColumn(&securityModel.SecurityConfig{}, "flow_sample_profile") {
			if err := db.Exec("ALTER TABLE sec_security_config ADD COLUMN flow_sample_profile VARCHAR(128) NULL AFTER flow_pcap_file_path").Error; err != nil {
				return nil, err
			}
		}
		if !db.Migrator().HasColumn(&securityModel.SecurityConfig{}, "flow_window_seconds") {
			if err := db.Exec("ALTER TABLE sec_security_config ADD COLUMN flow_window_seconds INT NOT NULL DEFAULT 60 AFTER flow_sample_profile").Error; err != nil {
				return nil, err
			}
		}
		if !db.Migrator().HasColumn(&securityModel.SecurityConfig{}, "flow_timeout_seconds") {
			if err := db.Exec("ALTER TABLE sec_security_config ADD COLUMN flow_timeout_seconds INT NOT NULL DEFAULT 5 AFTER flow_window_seconds").Error; err != nil {
				return nil, err
			}
		}
		if !db.Migrator().HasColumn(&securityModel.SecurityConfig{}, "mail_enabled") {
			if err := db.Exec("ALTER TABLE sec_security_config ADD COLUMN mail_enabled TINYINT(1) NOT NULL DEFAULT 0 AFTER notify_channel").Error; err != nil {
				return nil, err
			}
		}
		if !db.Migrator().HasColumn(&securityModel.SecurityConfig{}, "mail_sender") {
			if err := db.Exec("ALTER TABLE sec_security_config ADD COLUMN mail_sender VARCHAR(255) NULL AFTER mail_enabled").Error; err != nil {
				return nil, err
			}
		}
		if !db.Migrator().HasColumn(&securityModel.SecurityConfig{}, "mail_recipient") {
			if err := db.Exec("ALTER TABLE sec_security_config ADD COLUMN mail_recipient VARCHAR(255) NULL AFTER mail_sender").Error; err != nil {
				return nil, err
			}
		}
		if !db.Migrator().HasColumn(&securityModel.SecurityConfig{}, "smtp_host") {
			if err := db.Exec("ALTER TABLE sec_security_config ADD COLUMN smtp_host VARCHAR(255) NULL AFTER mail_recipient").Error; err != nil {
				return nil, err
			}
		}
		if !db.Migrator().HasColumn(&securityModel.SecurityConfig{}, "smtp_port") {
			if err := db.Exec("ALTER TABLE sec_security_config ADD COLUMN smtp_port INT NOT NULL DEFAULT 25 AFTER smtp_host").Error; err != nil {
				return nil, err
			}
		}
		if !db.Migrator().HasColumn(&securityModel.SecurityConfig{}, "smtp_username") {
			if err := db.Exec("ALTER TABLE sec_security_config ADD COLUMN smtp_username VARCHAR(255) NULL AFTER smtp_port").Error; err != nil {
				return nil, err
			}
		}
		if !db.Migrator().HasColumn(&securityModel.SecurityConfig{}, "smtp_password") {
			if err := db.Exec("ALTER TABLE sec_security_config ADD COLUMN smtp_password VARCHAR(255) NULL AFTER smtp_username").Error; err != nil {
				return nil, err
			}
		}
		if !db.Migrator().HasColumn(&securityModel.SecurityConfig{}, "smtp_use_tls") {
			if err := db.Exec("ALTER TABLE sec_security_config ADD COLUMN smtp_use_tls TINYINT(1) NOT NULL DEFAULT 0 AFTER smtp_password").Error; err != nil {
				return nil, err
			}
		}
	}

	if db.Migrator().HasTable(&securityModel.RiskScore{}) {
		scoreColumns := []struct {
			Name string
			SQL  string
		}{
			{"base_score", "ALTER TABLE sec_risk_score ADD COLUMN base_score DECIMAL(10,2) NOT NULL DEFAULT 0 AFTER ip"},
			{"reputation_score", "ALTER TABLE sec_risk_score ADD COLUMN reputation_score DECIMAL(10,2) NOT NULL DEFAULT 0 AFTER base_score"},
			{"attack_surface_score", "ALTER TABLE sec_risk_score ADD COLUMN attack_surface_score DECIMAL(10,2) NOT NULL DEFAULT 0 AFTER reputation_score"},
			{"behavior_score", "ALTER TABLE sec_risk_score ADD COLUMN behavior_score DECIMAL(10,2) NOT NULL DEFAULT 0 AFTER attack_surface_score"},
			{"rule_adjustment_value", "ALTER TABLE sec_risk_score ADD COLUMN rule_adjustment_value DECIMAL(10,2) NOT NULL DEFAULT 0 AFTER behavior_score"},
			{"algorithm_version", "ALTER TABLE sec_risk_score ADD COLUMN algorithm_version VARCHAR(128) NULL AFTER rule_adjustment"},
			{"weight_profile", "ALTER TABLE sec_risk_score ADD COLUMN weight_profile JSON NULL AFTER algorithm_version"},
		}
		for _, item := range scoreColumns {
			if !db.Migrator().HasColumn(&securityModel.RiskScore{}, item.Name) {
				if err := db.Exec(item.SQL).Error; err != nil {
					return nil, err
				}
			}
		}
	}

	if db.Migrator().HasTable(&securityModel.AlertRecord{}) {
		if err := db.Exec("ALTER TABLE sec_alert_record MODIFY COLUMN task_id BIGINT UNSIGNED NULL COMMENT '关联任务 ID'").Error; err != nil {
			return nil, err
		}
		if err := db.Exec("ALTER TABLE sec_alert_record MODIFY COLUMN score_id BIGINT UNSIGNED NULL COMMENT '关联评分 ID'").Error; err != nil {
			return nil, err
		}
		alertColumns := []struct {
			Name string
			SQL  string
		}{
			{"source_type", "ALTER TABLE sec_alert_record ADD COLUMN source_type VARCHAR(32) NOT NULL DEFAULT 'TASK' AFTER score_id"},
			{"source_label", "ALTER TABLE sec_alert_record ADD COLUMN source_label VARCHAR(128) NULL AFTER source_type"},
			{"monitor_session_id", "ALTER TABLE sec_alert_record ADD COLUMN monitor_session_id VARCHAR(64) NULL AFTER source_label"},
		}
		for _, item := range alertColumns {
			if !db.Migrator().HasColumn(&securityModel.AlertRecord{}, item.Name) {
				if err := db.Exec(item.SQL).Error; err != nil {
					return nil, err
				}
			}
		}
		if err := db.Exec("UPDATE sec_alert_record SET source_type = 'TASK' WHERE source_type IS NULL OR source_type = ''").Error; err != nil {
			return nil, err
		}
		if err := db.Exec("UPDATE sec_alert_record SET source_label = ip WHERE source_label IS NULL OR source_label = ''").Error; err != nil {
			return nil, err
		}
	}

	if db.Migrator().HasTable(&securityModel.FlowFeatureSnapshot{}) {
		flowFeatureColumns := []struct {
			Name string
			SQL  string
		}{
			{"parser_name", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN parser_name VARCHAR(128) NULL AFTER ip"},
			{"behavior_risk_score", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN behavior_risk_score DECIMAL(10,2) NOT NULL DEFAULT 0 AFTER parser_name"},
			{"packet_count", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN packet_count BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER behavior_risk_score"},
			{"byte_count", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN byte_count BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER packet_count"},
			{"conversation_count", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN conversation_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER byte_count"},
			{"peak_pps", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN peak_pps DECIMAL(12,2) NOT NULL DEFAULT 0 AFTER conversation_count"},
			{"burst_score", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN burst_score DECIMAL(10,2) NOT NULL DEFAULT 0 AFTER peak_pps"},
			{"scan_score", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN scan_score DECIMAL(10,2) NOT NULL DEFAULT 0 AFTER burst_score"},
			{"high_entropy_packet_count", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN high_entropy_packet_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER scan_score"},
			{"unique_target_port_count", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN unique_target_port_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER high_entropy_packet_count"},
			{"high_risk_target_port_count", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN high_risk_target_port_count INT UNSIGNED NOT NULL DEFAULT 0 AFTER unique_target_port_count"},
			{"target_port_density", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN target_port_density DECIMAL(10,4) DEFAULT NULL AFTER high_risk_target_port_count"},
			{"dominant_direction", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN dominant_direction VARCHAR(32) DEFAULT NULL AFTER target_port_density"},
			{"protocol_distribution", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN protocol_distribution JSON NULL AFTER dominant_direction"},
			{"dns_top_questions", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN dns_top_questions JSON NULL AFTER protocol_distribution"},
			{"dns_query_type_hints", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN dns_query_type_hints JSON NULL AFTER dns_top_questions"},
			{"http_host_hints", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN http_host_hints JSON NULL AFTER dns_query_type_hints"},
			{"http_method_hints", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN http_method_hints JSON NULL AFTER http_host_hints"},
			{"http_status_hints", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN http_status_hints JSON NULL AFTER http_method_hints"},
			{"tls_handshake_hints", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN tls_handshake_hints JSON NULL AFTER http_status_hints"},
			{"tls_version_hints", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN tls_version_hints JSON NULL AFTER tls_handshake_hints"},
			{"application_signals", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN application_signals JSON NULL AFTER tls_version_hints"},
			{"directionality_indicators", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN directionality_indicators JSON NULL AFTER application_signals"},
			{"port_density_indicators", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN port_density_indicators JSON NULL AFTER directionality_indicators"},
			{"payload_entropy_indicators", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN payload_entropy_indicators JSON NULL AFTER port_density_indicators"},
			{"top_ports", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN top_ports JSON NULL AFTER payload_entropy_indicators"},
			{"peer_endpoints", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN peer_endpoints JSON NULL AFTER top_ports"},
			{"evidence_payload", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN evidence_payload JSON NULL AFTER peer_endpoints"},
			{"feature_digest", "ALTER TABLE sec_flow_feature_snapshot ADD COLUMN feature_digest VARCHAR(128) NULL AFTER evidence_payload"},
		}
		for _, item := range flowFeatureColumns {
			if !db.Migrator().HasColumn(&securityModel.FlowFeatureSnapshot{}, item.Name) {
				if err := db.Exec(item.SQL).Error; err != nil {
					return nil, err
				}
			}
		}
	}

	return db, nil
}
