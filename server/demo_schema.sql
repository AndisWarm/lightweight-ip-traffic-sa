CREATE DATABASE IF NOT EXISTS `light_situation_awareness`
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_general_ci;

USE `light_situation_awareness`;

DROP TABLE IF EXISTS `sys_login_log`;
DROP TABLE IF EXISTS `sys_jwt_blacklist`;
DROP TABLE IF EXISTS `sys_user`;
DROP TABLE IF EXISTS `sec_flow_feature_snapshot`;
DROP TABLE IF EXISTS `sec_flow_window_aggregate`;
DROP TABLE IF EXISTS `sec_flow_collection`;
DROP TABLE IF EXISTS `sec_alert_record`;
DROP TABLE IF EXISTS `sec_audit_log`;
DROP TABLE IF EXISTS `sec_security_config`;
DROP TABLE IF EXISTS `sec_risk_score`;
DROP TABLE IF EXISTS `sec_feature_snapshot`;
DROP TABLE IF EXISTS `sec_ip_base_info`;
DROP TABLE IF EXISTS `sec_ip_task`;

CREATE TABLE `sys_user` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '用户主键',
  `username` VARCHAR(64) NOT NULL COMMENT '用户名',
  `password_hash` VARCHAR(255) NOT NULL COMMENT '密码哈希',
  `display_name` VARCHAR(128) NOT NULL COMMENT '显示名称',
  `role_code` VARCHAR(32) NOT NULL COMMENT '角色编码',
  `enable` TINYINT(1) NOT NULL DEFAULT 1 COMMENT '是否启用',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_sys_user_username` (`username`),
  KEY `idx_sys_user_role_code` (`role_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='系统用户表';

CREATE TABLE `sys_jwt_blacklist` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '黑名单主键',
  `token` VARCHAR(1024) NOT NULL COMMENT '失效令牌原文',
  `token_hash` VARCHAR(64) NOT NULL COMMENT '令牌哈希值',
  `username` VARCHAR(64) NOT NULL COMMENT '用户名',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_sys_jwt_blacklist_token_hash` (`token_hash`),
  KEY `idx_sys_jwt_blacklist_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='JWT 黑名单表';

CREATE TABLE `sys_login_log` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '登录日志主键',
  `username` VARCHAR(64) NOT NULL COMMENT '用户名',
  `ip` VARCHAR(64) DEFAULT NULL COMMENT '客户端 IP',
  `user_agent` VARCHAR(512) DEFAULT NULL COMMENT 'User-Agent',
  `status` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否成功',
  `error_message` VARCHAR(255) DEFAULT NULL COMMENT '错误信息',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_sys_login_log_username` (`username`),
  KEY `idx_sys_login_log_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='登录日志表';

CREATE TABLE `sec_ip_task` (
  `input_type` VARCHAR(16) NOT NULL DEFAULT 'IP' COMMENT '原始输入类型',
  `input_value` VARCHAR(255) DEFAULT NULL COMMENT '原始输入值',
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '任务主键',
  `task_no` VARCHAR(64) NOT NULL COMMENT '任务编号',
  `target_ip` VARCHAR(64) NOT NULL COMMENT '目标 IP',
  `created_by` VARCHAR(64) NOT NULL COMMENT '发起人标识',
  `task_status` VARCHAR(32) NOT NULL COMMENT '任务状态',
  `error_message` VARCHAR(500) DEFAULT NULL COMMENT '失败原因',
  `started_at` DATETIME DEFAULT NULL COMMENT '开始时间',
  `finished_at` DATETIME DEFAULT NULL COMMENT '完成时间',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_sec_ip_task_task_no` (`task_no`),
  KEY `idx_sec_ip_task_input_type` (`input_type`),
  KEY `idx_sec_ip_task_target_ip` (`target_ip`),
  KEY `idx_sec_ip_task_created_by` (`created_by`),
  KEY `idx_sec_ip_task_status` (`task_status`),
  KEY `idx_sec_ip_task_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='IP 检测任务表';

CREATE TABLE `sec_ip_base_info` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '基础信息主键',
  `task_id` BIGINT UNSIGNED NOT NULL COMMENT '关联任务 ID',
  `ip` VARCHAR(64) NOT NULL COMMENT '目标 IP',
  `country` VARCHAR(64) DEFAULT NULL COMMENT '国家',
  `region` VARCHAR(64) DEFAULT NULL COMMENT '地区',
  `city` VARCHAR(64) DEFAULT NULL COMMENT '城市',
  `isp` VARCHAR(128) DEFAULT NULL COMMENT '运营商',
  `whois_org` VARCHAR(255) DEFAULT NULL COMMENT 'WHOIS 组织信息',
  `whois_contact` VARCHAR(255) DEFAULT NULL COMMENT 'WHOIS 联系方式',
  `raw_payload` JSON DEFAULT NULL COMMENT '原始返回内容',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_sec_ip_base_info_task_id` (`task_id`),
  KEY `idx_sec_ip_base_info_ip` (`ip`),
  CONSTRAINT `fk_sec_ip_base_info_task_id` FOREIGN KEY (`task_id`) REFERENCES `sec_ip_task` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='IP 基础信息表';

CREATE TABLE `sec_feature_snapshot` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '特征快照主键',
  `task_id` BIGINT UNSIGNED NOT NULL COMMENT '关联任务 ID',
  `ip` VARCHAR(64) NOT NULL COMMENT '目标 IP',
  `reputation_score` DECIMAL(10,2) DEFAULT NULL COMMENT '信誉评分',
  `open_port_count` INT DEFAULT NULL COMMENT '开放端口数量',
  `high_risk_port_count` INT DEFAULT NULL COMMENT '高风险端口数量',
  `geo_risk_flag` TINYINT(1) DEFAULT 0 COMMENT '地理风险标记',
  `normalized_features` JSON NOT NULL COMMENT '标准化特征集合',
  `feature_digest` VARCHAR(128) DEFAULT NULL COMMENT '特征摘要哈希',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_sec_feature_snapshot_task_id` (`task_id`),
  KEY `idx_sec_feature_snapshot_ip` (`ip`),
  KEY `idx_sec_feature_snapshot_created_at` (`created_at`),
  CONSTRAINT `fk_sec_feature_snapshot_task_id` FOREIGN KEY (`task_id`) REFERENCES `sec_ip_task` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='IP 特征快照表';

CREATE TABLE `sec_flow_collection` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '流量采集主键',
  `task_id` BIGINT UNSIGNED NOT NULL COMMENT '关联任务 ID',
  `ip` VARCHAR(64) NOT NULL COMMENT '目标 IP',
  `collection_mode` VARCHAR(32) NOT NULL COMMENT '流量采集模式',
  `collection_status` VARCHAR(32) NOT NULL COMMENT '流量采集状态',
  `parser_name` VARCHAR(128) DEFAULT NULL COMMENT '解析器名称',
  `source_name` VARCHAR(128) DEFAULT NULL COMMENT '来源标识',
  `window_seconds` INT NOT NULL DEFAULT 0 COMMENT '采集窗口秒数',
  `sample_profile` VARCHAR(128) DEFAULT NULL COMMENT '样本画像名称',
  `interface_name` VARCHAR(128) DEFAULT NULL COMMENT '抓包网卡名称',
  `pcap_file_path` VARCHAR(255) DEFAULT NULL COMMENT 'pcap 文件路径',
  `packet_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '报文数量',
  `byte_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '字节数量',
  `conversation_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '会话数量',
  `summary` VARCHAR(500) DEFAULT NULL COMMENT '流量摘要',
  `error_message` VARCHAR(500) DEFAULT NULL COMMENT '错误信息',
  `evidence_payload` JSON DEFAULT NULL COMMENT '流量证据快照',
  `started_at` DATETIME DEFAULT NULL COMMENT '开始时间',
  `finished_at` DATETIME DEFAULT NULL COMMENT '结束时间',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  KEY `idx_sec_flow_collection_task_id` (`task_id`),
  KEY `idx_sec_flow_collection_ip` (`ip`),
  KEY `idx_sec_flow_collection_mode_status` (`collection_mode`, `collection_status`),
  KEY `idx_sec_flow_collection_created_at` (`created_at`),
  KEY `idx_sec_flow_collection_started_at` (`started_at`),
  KEY `idx_sec_flow_collection_task_created_at` (`task_id`, `created_at`),
  CONSTRAINT `fk_sec_flow_collection_task_id` FOREIGN KEY (`task_id`) REFERENCES `sec_ip_task` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='流量采集元数据表';

CREATE TABLE `sec_flow_window_aggregate` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '流量窗口聚合主键',
  `collection_id` BIGINT UNSIGNED NOT NULL COMMENT '关联流量采集 ID',
  `task_id` BIGINT UNSIGNED NOT NULL COMMENT '关联任务 ID',
  `ip` VARCHAR(64) NOT NULL COMMENT '目标 IP',
  `window_no` INT UNSIGNED NOT NULL COMMENT '窗口序号',
  `window_start` DATETIME NOT NULL COMMENT '窗口开始时间',
  `window_end` DATETIME NOT NULL COMMENT '窗口结束时间',
  `packet_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '报文数量',
  `byte_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '字节数量',
  `conversation_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '会话数量',
  `inbound_packet_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '入向报文数量',
  `outbound_packet_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '出向报文数量',
  `inbound_byte_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '入向字节数量',
  `outbound_byte_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '出向字节数量',
  `tcp_packet_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'TCP 报文数量',
  `udp_packet_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'UDP 报文数量',
  `icmp_packet_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'ICMP 报文数量',
  `dns_event_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'DNS 事件数量',
  `http_event_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'HTTP 事件数量',
  `tls_event_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'TLS 事件数量',
  `high_risk_port_hit_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '高危端口命中次数',
  `evidence_payload` JSON DEFAULT NULL COMMENT '窗口证据快照',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_sec_flow_window_collection_window` (`collection_id`, `window_no`),
  KEY `idx_sec_flow_window_task_window_start` (`task_id`, `window_start`),
  KEY `idx_sec_flow_window_collection_window_start` (`collection_id`, `window_start`),
  KEY `idx_sec_flow_window_ip_window_start` (`ip`, `window_start`),
  CONSTRAINT `fk_sec_flow_window_collection_id` FOREIGN KEY (`collection_id`) REFERENCES `sec_flow_collection` (`id`),
  CONSTRAINT `fk_sec_flow_window_task_id` FOREIGN KEY (`task_id`) REFERENCES `sec_ip_task` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='流量窗口聚合表';

CREATE TABLE `sec_flow_feature_snapshot` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '流量特征快照主键',
  `collection_id` BIGINT UNSIGNED NOT NULL COMMENT '关联流量采集 ID',
  `task_id` BIGINT UNSIGNED NOT NULL COMMENT '关联任务 ID',
  `ip` VARCHAR(64) NOT NULL COMMENT '目标 IP',
  `parser_name` VARCHAR(128) DEFAULT NULL COMMENT '解析器名称',
  `behavior_risk_score` DECIMAL(10,2) DEFAULT NULL COMMENT '流量行为风险分',
  `packet_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '报文数量',
  `byte_count` BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT '字节数量',
  `conversation_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '会话数量',
  `peak_pps` DECIMAL(12,2) DEFAULT NULL COMMENT '峰值每秒报文数',
  `burst_score` DECIMAL(10,2) DEFAULT NULL COMMENT '突发评分',
  `scan_score` DECIMAL(10,2) DEFAULT NULL COMMENT '扫描评分',
  `high_entropy_packet_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '高熵报文数量',
  `unique_target_port_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '目标端口去重数量',
  `high_risk_target_port_count` INT UNSIGNED NOT NULL DEFAULT 0 COMMENT '高危目标端口数量',
  `target_port_density` DECIMAL(10,4) DEFAULT NULL COMMENT '目标端口密度',
  `dominant_direction` VARCHAR(32) DEFAULT NULL COMMENT '主导流向',
  `protocol_distribution` JSON DEFAULT NULL COMMENT '协议分布',
  `dns_top_questions` JSON DEFAULT NULL COMMENT 'DNS Top 域名',
  `dns_query_type_hints` JSON DEFAULT NULL COMMENT 'DNS 查询类型提示',
  `http_host_hints` JSON DEFAULT NULL COMMENT 'HTTP Host 提示',
  `http_method_hints` JSON DEFAULT NULL COMMENT 'HTTP 方法提示',
  `http_status_hints` JSON DEFAULT NULL COMMENT 'HTTP 状态码提示',
  `tls_handshake_hints` JSON DEFAULT NULL COMMENT 'TLS 握手提示',
  `tls_version_hints` JSON DEFAULT NULL COMMENT 'TLS 版本提示',
  `application_signals` JSON DEFAULT NULL COMMENT '应用层动态信号',
  `directionality_indicators` JSON DEFAULT NULL COMMENT '方向性指标',
  `port_density_indicators` JSON DEFAULT NULL COMMENT '端口密度指标',
  `payload_entropy_indicators` JSON DEFAULT NULL COMMENT '载荷熵指标',
  `top_ports` JSON DEFAULT NULL COMMENT 'Top 端口分布',
  `peer_endpoints` JSON DEFAULT NULL COMMENT '对端端点分布',
  `evidence_payload` JSON DEFAULT NULL COMMENT '流量特征证据',
  `feature_digest` VARCHAR(128) DEFAULT NULL COMMENT '特征摘要哈希',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_sec_flow_feature_snapshot_collection_id` (`collection_id`),
  KEY `idx_sec_flow_feature_snapshot_task_id` (`task_id`),
  KEY `idx_sec_flow_feature_snapshot_ip` (`ip`),
  KEY `idx_sec_flow_feature_snapshot_behavior_risk_score` (`behavior_risk_score`),
  KEY `idx_sec_flow_feature_snapshot_created_at` (`created_at`),
  CONSTRAINT `fk_sec_flow_feature_snapshot_collection_id` FOREIGN KEY (`collection_id`) REFERENCES `sec_flow_collection` (`id`),
  CONSTRAINT `fk_sec_flow_feature_snapshot_task_id` FOREIGN KEY (`task_id`) REFERENCES `sec_ip_task` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='流量特征快照表';

CREATE TABLE `sec_risk_score` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '评分记录主键',
  `task_id` BIGINT UNSIGNED NOT NULL COMMENT '关联任务 ID',
  `ip` VARCHAR(64) NOT NULL COMMENT '目标 IP',
  `base_score` DECIMAL(10,2) NOT NULL DEFAULT 0 COMMENT '基础属性贡献分',
  `reputation_score` DECIMAL(10,2) NOT NULL DEFAULT 0 COMMENT '信誉贡献分',
  `attack_surface_score` DECIMAL(10,2) NOT NULL DEFAULT 0 COMMENT '攻击面贡献分',
  `behavior_score` DECIMAL(10,2) NOT NULL DEFAULT 0 COMMENT '行为贡献分',
  `rule_adjustment_value` DECIMAL(10,2) NOT NULL DEFAULT 0 COMMENT '规则修正值',
  `score_value` DECIMAL(10,2) NOT NULL COMMENT '风险分值',
  `risk_level` VARCHAR(32) NOT NULL COMMENT '风险等级',
  `score_reason` VARCHAR(500) DEFAULT NULL COMMENT '评分原因说明',
  `rule_adjustment` VARCHAR(255) DEFAULT NULL COMMENT '规则修正说明',
  `algorithm_version` VARCHAR(128) DEFAULT NULL COMMENT '算法版本',
  `weight_profile` JSON DEFAULT NULL COMMENT '权重口径',
  `is_alert_triggered` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否触发预警',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_sec_risk_score_task_id` (`task_id`),
  KEY `idx_sec_risk_score_ip` (`ip`),
  KEY `idx_sec_risk_score_score_value` (`score_value`),
  KEY `idx_sec_risk_score_risk_level` (`risk_level`),
  KEY `idx_sec_risk_score_created_at` (`created_at`),
  CONSTRAINT `fk_sec_risk_score_task_id` FOREIGN KEY (`task_id`) REFERENCES `sec_ip_task` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='风险评分记录表';

CREATE TABLE `sec_security_config` (
  `flow_enabled` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '流量总开关',
  `flow_mode` VARCHAR(32) NOT NULL DEFAULT 'sample' COMMENT '流量模式',
  `flow_interface_name` VARCHAR(128) DEFAULT NULL COMMENT '在线抓包网卡名',
  `flow_pcap_file_path` VARCHAR(255) DEFAULT NULL COMMENT '离线 pcap 文件路径',
  `flow_sample_profile` VARCHAR(128) DEFAULT NULL COMMENT '样本画像',
  `flow_window_seconds` INT NOT NULL DEFAULT 60 COMMENT '流量窗口秒数',
  `flow_timeout_seconds` INT NOT NULL DEFAULT 5 COMMENT '流量超时秒数',
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '配置主键',
  `whois_endpoint` VARCHAR(255) NOT NULL COMMENT 'WHOIS 数据源',
  `reputation_endpoint` VARCHAR(255) NOT NULL COMMENT '信誉数据源',
  `notify_channel` VARCHAR(64) NOT NULL COMMENT '默认通知渠道',
  `mail_enabled` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '邮件预警开关',
  `mail_sender` VARCHAR(255) DEFAULT NULL COMMENT '发件人',
  `mail_recipient` VARCHAR(255) DEFAULT NULL COMMENT '收件人',
  `smtp_host` VARCHAR(255) DEFAULT NULL COMMENT 'SMTP 主机',
  `smtp_port` INT NOT NULL DEFAULT 25 COMMENT 'SMTP 端口',
  `smtp_username` VARCHAR(255) DEFAULT NULL COMMENT 'SMTP 用户名',
  `smtp_password` VARCHAR(255) DEFAULT NULL COMMENT 'SMTP 密码',
  `smtp_use_tls` TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'SMTP TLS 开关',
  `high_risk_threshold` DECIMAL(10,2) NOT NULL COMMENT '高风险阈值',
  `critical_risk_threshold` DECIMAL(10,2) NOT NULL COMMENT '严重风险阈值',
  `whois_weight` DECIMAL(10,4) NOT NULL COMMENT 'WHOIS 权重',
  `reputation_weight` DECIMAL(10,4) NOT NULL COMMENT '信誉权重',
  `attack_surface_weight` DECIMAL(10,4) NOT NULL COMMENT '攻击面权重',
  `behavior_weight` DECIMAL(10,4) NOT NULL COMMENT '行为权重',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='安全业务配置表';

CREATE TABLE `sec_audit_log` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '审计日志主键',
  `category` VARCHAR(32) NOT NULL COMMENT '审计分类',
  `action` VARCHAR(64) NOT NULL COMMENT '操作动作',
  `actor` VARCHAR(64) DEFAULT NULL COMMENT '操作人',
  `role_code` VARCHAR(32) DEFAULT NULL COMMENT '角色编码',
  `target_type` VARCHAR(64) DEFAULT NULL COMMENT '目标类型',
  `target_id` VARCHAR(128) DEFAULT NULL COMMENT '目标标识',
  `target_label` VARCHAR(255) DEFAULT NULL COMMENT '目标展示名',
  `status` VARCHAR(32) NOT NULL DEFAULT 'SUCCESS' COMMENT '执行状态',
  `summary` VARCHAR(500) DEFAULT NULL COMMENT '摘要',
  `detail` JSON DEFAULT NULL COMMENT '明细载荷',
  `ip` VARCHAR(64) DEFAULT NULL COMMENT '来源 IP',
  `user_agent` VARCHAR(512) DEFAULT NULL COMMENT '来源 UA',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`),
  KEY `idx_sec_audit_log_category` (`category`),
  KEY `idx_sec_audit_log_action` (`action`),
  KEY `idx_sec_audit_log_actor` (`actor`),
  KEY `idx_sec_audit_log_status` (`status`),
  KEY `idx_sec_audit_log_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='安全域审计日志表';

CREATE TABLE `sec_alert_record` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '预警记录主键',
  `task_id` BIGINT UNSIGNED NOT NULL COMMENT '关联任务 ID',
  `score_id` BIGINT UNSIGNED NOT NULL COMMENT '关联评分 ID',
  `ip` VARCHAR(64) NOT NULL COMMENT '目标 IP',
  `alert_level` VARCHAR(32) NOT NULL COMMENT '预警等级',
  `alert_title` VARCHAR(255) NOT NULL COMMENT '预警标题',
  `alert_content` TEXT DEFAULT NULL COMMENT '预警内容',
  `channel` VARCHAR(32) NOT NULL COMMENT '通知渠道',
  `send_status` VARCHAR(32) NOT NULL COMMENT '发送状态',
  `send_time` DATETIME DEFAULT NULL COMMENT '发送时间',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  PRIMARY KEY (`id`),
  KEY `idx_sec_alert_record_task_id` (`task_id`),
  KEY `idx_sec_alert_record_score_id` (`score_id`),
  KEY `idx_sec_alert_record_ip` (`ip`),
  KEY `idx_sec_alert_record_alert_level` (`alert_level`),
  KEY `idx_sec_alert_record_send_status` (`send_status`),
  KEY `idx_sec_alert_record_created_at` (`created_at`),
  CONSTRAINT `fk_sec_alert_record_task_id` FOREIGN KEY (`task_id`) REFERENCES `sec_ip_task` (`id`),
  CONSTRAINT `fk_sec_alert_record_score_id` FOREIGN KEY (`score_id`) REFERENCES `sec_risk_score` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='预警记录表';
