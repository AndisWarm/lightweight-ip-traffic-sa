package security

import (
	"context"

	"lightweight-ip-traffic-sa/server/config"
)

// RealBaseInfoCollector 用于采集Real基础信息特征数据。
type RealBaseInfoCollector struct{}

// RealReputationCollector 用于执行真实信誉采集链路。
type RealReputationCollector struct{}

// RealAttackSurfaceCollector 用于执行真实攻击面采集链路。
type RealAttackSurfaceCollector struct{}

// Collect 用于执行Collect流程。
func (c RealBaseInfoCollector) Collect(taskID uint64, targetIP string, cfg config.SecurityConfig) (BaseInfoCollectedData, error) {
	// 真实采集器统一走"解析具体 provider → 带超时/缓存/校验的通用步骤"，
	// provider 由配置决定（如 GeoLite2+RDAP、本地黑名单、有限端口探测）。
	provider := resolveBaseInfoSourceProvider(cfg)
	configVersion := buildCollectorConfigVersion(cfg)
	return runExternalCollectorStep(
		"base_info",
		targetIP,
		provider.Name(),
		configVersion,
		resolveExternalCollectorTimeout("base_info", cfg),
		resolveExternalCollectorCacheTTL("base_info", cfg),
		func(ctx context.Context) (BaseInfoCollectedData, error) {
			return provider.CollectBaseInfo(ctx, targetIP, cfg)
		},
		validateBaseInfoCollectedData,
	)
}

// Collect 用于执行Collect流程。
func (c RealReputationCollector) Collect(targetIP string, cfg config.SecurityConfig) (ReputationCollectedData, error) {
	provider := resolveReputationSourceProvider(cfg)
	configVersion := buildCollectorConfigVersion(cfg)
	return runExternalCollectorStep(
		"reputation",
		targetIP,
		provider.Name(),
		configVersion,
		resolveExternalCollectorTimeout("reputation", cfg),
		resolveExternalCollectorCacheTTL("reputation", cfg),
		func(ctx context.Context) (ReputationCollectedData, error) {
			return provider.CollectReputation(ctx, targetIP, cfg)
		},
		validateReputationCollectedData,
	)
}

// Collect 用于执行Collect流程。
func (c RealAttackSurfaceCollector) Collect(targetIP string, baseInfo BaseInfoCollectedData, cfg config.SecurityConfig) (AttackSurfaceCollectedData, error) {
	provider := resolveAttackSurfaceSourceProvider(cfg)
	configVersion := buildCollectorConfigVersion(cfg)
	return runExternalCollectorStep(
		"attack_surface",
		targetIP,
		provider.Name(),
		configVersion,
		resolveExternalCollectorTimeout("attack_surface", cfg),
		resolveExternalCollectorCacheTTL("attack_surface", cfg),
		func(ctx context.Context) (AttackSurfaceCollectedData, error) {
			return provider.CollectAttackSurface(ctx, targetIP, baseInfo, cfg)
		},
		validateAttackSurfaceCollectedData,
	)
}
