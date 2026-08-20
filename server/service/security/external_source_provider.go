package security

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"lightweight-ip-traffic-sa/server/config"
	"lightweight-ip-traffic-sa/server/utils"
)

var ErrExternalProviderUnavailable = errors.New("external provider unavailable")

const externalCollectorCompletionGrace = time.Second

// BaseInfoSourceProvider 用于封装基础信息来源数据源访问能力。
type BaseInfoSourceProvider interface {
	Name() string
	CollectBaseInfo(ctx context.Context, targetIP string, cfg config.SecurityConfig) (BaseInfoCollectedData, error)
}

// ReputationSourceProvider 用于封装Reputation来源数据源访问能力。
type ReputationSourceProvider interface {
	Name() string
	CollectReputation(ctx context.Context, targetIP string, cfg config.SecurityConfig) (ReputationCollectedData, error)
}

// AttackSurfaceSourceProvider 用于封装AttackSurface来源数据源访问能力。
type AttackSurfaceSourceProvider interface {
	Name() string
	CollectAttackSurface(ctx context.Context, targetIP string, baseInfo BaseInfoCollectedData, cfg config.SecurityConfig) (AttackSurfaceCollectedData, error)
}

// resolveBaseInfoSourceProvider 用于解析基础信息来源Provider。
func resolveBaseInfoSourceProvider(cfg config.SecurityConfig) BaseInfoSourceProvider {
	return realBaseInfoSourceProvider{}
}

// resolveReputationSourceProvider 用于解析Reputation来源Provider。
func resolveReputationSourceProvider(cfg config.SecurityConfig) ReputationSourceProvider {
	return enhancedReputationSourceProvider{}
}

// resolveAttackSurfaceSourceProvider 用于解析AttackSurface来源Provider。
func resolveAttackSurfaceSourceProvider(cfg config.SecurityConfig) AttackSurfaceSourceProvider {
	if cfg.Source.AttackSurface.Enabled {
		if cfg.Source.AttackSurface.NmapEnabled {
			return nmapAttackSurfaceProvider{}
		}
		return limitedPortScanProvider{}
	}
	return noopAttackSurfaceProvider{}
}

// runExternalCollectorStep 用于运行服务启动或业务执行流程。
func runExternalCollectorStep[T any](
	stepName string,
	targetIP string,
	sourceName string,
	configVersion string,
	timeout time.Duration,
	cacheTTL time.Duration,
	execute func(context.Context) (T, error),
	validate func(T) error,
) (T, error) {
	return runCollectorStep(
		stepName,
		targetIP,
		sourceName,
		configVersion,
		extendExternalCollectorDeadline(timeout),
		cacheTTL,
		func() (T, error) {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			return execute(ctx)
		},
		validate,
	)
}

// extendExternalCollectorDeadline 用于执行extendExternalCollectorDeadline流程。
func extendExternalCollectorDeadline(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		timeout = collectorTimeout
	}
	return timeout + externalCollectorCompletionGrace
}

// resolveExternalCollectorTimeout 用于解析ExternalCollectorTimeout。
func resolveExternalCollectorTimeout(stepName string, cfg config.SecurityConfig) time.Duration {
	timeout := collectorTimeout
	switch stepName {
	case "base_info":
		if cfg.Source.RDAP.Enabled {
			rdapTimeout := resolveSourceTTL(cfg.Source.RDAP.TimeoutSeconds, collectorTimeout)
			if rdapTimeout+time.Second > timeout {
				timeout = rdapTimeout + time.Second
			}
		}
	case "reputation":
		if cfg.Source.AbuseIPDB.Enabled {
			abuseTimeout := resolveSourceTTL(cfg.Source.AbuseIPDB.TimeoutSeconds, collectorTimeout)
			if abuseTimeout+time.Second > timeout {
				timeout = abuseTimeout + time.Second
			}
		}
	case "attack_surface":
		timeout = resolveAttackSurfaceStepTimeout(cfg)
		if cfg.Source.AttackSurface.NmapEnabled {
			nmapTimeout := resolveSourceTTL(cfg.Source.AttackSurface.NmapTimeoutSeconds, 8*time.Second)
			if nmapTimeout+time.Second > timeout {
				timeout = nmapTimeout + time.Second
			}
		}
	}
	return timeout
}

// resolveExternalCollectorCacheTTL 用于解析ExternalCollector缓存TTL。
func resolveExternalCollectorCacheTTL(stepName string, cfg config.SecurityConfig) time.Duration {
	switch stepName {
	case "base_info":
		ttls := make([]time.Duration, 0, 2)
		if cfg.Source.GeoLite2.Enabled {
			ttls = append(ttls, resolveSourceTTL(cfg.Source.GeoLite2.CacheTTLSeconds, 24*time.Hour))
		}
		if cfg.Source.RDAP.Enabled {
			ttls = append(ttls, resolveSourceTTL(cfg.Source.RDAP.CacheTTLSeconds, 24*time.Hour))
		}
		return pickMinDuration(ttls, 24*time.Hour)
	case "reputation":
		if cfg.Source.AbuseIPDB.Enabled {
			return resolveSourceTTL(cfg.Source.AbuseIPDB.CacheTTLSeconds, time.Hour)
		}
		return utils.CollectorCacheTTL()
	case "attack_surface":
		return resolveSourceTTL(cfg.Source.AttackSurface.CacheTTLSeconds, 12*time.Hour)
	default:
		return utils.CollectorCacheTTL()
	}
}

// pickMinDuration 用于选取MinDuration。
func pickMinDuration(values []time.Duration, fallback time.Duration) time.Duration {
	if len(values) == 0 {
		return fallback
	}
	minValue := values[0]
	for _, value := range values[1:] {
		if value < minValue {
			minValue = value
		}
	}
	return minValue
}

// unavailableBaseInfoProvider 用于封装unavailable基础信息数据源访问能力。
type unavailableBaseInfoProvider struct {
	sourceName string
}

// Name 用于返回数据源名称。
func (p unavailableBaseInfoProvider) Name() string {
	return normalizeExternalSourceName(p.sourceName, "base-info-default")
}

// CollectBaseInfo 用于采集目标 IP 的基础画像信息。
func (p unavailableBaseInfoProvider) CollectBaseInfo(ctx context.Context, targetIP string, cfg config.SecurityConfig) (BaseInfoCollectedData, error) {
	return BaseInfoCollectedData{}, fmt.Errorf("%w: base info source %s for target %s", ErrExternalProviderUnavailable, p.Name(), targetIP)
}

// unavailableReputationProvider 用于封装unavailableReputation数据源访问能力。
type unavailableReputationProvider struct {
	sourceName string
}

// Name 用于返回数据源名称。
func (p unavailableReputationProvider) Name() string {
	return normalizeExternalSourceName(p.sourceName, "reputation-default")
}

// CollectReputation 用于采集目标 IP 的信誉风险信息。
func (p unavailableReputationProvider) CollectReputation(ctx context.Context, targetIP string, cfg config.SecurityConfig) (ReputationCollectedData, error) {
	return ReputationCollectedData{}, fmt.Errorf("%w: reputation source %s for target %s", ErrExternalProviderUnavailable, p.Name(), targetIP)
}

// unavailableAttackSurfaceProvider 用于封装unavailableAttackSurface数据源访问能力。
type unavailableAttackSurfaceProvider struct {
	sourceName string
}

// Name 用于返回数据源名称。
func (p unavailableAttackSurfaceProvider) Name() string {
	return normalizeExternalSourceName(p.sourceName, "attack-surface-default")
}

// CollectAttackSurface 用于采集目标 IP 的攻击面信息。
func (p unavailableAttackSurfaceProvider) CollectAttackSurface(ctx context.Context, targetIP string, baseInfo BaseInfoCollectedData, cfg config.SecurityConfig) (AttackSurfaceCollectedData, error) {
	return AttackSurfaceCollectedData{}, fmt.Errorf("%w: attack surface source %s for target %s", ErrExternalProviderUnavailable, p.Name(), targetIP)
}

// normalizeExternalSourceName 用于归一化输入参数或业务指标。
func normalizeExternalSourceName(sourceName string, fallback string) string {
	trimmed := strings.TrimSpace(sourceName)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}
