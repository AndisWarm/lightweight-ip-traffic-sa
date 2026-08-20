package utils

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"lightweight-ip-traffic-sa/server/global"
)

// 缓存 key 统一采用 "域:模块:标识" 的命名空间前缀，避免不同业务的数据相互覆盖。
const (
	SecurityDashboardSummaryCacheKey = "security:dashboard:summary"
	SecurityConfigCacheKey           = "security:config:current"
	SecurityTaskDetailCachePrefix    = "security:task:detail:v2"
	SecurityAlertDetailCachePrefix   = "security:alert:detail"
	defaultDashboardSummaryTTL       = 30 * time.Second
	defaultSecurityConfigTTL         = 5 * time.Minute
	defaultDetailQueryTTL            = 2 * time.Minute
	defaultCollectorTTL              = 30 * time.Minute
)

// CacheGetJSON 用于执行缓存GetJSON流程。
func CacheGetJSON(key string, dest interface{}) (bool, error) {
	// Redis 不可用时（global.RDB 为 nil，即初始化阶段降级）直接返回未命中，
	// 让调用方回退到直连数据源查库，缓存层对业务透明。
	if global.RDB == nil {
		return false, nil
	}

	value, err := global.RDB.Get(context.Background(), key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil
		}
		log.Printf("缓存读取失败，已降级为直连数据源，key=%s err=%v", key, err)
		return false, err
	}

	if err := json.Unmarshal([]byte(value), dest); err != nil {
		log.Printf("缓存反序列化失败，已忽略缓存内容，key=%s err=%v", key, err)
		return false, err
	}

	return true, nil
}

// CacheSetJSON 用于执行缓存SetJSON流程。
func CacheSetJSON(key string, value interface{}, ttl time.Duration) error {
	if global.RDB == nil {
		return nil
	}

	payload, err := json.Marshal(value)
	if err != nil {
		log.Printf("缓存序列化失败，已跳过写入，key=%s err=%v", key, err)
		return err
	}

	if err := global.RDB.Set(context.Background(), key, payload, ttl).Err(); err != nil {
		log.Printf("缓存写入失败，已降级为无缓存写入，key=%s ttl=%s err=%v", key, ttl, err)
		return err
	}
	return nil
}

// CacheDelete 用于执行缓存Delete流程。
func CacheDelete(keys ...string) error {
	if global.RDB == nil || len(keys) == 0 {
		return nil
	}

	if err := global.RDB.Del(context.Background(), keys...).Err(); err != nil {
		log.Printf("缓存失效失败，后续请求将继续尝试直连数据源，keys=%s err=%v", strings.Join(keys, ","), err)
		return err
	}
	return nil
}

// BuildCollectorCacheKey 用于构建Collector缓存Key。
func BuildCollectorCacheKey(targetIP, sourceName, configVersion string) string {
	// 关键点：key 必须同时包含 target_ip + source + config_version。
	// 目标 IP 与来源决定"缓存的是谁的、用什么数据源算的"；config_version 的哈希保证
	// 一旦改了权重/阈值等配置，key 随之变化、旧缓存自动失效，避免脏结果被长期复用。
	configHash := sha256.Sum256([]byte(configVersion))
	return fmt.Sprintf(
		"security:collector:%s:%s:%s",
		sanitizeCacheSegment(sourceName),
		sanitizeCacheSegment(targetIP),
		hex.EncodeToString(configHash[:8]),
	)
}

// BuildTaskDetailCacheKey 用于构建任务Detail缓存Key。
func BuildTaskDetailCacheKey(taskID uint64) string {
	return fmt.Sprintf("%s:%d", SecurityTaskDetailCachePrefix, taskID)
}

// BuildAlertDetailCacheKey 用于构建预警Detail缓存Key。
func BuildAlertDetailCacheKey(alertID uint64) string {
	return fmt.Sprintf("%s:%d", SecurityAlertDetailCachePrefix, alertID)
}

// sanitizeCacheSegment 用于清理缓存Segment展示数据。
func sanitizeCacheSegment(input string) string {
	// 清理 key 分段里的特殊字符：IP 中的点、路径里的斜杠、空格等会破坏 key 的可读性与工具解析，
	// 统一替换成下划线；保留冒号用于 Redis key 的分层结构。
	replacer := strings.NewReplacer(
		":", "_",
		".", "_",
		"/", "_",
		"\\", "_",
		" ", "_",
	)
	return replacer.Replace(strings.TrimSpace(input))
}

// DashboardSummaryCacheTTL 用于执行总览摘要缓存TTL流程。
func DashboardSummaryCacheTTL() time.Duration {
	return resolveCacheTTL(global.AppConfig.Security.Cache.DashboardSummaryTTLSeconds, defaultDashboardSummaryTTL)
}

// SecurityConfigCacheTTL 用于执行安全配置缓存TTL流程。
func SecurityConfigCacheTTL() time.Duration {
	return resolveCacheTTL(global.AppConfig.Security.Cache.SecurityConfigTTLSeconds, defaultSecurityConfigTTL)
}

// CollectorCacheTTL 用于执行Collector缓存TTL流程。
func CollectorCacheTTL() time.Duration {
	return resolveCacheTTL(global.AppConfig.Security.Cache.CollectorTTLSeconds, defaultCollectorTTL)
}

// DetailQueryCacheTTL 用于执行DetailQuery缓存TTL流程。
func DetailQueryCacheTTL() time.Duration {
	return resolveCacheTTL(global.AppConfig.Security.Cache.DetailQueryTTLSeconds, defaultDetailQueryTTL)
}

// resolveCacheTTL 用于解析缓存TTL。
func resolveCacheTTL(seconds int, fallback time.Duration) time.Duration {
	// 配置值 <= 0 视为未配置，回退到内置默认 TTL；大于 0 则按秒换算。
	if seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}
