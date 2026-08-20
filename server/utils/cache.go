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
	if seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}
