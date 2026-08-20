package initialize

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"lightweight-ip-traffic-sa/server/global"
)

// InitRedis 用于初始化运行时依赖或基础数据。
func InitRedis() (*redis.Client, error) {
	// 若配置显式关闭 Redis，直接返回 nil 客户端且不报错，调用方据此进入无缓存降级模式。
	cfg := global.AppConfig.Redis
	if !cfg.Enabled {
		return nil, nil
	}

	// PoolSize 是连接池缓存连接数的上限而非预建数量：连接按需创建，空闲时回收复用。
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
		PoolSize: cfg.PoolSize,
	})

	// NewClient 只注册配置不会立刻建连，必须 Ping 一次才能确认 Redis 真实可用；
	// 用 2 秒超时，避免 Redis 不可达时启动阶段卡死过久。
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		// 探活失败主动释放连接池资源并返回错误；上层 server.Run 捕获后降级，不会让进程崩溃。
		_ = client.Close()
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}

	return client, nil
}
