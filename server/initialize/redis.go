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
	cfg := global.AppConfig.Redis
	if !cfg.Enabled {
		return nil, nil
	}

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
		PoolSize: cfg.PoolSize,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}

	return client, nil
}
