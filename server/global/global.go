package global

import (
	"lightweight-ip-traffic-sa/server/config"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// 进程级全局单例：初始化完成后由 initialize 包写入，业务各层直接引用，避免层层传递依赖。
// AppConfig 与 Config 是同一份配置的两份副本（兼容历史命名）；DB/RDB 分别持有 MySQL 与 Redis 单例，RDB 在 Redis 降级时保持 nil。
var (
	AppConfig config.ServerConfig
	Config    config.ServerConfig
	DB        *gorm.DB
	RDB       *redis.Client
)
