package global

import (
	"lightweight-ip-traffic-sa/server/config"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

var (
	AppConfig config.ServerConfig
	Config    config.ServerConfig
	DB        *gorm.DB
	RDB       *redis.Client
)
