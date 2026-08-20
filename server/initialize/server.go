package initialize

import (
	"errors"
	"fmt"
	"syscall"

	"lightweight-ip-traffic-sa/server/config"
	"lightweight-ip-traffic-sa/server/global"
)

// Run 用于运行服务启动或业务执行流程。
func Run() error {
	// 启动链路：读配置 → 初始化 Redis（可降级）→ 初始化 MySQL（硬依赖）→ 补种子数据 → 装配并启动 HTTP 服务。
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	global.AppConfig = cfg
	global.Config = cfg

	// Redis 只承担缓存加速，挂了不影响主业务，因此失败仅打印日志并继续（降级为无缓存模式）；
	// 全局 global.RDB 保持 nil，utils/cache.go 会据此自动跳过缓存、直连数据源。
	rdb, err := InitRedis()
	if err != nil {
		fmt.Printf("redis 初始化失败，已降级为无缓存模式: %v\n", err)
	} else {
		global.RDB = rdb
	}

	// MySQL 是主存储，所有业务读写都依赖它；一旦连不上必须立即退出，避免带病运行产生脏数据。
	db, err := InitDB()
	if err != nil {
		return err
	}
	global.DB = db

	// 补齐种子数据：默认 admin/manager/user 账号与一条安全配置，保证项目 clone 后开箱即用。
	if err := InitDemoUsers(); err != nil {
		return err
	}

	engine := SetupRouter()
	if err := engine.Run(fmt.Sprintf(":%s", cfg.App.Port)); err != nil {
		// 端口占用是高频运维问题，单独识别 EADDRINUSE 给出可读中文提示，
		// 而不是把底层 "address already in use" 原始错误直接甩给用户。
		if errors.Is(err, syscall.EADDRINUSE) {
			return fmt.Errorf("服务启动失败：端口 %s 已被占用，请先停止已有进程或改用 APP_PORT/PORT 指定其他端口", cfg.App.Port)
		}
		return err
	}
	return nil
}
