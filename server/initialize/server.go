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
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}
	global.AppConfig = cfg
	global.Config = cfg

	rdb, err := InitRedis()
	if err != nil {
		fmt.Printf("redis 初始化失败，已降级为无缓存模式: %v\n", err)
	} else {
		global.RDB = rdb
	}

	db, err := InitDB()
	if err != nil {
		return err
	}
	global.DB = db

	if err := InitDemoUsers(); err != nil {
		return err
	}

	engine := SetupRouter()
	if err := engine.Run(fmt.Sprintf(":%s", cfg.App.Port)); err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			return fmt.Errorf("服务启动失败：端口 %s 已被占用，请先停止已有进程或改用 APP_PORT/PORT 指定其他端口", cfg.App.Port)
		}
		return err
	}
	return nil
}
