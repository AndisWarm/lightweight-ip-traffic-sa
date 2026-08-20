package main

import (
	"log"

	"lightweight-ip-traffic-sa/server/initialize"
)

// main 是后端服务或辅助脚本的启动入口。
func main() {
	// 启动逻辑全部收敛在 initialize.Run，main 只兜底：出错就 log.Fatal 打印并退出进程。
	if err := initialize.Run(); err != nil {
		log.Fatal(err)
	}
}
