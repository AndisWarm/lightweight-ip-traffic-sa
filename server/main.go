package main

import (
	"log"

	"lightweight-ip-traffic-sa/server/initialize"
)

// main 是后端服务或辅助脚本的启动入口。
func main() {
	if err := initialize.Run(); err != nil {
		log.Fatal(err)
	}
}
