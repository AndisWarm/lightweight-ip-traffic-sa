package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/oschwald/maxminddb-golang"
)

// main 是后端服务或辅助脚本的启动入口。
func main() {
	dbPath := flag.String("db", "", "mmdb 文件路径，例如 data/geoip/GeoLite2-City.mmdb")
	targetIP := flag.String("ip", "", "待查询 IP，例如 8.8.8.8")
	pretty := flag.Bool("pretty", true, "是否格式化输出 JSON")
	flag.Parse()

	if *dbPath == "" {
		exitWithMessage("缺少 -db 参数")
	}
	if *targetIP == "" {
		exitWithMessage("缺少 -ip 参数")
	}

	parsedIP := net.ParseIP(*targetIP)
	if parsedIP == nil {
		exitWithMessage(fmt.Sprintf("IP 格式不合法: %s", *targetIP))
	}

	reader, err := maxminddb.Open(*dbPath)
	if err != nil {
		exitWithMessage(fmt.Sprintf("打开 mmdb 文件失败: %v", err))
	}
	defer reader.Close()

	var payload map[string]any
	if err := reader.Lookup(parsedIP, &payload); err != nil {
		exitWithMessage(fmt.Sprintf("查询 mmdb 失败: %v", err))
	}

	var output []byte
	if *pretty {
		output, err = json.MarshalIndent(payload, "", "  ")
	} else {
		output, err = json.Marshal(payload)
	}
	if err != nil {
		exitWithMessage(fmt.Sprintf("序列化结果失败: %v", err))
	}

	fmt.Printf("db=%s\n", *dbPath)
	fmt.Printf("ip=%s\n", parsedIP.String())
	fmt.Println(string(output))
}

// exitWithMessage 用于输出错误信息并终止脚本。
func exitWithMessage(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
