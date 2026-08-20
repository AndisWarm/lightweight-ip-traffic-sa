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
	// 命令行工具：给定 mmdb 库文件与 IP，打印该 IP 的 GeoIP 查询结果，便于人工排查归属地解析问题。
	dbPath := flag.String("db", "", "mmdb 文件路径，例如 data/geoip/GeoLite2-City.mmdb")
	targetIP := flag.String("ip", "", "待查询 IP，例如 8.8.8.8")
	pretty := flag.Bool("pretty", true, "是否格式化输出 JSON")
	flag.Parse()

	// 先做参数校验：缺参数直接报错退出，避免后续拿空值做无意义查询。
	if *dbPath == "" {
		exitWithMessage("缺少 -db 参数")
	}
	if *targetIP == "" {
		exitWithMessage("缺少 -ip 参数")
	}

	// 用 net.ParseIP 校验 IP 合法性，非法 IP 提前拦截，否则 mmdb 查询会报错或返回空。
	parsedIP := net.ParseIP(*targetIP)
	if parsedIP == nil {
		exitWithMessage(fmt.Sprintf("IP 格式不合法: %s", *targetIP))
	}

	// 打开 mmdb 文件，失败多半是路径不对或文件损坏；defer Close 保证函数退出时释放文件句柄。
	reader, err := maxminddb.Open(*dbPath)
	if err != nil {
		exitWithMessage(fmt.Sprintf("打开 mmdb 文件失败: %v", err))
	}
	defer reader.Close()

	// Lookup 按 IP 精确查询并反序列化进 map，结果含国家/城市/经纬度/ASN 等字段。
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
