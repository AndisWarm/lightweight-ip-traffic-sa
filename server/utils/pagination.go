package utils

// NormalizePage 用于归一化输入参数或业务指标。
func NormalizePage(page int) int {
	// 页码最小为 1：前端可能传 0 或负数（或漏传默认 0），统一归一化避免 SQL LIMIT 出现非法值。
	if page <= 0 {
		return 1
	}
	return page
}

// NormalizePageSize 用于归一化输入参数或业务指标。
func NormalizePageSize(pageSize int) int {
	// 每页条数双向夹逼：默认 10、上限 100，防止恶意请求 pageSize=100000 打爆内存与数据库。
	switch {
	case pageSize <= 0:
		return 10
	case pageSize > 100:
		return 100
	default:
		return pageSize
	}
}
