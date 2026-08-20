package utils

// NormalizePage 用于归一化输入参数或业务指标。
func NormalizePage(page int) int {
	if page <= 0 {
		return 1
	}
	return page
}

// NormalizePageSize 用于归一化输入参数或业务指标。
func NormalizePageSize(pageSize int) int {
	switch {
	case pageSize <= 0:
		return 10
	case pageSize > 100:
		return 100
	default:
		return pageSize
	}
}
