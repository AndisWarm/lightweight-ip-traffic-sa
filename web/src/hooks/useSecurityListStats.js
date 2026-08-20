import { computed } from 'vue'

// 列表统计/筛选文案复用：把"当前列表的统计数字"和"当前筛选条件描述"抽成组合式函数，
// 让任务列表、预警列表等页面共用同一套派生逻辑，避免各自重复写 computed。
export const useSecurityListStats = (items, pagination, filters, statsBuilder, filterTextBuilder) => {
  const stats = computed(() => statsBuilder(items.value, pagination))
  const activeFilterText = computed(() => filterTextBuilder(filters))

  return {
    stats,
    activeFilterText,
  }
}
