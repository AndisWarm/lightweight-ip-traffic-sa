import { computed } from 'vue'

export const useSecurityListStats = (items, pagination, filters, statsBuilder, filterTextBuilder) => {
  const stats = computed(() => statsBuilder(items.value, pagination))
  const activeFilterText = computed(() => filterTextBuilder(filters))

  return {
    stats,
    activeFilterText,
  }
}
