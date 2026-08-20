// 流量配置同步：配置页改动流量开关后，通过自定义事件通知同窗口内其它组件，再写 localStorage 通过 storage 事件通知其它标签页，
// 保证"实时流量监控"等页面能即时感知配置变化而不用手动刷新。
const SECURITY_FLOW_CONFIG_SYNC_EVENT = 'security-flow-config-updated'
const SECURITY_FLOW_CONFIG_SYNC_STORAGE_KEY = 'security-flow-config-updated'

// 归一化载荷：统一字段、兜底默认值并打上时间戳，消费方拿到的结构稳定，避免因来源不同而字段缺失。
const normalizeFlowConfigPayload = (payload = {}) => ({
  flowEnabled: Boolean(payload.flowEnabled),
  flowMode: payload.flowMode || 'sample',
  updatedAt: Date.now(),
})

export const emitSecurityFlowConfigSync = (payload) => {
  // 兼容 SSR/测试环境：无 window 时静默跳过，避免在非浏览器环境报错。
  if (typeof window === 'undefined') {
    return
  }

  const normalizedPayload = normalizeFlowConfigPayload(payload)
  // 同窗口组件间通信用 CustomEvent；跨标签页则靠下面写入 localStorage 触发对方 storage 事件。
  window.dispatchEvent(new CustomEvent(SECURITY_FLOW_CONFIG_SYNC_EVENT, {
    detail: normalizedPayload,
  }))

  try {
    window.localStorage.setItem(
      SECURITY_FLOW_CONFIG_SYNC_STORAGE_KEY,
      JSON.stringify(normalizedPayload),
    )
  } catch {
    // 隐私模式/配额满等场景写入可能失败，忽略即可，不影响同窗口广播。
  }
}

export const readSecurityFlowConfigSync = () => {
  // 页面初次挂载时读取上次落库的配置作为默认值，避免刷新后丢失配置上下文。
  if (typeof window === 'undefined') {
    return null
  }

  try {
    const raw = window.localStorage.getItem(SECURITY_FLOW_CONFIG_SYNC_STORAGE_KEY)
    if (!raw) {
      return null
    }
    return normalizeFlowConfigPayload(JSON.parse(raw))
  } catch {
    // 数据被破坏/格式不符时回退 null，消费方走默认值，绝不因脏数据抛异常。
    return null
  }
}

export const subscribeSecurityFlowConfigSync = (listener) => {
  if (typeof window === 'undefined' || typeof listener !== 'function') {
    return () => {}
  }

  const handleCustomEvent = (event) => {
    listener(normalizeFlowConfigPayload(event.detail))
  }

  // storage 事件只在"其它标签页"修改 localStorage 时触发，是本窗口外的同步通道。
  const handleStorageEvent = (event) => {
    if (event.key !== SECURITY_FLOW_CONFIG_SYNC_STORAGE_KEY || !event.newValue) {
      return
    }

    try {
      listener(normalizeFlowConfigPayload(JSON.parse(event.newValue)))
    } catch {
    }
  }

  window.addEventListener(SECURITY_FLOW_CONFIG_SYNC_EVENT, handleCustomEvent)
  window.addEventListener('storage', handleStorageEvent)

  // 返回解绑函数供组件 onUnmounted 调用，避免组件销毁后监听器泄漏。
  return () => {
    window.removeEventListener(SECURITY_FLOW_CONFIG_SYNC_EVENT, handleCustomEvent)
    window.removeEventListener('storage', handleStorageEvent)
  }
}
