const SECURITY_FLOW_CONFIG_SYNC_EVENT = 'security-flow-config-updated'
const SECURITY_FLOW_CONFIG_SYNC_STORAGE_KEY = 'security-flow-config-updated'

const normalizeFlowConfigPayload = (payload = {}) => ({
  flowEnabled: Boolean(payload.flowEnabled),
  flowMode: payload.flowMode || 'sample',
  updatedAt: Date.now(),
})

export const emitSecurityFlowConfigSync = (payload) => {
  if (typeof window === 'undefined') {
    return
  }

  const normalizedPayload = normalizeFlowConfigPayload(payload)
  window.dispatchEvent(new CustomEvent(SECURITY_FLOW_CONFIG_SYNC_EVENT, {
    detail: normalizedPayload,
  }))

  try {
    window.localStorage.setItem(
      SECURITY_FLOW_CONFIG_SYNC_STORAGE_KEY,
      JSON.stringify(normalizedPayload),
    )
  } catch {
  }
}

export const readSecurityFlowConfigSync = () => {
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

  return () => {
    window.removeEventListener(SECURITY_FLOW_CONFIG_SYNC_EVENT, handleCustomEvent)
    window.removeEventListener('storage', handleStorageEvent)
  }
}
