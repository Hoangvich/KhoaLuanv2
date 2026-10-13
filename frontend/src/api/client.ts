import axios, { AxiosError } from 'axios'

const TOKEN_KEY = 'ids_token'

export const tokenStore = {
  get: (): string | null => {
    try {
      return localStorage.getItem(TOKEN_KEY)
    } catch {
      return null
    }
  },
  set: (t: string) => {
    try {
      localStorage.setItem(TOKEN_KEY, t)
    } catch {
      /* trình duyệt chặn lưu trữ: chỉ giữ trong phiên */
    }
  },
  clear: () => {
    try {
      localStorage.removeItem(TOKEN_KEY)
    } catch {
      /* bỏ qua */
    }
  },
}

export const api = axios.create({ baseURL: '/api', timeout: 30000 })

api.interceptors.request.use((cfg) => {
  const t = tokenStore.get()
  if (t) cfg.headers.Authorization = `Bearer ${t}`
  return cfg
})

let onUnauthorized: (() => void) | null = null
export const setUnauthorizedHandler = (fn: () => void) => {
  onUnauthorized = fn
}

api.interceptors.response.use(
  (r) => r,
  (err: AxiosError) => {
    if (err.response?.status === 401 && !err.config?.url?.includes('/auth/login')) onUnauthorized?.()
    return Promise.reject(err)
  },
)

/** Lấy thông báo lỗi tiếng Việt từ phản hồi FastAPI. */
export function errorMessage(err: unknown): string {
  const e = err as AxiosError<{ detail?: unknown }>
  const d = e.response?.data?.detail
  if (typeof d === 'string') return d
  if (Array.isArray(d) && d.length) {
    const first = d[0] as { loc?: string[]; msg?: string }
    return `${first.loc?.slice(-1)[0] ?? ''}: ${first.msg ?? 'giá trị không hợp lệ'}`
  }
  if (e.code === 'ERR_NETWORK') return 'Không kết nối được tới máy chủ API'
  return e.message || 'Đã có lỗi xảy ra'
}
