import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { api, setUnauthorizedHandler, tokenStore } from '../api/client'
import type { User } from '../api/types'

interface AuthState {
  user: User | null
  loading: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => void
  refresh: () => Promise<void>
}

const Ctx = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const qc = useQueryClient()

  const logout = useCallback(() => {
    tokenStore.clear()
    setUser(null)
    qc.clear()
  }, [qc])

  const refresh = useCallback(async () => {
    if (!tokenStore.get()) {
      setUser(null)
      return
    }
    const { data } = await api.get<User>('/auth/me')
    setUser(data)
  }, [])

  useEffect(() => {
    setUnauthorizedHandler(logout)
    refresh()
      .catch(() => logout())
      .finally(() => setLoading(false))
  }, [logout, refresh])

  const login = async (username: string, password: string) => {
    const { data } = await api.post<{ access_token: string; user: User }>('/auth/login', { username, password })
    tokenStore.set(data.access_token)
    setUser(data.user)
  }

  return <Ctx.Provider value={{ user, loading, login, logout, refresh }}>{children}</Ctx.Provider>
}

export function useAuth() {
  const c = useContext(Ctx)
  if (!c) throw new Error('useAuth phải nằm trong AuthProvider')
  return c
}
