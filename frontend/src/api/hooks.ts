import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from './client'
import type {
  Alert,
  AlertDetail,
  AlertPage,
  Flow,
  ModelInfo,
  Overview,
  PipelineRun,
  PipelineStatus,
  RuntimeSettings,
  Timeseries,
  TopRow,
  User,
} from './types'

const LIVE = 5000 // làm mới theo chu kỳ pipeline (5 s)

export const useOverview = (minutes: number) =>
  useQuery({
    queryKey: ['overview', minutes],
    queryFn: async () => (await api.get<Overview>('/stats/overview', { params: { minutes } })).data,
    refetchInterval: LIVE,
    placeholderData: keepPreviousData,
  })

export const useTimeseries = (minutes: number) =>
  useQuery({
    queryKey: ['timeseries', minutes],
    queryFn: async () => (await api.get<Timeseries>('/stats/timeseries', { params: { minutes } })).data,
    refetchInterval: LIVE,
    placeholderData: keepPreviousData,
  })

export const useTop = (minutes: number) =>
  useQuery({
    queryKey: ['top', minutes],
    queryFn: async () =>
      (await api.get<{ sources: TopRow[]; targets: TopRow[] }>('/stats/top', { params: { minutes } })).data,
    refetchInterval: LIVE * 2,
    placeholderData: keepPreviousData,
  })

export interface AlertFilters {
  status?: string
  label?: string
  severity?: string
  q?: string
  since?: string
  until?: string
  page: number
  size: number
}

export const useAlerts = (f: AlertFilters) =>
  useQuery({
    queryKey: ['alerts', f],
    queryFn: async () => {
      const params = Object.fromEntries(Object.entries(f).filter(([, v]) => v !== undefined && v !== ''))
      return (await api.get<AlertPage>('/alerts', { params })).data
    },
    refetchInterval: LIVE,
    placeholderData: keepPreviousData,
  })

export const useAlert = (id: number) =>
  useQuery({
    queryKey: ['alert', id],
    queryFn: async () => (await api.get<AlertDetail>(`/alerts/${id}`)).data,
    refetchInterval: LIVE,
  })

export const useAlertAction = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, action, note }: { id: number; action: 'ack' | 'close'; note?: string }) =>
      (await api.post<Alert>(`/alerts/${id}/${action}`, { note })).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['alerts'] })
      qc.invalidateQueries({ queryKey: ['alert'] })
      qc.invalidateQueries({ queryKey: ['overview'] })
    },
  })
}

export const useRecentFlows = (params: { attacks_only?: boolean; limit?: number }) =>
  useQuery({
    queryKey: ['flows', params],
    queryFn: async () => (await api.get<Flow[]>('/flows', { params })).data,
    refetchInterval: LIVE,
  })

export const usePipelineStatus = () =>
  useQuery({
    queryKey: ['pipeline-status'],
    queryFn: async () => (await api.get<PipelineStatus>('/pipeline/status')).data,
    refetchInterval: LIVE,
  })

export const usePipelineRuns = (onlyData: boolean) =>
  useQuery({
    queryKey: ['pipeline-runs', onlyData],
    queryFn: async () =>
      (await api.get<PipelineRun[]>('/pipeline/runs', { params: { limit: 100, only_data: onlyData } })).data,
    refetchInterval: LIVE,
  })

export const useModelInfo = () =>
  useQuery({ queryKey: ['model'], queryFn: async () => (await api.get<ModelInfo>('/model')).data })

export const useSettings = () =>
  useQuery({ queryKey: ['settings'], queryFn: async () => (await api.get<RuntimeSettings>('/settings')).data })

export const useSaveSettings = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: Partial<RuntimeSettings>) => (await api.put<RuntimeSettings>('/settings', body)).data,
    onSuccess: (data) => {
      qc.setQueryData(['settings'], data)
      qc.invalidateQueries({ queryKey: ['overview'] })
      qc.invalidateQueries({ queryKey: ['model'] })
    },
  })
}

export const useTestNotification = () =>
  useMutation({
    mutationFn: async (body: { channel: 'telegram' | 'email'; recipient?: string }) =>
      (await api.post<{ ok: boolean; recipient: string }>('/settings/test-notification', body)).data,
  })

export const useUsers = () =>
  useQuery({ queryKey: ['users'], queryFn: async () => (await api.get<User[]>('/users')).data })

export const useSaveUser = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, ...body }: Partial<User> & { id?: number; password?: string }) =>
      id ? (await api.put<User>(`/users/${id}`, body)).data : (await api.post<User>('/users', body)).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })
}

export const useDeleteUser = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: number) => api.delete(`/users/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })
}
