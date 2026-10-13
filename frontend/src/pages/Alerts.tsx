import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Card, DatePicker, Input, Segmented, Select, Space, Table, Typography } from 'antd'
import type { Dayjs } from 'dayjs'
import { useAlerts } from '../api/hooks'
import type { Alert } from '../api/types'
import { LabelTag, SeverityTag, SourceTag, StatusTag } from '../components/Tags'
import { fmtDuration, fmtInt, fmtShort, fromNow, target } from '../utils/format'

const STATUS_OPTS = [
  { label: 'Đang xử lý', value: 'active' },
  { label: 'Đang mở', value: 'open' },
  { label: 'Đã xác nhận', value: 'ack' },
  { label: 'Đã đóng', value: 'closed' },
  { label: 'Tất cả', value: '' },
]

export default function Alerts() {
  const nav = useNavigate()
  const [sp, setSp] = useSearchParams()
  const [range, setRange] = useState<[Dayjs | null, Dayjs | null] | null>(null)
  const status = sp.get('status') ?? 'active'
  const label = sp.get('label') ?? undefined
  const severity = sp.get('severity') ?? undefined
  const q = sp.get('q') ?? ''
  const page = Number(sp.get('page') ?? 1)
  const size = Number(sp.get('size') ?? 20)

  const set = (patch: Record<string, string | number | undefined>) => {
    const next = new URLSearchParams(sp)
    for (const [k, v] of Object.entries(patch)) {
      if (v === undefined || v === '') next.delete(k)
      else next.set(k, String(v))
    }
    if (!('page' in patch)) next.delete('page')
    setSp(next, { replace: true })
  }

  const { data, isFetching } = useAlerts({
    status: status || undefined,
    label,
    severity,
    q: q || undefined,
    since: range?.[0]?.toISOString(),
    until: range?.[1]?.toISOString(),
    page,
    size,
  })

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Typography.Title level={4} style={{ margin: 0 }}>
        Cảnh báo
      </Typography.Title>
      <Card size="small">
        <div style={{ overflowX: 'auto', marginBottom: 12 }}>
          <Segmented options={STATUS_OPTS} value={status} onChange={(v) => set({ status: v as string })} />
        </div>
        <Space wrap>
          <Select
            allowClear
            placeholder="Loại tấn công"
            style={{ width: 160 }}
            value={label}
            onChange={(v) => set({ label: v })}
            options={[
              { value: 'DoS/DDoS', label: 'DoS/DDoS' },
              { value: 'PortScan', label: 'Quét cổng' },
              { value: 'BruteForce', label: 'Dò mật khẩu' },
            ]}
          />
          <Select
            allowClear
            placeholder="Mức độ"
            style={{ width: 130 }}
            value={severity}
            onChange={(v) => set({ severity: v })}
            options={[
              { value: 'high', label: 'Cao' },
              { value: 'medium', label: 'Trung bình' },
              { value: 'low', label: 'Thấp' },
            ]}
          />
          <Input.Search
            allowClear
            placeholder="Tìm theo IP"
            defaultValue={q}
            style={{ width: 200 }}
            onSearch={(v) => set({ q: v.trim() })}
          />
          <DatePicker.RangePicker
            showTime
            format="HH:mm DD/MM"
            value={range}
            onChange={(v) => setRange(v as [Dayjs | null, Dayjs | null] | null)}
            placeholder={['Từ', 'Đến']}
          />
        </Space>
      </Card>
      <Card size="small">
        <Table<Alert>
          size="middle"
          rowKey="id"
          loading={isFetching && !data}
          dataSource={data?.items ?? []}
          locale={{ emptyText: 'Không có cảnh báo phù hợp' }}
          onRow={(r) => ({ onClick: () => nav(`/alerts/${r.id}`), style: { cursor: 'pointer' } })}
          pagination={{
            current: page,
            pageSize: size,
            total: data?.total ?? 0,
            showSizeChanger: true,
            showTotal: (t) => `${fmtInt(t)} cảnh báo`,
            onChange: (p, s) => set({ page: p, size: s }),
          }}
          scroll={{ x: 1000 }}
          columns={[
            { title: '#', dataIndex: 'id', width: 70 },
            { title: 'Mức', dataIndex: 'severity', width: 110, render: (s) => <SeverityTag severity={s} /> },
            { title: 'Loại', dataIndex: 'label', width: 130, render: (l) => <LabelTag label={l} /> },
            {
              title: 'Nguồn',
              render: (_, a) =>
                a.src_ip ? <Typography.Text code>{a.src_ip}</Typography.Text> : `${fmtInt(a.src_count)} IP nguồn`,
            },
            { title: 'Đích', render: (_, a) => <Typography.Text code>{target(a.dst_ip, a.dst_port)}</Typography.Text> },
            { title: 'Số luồng', dataIndex: 'flow_count', align: 'right', render: fmtInt },
            { title: 'Phát hiện bởi', dataIndex: 'source', render: (s) => <SourceTag source={s} /> },
            { title: 'Bắt đầu', dataIndex: 'first_seen', render: fmtShort },
            { title: 'Kéo dài', render: (_, a) => fmtDuration(a.first_seen, a.last_seen) },
            { title: 'Lần cuối', dataIndex: 'last_seen', render: fromNow },
            { title: 'Trạng thái', dataIndex: 'status', width: 120, render: (s) => <StatusTag status={s} /> },
          ]}
        />
      </Card>
    </Space>
  )
}
