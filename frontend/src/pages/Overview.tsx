import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Card, Col, Empty, Row, Segmented, Space, Statistic, Table, Tag, Tooltip, Typography } from 'antd'
import ReactECharts from 'echarts-for-react'
import dayjs from 'dayjs'
import { useAlerts, useOverview, useTimeseries, useTop } from '../api/hooks'
import type { Alert, FlowLabel, TopRow } from '../api/types'
import { LABEL_COLOR, LABEL_VI, LabelTag, SeverityTag, SourceTag } from '../components/Tags'
import { fmtInt, fmtPct, fromNow, target } from '../utils/format'

const RANGES = [
  { label: '15 phút', value: 15 },
  { label: '1 giờ', value: 60 },
  { label: '6 giờ', value: 360 },
  { label: '24 giờ', value: 1440 },
  { label: '7 ngày', value: 10080 },
]
const ORDER: FlowLabel[] = ['BENIGN', 'DoS/DDoS', 'PortScan', 'BruteForce', 'INVALID']

function bucketMinutes(range: number) {
  if (range <= 60) return 1
  if (range <= 360) return 5
  if (range <= 1440) return 15
  return 60
}

function TrafficChart({ minutes }: { minutes: number }) {
  const { data } = useTimeseries(minutes)
  const option = useMemo(() => {
    const step = bucketMinutes(minutes)
    const lastData = data?.flows.length ? dayjs(data.flows[data.flows.length - 1].minute) : dayjs()
    const end = (lastData.isAfter(dayjs()) ? lastData : dayjs()).startOf('minute')
    const start = dayjs().subtract(minutes, 'minute').startOf('minute')
    const slot = (t: dayjs.Dayjs) => Math.floor(t.diff(start, 'minute') / step)
    const n = Math.max(1, slot(end) + 1)
    const xs = Array.from({ length: n }, (_, i) => start.add(i * step, 'minute').format(step >= 60 ? 'DD/MM HH:mm' : 'HH:mm'))
    const series = ORDER.map((lab) => ({ lab, values: new Array(n).fill(0) as number[] }))
    for (const r of data?.flows ?? []) {
      const i = slot(dayjs(r.minute))
      const s = series.find((x) => x.lab === r.label)
      if (s && i >= 0 && i < n) s.values[i] += r.flows
    }
    return {
      tooltip: { trigger: 'axis' },
      legend: { top: 0, type: 'scroll' },
      grid: { left: 50, right: 16, top: 56, bottom: 30 },
      xAxis: { type: 'category', data: xs, boundaryGap: false },
      yAxis: { type: 'value', name: 'luồng', minInterval: 1 },
      series: series
        .filter((s) => s.values.some((v) => v > 0) || s.lab === 'BENIGN')
        .map((s) => ({
          name: LABEL_VI[s.lab],
          type: 'line',
          stack: 'flows',
          areaStyle: { opacity: 0.35 },
          showSymbol: false,
          lineStyle: { width: 1.5 },
          color: LABEL_COLOR[s.lab],
          data: s.values,
        })),
    }
  }, [data, minutes])
  return <ReactECharts option={option} style={{ height: 300 }} notMerge />
}

function LabelPie({ byLabel }: { byLabel: Partial<Record<FlowLabel, number>> }) {
  const items = ORDER.filter((l) => (byLabel[l] ?? 0) > 0).map((l) => ({
    name: LABEL_VI[l],
    value: byLabel[l],
    itemStyle: { color: LABEL_COLOR[l] },
  }))
  if (!items.length) return <Empty description="Chưa có luồng" />
  return (
    <ReactECharts
      style={{ height: 300 }}
      notMerge
      option={{
        tooltip: { trigger: 'item', formatter: '{b}: {c} luồng ({d}%)' },
        legend: { bottom: 0 },
        series: [{ type: 'pie', radius: ['45%', '70%'], center: ['50%', '45%'], data: items, label: { show: false } }],
      }}
    />
  )
}

function TopTable({ rows, title }: { rows: TopRow[]; title: string }) {
  return (
    <Card title={title} size="small">
      <Table<TopRow>
        size="small"
        rowKey={(r) => `${r.ip}-${r.label}`}
        dataSource={rows}
        pagination={false}
        scroll={{ x: 460 }}
        locale={{ emptyText: 'Không có luồng tấn công' }}
        columns={[
          { title: 'IP', dataIndex: 'ip', render: (ip: string) => <Typography.Text code>{ip}</Typography.Text> },
          { title: 'Loại', dataIndex: 'label', render: (l: FlowLabel) => <LabelTag label={l} /> },
          { title: 'Số luồng', dataIndex: 'flows', align: 'right', render: fmtInt },
          { title: 'Lần cuối', dataIndex: 'last_seen', render: fromNow },
        ]}
      />
    </Card>
  )
}

export default function Overview() {
  const [minutes, setMinutes] = useState(60)
  const nav = useNavigate()
  const { data: ov } = useOverview(minutes)
  const { data: top } = useTop(minutes)
  const { data: active } = useAlerts({ status: 'active', page: 1, size: 6 })
  const p = ov?.pipeline

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Space style={{ justifyContent: 'space-between', width: '100%', flexWrap: 'wrap' }}>
        <Typography.Title level={4} style={{ margin: 0 }}>
          Tổng quan
        </Typography.Title>
        <Segmented options={RANGES} value={minutes} onChange={(v) => setMinutes(v as number)} />
      </Space>

      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} xl={6}>
          <Card>
            <Statistic title="Tổng số luồng" value={ov?.flows_total ?? 0} formatter={(v) => fmtInt(Number(v))} />
            <Typography.Text type="secondary">trong {RANGES.find((r) => r.value === minutes)?.label}</Typography.Text>
          </Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card>
            <Statistic
              title="Luồng tấn công"
              value={ov?.flows_attack ?? 0}
              formatter={(v) => fmtInt(Number(v))}
              valueStyle={{ color: (ov?.flows_attack ?? 0) > 0 ? '#d64545' : undefined }}
            />
            <Typography.Text type="secondary">{fmtPct(ov?.attack_ratio)} tổng lưu lượng</Typography.Text>
          </Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card hoverable onClick={() => nav('/alerts')}>
            <Statistic
              title="Cảnh báo đang mở"
              value={ov?.alerts_open ?? 0}
              valueStyle={{ color: (ov?.alerts_open ?? 0) > 0 ? '#d64545' : '#52a37a' }}
            />
            <Space size={4}>
              <Tag color="red">Cao: {ov?.alerts_open_by_severity.high ?? 0}</Tag>
              <Tag color="orange">TB: {ov?.alerts_open_by_severity.medium ?? 0}</Tag>
            </Space>
          </Card>
        </Col>
        <Col xs={24} sm={12} xl={6}>
          <Card>
            <Tooltip title="Số chu kỳ đã chạy / số chu kỳ dự kiến trong 10 phút gần nhất (yêu cầu CN1)">
              <Statistic
                title="Pipeline (10 phút gần nhất)"
                value={p?.runs_10min ?? 0}
                suffix={`/ ${p?.expected_runs_10min ?? '—'} chu kỳ`}
                valueStyle={{ color: p?.state === 'running' ? '#52a37a' : '#d64545' }}
              />
            </Tooltip>
            <Typography.Text type="secondary">
              {p?.avg_ms_10min != null ? `TB ${fmtInt(Math.round(p.avg_ms_10min))} ms/chu kỳ` : 'Chưa có chu kỳ'} · τ ={' '}
              {ov?.model.tau}
            </Typography.Text>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={16}>
          <Card title="Lưu lượng theo thời gian" size="small">
            <TrafficChart minutes={minutes} />
          </Card>
        </Col>
        <Col xs={24} xl={8}>
          <Card title="Tỉ lệ theo nhãn" size="small">
            <LabelPie byLabel={ov?.flows_by_label ?? {}} />
          </Card>
        </Col>
      </Row>

      <Card
        title="Cảnh báo đang mở"
        size="small"
        extra={<Link to="/alerts">Xem tất cả</Link>}
      >
        <Table<Alert>
          size="small"
          rowKey="id"
          dataSource={active?.items ?? []}
          pagination={false}
          scroll={{ x: 820 }}
          locale={{ emptyText: 'Không có cảnh báo đang mở' }}
          onRow={(r) => ({ onClick: () => nav(`/alerts/${r.id}`), style: { cursor: 'pointer' } })}
          columns={[
            { title: 'Mức', dataIndex: 'severity', render: (s) => <SeverityTag severity={s} /> },
            { title: 'Loại', dataIndex: 'label', render: (l) => <LabelTag label={l} /> },
            { title: 'Nguồn', render: (_, a) => a.src_ip ?? `${fmtInt(a.src_count)} nguồn` },
            { title: 'Đích', render: (_, a) => target(a.dst_ip, a.dst_port) },
            { title: 'Số luồng', dataIndex: 'flow_count', align: 'right', render: fmtInt },
            { title: 'Phát hiện bởi', dataIndex: 'source', render: (s) => <SourceTag source={s} /> },
            { title: 'Lần cuối', dataIndex: 'last_seen', render: fromNow },
          ]}
        />
      </Card>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={12}>
          <TopTable title="IP nguồn tấn công nhiều nhất" rows={top?.sources ?? []} />
        </Col>
        <Col xs={24} xl={12}>
          <TopTable title="IP bị nhắm nhiều nhất" rows={top?.targets ?? []} />
        </Col>
      </Row>
    </Space>
  )
}
