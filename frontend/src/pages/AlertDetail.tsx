import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  App,
  Breadcrumb,
  Button,
  Card,
  Col,
  Descriptions,
  Empty,
  Input,
  Modal,
  Result,
  Row,
  Space,
  Spin,
  Table,
  Tag,
  Typography,
} from 'antd'
import { CheckOutlined, CloseCircleOutlined } from '@ant-design/icons'
import { errorMessage } from '../api/client'
import { useAlert, useAlertAction } from '../api/hooks'
import type { Flow, NotificationRow } from '../api/types'
import { LabelTag, SeverityTag, SourceTag, StatusTag } from '../components/Tags'
import { PROTOCOLS, fmtDuration, fmtInt, fmtTime, target } from '../utils/format'

const LABEL_EXPLAIN: Record<string, string> = {
  'DoS/DDoS':
    'Nhiều luồng dồn về cùng một máy đích nhằm làm cạn tài nguyên. Kiểm tra băng thông và tải của máy đích; cân nhắc chặn tạm các nguồn có lưu lượng lớn tại firewall.',
  PortScan:
    'Một máy đang dò lần lượt các cổng của máy đích, thường là bước trinh sát trước khi tấn công. Kiểm tra máy nguồn có phải thiết bị nội bộ bị chiếm quyền không.',
  BruteForce:
    'Một máy liên tục mở phiên đăng nhập mới tới dịch vụ xác thực (SSH, FTP, RDP...) để thử mật khẩu. Kiểm tra log đăng nhập của máy đích và khoá tài khoản bị nhắm nếu cần.',
}

export default function AlertDetail() {
  const id = Number(useParams().id)
  const { data, isLoading, error } = useAlert(id)
  const act = useAlertAction()
  const { message } = App.useApp()
  const [dialog, setDialog] = useState<'ack' | 'close' | null>(null)
  const [note, setNote] = useState('')

  if (isLoading) return <Spin />
  if (error || !data) return <Result status="404" title="Không tìm thấy cảnh báo" extra={<Link to="/alerts">Quay lại</Link>} />
  const a = data.alert

  const submit = async () => {
    try {
      await act.mutateAsync({ id, action: dialog!, note: note || undefined })
      message.success(dialog === 'ack' ? 'Đã xác nhận cảnh báo' : 'Đã đóng cảnh báo')
      setDialog(null)
      setNote('')
    } catch (e) {
      message.error(errorMessage(e))
    }
  }

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Breadcrumb items={[{ title: <Link to="/alerts">Cảnh báo</Link> }, { title: `#${a.id}` }]} />
      <Card
        title={
          <Space wrap>
            <span>Cảnh báo #{a.id}</span>
            <LabelTag label={a.label} />
            <SeverityTag severity={a.severity} />
            <StatusTag status={a.status} />
          </Space>
        }
        extra={
          <Space>
            {a.status === 'open' && (
              <Button icon={<CheckOutlined />} onClick={() => setDialog('ack')}>
                Xác nhận
              </Button>
            )}
            {a.status !== 'closed' && (
              <Button danger icon={<CloseCircleOutlined />} onClick={() => setDialog('close')}>
                Đóng
              </Button>
            )}
          </Space>
        }
      >
        <Typography.Paragraph type="secondary">{LABEL_EXPLAIN[a.label]}</Typography.Paragraph>
        <Descriptions column={{ xs: 1, md: 2, xl: 3 }} size="small" bordered>
          <Descriptions.Item label="Nguồn">
            {a.src_ip ? <Typography.Text code>{a.src_ip}</Typography.Text> : `${fmtInt(a.src_count)} IP nguồn`}
          </Descriptions.Item>
          <Descriptions.Item label="Đích">
            <Typography.Text code>{target(a.dst_ip, a.dst_port)}</Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label="Phát hiện bởi">
            <SourceTag source={a.source} />
          </Descriptions.Item>
          <Descriptions.Item label="Bắt đầu">{fmtTime(a.first_seen)}</Descriptions.Item>
          <Descriptions.Item label="Lần cuối">{fmtTime(a.last_seen)}</Descriptions.Item>
          <Descriptions.Item label="Kéo dài">{fmtDuration(a.first_seen, a.last_seen)}</Descriptions.Item>
          <Descriptions.Item label="Số luồng">{fmtInt(a.flow_count)}</Descriptions.Item>
          <Descriptions.Item label="Điểm tấn công cao nhất">
            {a.max_score != null ? a.max_score.toFixed(3) : '—'}
          </Descriptions.Item>
          <Descriptions.Item label="Chi tiết luật">{a.rule_detail ?? '—'}</Descriptions.Item>
          <Descriptions.Item label="Xử lý bởi">
            {a.ack_by ? `${a.ack_by} lúc ${fmtTime(a.ack_at)}` : '—'}
          </Descriptions.Item>
          <Descriptions.Item label="Đóng lúc">{fmtTime(a.closed_at)}</Descriptions.Item>
          <Descriptions.Item label="Ghi chú">{a.note ?? '—'}</Descriptions.Item>
        </Descriptions>
      </Card>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={8}>
          <Card title="IP nguồn đóng góp nhiều nhất" size="small">
            <Table
              size="small"
              rowKey="ip"
              pagination={false}
              dataSource={data.top_sources}
              columns={[
                { title: 'IP', dataIndex: 'ip', render: (ip: string) => <Typography.Text code>{ip}</Typography.Text> },
                { title: 'Số luồng', dataIndex: 'flows', align: 'right', render: fmtInt },
              ]}
            />
          </Card>
          <Card title="Thông báo đã gửi" size="small" style={{ marginTop: 16 }}>
            {data.notifications.length === 0 ? (
              <Empty description="Chưa gửi thông báo nào" image={Empty.PRESENTED_IMAGE_SIMPLE} />
            ) : (
              <Table<NotificationRow>
                size="small"
                rowKey="id"
                pagination={false}
                scroll={{ x: 420 }}
                dataSource={data.notifications}
                columns={[
                  { title: 'Kênh', dataIndex: 'channel' },
                  { title: 'Người nhận', dataIndex: 'recipient' },
                  {
                    title: 'Kết quả',
                    render: (_, n) => (
                      <Tag color={n.status === 'sent' ? 'green' : n.status === 'failed' ? 'red' : 'default'}>
                        {n.status === 'sent' ? 'Đã gửi' : n.status === 'failed' ? 'Lỗi' : 'Chờ gửi'}
                      </Tag>
                    ),
                  },
                  {
                    title: 'Độ trễ',
                    dataIndex: 'latency_ms',
                    render: (v: number | null) => (v == null ? '—' : `${(v / 1000).toFixed(1)} s`),
                  },
                ]}
              />
            )}
          </Card>
        </Col>
        <Col xs={24} xl={16}>
          <Card title={`Luồng thuộc cảnh báo (${fmtInt(data.flows.length)} luồng gần nhất)`} size="small">
            <Table<Flow>
              size="small"
              rowKey="id"
              dataSource={data.flows}
              pagination={{ pageSize: 15, showSizeChanger: false }}
              scroll={{ x: 900 }}
              columns={[
                { title: 'Thời điểm', dataIndex: 'ts', render: fmtTime, width: 170 },
                { title: 'Nguồn', render: (_, f) => `${f.src_ip}:${f.src_port}` },
                { title: 'Đích', render: (_, f) => `${f.dst_ip}:${f.dst_port}` },
                { title: 'Giao thức', dataIndex: 'protocol', render: (p: number) => PROTOCOLS[p] ?? p },
                { title: 'Gói đi/về', render: (_, f) => `${f.fwd_pkts ?? '—'} / ${f.bwd_pkts ?? '—'}` },
                { title: 'Nhãn', dataIndex: 'label', render: (l) => <LabelTag label={l} /> },
                {
                  title: 'Điểm',
                  dataIndex: 'attack_score',
                  align: 'right',
                  render: (v: number | null) => (v == null ? '—' : v.toFixed(3)),
                },
                { title: 'Phát hiện bởi', dataIndex: 'source', render: (s) => <SourceTag source={s} /> },
              ]}
            />
          </Card>
        </Col>
      </Row>

      <Modal
        open={dialog !== null}
        title={dialog === 'ack' ? 'Xác nhận đã tiếp nhận cảnh báo' : 'Đóng cảnh báo'}
        okText={dialog === 'ack' ? 'Xác nhận' : 'Đóng cảnh báo'}
        okButtonProps={{ danger: dialog === 'close', loading: act.isPending }}
        cancelText="Huỷ"
        onOk={submit}
        onCancel={() => setDialog(null)}
      >
        <Input.TextArea
          rows={3}
          placeholder="Ghi chú xử lý (không bắt buộc), ví dụ: đã chặn IP nguồn tại pfSense"
          value={note}
          onChange={(e) => setNote(e.target.value)}
        />
      </Modal>
    </Space>
  )
}
