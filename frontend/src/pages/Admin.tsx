import { useEffect, useState } from 'react'
import {
  Alert as AntAlert,
  App,
  Button,
  Card,
  Col,
  Descriptions,

  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Row,
  Select,
  Slider,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
} from 'antd'
import { DeleteOutlined, EditOutlined, PlusOutlined, SendOutlined } from '@ant-design/icons'
import { errorMessage } from '../api/client'
import {
  useDeleteUser,
  useModelInfo,
  usePipelineRuns,
  useSaveSettings,
  useSaveUser,
  useSettings,
  useTestNotification,
  useUsers,
} from '../api/hooks'
import type { PipelineRun, RuntimeSettings, User } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { fmtInt, fmtTime } from '../utils/format'

// ------------------------------------------------------------------ Ngưỡng phát hiện
function DetectionTab() {
  const { data } = useSettings()
  const save = useSaveSettings()
  const [form] = Form.useForm<RuntimeSettings>()
  const { message } = App.useApp()
  const tau = Form.useWatch('tau', form)

  useEffect(() => {
    if (data) form.setFieldsValue(data)
  }, [data, form])

  const submit = async () => {
    const v = await form.validateFields()
    try {
      await save.mutateAsync({ tau: v.tau, ps_min: v.ps_min, bf_min: v.bf_min, alert_idle_seconds: v.alert_idle_seconds })
      message.success('Đã lưu. Pipeline áp dụng từ chu kỳ kế tiếp.')
    } catch (e) {
      message.error(errorMessage(e))
    }
  }

  return (
    <Form form={form} layout="vertical" style={{ maxWidth: 720 }}>
      <AntAlert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="Thay đổi có hiệu lực từ chu kỳ pipeline kế tiếp (≤ 5 giây), không cần khởi động lại."
      />
      <Card size="small" title="Mô hình học máy">
        <Form.Item
          label="Ngưỡng quyết định τ"
          extra={
            <>
              Một luồng bị coi là tấn công khi 1 − P(BENIGN) ≥ τ. τ thấp: bắt được nhiều tấn công hơn nhưng nhiều báo động
              giả hơn. Giá trị 0,48 được hiệu chỉnh ở kịch bản C với tỉ lệ báo động giả ≤ 1%.
            </>
          }
        >
          <Row gutter={16} align="middle">
            <Col flex="auto">
              <Form.Item name="tau" noStyle>
                <Slider min={0.05} max={0.95} step={0.01} />
              </Form.Item>
            </Col>
            <Col>
              <Form.Item name="tau" noStyle rules={[{ required: true }]}>
                <InputNumber min={0.01} max={0.99} step={0.01} style={{ width: 90 }} />
              </Form.Item>
            </Col>
          </Row>
        </Form.Item>
        {tau != null && tau < 0.3 && (
          <AntAlert type="warning" showIcon message="τ rất thấp có thể làm báo động giả tăng mạnh." />
        )}
      </Card>
      <Card size="small" title="Tầng luật theo nguồn" style={{ marginTop: 16 }}>
        <Row gutter={16}>
          <Col xs={24} md={12}>
            <Form.Item
              name="ps_min"
              label="Quét cổng: số cổng khác nhau / 10 giây"
              extra="Một IP chạm tới ít nhất ngần này cổng của cùng một máy đích thì báo PortScan."
              rules={[{ required: true }]}
            >
              <InputNumber min={2} max={100000} style={{ width: '100%' }} />
            </Form.Item>
          </Col>
          <Col xs={24} md={12}>
            <Form.Item
              name="bf_min"
              label="Dò mật khẩu: số phiên đăng nhập / 60 giây"
              extra="Áp cho cổng 21, 22, 23, 3389, 3306... Một IP mở ít nhất ngần này phiên mới thì báo BruteForce."
              rules={[{ required: true }]}
            >
              <InputNumber min={2} max={10000} style={{ width: '100%' }} />
            </Form.Item>
          </Col>
        </Row>
      </Card>
      <Card size="small" title="Gom cảnh báo" style={{ marginTop: 16 }}>
        <Form.Item
          name="alert_idle_seconds"
          label="Đóng cảnh báo sau (giây) không có luồng mới"
          extra="Các luồng cùng loại, cùng nguồn – đích trong khoảng này được gom vào một cảnh báo."
          rules={[{ required: true }]}
        >
          <InputNumber min={10} max={3600} style={{ width: 200 }} />
        </Form.Item>
      </Card>
      <Button type="primary" onClick={submit} loading={save.isPending} style={{ marginTop: 16 }}>
        Lưu cấu hình
      </Button>
    </Form>
  )
}

// ------------------------------------------------------------------ Thông báo
function NotifyTab() {
  const { data } = useSettings()
  const save = useSaveSettings()
  const test = useTestNotification()
  const [form] = Form.useForm<RuntimeSettings>()
  const { message } = App.useApp()

  useEffect(() => {
    if (data) form.setFieldsValue(data)
  }, [data, form])

  const submit = async () => {
    const v = await form.validateFields()
    try {
      await save.mutateAsync(v)
      message.success('Đã lưu cấu hình thông báo')
    } catch (e) {
      message.error(errorMessage(e))
    }
  }

  const sendTest = async (channel: 'telegram' | 'email') => {
    try {
      const r = await test.mutateAsync({ channel })
      message.success(`Đã gửi thử tới ${r.recipient}`)
    } catch (e) {
      message.error(errorMessage(e))
    }
  }

  return (
    <Form form={form} layout="vertical" style={{ maxWidth: 720 }}>
      <AntAlert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="Người nhận là các tài khoản đã bật “Nhận thông báo” và điền chat id / email trong hồ sơ."
        description="Lưu cấu hình trước khi bấm gửi thử. Gửi thử dùng chat id / email trong hồ sơ của bạn."
      />
      <Card size="small" title="Telegram">
        <Form.Item name="telegram_enabled" label="Bật gửi Telegram" valuePropName="checked">
          <Switch />
        </Form.Item>
        <Form.Item name="telegram_bot_token" label="Bot token" extra="Tạo bot bằng @BotFather để lấy token.">
          <Input.Password placeholder="123456:ABC-DEF..." />
        </Form.Item>
        <Button icon={<SendOutlined />} onClick={() => sendTest('telegram')} loading={test.isPending}>
          Gửi thử Telegram
        </Button>
      </Card>
      <Card size="small" title="Email (SMTP)" style={{ marginTop: 16 }}>
        <Form.Item name="email_enabled" label="Bật gửi email" valuePropName="checked">
          <Switch />
        </Form.Item>
        <Row gutter={16}>
          <Col xs={24} md={16}>
            <Form.Item name="smtp_host" label="Máy chủ SMTP">
              <Input placeholder="smtp.gmail.com" />
            </Form.Item>
          </Col>
          <Col xs={24} md={8}>
            <Form.Item name="smtp_port" label="Cổng">
              <InputNumber min={1} max={65535} style={{ width: '100%' }} />
            </Form.Item>
          </Col>
          <Col xs={24} md={12}>
            <Form.Item name="smtp_user" label="Tài khoản">
              <Input />
            </Form.Item>
          </Col>
          <Col xs={24} md={12}>
            <Form.Item name="smtp_password" label="Mật khẩu ứng dụng">
              <Input.Password />
            </Form.Item>
          </Col>
          <Col xs={24} md={12}>
            <Form.Item name="smtp_from" label="Địa chỉ gửi">
              <Input placeholder="ids@congty.vn" />
            </Form.Item>
          </Col>
          <Col xs={24} md={12}>
            <Form.Item name="smtp_starttls" label="STARTTLS" valuePropName="checked">
              <Switch />
            </Form.Item>
          </Col>
        </Row>
        <Button icon={<SendOutlined />} onClick={() => sendTest('email')} loading={test.isPending}>
          Gửi thử email
        </Button>
      </Card>
      <Card size="small" title="Mức gửi thông báo" style={{ marginTop: 16 }}>
        <Form.Item name="notify_min_severity" label="Chỉ gửi cảnh báo từ mức">
          <Select
            style={{ width: 200 }}
            options={[
              { value: 'low', label: 'Thấp trở lên' },
              { value: 'medium', label: 'Trung bình trở lên' },
              { value: 'high', label: 'Chỉ mức cao' },
            ]}
          />
        </Form.Item>
      </Card>
      <Button type="primary" onClick={submit} loading={save.isPending} style={{ marginTop: 16 }}>
        Lưu cấu hình thông báo
      </Button>
    </Form>
  )
}

// ------------------------------------------------------------------ Người dùng
function UsersTab() {
  const { data } = useUsers()
  const saveUser = useSaveUser()
  const del = useDeleteUser()
  const { user: me } = useAuth()
  const { message } = App.useApp()
  const [editing, setEditing] = useState<User | 'new' | null>(null)
  const [form] = Form.useForm()

  useEffect(() => {
    if (editing === 'new') form.setFieldsValue({ role: 'viewer', notify: false, is_active: true, username: '', password: '' })
    else if (editing) form.setFieldsValue({ ...editing, password: '' })
  }, [editing, form])

  const submit = async () => {
    const v = await form.validateFields()
    if (editing !== 'new' && !v.password) delete v.password
    try {
      await saveUser.mutateAsync(editing === 'new' ? v : { ...v, id: (editing as User).id, username: undefined })
      message.success('Đã lưu người dùng')
      setEditing(null)
    } catch (e) {
      message.error(errorMessage(e))
    }
  }

  return (
    <>
      <Button type="primary" icon={<PlusOutlined />} onClick={() => setEditing('new')} style={{ marginBottom: 12 }}>
        Thêm người dùng
      </Button>
      <Table<User>
        rowKey="id"
        size="middle"
        dataSource={data ?? []}
        pagination={false}
        scroll={{ x: 800 }}
        columns={[
          { title: 'Tên đăng nhập', dataIndex: 'username' },
          { title: 'Họ tên', dataIndex: 'full_name' },
          {
            title: 'Vai trò',
            dataIndex: 'role',
            render: (r) => <Tag color={r === 'admin' ? 'gold' : 'blue'}>{r === 'admin' ? 'Quản trị' : 'Xem'}</Tag>,
          },
          { title: 'Email', dataIndex: 'email' },
          { title: 'Telegram', dataIndex: 'telegram_chat_id' },
          { title: 'Nhận thông báo', dataIndex: 'notify', render: (v) => (v ? 'Có' : 'Không') },
          {
            title: 'Trạng thái',
            dataIndex: 'is_active',
            render: (v) => (v ? <Tag color="green">Hoạt động</Tag> : <Tag>Đã khoá</Tag>),
          },
          {
            title: '',
            width: 110,
            render: (_, u) => (
              <Space>
                <Button size="small" icon={<EditOutlined />} onClick={() => setEditing(u)} />
                <Popconfirm
                  title={`Xoá tài khoản ${u.username}?`}
                  okText="Xoá"
                  cancelText="Huỷ"
                  disabled={u.id === me?.id}
                  onConfirm={async () => {
                    try {
                      await del.mutateAsync(u.id)
                      message.success('Đã xoá')
                    } catch (e) {
                      message.error(errorMessage(e))
                    }
                  }}
                >
                  <Button size="small" danger icon={<DeleteOutlined />} disabled={u.id === me?.id} />
                </Popconfirm>
              </Space>
            ),
          },
        ]}
      />
      <Modal
        open={editing !== null}
        title={editing === 'new' ? 'Thêm người dùng' : `Sửa ${(editing as User | null)?.username ?? ''}`}
        onCancel={() => setEditing(null)}
        onOk={submit}
        okText="Lưu"
        cancelText="Huỷ"
        confirmLoading={saveUser.isPending}
      >
        <Form form={form} layout="vertical">
          {editing === 'new' && (
            <Form.Item
              name="username"
              label="Tên đăng nhập"
              rules={[
                { required: true, message: 'Bắt buộc' },
                { min: 3, message: 'Ít nhất 3 ký tự' },
                { pattern: /^[A-Za-z0-9_.-]+$/, message: 'Chỉ chữ, số và _ . -' },
              ]}
            >
              <Input />
            </Form.Item>
          )}
          <Form.Item
            name="password"
            label={editing === 'new' ? 'Mật khẩu' : 'Mật khẩu mới (để trống nếu không đổi)'}
            rules={[
              ...(editing === 'new' ? [{ required: true, message: 'Bắt buộc' }] : []),
              { min: 6, message: 'Ít nhất 6 ký tự' },
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item name="full_name" label="Họ tên">
            <Input />
          </Form.Item>
          <Form.Item name="role" label="Vai trò">
            <Select
              options={[
                { value: 'viewer', label: 'Xem — xem dashboard, xử lý cảnh báo' },
                { value: 'admin', label: 'Quản trị — chỉnh ngưỡng, người dùng, thông báo' },
              ]}
            />
          </Form.Item>
          <Form.Item name="email" label="Email" rules={[{ type: 'email', message: 'Email không hợp lệ' }]}>
            <Input />
          </Form.Item>
          <Form.Item name="telegram_chat_id" label="Telegram chat id">
            <Input />
          </Form.Item>
          <Space size={32}>
            <Form.Item name="notify" label="Nhận thông báo" valuePropName="checked">
              <Switch />
            </Form.Item>
            {editing !== 'new' && (
              <Form.Item name="is_active" label="Đang hoạt động" valuePropName="checked">
                <Switch />
              </Form.Item>
            )}
          </Space>
        </Form>
      </Modal>
    </>
  )
}

// ------------------------------------------------------------------ Mô hình & pipeline
function SystemTab() {
  const { data: m } = useModelInfo()
  const [onlyData, setOnlyData] = useState(true)
  const { data: runs } = usePipelineRuns(onlyData)
  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card size="small" title="Mô hình đang chạy">
        {m && (
          <Descriptions column={{ xs: 1, md: 2, xl: 3 }} size="small" bordered>
            <Descriptions.Item label="Mô hình">{m.model_name}</Descriptions.Item>
            <Descriptions.Item label="Tệp">
              {m.file} ({m.file_size_mb} MB)
            </Descriptions.Item>
            <Descriptions.Item label="Mã lần huấn luyện">{m.run_id}</Descriptions.Item>
            <Descriptions.Item label="Bộ đặc trưng">
              {m.feature_set} ({m.n_features} đặc trưng)
            </Descriptions.Item>
            <Descriptions.Item label="Lớp">{m.classes.join(', ')}</Descriptions.Item>
            <Descriptions.Item label="macro-F1 (kịch bản A)">{m.macro_f1_test?.toFixed(4) ?? '—'}</Descriptions.Item>
            <Descriptions.Item label="τ đang dùng">{m.tau}</Descriptions.Item>
            <Descriptions.Item label="τ trong gói mô hình">{m.bundle_threshold.toFixed(2)}</Descriptions.Item>
            <Descriptions.Item label="Thư viện">
              {Object.entries(m.versions ?? {})
                .map(([k, v]) => `${k} ${v}`)
                .join(', ')}
            </Descriptions.Item>
          </Descriptions>
        )}
      </Card>
      <Card
        size="small"
        title="Nhật ký chu kỳ pipeline"
        extra={
          <Space>
            <Typography.Text type="secondary">Chỉ chu kỳ có dữ liệu / lỗi</Typography.Text>
            <Switch size="small" checked={onlyData} onChange={setOnlyData} />
          </Space>
        }
      >
        <Table<PipelineRun>
          rowKey="id"
          size="small"
          dataSource={runs ?? []}
          pagination={{ pageSize: 15 }}
          scroll={{ x: 900 }}
          columns={[
            { title: '#', dataIndex: 'id', width: 80 },
            { title: 'Bắt đầu', dataIndex: 'started_at', render: fmtTime },
            { title: 'Luồng', dataIndex: 'rows_in', align: 'right', render: fmtInt },
            { title: 'Tấn công', dataIndex: 'rows_attack', align: 'right', render: fmtInt },
            { title: 'Cảnh báo mới', dataIndex: 'alerts_new', align: 'right' },
            { title: 'Quy ước cờ', dataIndex: 'flag_mode' },
            { title: 'τ', dataIndex: 'tau' },
            { title: 'Thời gian', dataIndex: 'ms', align: 'right', render: (v: number | null) => (v == null ? '—' : `${fmtInt(Math.round(v))} ms`) },
            { title: 'Tệp', dataIndex: 'files', ellipsis: true },
            {
              title: 'Lỗi',
              dataIndex: 'error',
              ellipsis: true,
              render: (e: string | null) => (e ? <Typography.Text type="danger">{e}</Typography.Text> : '—'),
            },
          ]}
        />
      </Card>
    </Space>
  )
}

export default function Admin() {
  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Typography.Title level={4} style={{ margin: 0 }}>
        Quản trị
      </Typography.Title>
      <Card>
        <Tabs
          items={[
            { key: 'detect', label: 'Ngưỡng phát hiện', children: <DetectionTab /> },
            { key: 'notify', label: 'Thông báo', children: <NotifyTab /> },
            { key: 'users', label: 'Người dùng', children: <UsersTab /> },
            { key: 'system', label: 'Mô hình & pipeline', children: <SystemTab /> },
          ]}
        />
      </Card>
    </Space>
  )
}
