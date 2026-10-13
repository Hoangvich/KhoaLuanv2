import { useEffect } from 'react'
import { App, Divider, Form, Input, Modal, Switch } from 'antd'
import { api, errorMessage } from '../api/client'
import { useAuth } from '../auth/AuthContext'

interface Props {
  open: boolean
  onClose: () => void
}

export default function ProfileModal({ open, onClose }: Props) {
  const { user, refresh } = useAuth()
  const [form] = Form.useForm()
  const { message } = App.useApp()

  useEffect(() => {
    if (open && user) form.setFieldsValue({ ...user, current_password: '', new_password: '' })
  }, [open, user, form])

  const submit = async () => {
    const v = await form.validateFields()
    const body = { ...v }
    if (!body.new_password) {
      delete body.new_password
      delete body.current_password
    }
    try {
      await api.put('/auth/me', body)
      await refresh()
      message.success('Đã lưu hồ sơ')
      onClose()
    } catch (e) {
      message.error(errorMessage(e))
    }
  }

  return (
    <Modal title="Hồ sơ & nhận thông báo" open={open} onCancel={onClose} onOk={submit} okText="Lưu" cancelText="Huỷ">
      <Form form={form} layout="vertical">
        <Form.Item name="full_name" label="Họ tên">
          <Input />
        </Form.Item>
        <Form.Item name="email" label="Email nhận cảnh báo" rules={[{ type: 'email', message: 'Email không hợp lệ' }]}>
          <Input placeholder="ten@congty.vn" />
        </Form.Item>
        <Form.Item
          name="telegram_chat_id"
          label="Telegram chat id"
          extra="Nhắn /start cho bot của hệ thống, rồi lấy chat id qua @userinfobot."
        >
          <Input placeholder="123456789" />
        </Form.Item>
        <Form.Item name="notify" label="Nhận thông báo khi có cảnh báo mới" valuePropName="checked">
          <Switch />
        </Form.Item>
        <Divider plain>Đổi mật khẩu (không bắt buộc)</Divider>
        <Form.Item name="current_password" label="Mật khẩu hiện tại">
          <Input.Password autoComplete="current-password" />
        </Form.Item>
        <Form.Item name="new_password" label="Mật khẩu mới" rules={[{ min: 6, message: 'Ít nhất 6 ký tự' }]}>
          <Input.Password autoComplete="new-password" />
        </Form.Item>
      </Form>
    </Modal>
  )
}
