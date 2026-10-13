import { useState } from 'react'
import { Link, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { Avatar, Badge, Dropdown, Grid, Layout, Menu, Space, Tooltip, Typography, theme } from 'antd'
import {
  AlertOutlined,
  DashboardOutlined,
  LogoutOutlined,
  SettingOutlined,
  UserOutlined,
} from '@ant-design/icons'
import { useAuth } from '../auth/AuthContext'
import { usePipelineStatus } from '../api/hooks'
import { fromNow } from '../utils/format'
import ProfileModal from './ProfileModal'

const { Header, Sider, Content } = Layout

function PipelineBadge() {
  const { data } = usePipelineStatus()
  if (!data) return null
  const running = data.state === 'running'
  const text = running ? 'Pipeline đang chạy' : data.state === 'never' ? 'Pipeline chưa chạy' : 'Pipeline đã dừng'
  return (
    <Tooltip
      title={
        data.last_run
          ? `Chu kỳ gần nhất: ${fromNow(data.last_run)}` + (data.last_error ? ` — lỗi: ${data.last_error}` : '')
          : 'Chưa có chu kỳ nào'
      }
    >
      <Badge status={running ? 'processing' : 'error'} text={text} />
    </Tooltip>
  )
}

export default function AppLayout() {
  const { user, logout } = useAuth()
  const loc = useLocation()
  const nav = useNavigate()
  const [profile, setProfile] = useState(false)
  const { token } = theme.useToken()
  const screens = Grid.useBreakpoint()

  const items = [
    { key: '/', icon: <DashboardOutlined />, label: <Link to="/">Tổng quan</Link> },
    { key: '/alerts', icon: <AlertOutlined />, label: <Link to="/alerts">Cảnh báo</Link> },
    ...(user?.role === 'admin'
      ? [{ key: '/admin', icon: <SettingOutlined />, label: <Link to="/admin">Quản trị</Link> }]
      : []),
  ]
  const selected = items.map((i) => i.key).filter((k) => k !== '/' && loc.pathname.startsWith(k))[0] ?? '/'

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider breakpoint="lg" collapsedWidth={56} width={200} theme="dark">
        <div style={{ color: '#fff', padding: '18px 16px', fontWeight: 600, fontSize: 16, whiteSpace: 'nowrap' }}>
          {screens.lg ? '🛡️ IDS AAHKL' : '🛡️'}
        </div>
        <Menu theme="dark" mode="inline" selectedKeys={[selected]} items={items} />
      </Sider>
      <Layout>
        <Header
          style={{
            background: token.colorBgContainer,
            padding: screens.md ? '0 20px' : '0 16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            borderBottom: `1px solid ${token.colorBorderSecondary}`,
          }}
        >
          <PipelineBadge />
          <Dropdown
            menu={{
              items: [
                { key: 'profile', icon: <UserOutlined />, label: 'Hồ sơ & thông báo', onClick: () => setProfile(true) },
                {
                  key: 'logout',
                  icon: <LogoutOutlined />,
                  label: 'Đăng xuất',
                  onClick: () => {
                    logout()
                    nav('/login')
                  },
                },
              ],
            }}
          >
            <Space style={{ cursor: 'pointer' }}>
              <Avatar size="small" icon={<UserOutlined />} />
              {screens.sm && <Typography.Text>{user?.full_name || user?.username}</Typography.Text>}
              {screens.md && (
                <Typography.Text type="secondary">({user?.role === 'admin' ? 'Quản trị' : 'Xem'})</Typography.Text>
              )}
            </Space>
          </Dropdown>
        </Header>
        <Content style={{ padding: screens.md ? 20 : 16, minWidth: 0 }}>
          <Outlet />
        </Content>
      </Layout>
      <ProfileModal open={profile} onClose={() => setProfile(false)} />
    </Layout>
  )
}
