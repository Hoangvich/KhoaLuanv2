import { Tag, Tooltip } from 'antd'
import type { AlertStatus, FlowLabel, Severity } from '../api/types'

// Một bảng màu dùng chung cho mọi biểu đồ và nhãn, để cùng một loại tấn công luôn cùng một màu
export const LABEL_COLOR: Record<FlowLabel, string> = {
  BENIGN: '#52a37a',
  'DoS/DDoS': '#d64545',
  PortScan: '#e08a1e',
  BruteForce: '#7b5cd6',
  INVALID: '#a3a3a3',
}

export const LABEL_VI: Record<FlowLabel, string> = {
  BENIGN: 'Bình thường',
  'DoS/DDoS': 'DoS/DDoS',
  PortScan: 'Quét cổng',
  BruteForce: 'Dò mật khẩu',
  INVALID: 'Không chấm được',
}

export const LABEL_HINT: Record<FlowLabel, string> = {
  BENIGN: 'Luồng được mô hình đánh giá là bình thường',
  'DoS/DDoS': 'Tấn công từ chối dịch vụ: làm cạn tài nguyên máy đích',
  PortScan: 'Trinh sát: dò các cổng đang mở trên máy đích',
  BruteForce: 'Thử liên tục nhiều mật khẩu vào dịch vụ đăng nhập (SSH, FTP...)',
  INVALID: 'Luồng chỉ có 1 gói (thời lượng 0), mô hình không chấm điểm; vẫn được tầng luật xét',
}

export function LabelTag({ label }: { label: FlowLabel | null }) {
  const l = (label ?? 'INVALID') as FlowLabel
  return (
    <Tooltip title={LABEL_HINT[l]}>
      <Tag color={LABEL_COLOR[l]} style={{ marginInlineEnd: 0 }}>
        {LABEL_VI[l]}
      </Tag>
    </Tooltip>
  )
}

const SEV: Record<Severity, { color: string; text: string }> = {
  high: { color: 'red', text: 'Cao' },
  medium: { color: 'orange', text: 'Trung bình' },
  low: { color: 'blue', text: 'Thấp' },
}

export const SeverityTag = ({ severity }: { severity: Severity }) => (
  <Tag color={SEV[severity].color}>{SEV[severity].text}</Tag>
)

const STATUS: Record<AlertStatus, { color: string; text: string }> = {
  open: { color: 'error', text: 'Đang mở' },
  ack: { color: 'processing', text: 'Đã xác nhận' },
  closed: { color: 'default', text: 'Đã đóng' },
}

export const StatusTag = ({ status }: { status: AlertStatus }) => (
  <Tag color={STATUS[status].color}>{STATUS[status].text}</Tag>
)

export function SourceTag({ source }: { source: string | null }) {
  if (!source) return <span>—</span>
  const parts = source.split('+')
  return (
    <>
      {parts.map((p) => (
        <Tooltip
          key={p}
          title={
            p === 'rule'
              ? 'Tầng luật theo nguồn: đếm số cổng / số phiên của một IP trong cửa sổ thời gian'
              : 'Mô hình học máy chấm điểm từng luồng'
          }
        >
          <Tag color={p === 'rule' ? 'geekblue' : 'cyan'}>{p === 'rule' ? 'Luật' : 'Mô hình'}</Tag>
        </Tooltip>
      ))}
    </>
  )
}
