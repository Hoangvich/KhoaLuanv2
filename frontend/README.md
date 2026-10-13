# Frontend — dashboard

React 18 + Vite + TypeScript, Ant Design 5 (giao diện tiếng Việt), ECharts, TanStack Query, React Router.

```powershell
npm install
npm run dev        # http://localhost:5173, /api được chuyển tới http://127.0.0.1:8000
npm run build      # kiểm tra kiểu + đóng gói vào dist/
```

| Thư mục | Nội dung |
|---|---|
| `src/api/` | `client.ts` (axios + JWT), `types.ts` (khớp `backend/app/schemas.py`), `hooks.ts` (truy vấn, tự làm mới 5 s) |
| `src/auth/` | Đăng nhập, lưu token, tự đăng xuất khi API trả 401 |
| `src/components/` | Khung trang, nhãn màu dùng chung (`Tags.tsx`), hồ sơ người dùng |
| `src/pages/` | `Overview` (Tổng quan), `Alerts` + `AlertDetail` (Cảnh báo), `Admin` (Quản trị), `Login` |

Màu nhãn thống nhất mọi nơi (định nghĩa ở `components/Tags.tsx`): Bình thường xanh lá, DoS/DDoS đỏ, Quét cổng cam,
Dò mật khẩu tím, Không chấm được xám.

Phân quyền: vai trò **Xem** dùng Tổng quan và Cảnh báo (xác nhận, đóng cảnh báo); vai trò **Quản trị** thêm trang
Quản trị (ngưỡng τ, ngưỡng luật, thông báo, người dùng, nhật ký pipeline).
