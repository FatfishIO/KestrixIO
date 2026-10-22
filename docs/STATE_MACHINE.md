# Kestrix — Finding Lifecycle State Machine

## 1. Các trạng thái hợp lệ
Finding trong Kestrix có 6 trạng thái vòng đời duy nhất:
- `new`: Vừa được phát hiện lần đầu từ lần quét của công cụ.
- `triaged`: Đã được chuyên viên AppSec hoặc Tech Lead xem xét và xác nhận là vấn đề thật cần xử lý.
- `in_progress`: Đang được nhóm phát triển sửa lỗi hoặc xử lý.
- `fixed`: Lỗ hổng đã được sửa triệt để (Hệ thống tự động đánh dấu khi lần quét tiếp theo không còn thấy).
- `false_positive`: Báo động giả (Con người xác nhận và ghi rõ lý do).
- `risk_accepted`: Chấp nhận rủi ro (Con người xác nhận, có thời hạn `expires_at` và lý do kinh doanh).

---

## 2. Bảng ma trận chuyển trạng thái

| Trạng thái hiện tại | Trạng thái đích | Tác nhân (Actor) | Điều kiện / Ghi chú |
|---|---|---|---|
| `new` | `triaged` | Con người (User) | Bắt buộc có `reason`. |
| `new` | `false_positive` | Con người (User) | Bắt buộc có `reason` giải thích vì sao là báo động giả. |
| `new` | `risk_accepted` | Con người (User) | Bắt buộc có `reason` và `expires_at`. |
| `new` | `fixed` | **Hệ thống (System)** | Lần quét đầy đủ tiếp theo của Asset không còn phát hiện finding này. |
| `triaged` | `in_progress` | Con người (User) | Gán người thực hiện hoặc liên kết ticket. |
| `triaged` | `false_positive` | Con người (User) | Bắt buộc có `reason`. |
| `triaged` | `risk_accepted` | Con người (User) | Bắt buộc có `reason` và `expires_at`. |
| `triaged` | `fixed` | **Hệ thống (System)** | Lần quét tiếp theo không còn thấy finding. |
| `in_progress` | `fixed` | **Hệ thống (System)** | Lần quét tiếp theo không còn thấy finding. |
| `in_progress` | `triaged` | Con người (User) | Trả về hàng đợi nếu hoãn xử lý. |
| `fixed` | `triaged` | **Hệ thống (System)** | **REOPENED!** Finding tái xuất hiện trong lần quét sau; đặt `reopened = true`. |
| `false_positive` | `triaged` | Con người (User) | Phục hồi lại nếu trước đó đánh giá nhầm. |
| `risk_accepted` | `triaged` | Con người / Hệ thống | Khi hết hạn `expires_at` hoặc người dùng chủ động thu hồi ngoại lệ. |

---

## 3. Quy tắc cốt lõi
1. **Con người quyết định**: AI **tuyệt đối không bao giờ** được trực tiếp chuyển trạng thái của finding. AI chỉ sinh ra bản ghi `AiOutput` kèm `confidence` và `recommendation`.
2. **Quy tắc Auto-Fixed**:
   - Khi một `Scan` loại full scan hoàn tất thành công cho một `asset_id`:
   - Mọi finding thuộc `asset_id` có cùng `type` và `status IN ('new', 'triaged', 'in_progress')` nhưng **không xuất hiện** trong danh sách occurrences của lần quét này sẽ được hệ thống chuyển sang `fixed`.
   - Tạo bản ghi `status_changes`: `from_status`, `to_status: fixed`, `actor: system`, `reason: "Resolved in scan {scan_id} (commit {commit_sha})"`.
3. **Quy tắc Reopened**:
   - Nếu một finding đang ở trạng thái `fixed` lại xuất hiện trong lần quét mới:
   - Hệ thống tự động chuyển trạng thái về `triaged`.
   - Đánh dấu `reopened = true`.
   - Tạo bản ghi `status_changes`: `from_status: fixed`, `to_status: triaged`, `actor: system`, `reason: "Reappeared in scan {scan_id} (commit {commit_sha})"`.
4. **Quy tắc Bất biến Audit Log**:
   - Mọi lần chuyển đổi trạng thái phải tạo một bản ghi trong bảng `status_changes`. Không được ghi đè hay xóa lịch sử.
