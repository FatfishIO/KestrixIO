# Kestrix — Threat Model & Security Architecture

Hệ thống Kestrix lưu trữ toàn bộ bản đồ lỗ hổng của doanh nghiệp và nắm giữ quyền truy cập kho mã nguồn, do đó Kestrix là mục tiêu tấn công giá trị rất cao. Mọi thiết kế phải triệt để tuân thủ 10 quy tắc bảo mật không ngoại lệ.

---

## 1. Phân tích mối đe dọa (STRIDE)

| Rủi ro | Nguy cơ | Biện pháp bảo vệ bắt buộc của Kestrix |
|---|---|---|
| **Spoofing** (Giả mạo) | Kẻ tấn công giả lập CI/CD đẩy kết quả scan giả mạo để làm nhiễu hệ thống hoặc che giấu lỗi. | Mọi API ingest yêu cầu Token xác thực theo team/asset; kiểm tra quyền ở tầng Service. |
| **Tampering** (Can thiệp sửa đổi) | Sửa đổi mã nguồn hoặc file SARIF chèn mã độc vào hệ thống. | Validate toàn bộ schema SARIF/CycloneDX; đường dẫn file phải qua hàm `normalize_and_sanitize_path` chống Path Traversal. |
| **Repudiation** (Chối bỏ) | Thành viên đóng hoặc bỏ qua lỗ hổng nghiêm trọng mà không nhận trách nhiệm. | Bảng `status_changes` lưu bất biến mọi hành động: ai đổi (`actor`), lý do (`reason`), thời gian (`changed_at`). |
| **Information Disclosure** (Lộ lọt thông tin) | Rò rỉ thông tin secret phát hiện từ Gitleaks hoặc mã nguồn gửi cho bên thứ 3. | **Quy tắc #1 & #4**: Tuyệt đối không lưu secret thô; chỉ lưu SHA-256 và bản che 4 ký tự cuối. Redact toàn bộ pattern nhạy cảm trước khi gửi tới LLM Gateway. |
| **Denial of Service** (Từ chối dịch vụ) | Scanner tiêu thụ cạn kiệt tài nguyên máy chủ hoặc prompt injection làm sập worker. | Giới hạn tài nguyên container scanner (CPU 2 cores, RAM 2GB, timeout 10 phút, non-root, read-only root fs). Token budget cho mỗi lần gọi LLM. |
| **Elevation of Privilege** (Leo thang đặc quyền) | Repo độc hại chứa mã khai thác trong `package.json` postinstall script hoặc Git hook. | **Quy tắc #2**: Repo là dữ liệu không tin cậy. Tuyệt đối không chạy `npm install`, build script hay binary từ repo được quét. |

---

## 2. Chi tiết 10 Quy tắc bảo mật bắt buộc

### Quy tắc 1: Bảo mật Secret (Gitleaks Ingestion)
- Không bao giờ lưu, log, trả qua API, gửi cho LLM hay đưa vào ticket giá trị thô của secret.
- Công thức mã hóa:
  - `secret_hash = sha256(raw_secret)`
  - `secret_masked = "****" + raw_secret.slice(-4)` (nếu độ dài > 4)
- Khi serialize JSON để hiển thị ra UI hoặc API, chỉ trả về `secret_masked` và `secret_hash`.

### Quy tắc 2: Không thực thi code không tin cậy
- Repo Git chỉ được đối xử như chuỗi ký tự tĩnh (Plain text AST analysis).
- Không bao giờ chạy hook, script cài đặt gói phụ thuộc (`setup.py`, `package.json:postinstall`, `Makefile`).

### Quy tắc 3: Cô lập Scanner Container
- Container quét mã nguồn thực thi:
  - `USER nonroot (uid 10001)`
  - `--read-only` (chỉ cho phép ghi tại `/tmp` dung lượng tối đa 100MB)
  - `--network=none` (không có quyền truy cập internet trong lúc quét)
  - Giới hạn cgroups CPU và RAM.

### Quy tắc 4: Cô lập LLM qua LLM Gateway
- Không component nào được gọi trực tiếp SDK của OpenAI / Google / Anthropic.
- Tất cả phải đi qua `packages/llm-gateway`:
  1. Chạy bộ lọc Redaction (Secret, Token, IP nội bộ, Email).
  2. Áp dụng giới hạn hạn ngạch (Token Budget per Scan).
  3. Cache theo `hash(input)` để chống lãng phí chi phí.
  4. Ghi mọi request/response vào bảng kiểm toán `ai_outputs`.

### Quy tắc 5: Guardrail & Schema Validation cho AI
- LLM không bao giờ có thẩm quyền thực thi lệnh hay đổi trạng thái database.
- Mọi phản hồi dạng JSON từ LLM phải thỏa mãn Zod Schema. Nếu parse thất bại, hệ thống loại bỏ ngay lập tức (fail-safe).

### Quy tắc 6: Giới hạn quyền GitHub App
- Sử dụng GitHub App với quyền tối thiểu:
  - `Repository contents: Read`
  - `Pull requests: Write`
- Khi tạo bản vá: Chỉ tạo nhánh tạm thời (`kestrix-fix-...`) và mở **Draft Pull Request**.
- Không cấp quyền merge tự động vào nhánh chính.

### Quy tắc 7: Phân quyền theo Team ở tầng Service
- Mọi truy vấn đọc/ghi finding phải được lọc theo `team_id` của tài sản gắn liền.
- Không phụ thuộc vào frontend hay URL path để bảo vệ dữ liệu.

### Quy tắc 8: Tham số hóa triệt để Drizzle ORM
- Tuyệt đối không sử dụng `sql.raw()` hoặc nối chuỗi để tạo câu lệnh SQL.
- Sử dụng Typed Prepared Statements của Drizzle.

### Quy tắc 9: Chống Path Traversal
- Đường dẫn file từ SARIF (`artifactLocation.uri`) hoặc Gitleaks phải được chuẩn hóa:
  - Loại bỏ các ký tự `../`, `..\\`.
  - Phải nằm trong đường dẫn tương đối của workspace làm việc.

### Quy tắc 10: Quản lý bí mật môi trường
- Không commit file `.env`.
- Cấu hình qua biến môi trường tại runtime; duy trì `.env.example` với các biến giả lập.
