# Kestrix — Product Requirements Document (PRD) v1.0

## 1. Giới thiệu & Mục tiêu sản phẩm
**Kestrix** là nền tảng quản lý lỗ hổng bảo mật (Application Security & Vulnerability Management - ASVM) cho mã nguồn phần mềm.
Vấn đề cốt lõi của các nhóm AppSec hiện nay:
- Bùng nổ cảnh báo rác (alert fatigue) do nhiều scanner chạy độc lập.
- Thiếu ngữ cảnh tài sản (Asset Criticality, Internet-facing, Data classification).
- Khử trùng lặp kém dẫn đến một lỗi xuất hiện lại ở mỗi commit làm sai lệch MTTR và SLA.
- AI quá tự do gây rủi ro bảo mật (prompt injection, tự ý đổi trạng thái, làm lộ secret).

**Nguyên tắc chỉ đạo của Kestrix**:
> *"Facts đến từ công cụ quét và nguồn dữ liệu uy tín (OSV, CVE, KEV, EPSS). Logic chấm điểm và khử trùng lặp hoàn toàn mang tính tất định (deterministic). AI chỉ đóng vai trò phân tích, giải thích và đề xuất. Con người giữ quyền quyết định tối cao về mọi thay đổi trạng thái."*

---

## 2. Người dùng & Phân quyền (Personas)
1. **Security Engineer (SecOps / AppSec)**:
   - Cấu hình asset, xem toàn cảnh rủi ro theo team.
   - Phân loại (triage), xác nhận false positive, cấp ngoại lệ có thời hạn (risk_accepted).
   - Tương tác với AI Advisor để phân tích ngữ cảnh mã nguồn.
2. **Developer / Tech Lead (Engineers)**:
   - Xem danh sách finding được giao kèm theo lý do rủi ro tường minh (`risk_reasons`).
   - Đọc hướng dẫn khắc phục và đề xuất bản vá đã kiểm chứng.
   - Sửa lỗi và verify qua lần quét tiếp theo (hệ thống tự động chuyển sang `fixed`).
3. **CISO / Engineering Director**:
   - Theo dõi dashboard SLA vi phạm (P1 7 ngày, P2 30 ngày, P3 90 ngày).
   - Kiểm toán nhật ký thay đổi trạng thái (`status_changes`) và lịch sử can thiệp của AI (`ai_outputs`).

---

## 3. Các tính năng cốt lõi (Core Epics)

### Epic 1: Quản lý Asset & Team
- Quản lý kho mã nguồn (Git repos) gắn với Team sở hữu.
- Thuộc tính ngữ cảnh:
  - `criticality`: 1 (Cực kỳ quan trọng / Core banking / Payment) đến 4 (Tiện ích phụ).
  - `internet_facing`: boolean (Dịch vụ tiếp xúc internet công cộng).
  - `environment`: `production`, `staging`, `development`.
  - `data_class`: `pci_dss`, `pii`, `internal`, `public`.

### Epic 2: Quét & Ingest Đa Scanner
Hỗ trợ 3 dòng công cụ:
1. **SAST**: Semgrep CE / Opengrep (chuẩn định dạng SARIF 2.1.0).
2. **Secret Detection**: Gitleaks (JSON / SARIF).
3. **Dependency Scanning**: OSV-Scanner (JSON / CycloneDX).

### Epic 3: Chuẩn hóa & Khử trùng lặp (Deterministic Fingerprinting)
- Tính fingerprint duy nhất cho mỗi finding theo quy tắc nghiêm ngặt:
  - **SAST**: `sha256(rule_id + ":" + normalized_path + ":" + normalized_snippet)`
  - **Secret**: `sha256(rule_id + ":" + normalized_path + ":" + sha256(secret_raw))` (Giá trị thô không bao giờ lưu trữ).
  - **Dependency**: `sha256(ecosystem + ":" + package + ":" + vuln_id + ":" + manifest_path)` (Không chứa version để việc bump version chưa đủ fix vẫn duy trì cùng một finding).
- Finding tồn tại độc lập qua các lần quét (Scans), liên kết với các `Occurrences` cụ thể.

### Epic 4: Chấm điểm rủi ro theo ngữ cảnh (Contextual Decision Tree)
Thay thế công thức nhân trọng số "ma thuật" bằng cây quyết định có thể giải thích:
- **P1 (Critical - SLA 7 ngày)**:
  - Dependency: Có trong CISA KEV + gọi trúng hàm có lỗ hổng (reachability = true) + Asset internet-facing / Crit 1-2.
  - SAST: Lỗ hổng injection/auth trên public endpoint + Production.
  - Secret: Secret còn hiệu lực (active) trong repo công khai hoặc production.
- **P2 (High - SLA 30 ngày)**:
  - Dependency: EPSS > 0.1 hoặc CVSS >= 7.0 trên asset quan trọng nhưng chưa có KEV.
  - SAST: High confidence flaw trong logic kinh doanh.
- **P3 (Medium - SLA 90 ngày)**:
  - Lỗ hổng nội bộ, dev/staging, hoặc không internet-facing.
- **P4 (Low - Không SLA)**:
  - Thông tin theo dõi, test directory, best practice.
- Mỗi finding lưu mảng `risk_reasons` giải thích tường minh lý do xếp hạng.

### Epic 5: Vòng đời Finding & Trạng thái
- 6 trạng thái chuẩn: `new`, `triaged`, `in_progress`, `fixed`, `false_positive`, `risk_accepted`.
- **Hệ thống tự động**: Khi lần quét đầy đủ tiếp theo của Asset không còn thấy finding -> Chuyển sang `fixed`. Nếu xuất hiện lại -> Chuyển về `triaged` với cờ `reopened = true`.
- **Con người quyết định**: Mọi thao tác đổi sang `triaged`, `in_progress`, `false_positive`, `risk_accepted` đều yêu cầu `actor` (ID người dùng) và `reason` (lý do cụ thể).

### Epic 6: AI-Augmented Advisory (Bảo vệ bởi Guardrails)
- 4 năng lực AI:
  1. Giải thích lỗ hổng theo ngữ cảnh codebase.
  2. Gợi ý đánh giá False Positive kèm điểm tin cậy và lý giải kỹ thuật.
  3. Dự đoán chỉ số CVSS khi nguồn chính thức chưa có (bắt buộc gắn nhãn `[Dự đoán]`).
  4. Đề xuất bản vá mã nguồn.
- Mọi tương tác AI tuân theo:
  - Secret redaction trước khi gửi qua API.
  - Output bắt buộc qua Zod schema định dạng chặt.
  - Audit log vào bảng `ai_outputs`.

---

## 4. Yêu cầu phi chức năng (NFR)
- **Bảo mật**: Tuyệt đối không rò rỉ secret; không thực thi mã nguồn repo không tin cậy.
- **Khả năng kiểm toán (Auditability)**: Mọi thay đổi trạng thái và prompt AI đều được lưu vết vĩnh viễn.
- **Hiệu năng**: Quá trình fingerprinting và khử trùng lặp dưới 100ms cho 1.000 findings.
