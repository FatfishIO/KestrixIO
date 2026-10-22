# Kestrix — Plan hệ thống Vulnerability Management tích hợp AI

Oct 20, 2026 · @leone / Kestrix Core Architecture

## Giả định và phạm vi v1

v1 là hệ thống quản lý lỗ hổng cho **mã nguồn**: quét repo, gom và khử trùng lặp finding, chấm điểm theo ngữ cảnh, rồi giao việc cho team. AI chỉ giải thích và đề xuất; con người quyết định.

### Giả định đang dùng
- Mục tiêu là hệ thống nội bộ / nền tảng AppSec tự xây dựng từ đầu (không phụ thuộc nguyên khối vào DefectDojo).
- Đối tượng quét là repo Git, bắt đầu với GitHub.
- Được dùng LLM API bên ngoài qua LLM Gateway, có cơ chế redact secret và tùy chọn chuyển model nội bộ (Ollama/vLLM).

### Trong phạm vi v1
- Ba loại finding:
  1. **SAST**: Semgrep CE / Opengrep
  2. **Secret**: Gitleaks
  3. **Dependency**: OSV-Scanner
- Ingest, chuẩn hóa, khử trùng lặp (deterministic fingerprinting), vòng đời finding, chấm điểm rủi ro theo ngữ cảnh (SSVC/EPSS/KEV), SLA, ticket/team assignment.
- AI: giải thích finding, gợi ý false positive, dự đoán CVSS còn thiếu (có nhãn dự đoán), đề xuất bản vá có kiểm soát.

### Ngoài phạm vi v1 (ghi nhận vào docs/TODO.md)
- Quét hạ tầng và network (Tenable, Qualys).
- DAST và pentest tự động.
- AI copilot trong IDE hoặc pre-commit.
- Tự động merge bản vá mà không qua con người review.

---

## Kiến trúc cốt lõi

Bắt đầu bằng **modular monolith**:
- `packages/core`: Logic thuần (types, fingerprint, normalize, scoring, lifecycle), không I/O.
- `packages/db`: Drizzle ORM + PostgreSQL schema & migrations.
- `packages/llm-gateway`: Cửa duy nhất gọi LLM (redact secret, JSON schema validation, caching, token budget).
- `apps/api`: Fastify + Zod cho ingest, query và lifecycle management.
- `apps/worker`: BullMQ xử lý background scan và LLM enrichment.
- `apps/web`: Next.js / React interactive AppSec dashboard.

---

## 10 Quy tắc bảo mật cốt lõi
1. Không bao giờ lưu, log, trả qua API, gửi cho LLM hay đưa vào ticket giá trị thô của secret. Chỉ lưu hash SHA-256 và bản che (`****` + 4 ký tự cuối).
2. Repo được quét là dữ liệu không tin cậy. Không thực thi code của repo và không chạy install script của package manager.
3. Scanner chạy trong container tạm thời: non-root, root filesystem chỉ đọc, `--network=none`, giới hạn CPU, RAM và thời gian.
4. Mọi lời gọi LLM đi qua `packages/llm-gateway`.
5. Output của LLM phải qua Zod schema; không hợp lệ thì loại bỏ. LLM không bao giờ trực tiếp đổi trạng thái finding.
6. Truy cập GitHub để ghi: GitHub App quyền tối thiểu, token ngắn hạn, chỉ tạo branch và draft PR.
7. Mọi endpoint trừ `/healthz` yêu cầu xác thực và kiểm tra quyền theo team ở tầng service.
8. Truy vấn DB chỉ qua Drizzle với tham số hóa; cấm nối chuỗi SQL.
9. Đường dẫn file lấy từ output scanner hoặc từ repo phải được chuẩn hóa và giới hạn trong thư mục làm việc (chống path traversal).
10. Không commit secret. Mọi cấu hình qua biến môi trường.
