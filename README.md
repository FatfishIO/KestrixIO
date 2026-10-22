# Kestrix — Hệ thống Quản lý Lỗ hổng Mã nguồn Tích hợp AI (AI-Augmented Vulnerability Management)

**Kestrix** là hệ thống quản lý lỗ hổng bảo mật mã nguồn (Source Code Vulnerability Management) khép kín từ **Phát hiện → Làm giàu → Ưu tiên hóa (CARE) → Khắc phục (Self-Correction Sandbox)**. Hệ thống tích hợp **Semgrep** (SAST), **Gitleaks** (Secret Detection), và **OSV-Scanner** (Dependency/SCA), chuẩn hóa dữ liệu, khử trùng lặp qua nhiều lần quét, chấm điểm rủi ro theo ngữ cảnh thực tế, và quản lý vòng đời lỗ hổng.

> **Triết lý Cốt lõi**: Facts (bằng chứng thực tế) đến từ Scanner và cơ sở dữ liệu chuẩn (OSV, NVD CVE, CISA KEV, FIRST EPSS). **AI chỉ đóng vai trò giải thích và đề xuất — Con người quyết định mọi thay đổi trạng thái.**

---

## Kiến trúc Tổng thể & Cấu trúc Monorepo

```text
kestrix/
├── apps/
│   ├── api/                        # API Gateway (Fastify + Zod schemas, RBAC, SSE progress)
│   ├── worker/                     # Async Worker (BullMQ + Ephemeral Container Sandbox)
│   └── web/ (src/)                 # Dashboard điều hành bảo mật (React / Next-ready UI)
├── packages/
│   ├── core/                       # Logic thuần không I/O (fingerprint, normalize, CARE scoring, stateMachine)
│   ├── db/                         # Drizzle ORM + PostgreSQL schema, migrations & repository
│   └── llm-gateway/                # Cửa duy nhất gọi LLM (Secret redaction, XML sandboxing, Zod validation)
├── docs/
│   ├── PLAN.md                     # Lộ trình phát triển 5 Phase
│   ├── PRD.md                      # Yêu cầu sản phẩm & Công thức chấm điểm CARE + SSVC
│   ├── ERD.md                      # Sơ đồ thực thể (8 bảng) & Unique Index (asset_id, fingerprint)
│   ├── STATE_MACHINE.md            # Máy trạng thái vòng đời Finding & Quy tắc Auto-Fixed / Reopened
│   ├── THREAT_MODEL.md             # Mô hình mối đe dọa & 10 Quy tắc bảo mật bắt buộc
│   ├── openapi.yaml                # Đặc tả REST API OpenAPI 3.1.0
│   └── TODO.md                     # Danh sách hạng mục mở rộng ngoài phạm vi phiên hiện tại
├── tests/                          # Bộ Unit Tests (Vitest) cho toàn bộ core logic & guardrails
├── docker-compose.yml              # Hạ tầng local: PostgreSQL 16, Valkey 7.2, MinIO
└── pnpm-workspace.yaml             # Cấu hình pnpm workspaces
```

---

## 5 Điểm Tích hợp AI Trọng tâm (Guardrailed qua `packages/llm-gateway`)

1. **Giải thích theo ngữ cảnh (`explain`)**: Phân tích nguyên nhân gốc rễ, kịch bản khai thác, tác động kỹ thuật và ánh xạ CWE/OWASP.
2. **Tóm tắt Advisory & Trích xuất TTPs (`advisory`)**: Đọc báo cáo CVE/GHSA để trích xuất phần mềm bị ảnh hưởng, kỹ thuật tấn công MITRE ATT&CK (TTPs), biện pháp giảm thiểu và **bắt buộc đính kèm nguồn trích dẫn (`sourceCitations`)** chống ảo giác.
3. **Gợi ý Triage False Positive (`triage`)**: Đánh giá độ tin cậy (`confidence`) và bằng chứng trong code. Không bao giờ tự động đóng finding.
4. **Dự đoán CVSS còn thiếu (`cvss`)**: Ước tính điểm và vector CVSS v3.1 khi CNA chưa công bố. Bắt buộc gắn nhãn **`[Dự đoán]`** và không bao giờ ghi đè điểm chính thức từ CNA.
5. **Sinh bản vá & Vòng lặp Tự sửa lỗi (`patch` + Self-Correction Loop)**:
   - Sinh `unified diff` cho lỗi SAST.
   - Đưa bản vá vào **Sandbox cô lập** chạy lại Scanner (đảm bảo hết lỗi và không sinh lỗi mới) + chạy Unit Test (nếu asset bật `sandboxTestsEnabled`).
   - Tối đa **3 vòng lặp tự sửa lỗi** trước khi cho phép mở **Draft PR** qua GitHub App (cấm tự động merge — Quy tắc #6).

---

## 10 Quy tắc Bảo mật Bắt buộc (Hard Security Invariants)

1. **Bảo vệ Secret tuyệt đối**: Không bao giờ lưu, log, trả qua API, gửi cho LLM hay đưa vào ticket giá trị thô của secret. Chỉ lưu hash `SHA-256` và bản che `****` (4 ký tự cuối).
2. **Không thực thi mã nguồn không tin cậy**: Repo được quét là dữ liệu không tin cậy. Quét trong container cách ly (`--network=none --read-only --cap-drop=ALL --pids-limit=128`), không chạy install script của package manager.
3. **Chống SSRF**: Kiểm tra URL repo/webhook và chặn toàn bộ dải IP nội bộ (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.169.254`).
4. **Cửa gọi LLM duy nhất (`packages/llm-gateway`)**: Mọi lệnh gọi AI phải đi qua gateway để tự động redact secret, bọc mã nguồn trong thẻ `<untrusted_code_context>` chống Prompt Injection, kiểm soát ngân sách token và cache theo `input_hash`.
5. **Zod Schema Validation cho AI**: Mọi đầu ra từ LLM đều phải được parse qua Zod schema nghiêm ngặt trước khi lưu vào bảng `ai_outputs` hoặc hiển thị.
6. **Quyết định thuộc về con người**: AI và hệ thống không bao giờ tự động merge PR và không tự chuyển trạng thái sang `false_positive` hoặc `risk_accepted`.
7. **Phân quyền ở tầng Service (RBAC)**: Mọi truy vấn đọc/ghi đều kiểm tra quyền sở hữu `team_id` tại tầng service (`assertTeamAccess`), không phụ thuộc vào UI.
8. **Giới hạn tài nguyên Worker**: Mỗi job quét có giới hạn CPU, RAM, PID và thời gian chạy tối đa.
9. **Chống Path Traversal**: Mọi đường dẫn file từ báo cáo SARIF/JSON đều được chuẩn hóa qua `normalizePath`, loại bỏ `../` và đảm bảo nằm trong thư mục gốc của repo.
10. **Xác thực Webhook**: Mọi webhook từ GitHub/GitLab phải được kiểm tra chữ ký HMAC-SHA256 bằng `crypto.timingSafeEqual`.

---

## Hướng dẫn Cài đặt & Chạy Dự án

### 1. Yêu cầu hệ thống
- **Node.js**: Bản LTS hiện hành (>= 20.x)
- **Package Manager**: `pnpm` (hoặc `npm`)
- **Docker & Docker Compose** (tùy chọn khi chạy đầy đủ PostgreSQL + Valkey + MinIO local)

### 2. Cài đặt dependencies
```bash
pnpm install
# hoặc: npm install
```

### 3. Khởi chạy Dashboard & Full-Stack API (Chế độ Không cần cấu hình DB ngoài)
Dự án đã tích hợp sẵn tầng Repository khởi tạo dữ liệu mẫu xác định (Deterministic In-Memory + Drizzle Schema), cho phép chạy ngay lập tức mà không cần cấu hình PostgreSQL hay API key:
```bash
pnpm dev
# hoặc: npm run dev
```
Truy cập ứng dụng tại: `http://localhost:3000`

### 4. Khởi chạy Hạ tầng Đầy đủ bằng Docker Compose (Tùy chọn)
```bash
cp .env.example .env
docker compose up -d
```

### 5. Kiểm tra TypeScript Lint & Chạy Bộ Unit Tests (Vitest)
```bash
pnpm lint && pnpm test
# hoặc: npm run lint && npx vitest run
```
Toàn bộ **6 bộ test (40 test cases)** kiểm chứng:
- `tests/fingerprint.test.ts`: Tính ổn định của fingerprint SAST, Secret (`SHA-256` + che 4 ký tự cuối), Dependency và chống Path Traversal.
- `tests/normalize.test.ts`: Chuẩn hóa báo cáo thực tế từ Semgrep SARIF 2.1.0, Gitleaks JSON, OSV-Scanner JSON và kiểm tra RBAC `assertTeamAccess`.
- `tests/scoring.test.ts`: Công thức chấm điểm rủi ro theo ngữ cảnh CARE (P1..P4) và tính hạn SLA.
- `tests/stateMachine.test.ts`: Chuyển trạng thái hợp lệ, bắt buộc nhập lý do, tự động đánh dấu `fixed` và kích hoạt `reopened = true`.
- `tests/llmGateway.test.ts`: Tự động che secret trước khi gọi LLM, cô lập `<untrusted_code_context>`, và xác thực Zod schema.
- `tests/pipeline.test.ts`: Phễu giảm tải cảnh báo (Alert Reduction Funnel), phân tách CVSS CNA vs `[Dự đoán]`, và cổng kiểm chứng bản vá Self-Correction Sandbox.
