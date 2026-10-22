# Kestrix — Danh sách công việc mở rộng (TODO Backlog)

Các hạng mục dưới đây nằm ngoài phạm vi v1 hiện tại và sẽ được triển khai theo đúng lộ trình phase trong `docs/PLAN.md`:

## Phase 2: Ingestion & Pipeline Scanners nâng cao
- [ ] Xây dựng container image tạm thời cho Semgrep CE / Opengrep với non-root, `--read-only`, `--network=none`.
- [ ] Xây dựng container image tạm thời cho Gitleaks và OSV-Scanner với pinned versions.
- [ ] Tích hợp MinIO / S3 object storage để lưu trữ raw SARIF / CycloneDX artifact dài hạn.
- [ ] Thiết lập worker BullMQ với concurrency và token rate limiting trên Redis.

## Phase 3: Vulnerability Feeds Automation
- [ ] Định kỳ cronjob đồng bộ CISA KEV (JSON feed) mỗi 24 giờ.
- [ ] Định kỳ cronjob tải toàn bộ FIRST EPSS scores hàng ngày và cache theo CVE-ID.
- [ ] Tích hợp OSV.dev REST API v1 để tự động tra cứu fixed versions và commit ranges.

## Phase 4: AI Enrichment & Model Governance
- [ ] Hỗ trợ local self-hosted LLM qua Ollama / vLLM song song với Google Gemini API.
- [ ] Bộ eval 50-100 test cases từ OWASP Juice Shop / WebGoat để benchmark tỉ lệ precision/recall của AI False Positive triage.
- [ ] Giao diện cấu hình Token Budget theo từng Asset và Team.

## Phase 5: Automated Remediation Sandbox
- [ ] Runner sandbox chạy test isolated của repo để verify patch trước khi tạo PR.
- [ ] Tích hợp GitHub App để tự động mở Draft Pull Request cho SAST findings đã pass sandbox test.

## Ngoài phạm vi v1 (Ghi nhận từ yêu cầu mở rộng)
- [ ] **AI Copilot cho nhà phát triển (Shift-Left IDE / Pre-commit Agent)**: Phân tích prompt/code tại thời điểm commit để cảnh báo sớm prompt injection hoặc rò rỉ secret. Theo `docs/PLAN.md`, đây là một dòng sản phẩm riêng biệt ngoài phạm vi hệ thống quản lý lỗ hổng trung tâm v1.
- [ ] **Quét hạ tầng / DAST / Pentest tự động**: Ngoài phạm vi v1 (chỉ tập trung vào SAST, Secret, Dependency cho mã nguồn).
