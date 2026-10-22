# Kestrix — Entity Relationship Diagram & Data Models (ERD)

## 1. Sơ đồ thực thể quan hệ

```
  +-------------------+              +-------------------+
  |       Team        | 1          * |       Asset       |
  |-------------------|--------------|-------------------|
  | id (PK)           |              | id (PK)           |
  | name              |              | team_id (FK)      |
  | owners (jsonb)    |              | repo_url          |
  | created_at        |              | criticality (1-4) |
  +-------------------+              | internet_facing   |
                                     | environment       |
                                     | data_class        |
                                     +-------------------+
                                        | 1           | 1
                                        |             |
                                        | *           | *
                         +-------------------+   +--------------------+
                         |       Scan        |   |      Finding       |
                         |-------------------|   |--------------------|
                         | id (PK)           |   | id (PK)            |
                         | asset_id (FK)     |   | asset_id (FK)      |
                         | commit_sha        |   | type (sast/secret/ |
                         | scanner           |   |       dependency)  |
                         | scanner_version   |   | fingerprint (UQ)   |
                         | rules_version     |   | rule_or_vuln_id    |
                         | status            |   | status             |
                         | started_at        |   | risk_level (P1-P4) |
                         | completed_at      |   | risk_reasons []    |
                         +-------------------+   | first_seen         |
                            | 1                  | last_seen          |
                            |                    | sla_due            |
                            | *                  | reopened (bool)    |
                         +-------------------+   +--------------------+
                         |    Occurrence     |     | 1          | 1
                         |-------------------|     |            |
                         | id (PK)           |     | *          | *
                         | scan_id (FK)      |<----+     +-------------------+
                         | finding_id (FK)   |           |   StatusChange    |
                         | file_path         |           |-------------------|
                         | line_start        |           | id (PK)           |
                         | line_end          |           | finding_id (FK)   |
                         | snippet_hash      |           | from_status       |
                         +-------------------+           | to_status         |
                                                         | actor             |
                                                         | reason            |
                                                         | expires_at        |
                                                         | changed_at        |
                                                         +-------------------+
                                                           |
                                                           | 1
                                                           | *
                                                         +-------------------+
                                                         |     AiOutput      |
                                                         |-------------------|
                                                         | id (PK)           |
                                                         | finding_id (FK)   |
                                                         | kind (explain/    |
                                                         |   triage/cvss/    |
                                                         |   patch/advisory) |
                                                         | model             |
                                                         | prompt_version    |
                                                         | input_hash        |
                                                         | output_json       |
                                                         | confidence        |
                                                         | reviewed_by       |
                                                         | created_at        |
                                                         +-------------------+

  +-----------------------+
  |     Vulnerability     |  (Cache toàn cục tra cứu theo mã lỗ hổng)
  |-----------------------|
  | id (PK: CVE/GHSA/OSV) |
  | aliases (jsonb)       |
  | cvss_vector           |
  | cvss_score (numeric)  |
  | cvss_source           |
  | epss (numeric)        |
  | kev (boolean)         |
  | ssvc (text)           |
  | fixed_versions []     |
  | fetched_at            |
  +-----------------------+
```

---

## 2. Chi tiết các bảng

### Bảng `teams`
| Cột | Kiểu dữ liệu | Ràng buộc | Mô tả |
|---|---|---|---|
| `id` | uuid | PK, default gen_random_uuid() | ID định danh team |
| `name` | varchar(100) | NOT NULL, UNIQUE | Tên team (ví dụ: Core Services, Mobile App) |
| `owners` | jsonb | NOT NULL, default '[]' | Danh sách email hoặc user handle chịu trách nhiệm |
| `created_at` | timestamptz | NOT NULL, default now() | Thời điểm tạo |

### Bảng `assets`
| Cột | Kiểu dữ liệu | Ràng buộc | Mô tả |
|---|---|---|---|
| `id` | uuid | PK, default gen_random_uuid() | ID định danh asset |
| `team_id` | uuid | FK -> teams(id), ON DELETE RESTRICT | Team chịu trách nhiệm |
| `name` | varchar(150) | NOT NULL | Tên dự án / kho mã nguồn |
| `repo_url` | text | NOT NULL | Đường dẫn repo Git |
| `criticality` | smallint | NOT NULL, CHECK (criticality BETWEEN 1 AND 4) | 1: Tối quan trọng -> 4: Phụ trợ |
| `internet_facing` | boolean | NOT NULL, default false | Có tiếp xúc trực tiếp mạng internet |
| `environment` | varchar(20) | NOT NULL (production, staging, development) | Môi trường triển khai |
| `data_class` | varchar(20) | NOT NULL (pci_dss, pii, internal, public) | Phân loại dữ liệu xử lý |
| `created_at` | timestamptz | NOT NULL, default now() | Thời điểm tạo |

### Bảng `scans`
| Cột | Kiểu dữ liệu | Ràng buộc | Mô tả |
|---|---|---|---|
| `id` | uuid | PK, default gen_random_uuid() | ID lần quét |
| `asset_id` | uuid | FK -> assets(id), ON DELETE CASCADE | Asset được quét |
| `commit_sha` | varchar(40) | NOT NULL | Git commit hash |
| `branch` | varchar(100) | NOT NULL, default 'main' | Nhánh quét |
| `scanner` | varchar(30) | NOT NULL (semgrep, gitleaks, osv-scanner) | Công cụ quét |
| `scanner_version` | varchar(30) | NOT NULL | Phiên bản cố định của scanner |
| `rules_version` | varchar(30) | NOT NULL | Phiên bản rule set |
| `status` | varchar(20) | NOT NULL (queued, running, completed, failed) | Trạng thái scan |
| `findings_count` | integer | NOT NULL, default 0 | Số finding phát hiện |
| `started_at` | timestamptz | NULL | Thời gian bắt đầu chạy |
| `completed_at` | timestamptz | NULL | Thời gian hoàn tất |

### Bảng `findings`
| Cột | Kiểu dữ liệu | Ràng buộc | Mô tả |
|---|---|---|---|
| `id` | uuid | PK, default gen_random_uuid() | ID định danh finding |
| `asset_id` | uuid | FK -> assets(id), ON DELETE CASCADE | Asset bị ảnh hưởng |
| `type` | varchar(20) | NOT NULL (sast, secret, dependency) | Loại lỗ hổng |
| `fingerprint` | varchar(64) | NOT NULL | SHA-256 fingerprint duy nhất |
| `rule_or_vuln_id` | varchar(100) | NOT NULL | ID rule (ví dụ: python.lang.security.injection) hoặc CVE/GHSA |
| `title` | varchar(255) | NOT NULL | Tiêu đề tóm lược |
| `status` | varchar(30) | NOT NULL (new, triaged, in_progress, fixed, false_positive, risk_accepted) | Trạng thái vòng đời |
| `risk_level` | varchar(5) | NOT NULL (P1, P2, P3, P4) | Cấp độ rủi ro |
| `risk_reasons` | jsonb | NOT NULL, default '[]' | Mảng lý do cụ thể quyết định mức P |
| `first_seen` | timestamptz | NOT NULL, default now() | Lần đầu phát hiện |
| `last_seen` | timestamptz | NOT NULL, default now() | Lần gần nhất phát hiện |
| `sla_due` | timestamptz | NULL | Hạn chót khắc phục theo SLA |
| `reopened` | boolean | NOT NULL, default false | Đã từng bị reopen sau khi fixed |
| `secret_hash` | varchar(64) | NULL | SHA-256 của secret (nếu type=secret, cấm lưu giá trị thô) |
| `secret_masked` | varchar(16) | NULL | Giá trị che (ví dụ: '****4f9a') |

**Chỉ mục duy nhất bắt buộc**:
`CREATE UNIQUE INDEX idx_findings_asset_fingerprint ON findings(asset_id, fingerprint);`

### Bảng `occurrences`
| Cột | Kiểu dữ liệu | Ràng buộc | Mô tả |
|---|---|---|---|
| `id` | uuid | PK, default gen_random_uuid() | ID lần xuất hiện |
| `finding_id` | uuid | FK -> findings(id), ON DELETE CASCADE | Finding tương ứng |
| `scan_id` | uuid | FK -> scans(id), ON DELETE CASCADE | Lần quét phát hiện |
| `file_path` | text | NOT NULL | Đường dẫn file chuẩn hóa |
| `line_start` | integer | NULL | Dòng bắt đầu |
| `line_end` | integer | NULL | Dòng kết thúc |
| `snippet_hash` | varchar(64) | NULL | SHA-256 hash của đoạn code bao quanh |

### Bảng `vulnerabilities` (Global Cache)
| Cột | Kiểu dữ liệu | Ràng buộc | Mô tả |
|---|---|---|---|
| `id` | varchar(50) | PK (CVE-..., GHSA-..., OSV-...) | Định danh lỗ hổng |
| `aliases` | jsonb | NOT NULL, default '[]' | Các mã định danh tương đương |
| `cvss_vector` | varchar(100) | NULL | Chuỗi vector CVSS v3.1 / v4 |
| `cvss_score` | numeric(3,1) | NULL | Điểm số CVSS chính thức |
| `cvss_source` | varchar(50) | NULL | Nguồn CVSS (CNA, NVD, AI_PREDICTED) |
| `epss` | numeric(5,4) | NULL | Điểm xác suất khai thác EPSS |
| `kev` | boolean | NOT NULL, default false | Nằm trong CISA Known Exploited Vulnerabilities |
| `ssvc` | varchar(30) | NULL | Quyết định SSVC (Track, Attend, Act) |
| `fixed_versions` | jsonb | NOT NULL, default '[]' | Danh sách phiên bản đã sửa |
| `fetched_at` | timestamptz | NOT NULL, default now() | Thời điểm đồng bộ gần nhất |

### Bảng `status_changes` (Audit Log)
| Cột | Kiểu dữ liệu | Ràng buộc | Mô tả |
|---|---|---|---|
| `id` | uuid | PK, default gen_random_uuid() | ID bản ghi đổi trạng thái |
| `finding_id` | uuid | FK -> findings(id), ON DELETE CASCADE | Finding bị đổi |
| `from_status` | varchar(30) | NOT NULL | Trạng thái trước |
| `to_status` | varchar(30) | NOT NULL | Trạng thái sau |
| `actor` | varchar(100) | NOT NULL | Người thực hiện (hoặc 'system' khi auto-fixed) |
| `reason` | text | NOT NULL | Lý do chi tiết |
| `expires_at` | timestamptz | NULL | Hạn chấp nhận rủi ro (khi to_status = 'risk_accepted') |
| `changed_at` | timestamptz | NOT NULL, default now() | Thời điểm chuyển đổi |

### Bảng `ai_outputs` (Audit & Governance cho AI)
| Cột | Kiểu dữ liệu | Ràng buộc | Mô tả |
|---|---|---|---|
| `id` | uuid | PK, default gen_random_uuid() | ID đầu ra AI |
| `finding_id` | uuid | FK -> findings(id), ON DELETE CASCADE | Finding được phân tích |
| `kind` | varchar(30) | NOT NULL (explain, triage, cvss, patch, advisory) | Loại tác vụ AI |
| `model` | varchar(50) | NOT NULL | Tên model (ví dụ: gemini-2.5-flash) |
| `prompt_version` | varchar(20) | NOT NULL | Phiên bản prompt |
| `input_hash` | varchar(64) | NOT NULL | Hash dữ liệu đầu vào |
| `output_json` | jsonb | NOT NULL | Dữ liệu có cấu trúc qua Zod |
| `confidence` | numeric(3,2) | NULL | Độ tin cậy (0.00 - 1.00) |
| `reviewed_by` | varchar(100) | NULL | Người duyệt (hoặc null nếu chưa duyệt) |
| `created_at` | timestamptz | NOT NULL, default now() | Thời gian sinh |
