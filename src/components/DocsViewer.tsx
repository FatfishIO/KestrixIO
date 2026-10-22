import React, { useState } from 'react';
import { FileText, Shield, Database, Activity, Terminal, AlertCircle, Copy, Check } from 'lucide-react';

interface DocsViewerProps {
  initialDoc?: string;
}

const DOCS_LIST = [
  {
    id: 'PLAN.md',
    title: 'PLAN.md — Kế hoạch & Kiến trúc',
    description: 'Giả định v1, stack công nghệ, modular monolith, và lộ trình 6 phase.',
  },
  {
    id: 'PRD.md',
    title: 'PRD.md — Yêu cầu Sản phẩm',
    description: 'Personas, Epics, quy tắc fingerprint, cây quyết định SSVC và guardrails AI.',
  },
  {
    id: 'ERD.md',
    title: 'ERD.md — Mô hình Dữ liệu',
    description: 'Bảng Team, Asset, Scan, Finding, Occurrence, StatusChange, AiOutput, Vulnerability.',
  },
  {
    id: 'STATE_MACHINE.md',
    title: 'STATE_MACHINE.md — Máy trạng thái',
    description: '6 trạng thái, quyền con người vs hệ thống, quy tắc auto-fixed và reopened.',
  },
  {
    id: 'THREAT_MODEL.md',
    title: 'THREAT_MODEL.md — Mô hình Đe dọa',
    description: 'Phân tích STRIDE và 10 quy tắc bảo mật bất di bất dịch của Kestrix.',
  },
  {
    id: 'openapi.yaml',
    title: 'openapi.yaml — API Contract',
    description: 'Đặc tả OpenAPI 3.1 cho ingestion, lifecycle và LLM gateway endpoints.',
  },
  {
    id: 'TODO.md',
    title: 'TODO.md — Danh mục công việc',
    description: 'Theo dõi các đầu việc ngoài phạm vi v1 (Phase 2-6 backlog).',
  },
];

// Document summaries and contents for fast, self-contained, in-app navigation
const DOCS_CONTENT: Record<string, string> = {
  'PLAN.md': `# Kestrix — Plan hệ thống Vulnerability Management tích hợp AI

## Giả định và phạm vi v1
- Hệ thống quản lý lỗ hổng mã nguồn: quét repo, gom và khử trùng lặp finding, chấm điểm theo ngữ cảnh, giao việc cho team.
- AI chỉ giải thích và đề xuất; con người quyết định.
- Ba loại finding: SAST (Semgrep/Opengrep), Secret (Gitleaks), Dependency (OSV-Scanner).

## Kiến trúc cốt lõi: Modular Monolith
- packages/core: logic thuần (types, fingerprint, normalize, scoring, lifecycle), không I/O.
- packages/db: Drizzle ORM + PostgreSQL schema & migrations.
- packages/llm-gateway: Cửa duy nhất gọi LLM (redact secret, JSON schema validation, caching, token budget).
- apps/api: Fastify + Zod cho ingest, query và lifecycle management.
- apps/worker: BullMQ xử lý background scan và LLM enrichment.

## 10 Quy tắc bảo mật cốt lõi
1. Không bao giờ lưu, log, trả qua API, gửi cho LLM hay đưa vào ticket giá trị thô của secret.
2. Repo được quét là dữ liệu không tin cậy. Không thực thi code của repo và không chạy install script.
3. Scanner chạy trong container tạm thời: non-root, root filesystem chỉ đọc, --network=none.
4. Mọi lời gọi LLM đi qua packages/llm-gateway.
5. Output của LLM phải qua Zod schema; không hợp lệ thì loại bỏ.
6. GitHub App quyền tối thiểu, token ngắn hạn; chỉ tạo branch và draft PR.
7. Kiểm tra quyền theo team ở tầng service.
8. Truy vấn DB chỉ qua Drizzle với tham số hóa.
9. Đường dẫn file lấy từ output scanner hoặc repo phải được chuẩn hóa (chống path traversal).
10. Không commit secret. Mọi cấu hình qua biến môi trường.`,

  'PRD.md': `# Kestrix — Product Requirements Document (PRD) v1.0

## Nguyên tắc chỉ đạo
"Facts đến từ công cụ quét và nguồn dữ liệu uy tín (OSV, CVE, KEV, EPSS). Logic chấm điểm và khử trùng lặp hoàn toàn mang tính tất định (deterministic). AI chỉ đóng vai trò phân tích, giải thích và đề xuất. Con người giữ quyền quyết định tối cao về mọi thay đổi trạng thái."

## Các tính năng cốt lõi (Core Epics)
- Epic 1: Quản lý Asset & Team (Criticality 1-4, internet-facing, environment, data_class).
- Epic 2: Quét & Ingest Đa Scanner (Semgrep SARIF, Gitleaks, OSV-Scanner).
- Epic 3: Khử trùng lặp Deterministic Fingerprinting:
  * SAST: sha256(rule_id + ":" + path + ":" + snippet)
  * Secret: sha256(rule_id + ":" + path + ":" + sha256(raw_secret)) [giá trị thô không bao giờ lưu]
  * Dependency: sha256(ecosystem + ":" + package + ":" + vuln_id + ":" + manifest) [không chứa version]
- Epic 4: Chấm điểm rủi ro theo ngữ cảnh (Cây quyết định SSVC: P1 7d, P2 30d, P3 90d, P4 low).
- Epic 5: Vòng đời Finding & Trạng thái (new, triaged, in_progress, fixed, false_positive, risk_accepted).
- Epic 6: AI-Augmented Advisory có kiểm soát (Explain, False Positive Triage, Missing CVSS Predict, Patch).`,

  'ERD.md': `# Kestrix — Entity Relationship Diagram & Data Models (ERD)

## Các bảng chính
- teams: id, name, owners (jsonb), created_at
- assets: id, team_id, name, repo_url, criticality (1-4), internet_facing, environment, data_class
- scans: id, asset_id, commit_sha, branch, scanner, scanner_version, rules_version, status, findings_count
- findings: id, asset_id, type, fingerprint, rule_or_vuln_id, title, status, risk_level, risk_reasons, first_seen, last_seen, sla_due, reopened, secret_hash, secret_masked
  * UNIQUE INDEX: idx_findings_asset_fingerprint (asset_id, fingerprint)
- occurrences: id, finding_id, scan_id, file_path, line_start, line_end, snippet_hash
- vulnerabilities: id (CVE/GHSA/OSV), aliases, cvss_vector, cvss_score, cvss_source, epss, kev, ssvc, fixed_versions
- status_changes: id, finding_id, from_status, to_status, actor, reason, expires_at, changed_at
- ai_outputs: id, finding_id, kind, model, prompt_version, input_hash, output_json, confidence, reviewed_by, created_at`,

  'STATE_MACHINE.md': `# Kestrix — Finding Lifecycle State Machine

## 6 Trạng thái chuẩn
- new: Mới phát hiện lần đầu từ công cụ quét.
- triaged: Con người xác nhận là vấn đề thật cần xử lý.
- in_progress: Đang giao cho nhóm phát triển sửa lỗi.
- fixed: Đã sửa triệt để (Hệ thống tự động đặt khi scan sau không còn thấy).
- false_positive: Báo động giả (Con người duyệt kèm lý do).
- risk_accepted: Chấp nhận rủi ro có thời hạn (Bắt buộc expires_at và lý do).

## Quy tắc cốt lõi
1. Con người quyết định: AI tuyệt đối không bao giờ được tự đổi trạng thái finding.
2. Quy tắc Auto-Fixed: Lần quét đầy đủ tiếp theo của Asset không còn thấy finding -> Chuyển sang fixed (Actor: system).
3. Quy tắc Reopened: Finding đang fixed lại xuất hiện trong scan mới -> Chuyển về triaged và đặt reopened = true.
4. Bất biến Audit Log: Mọi lần chuyển đổi trạng thái phải tạo một bản ghi trong bảng status_changes.`,

  'THREAT_MODEL.md': `# Kestrix — Threat Model & Security Architecture

## Phân tích STRIDE & 10 Quy tắc bắt buộc
- Quy tắc 1: Bảo mật Secret (Chỉ lưu SHA-256 và bản che ****4f9a; không bao giờ log hay lưu raw secret).
- Quy tắc 2: Repo được quét là dữ liệu không tin cậy. Tuyệt đối không chạy install script hay thực thi code lạ.
- Quy tắc 3: Cô lập Scanner Container: non-root, root fs read-only, --network=none, giới hạn CPU/RAM.
- Quy tắc 4: Cô lập LLM qua LLM Gateway (Redaction, caching, token budget, ghi ai_outputs).
- Quy tắc 5: Guardrail & Zod Schema Validation cho AI (LLM output không khớp schema thì loại bỏ ngay).
- Quy tắc 6: Giới hạn GitHub App quyền tối thiểu; chỉ tạo branch và draft PR.
- Quy tắc 7: Phân quyền theo Team ở tầng Service.
- Quy tắc 8: Tham số hóa triệt để qua Drizzle ORM (cấm nối chuỗi SQL).
- Quy tắc 9: Chống Path Traversal (chuẩn hóa artifactLocation và gitleaks paths).
- Quy tắc 10: Quản lý bí mật qua biến môi trường (.env.example).`,

  'openapi.yaml': `openapi: 3.1.0
info:
  title: Kestrix Vulnerability Management API
  version: 1.0.0
paths:
  /healthz:
    get: { summary: Liveness check, responses: { '200': { description: ok } } }
  /assets:
    get: { summary: Danh sách asset theo team }
    post: { summary: Khai báo asset mới }
  /scans/ingest:
    post: { summary: Ingest SARIF, Gitleaks, OSV-Scanner json }
  /findings:
    get: { summary: Tra cứu finding kèm bộ lọc P1-P4, SLA, status }
  /findings/{id}/status:
    patch: { summary: Đổi trạng thái finding (chỉ con người thực hiện) }
  /findings/{id}/ai/{kind}:
    post: { summary: Yêu cầu AI Advisor phân tích finding qua LLM Gateway }`,

  'TODO.md': `# Kestrix — Danh sách công việc mở rộng (TODO Backlog)

## Phase 2: Ingestion & Pipeline Scanners nâng cao
- [ ] Xây dựng container image tạm thời cho Semgrep CE / Opengrep với non-root, --read-only, --network=none.
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
- [ ] Tích hợp GitHub App để tự động mở Draft Pull Request cho SAST findings đã pass sandbox test.`,
};

export const DocsViewer: React.FC<DocsViewerProps> = ({ initialDoc = 'PLAN.md' }) => {
  const [selectedDoc, setSelectedDoc] = useState(initialDoc);
  const [copied, setCopied] = useState(false);

  const doc = DOCS_LIST.find((d) => d.id === selectedDoc) || DOCS_LIST[0];
  const content = DOCS_CONTENT[selectedDoc] || 'Tài liệu đang được cập nhật...';

  const copyToClipboard = () => {
    navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
      {/* Sidebar List */}
      <div className="space-y-2">
        <div className="text-xs uppercase font-mono text-slate-400 font-semibold px-2 mb-2">
          Tài liệu Thiết kế Hệ thống
        </div>
        {DOCS_LIST.map((item) => {
          const isSelected = selectedDoc === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setSelectedDoc(item.id)}
              className={`w-full text-left p-3 rounded-xl border transition-all cursor-pointer ${
                isSelected
                  ? 'bg-indigo-600/20 border-indigo-500/80 text-white shadow-sm'
                  : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <div className="font-semibold text-xs flex items-center justify-between">
                <span>{item.id}</span>
                {isSelected && <span className="w-1.5 h-1.5 rounded-full bg-indigo-400"></span>}
              </div>
              <div className="text-[11px] text-slate-500 mt-1 line-clamp-1">{item.description}</div>
            </button>
          );
        })}
      </div>

      {/* Main Document Content */}
      <div className="md:col-span-3 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm flex flex-col">
        {/* Doc Header */}
        <div className="p-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <FileText className="w-4 h-4 text-indigo-400" />
              <span>{doc.title}</span>
            </div>
            <div className="text-xs text-slate-400 mt-0.5">{doc.description}</div>
          </div>

          <button
            onClick={copyToClipboard}
            className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium flex items-center space-x-1.5 transition-colors cursor-pointer"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span>Đã sao chép</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Sao chép nội dung</span>
              </>
            )}
          </button>
        </div>

        {/* Doc Body */}
        <div className="p-6 overflow-y-auto max-h-[750px] font-mono text-xs leading-relaxed text-slate-300 bg-slate-950/40">
          <pre className="whitespace-pre-wrap font-mono text-xs text-slate-200 select-text">
            {content}
          </pre>
        </div>
      </div>
    </div>
  );
};
