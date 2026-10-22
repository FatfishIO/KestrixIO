# Kestrix — Kế hoạch Rà soát & Làm sạch Dữ liệu Nhạy cảm / Định danh Cá nhân

Cập nhật toàn bộ mã nguồn để loại bỏ triệt để tên cá nhân (`Minh Hoàng`, `Leone`, `Trần Nam`, `Lê Hương`), chuẩn hóa sang định danh vai trò kiểm thử (`Global SecOps`, `Test Core Lead`, `Test Payments Lead`, `Test Mobile Lead`), đồng thời làm sạch các mẫu chuỗi trong bộ test/simulator để không bị GitHub Push Protection cảnh báo nhầm khi đẩy code lên GitHub.

## User Review & Critical Decisions

> [!IMPORTANT]
> Toàn bộ mã nguồn đã được rà soát tự động. Không có API key thật hay thông tin tài khoản thật nào được lưu trong dự án, tuy nhiên có tên hiển thị cá nhân trong dữ liệu mẫu và một số chuỗi giả lập (`sk_live_...`, `AKIA...`, `ghp_...`) có thể kích hoạt bộ lọc GitHub Secret Scanning khi push.

- **Quyết định 1 (Chuẩn hóa Tên Tài khoản & Chủ sở hữu Team)**:
  - Đổi `Minh Hoàng (Global SecOps)` thành **`Global SecOps`** (`secops@kestrix.local`).
  - Đổi các tài khoản mẫu khác thành **`Test Core Lead`** (`test-core@kestrix.local`), **`Test Payments Lead`** (`test-pay@kestrix.local`), và **`Test Mobile Lead`** (`test-mobile@kestrix.local`).
  - Xóa hoàn toàn email `minhhoang@kestrix.local` và `leone@kestrix.local` trong dữ liệu khởi tạo Team Owners.
- **Quyết định 2 (Làm sạch Chuỗi Mẫu Giả lập cho GitHub Push Protection)**:
  - Thay thế các tiền tố giống khóa thật (`sk_live_...`, `ghp_...`, `AKIA...`) trong bộ dữ liệu mẫu và simulator bằng chuỗi giả lập an toàn (`TEST_SECRET_SAMPLE_...`) để GitHub không chặn lệnh `git push`, đồng thời giữ nguyên 100% logic kiểm thử SHA-256 và che 4 ký tự cuối.

---

## 1. Overview & Core Concept

- **What It Does**: Đảm bảo kho mã nguồn Kestrix hoàn toàn ẩn danh (Zero PII) và vượt qua mọi trình quét bảo mật của GitHub (GitHub Secret Scanning / Push Protection) ngay từ lần commit đầu tiên.
- **Target Audience / Persona**: Đội ngũ phát triển và kỹ sư bảo mật sử dụng kho mã nguồn công khai hoặc nội bộ trên GitHub.
- **Key Value**: Loại bỏ hoàn toàn thông tin định danh cá nhân và các chuỗi test dễ gây cảnh báo giả trên GitHub.

---

## 2. User Experience & Visual Design

- **Key User Flows**:
  1. Trên **Trang Đăng nhập**: Hiển thị 3 thẻ chọn nhanh với tên vai trò thuần túy: **Global SecOps**, **Test Core Lead**, **Test Payments Lead**.
  2. Trên **Thanh Ngữ cảnh & Nhật ký Kiểm toán (`StatusChange`)**: Hiển thị định danh `Global SecOps (secops@kestrix.local)` hoặc `test-*@kestrix.local`.
  3. Trên **Danh mục Asset & Team**: Hiển thị danh sách `owners` của các Team bằng các email kiểm thử tiêu chuẩn (`test-core@kestrix.local`, `test-pay@kestrix.local`, `test-mobile@kestrix.local`).
- **Visual Identity & Theme**: Giữ nguyên thiết kế High-Craft Dark UI (`#090D16` / `#111827`), cấu trúc Top Bar 3 vùng, phông chữ `Plus Jakarta Sans` + `DM Sans` + `JetBrains Mono` (`tabular-nums`).

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Loại bỏ tiền tố nhạy cảm trong dữ liệu mẫu Scanner**
  - *Chosen Approach*: Sử dụng các chuỗi test trung tính (`TEST_STRIPE_KEY_SAMPLE_9900ABCD`, `TEST_AWS_KEY_SAMPLE_7EXAMPLE`, `TEST_PAT_TOKEN_SAMPLE_9999`) thay cho các tiền tố thực tế của nhà cung cấp.
  - *Why*: GitHub Push Protection tự động quét regex theo tiền tố (`sk_live_`, `ghp_`, `AKIA`). Việc đổi sang tiền tố `TEST_` giúp push code lên GitHub mượt mà mà vẫn kiểm thử đầy đủ cơ chế băm SHA-256 và che `****`.

---

## 4. Technical Architecture & Data Strategy *(Technical Reference)*

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                     Kestrix Sanitization & Anonymization                │
├───────────────────────┬─────────────────────────┬───────────────────────┤
│   Authentication UI   │   Backend Auth & Seed   │  Scanner & Test Data  │
│  ┌─────────────────┐  │  ┌───────────────────┐  │  ┌─────────────────┐  │
│  │ Global SecOps   │  │  │ KNOWN_USERS Map   │  │  │ Neutralized     │  │
│  │ Test Core Lead  │──┼─▶│ (No Personal Name)│  │  │ Test Prefixes   │  │
│  │ Test Pay Lead   │  │  │ Team Owners Seed  │  │  │ (GitHub Safe)   │  │
│  └─────────────────┘  │  └───────────────────┘  │  └─────────────────┘  │
└───────────────────────┴─────────────────────────┴───────────────────────┘
```

- **Data Model & State**:
  - Danh sách tài khoản đăng nhập và dữ liệu khởi tạo (`INITIAL_TEAMS`, `KNOWN_USERS`) chỉ dùng định danh vai trò (`Global SecOps`, `Test Core Lead`, `Test Payments Lead`, `Test Mobile Lead`).
  - Cấu hình `docker-compose.yml` và `.env.example` chỉ sử dụng biến môi trường mẫu (`PLACEHOLDER`), không chứa bất kỳ khóa hay thông tin cá nhân nào.
