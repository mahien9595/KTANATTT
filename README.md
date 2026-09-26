# KTANATTT — Bộ công cụ kiểm tra An ninh, An toàn thông tin

Phần mềm hỗ trợ cơ quan quản lý (Tổ ANATTT Công an xã) kiểm tra nhanh an ninh, an toàn thông tin
hệ thống máy tính Windows và tổng hợp kết quả.

## Hai công cụ

| File | Vai trò |
|---|---|
| `tong_hop_kiem_tra.py` | **Công cụ TỔNG HỢP (cơ quan quản lý)** — cập nhật dữ liệu CVE/IOC, build công cụ kiểm tra mang đi, và tổng hợp/phân tích biên bản thu về. Phiên bản 3.0.0 |
| `auto_fill_bien_ban.py` | **Công cụ KIỂM TRA (chạy trên từng máy)** — thu thập thông tin máy, đối chiếu lỗ hổng/mã độc và tự điền biên bản .docx kèm file dữ liệu đã ký |

> Tên file không kèm số phiên bản để không phải đổi tên mỗi lần nâng cấp. Số phiên bản nằm trong
> hằng số `APP_VERSION_TH` (công cụ tổng hợp) và `APP_VERSION` (công cụ kiểm tra).

## Quy trình

1. **Trước mỗi đợt:** mở công cụ tổng hợp → tab 3 → cập nhật CVE (MSRC + CISA KEV) và IOC (ThreatFox),
   rồi build `auto_fill_bien_ban.exe`. Công cụ tự kiểm tra dữ liệu trước khi build và ghi kèm `manifest.json`.
2. **Khi kiểm tra:** chạy công cụ kiểm tra trên từng máy (nên "Run as administrator"). Mỗi máy sinh ra
   một biên bản `.docx` và một file dữ liệu `.attt.json` có chữ ký toàn vẹn.
3. **Sau đợt:** mở công cụ tổng hợp → tab 1/2 → chọn thư mục biên bản để tổng hợp, phân tích rủi ro,
   kiểm tra tính toàn vẹn và xuất báo cáo Excel.

## Tài liệu

- `DANH_GIA_VA_DE_XUAT.md` — đánh giá hiện trạng, các cải tiến đã thực hiện và lộ trình phát triển.

## Yêu cầu

- Python 3.11+ trên Windows.
- Thư viện: `python-docx`, `openpyxl`, `PySide6` (công cụ tổng hợp); `python-docx` (công cụ kiểm tra).
  Tùy chọn: `pyzipper` (nén log có mật khẩu), `nuitka` (build .exe).
