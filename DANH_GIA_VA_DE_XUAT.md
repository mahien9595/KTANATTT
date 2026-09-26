# Đánh giá và đề xuất phương hướng phát triển — Công cụ TỔNG HỢP & TẠO CÔNG CỤ KIỂM TRA

Phạm vi: `TONG HOP VA TAO CONG CU KIEM TRA.py`. Công cụ này là phần mềm dành cho **cơ quan quản lý**
(Tổ ANATTT Công an xã). File `auto_fill_bien_ban_V1.6.py` là công cụ chạy trên từng máy được kiểm tra.
Ở đây chỉ đọc file đó để biết định dạng biên bản mà công cụ tổng hợp phải phân tích.

## 1. Hiện trạng

Quy trình hiện tại:

```
[Tab 3] Tải CVE (MSRC) + IOC (ThreatFox) ──> build auto_fill_bien_ban.exe ──> chép USB
                                                      │
                             chạy trên từng máy của xã ▼
                                           Biên bản .docx (mỗi máy 1 file)
                                                      │
[Tab 1] Đọc cả thư mục biên bản ──> bảng tổng hợp ──> Excel
[Tab 2] Thống kê: KPI, top lỗ hổng, danh sách USB
```

Hướng đi này đúng. Công cụ đã khép kín được vòng "chuẩn bị dữ liệu → phát công cụ → thu biên bản → tổng hợp".
Riêng việc kiểm tra thụ động (đối chiếu KB đã cài, không gửi payload) là phù hợp với vai trò kiểm tra hành chính.

## 2. Lỗi nghiêm trọng đã phát hiện và ĐÃ SỬA

Để kiểm chứng, tôi dùng **chính hàm `fill_form` của công cụ kiểm tra** (giả lập dữ liệu máy) tạo biên bản mẫu,
sau đó cho bộ phân tích của công cụ tổng hợp đọc lại. Kết quả của phiên bản cũ:

| Trường | Biên bản thực tế | Công cụ cũ đọc được | Hậu quả |
|---|---|---|---|
| **Mã độc** | "WannaCry: tiến trình đang chạy tasksche.exe" | `Không phát hiện` (**luôn luôn**) | **Máy nhiễm mã độc bị báo sạch**. Mức rủi ro không tính đến mã độc |
| **Mật khẩu** | Tích ô "không" | `Có đặt mật khẩu` (**luôn luôn**) | Không phát hiện được máy không đặt mật khẩu |
| **Phân loại máy** | Tích "Độc lập" + "Internet" | `Nội bộ` (**luôn luôn**) | Sai phân loại, không phát hiện máy nội bộ nối Internet |
| CPU | Intel(R) Core(TM) i5-10400 | `Intel(` | Regex `[^R…]` dừng ở chữ R |
| Loại ổ cứng | SSD | `SS` | Regex `[^Dung]` dừng ở chữ D |
| Cán bộ kiểm tra | Nguyễn Văn A | `Không rõ` | Regex không khớp khi có chức vụ |
| Kết nối mạng | Có (Wifi) | "(liệt kê chi tiết nếu có): …" | Bắt nhầm đoạn văn khác |
| Tên USB | SanDisk Ultra 3.0 USB Device | `SanDisk Ultra` | Regex dừng ở chữ số |

Nguyên nhân gốc: ô tích (☒/☐) trong mẫu là ký tự `w:sym` của Wingdings, còn `paragraph.text` của
python-docx **không chứa** ký tự này. Vì vậy mọi regex trên văn bản đều chỉ thấy chữ "Có… không…" của mẫu.

**Các thay đổi đã thực hiện trong mã nguồn:**

1. **Viết lại `parse_docx_content`:**
   - đọc ô tích trực tiếp từ XML (hỗ trợ cả ô tích tay trong Word và content control);
   - đọc bảng thông tin theo nhãn cột 1, không dùng regex trên toàn văn;
   - đọc kết quả mục II.1 theo đúng các dòng mà `auto_fill` ghi thêm.
2. **Đọc được kết quả mã độc** (họ mã độc, dấu hiệu). Phân biệt 3 trạng thái: "Không phát hiện", "Chưa kiểm tra (thiếu file IOC)"
   và "Không rõ" (biên bản không ghi). Hai trạng thái sau **không còn bị coi là An toàn**.
3. **Đánh giá rủi ro đa tiêu chí, có ghi lý do** (cột "Lý do xếp mức rủi ro" và tooltip trên bảng):
   - có mã độc;
   - CVE mức CRITICAL (đọc mức độ từ `windows_vulnerabilities.txt`, không chỉ 6 CVE viết cứng);
   - số lượng lỗ hổng;
   - máy nội bộ nối Internet;
   - không đặt mật khẩu hoặc cung cấp mật khẩu cho người khác;
   - không xác định được phần mềm diệt virus;
   - HĐH hết hỗ trợ (Win XP/7/8 xếp Cao; Win 10 xếp Trung bình vì hết hỗ trợ từ 14/10/2025);
   - thiếu kết quả kiểm tra.
4. **Tab 2 – "Cảnh báo trọng điểm"**: liệt kê theo nhóm các máy có mã độc, có CVE nguy cấp, là máy nội bộ nối Internet,
   không có mật khẩu, dùng HĐH hết hỗ trợ hoặc thiếu kết quả.
5. **Tab 2 – phát hiện USB dùng chung nhiều máy** (cùng số seri). Công cụ **gắn cờ "CẦU NỐI"** khi cùng một USB được cắm
   vào cả máy có Internet và máy không có Internet. Đây là con đường lây nhiễm mã độc và làm lộ lọt dữ liệu điển hình.
6. Đọc cả **thư mục con**. Báo rõ các file không đọc được (bản cũ chỉ `print`, người dùng không thấy).
7. Excel: thêm cột (chức vụ, cung cấp MK, phần mềm ứng dụng, lịch sử Internet, lý do rủi ro), tô màu theo mức rủi ro,
   cố định dòng tiêu đề và bật bộ lọc. Khi file đang mở thì báo lỗi rõ ràng.
8. **Sửa lỗi mất cấu hình khi chạy bản .exe onefile.** `__file__` trỏ vào thư mục tạm, nên đổi sang `sys.argv[0]`.
9. **Giảm báo động giả do IOC ThreatFox.** Bản cũ đổi URL độc hại sang IOC tên miền, kể cả URL đặt trên github.com,
   drive.google.com, discord…. Vì công cụ kiểm tra so khớp tên miền trong cache DNS, máy nào từng mở Google Drive cũng sẽ bị báo
   "có mã độc". Nay các tên miền dịch vụ hợp pháp phổ biến được loại trừ.

## 3. Hạn chế còn tồn tại (chưa sửa — cần quyết định hướng đi)

### 3.1. Kết quả "lỗ hổng" có thể bị thổi phồng (vấn đề phương pháp, rất quan trọng)
Công cụ kiểm tra coi một CVE là "chưa vá" khi **không có KB nào trong danh sách** được cài. Tuy nhiên, Windows 10/11 dùng
**bản cập nhật tích lũy** (cumulative update): một máy cập nhật đầy đủ thường *không có* các KB cũ trong `Get-HotFix`,
vì chúng đã được thay thế. Hệ quả là máy đã vá vẫn có thể bị báo hàng chục CVE. Cột "build tối thiểu" có thể khắc phục
nhưng đang để trống với dữ liệu tải từ MSRC. Ngoài ra, cột này chỉ so số build chính (19045), chưa so bản sửa đổi (UBR, vd `19045.4291`).

→ Đề xuất:
- **Tab 3**: lấy trường `FixedBuild` (nếu MSRC cung cấp) trong Remediations của MSRC và ghi vào cột build tối thiểu, dạng `19045.4291`.
- **Công cụ kiểm tra**: đọc thêm UBR trong registry (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UBR`) rồi so sánh
  theo `build.UBR`. Trước khi làm, nên ghi chú trên báo cáo rằng số lỗ hổng là **kết quả sơ bộ, cần xác minh**.

### 3.2. Biên bản .docx vừa là báo cáo, vừa là dữ liệu — dễ vỡ và dễ bị sửa
- Chỉ cần sửa mẫu (thêm/bớt một dòng) là bộ phân tích có thể đọc sai.
- Người được kiểm tra có thể sửa file Word (xoá dòng "mã độc") mà không ai phát hiện.

→ Đề xuất: công cụ kiểm tra xuất **thêm một file dữ liệu `.json`** kèm biên bản, có **mã kiểm tra toàn vẹn**
(HMAC với khoá nhúng lúc build ở Tab 3, hoặc ký số). Công cụ tổng hợp sẽ:
1. ưu tiên đọc JSON, dùng docx làm dự phòng;
2. **cảnh báo biên bản bị chỉnh sửa** khi nội dung docx không khớp JSON hoặc chữ ký sai.

Đây là tính năng quan trọng nhất cho vai trò cơ quan quản lý, vì nó bảo đảm giá trị pháp lý của kết quả kiểm tra.

### 3.3. Chưa có lịch sử giữa các đợt kiểm tra
Mỗi lần mở chương trình chỉ xem được một thư mục, nên không trả lời được các câu hỏi như:
- "Sau lần kiểm tra trước, đơn vị đã khắc phục chưa?"
- "Máy nào lần này mới xuất hiện lỗ hổng hoặc mã độc?"

→ Đề xuất: lưu kết quả vào **SQLite** (có sẵn trong Python, không cần cài thêm). Định danh máy bằng MAC + tên máy
và gắn mỗi kết quả với một **đợt kiểm tra**. Thêm tab "So sánh đợt" để biết:
- lỗ hổng nào đã vá, lỗ hổng nào mới;
- mức rủi ro tăng hay giảm;
- máy nào lần này không được kiểm tra.

### 3.4. Chưa quản lý danh mục tài sản, chưa biết độ phủ kiểm tra
Hiện tại không biết xã có bao nhiêu máy và **còn máy nào chưa được kiểm tra**. Cũng không phát hiện được biên bản trùng
(một máy kiểm tra hai lần).

→ Đề xuất: nhập danh mục máy theo từng cơ quan (UBND, Đảng ủy, trạm y tế, trường học…) từ Excel. Báo cáo tỉ lệ đã kiểm tra
theo từng cơ quan. Gộp biên bản trùng theo MAC và giữ lần kiểm tra mới nhất.

### 3.5. Chưa có sản phẩm đầu ra dạng văn bản hành chính
Cơ quan quản lý cần hai loại văn bản:
- **Báo cáo kết quả kiểm tra** gửi cấp trên;
- **Thông báo/kiến nghị khắc phục** gửi từng cơ quan hoặc cán bộ, có thời hạn.

→ Đề xuất: sinh báo cáo Word theo mẫu (python-docx đã có sẵn) gồm:
- số liệu tổng quan, bảng thống kê theo mức rủi ro và theo cơ quan;
- danh sách vi phạm trọng điểm;
- kiến nghị khắc phục tự động theo từng "lý do rủi ro". Ví dụ: "Không đặt mật khẩu → yêu cầu đặt mật khẩu ≥ 8 ký tự",
  "Máy nội bộ nối Internet → tách mạng, ngắt kết nối Internet".

Có thể xuất riêng cho từng cơ quan một thông báo khắc phục.

### 3.6. Khác (mức nhỏ)
- Auth-Key ThreatFox đang lưu dạng rõ trong `tong_hop_config.json`. Nên dùng Windows Credential Manager (thư viện `keyring`)
  hoặc DPAPI.
- File CVE/IOC nhúng vào .exe chưa ghi **ngày/phiên bản dữ liệu** lên biên bản. Nên in "Dữ liệu CVE cập nhật ngày …" để biết
  một biên bản được kiểm tra với bộ dữ liệu cũ hay mới.
- *(Thuộc công cụ kiểm tra, ghi lại để tham khảo)*: điều kiện `startswith("- mã độc")` trong `fill_form` khớp cả mục II.2
  "- Mã độc hoặc phần mềm độc hại…", nên kết quả quét mã độc của máy bị ghi sai sang mục thiết bị khác. Công cụ tổng hợp
  hiện chỉ lấy lần khớp đầu tiên nên không bị ảnh hưởng.

## 4. Lộ trình đề xuất

| Giai đoạn | Nội dung | Ghi chú |
|---|---|---|
| **1 – Đúng dữ liệu** | Mục 2 ở trên | **Đã thực hiện** trong lần cập nhật này |
| **2 – Tin cậy kết quả** | 3.1 (FixedBuild/UBR), in ngày dữ liệu lên biên bản | Giảm báo động giả về lỗ hổng. Cần sửa cả 2 công cụ |
| **3 – Toàn vẹn biên bản** | 3.2 (JSON + HMAC/ký số, phát hiện biên bản bị sửa) | Giá trị pháp lý của kết quả. Cần sửa cả 2 công cụ |
| **4 – Quản lý theo thời gian** | 3.3 (SQLite, so sánh đợt), 3.4 (danh mục, độ phủ, chống trùng) | Chỉ sửa công cụ tổng hợp |
| **5 – Văn bản đầu ra** | 3.5 (báo cáo cấp trên, thông báo khắc phục từng đơn vị) | Chỉ sửa công cụ tổng hợp |
| 6 – Mở rộng tiêu chí | Tiêu chí mới do công cụ kiểm tra thu thập: tường lửa, SMBv1, RDP, BitLocker, ngày cập nhật Windows gần nhất, tuổi bản mẫu nhận diện của Defender, tài khoản quản trị | Công cụ tổng hợp chỉ cần thêm quy tắc chấm điểm |

Nên làm theo thứ tự trên. Giai đoạn 2 và 3 tác động trực tiếp đến **độ tin cậy và giá trị pháp lý** của kết luận kiểm tra,
nên ưu tiên hơn các tính năng hiển thị.
