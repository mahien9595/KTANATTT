# Đánh giá và đề xuất phương hướng phát triển — Công cụ TỔNG HỢP & TẠO CÔNG CỤ KIỂM TRA

Phạm vi: `tong_hop_kiem_tra.py` (trước đây là `TONG HOP VA TAO CONG CU KIEM TRA.py`), phiên bản **3.0.0** —
phần mềm dành cho **cơ quan quản lý** (Tổ ANATTT Công an xã). File `auto_fill_bien_ban.py`
(trước đây là `auto_fill_bien_ban_V1.6.py`) là công cụ chạy trên từng máy được kiểm tra.
Hai file đã được đổi tên bỏ số phiên bản để không phải đổi tên mỗi lần nâng cấp.
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

## 2b. Giai đoạn 2 — ĐÃ THỰC HIỆN (nâng chất lượng dữ liệu, sửa cả 2 công cụ)

Trọng tâm giai đoạn 2: dữ liệu đóng gói vào công cụ kiểm tra phải **đúng, gọn, kiểm soát được** —
vì sai dữ liệu thì hàng trăm biên bản sai theo. Các thay đổi:

**A. Dữ liệu lỗ hổng (Tab 3 — MSRC):**
- Lấy `FixedBuild` từ MSRC và ghi vào cột "build đã vá" dạng `19045.4291;22631.3447` (theo từng dòng Windows).
- Công cụ kiểm tra đọc thêm **UBR** (`…\CurrentVersion\UBR`) và so theo `build.UBR`. Máy cập nhật tích lũy đầy đủ
  không còn bị báo thừa lỗ hổng chỉ vì thiếu KB cũ đã bị thay thế (đã kiểm chứng: 19045.5000 → sạch, 19045.4000 → còn cảnh báo).
- Đối chiếu **CISA KEV** + cờ `Exploited` của MSRC, đánh dấu và cho **lọc chỉ lấy lỗ hổng đã bị khai thác thực tế**.
- Tải **nhiều tháng một lần** (mặc định 12 tháng), tự gộp và khử trùng.

**B. Dữ liệu mã độc (Tab 3 — ThreatFox):**
- Lọc **độ tin cậy ≥ 75%** (điều chỉnh được) và **loại IOC/IP quá hạn** (mặc định > 90 ngày).
- Chặn dữ liệu gây báo nhầm diện rộng: **IP nội bộ**, **DNS công cộng** (8.8.8.8…), **tên miền dịch vụ hợp pháp**,
  và **kiểm tra định dạng** (SHA256 đủ 64 ký tự, IP/tên miền hợp lệ). Khử trùng ngay khi tải.

**C. Kiểm tra trước khi build:** rà file mẫu docx (đúng cấu trúc auto_fill cần), file CVE/IOC (đọc được, có dữ liệu),
`APP_VERSION`. Có lỗi nghiêm trọng thì **dừng build** kèm thông báo rõ.

**D. Truy vết phiên bản dữ liệu:**
- Ghi dòng `# DATA_VERSION: <ngày>` ở đầu file CVE/IOC mỗi khi lưu. Công cụ kiểm tra đọc và **in "ngày dữ liệu" lên biên bản**
  (mục "Các nội dung khác") — phục vụ tính pháp lý.
- Sau khi build, ghi kèm **`manifest.json`**: phiên bản công cụ, ngày build, ngày dữ liệu, số CVE/IOC, và SHA256 của .exe + file dữ liệu.

**E. Giao diện:** công cụ tổng hợp dùng bộ style thống nhất (tab, bảng, nút, thẻ KPI); công cụ kiểm tra hiển thị
thanh trạng thái dữ liệu (ngày CVE/IOC, số mục) và quyền Administrator ngay dưới banner.

## 2d. Tinh chỉnh công cụ kiểm tra sau khi chạy thử thực tế

- **Phát hiện mật khẩu đăng nhập chính xác:** dùng phép thử đăng nhập với mật khẩu rỗng (API LogonUser)
  thay cho cờ `PasswordRequired` — cờ này vẫn báo "không" ngay cả khi máy đã đặt mật khẩu.
- **Liệt kê đủ mọi ổ đĩa:** máy nhiều ổ (HDD + SSD) nay hiện tất cả kèm loại và dung lượng, thay vì chỉ ổ đầu tiên.
- **Kiểm tra bản quyền Office:** ô "Phần mềm ứng dụng" thêm dòng bản quyền Office (hợp lệ/chưa kích hoạt);
  Microsoft 365/Click-to-Run báo "có cài, cần kiểm tra thủ công".
- **Thiết bị ngoại vi rõ loại + khử trùng:** phân loại USB / ổ cứng gắn ngoài / điện thoại / thẻ nhớ / máy in;
  thiết bị cùng số seri chỉ hiện một lần.
- **Định dạng đồng nhất:** mỗi kết quả kiểm tra là một đoạn văn riêng, thụt đầu dòng **1,27cm** thống nhất
  (trước đây các dòng sau dòng đầu không thụt đầu dòng).
- **Mục II.2 để trống:** công cụ chỉ điền kết quả cho mục II.1 (máy vi tính); mục II.2 (thiết bị khác) để trống
  vì không kiểm tra trực tiếp được.

> Bộ đọc docx dự phòng của công cụ tổng hợp đã được cập nhật để đọc được cả định dạng đoạn văn mới lẫn định dạng cũ.

## 3. Hạn chế còn tồn tại (chưa sửa — cần quyết định hướng đi)

### 3.1. Lưu ý về kết quả "lỗ hổng" (đã cải thiện ở giai đoạn 2, còn điểm cần biết)
Việc so theo `build.UBR` đã xử lý phần lớn báo động thừa. Còn hai điểm cần lưu ý khi vận hành:
- CVE cũ (trước khi có dữ liệu FixedBuild) vẫn chỉ so theo KB nên có thể còn báo thừa — nên **tải lại nhiều tháng** để bổ sung cột build.
- Với dòng Windows không có trong danh sách FixedBuild, công cụ giữ nguyên cảnh báo (an toàn về phía thận trọng) — kiểm tra viên xác minh thêm.

## 2c. Giai đoạn 3 — ĐÃ THỰC HIỆN (toàn vẹn biên bản, giá trị pháp lý)

Đây là tính năng quan trọng nhất cho vai trò cơ quan quản lý. Trước đây người được kiểm tra có thể mở
file Word xóa dòng "mã độc" mà không ai phát hiện, và biên bản .docx vừa là báo cáo vừa là dữ liệu nên dễ đọc sai.

Cách làm:
- Công cụ kiểm tra ghi kèm mỗi biên bản một file **`<tên>.attt.json`** chứa toàn bộ dữ liệu thu thập có cấu trúc,
  cùng **chữ ký HMAC-SHA256** và mã băm của file .docx.
- Khoá ký được công cụ tổng hợp **sinh ngẫu nhiên một lần** (lưu trong cấu hình) và **nhúng vào .exe** khi build
  (`bien_ban_key.dat`). Nhờ vậy chỉ bộ công cụ của đơn vị mới tạo/kiểm được chữ ký hợp lệ.
- Công cụ tổng hợp khi đọc biên bản sẽ **ưu tiên dữ liệu trong file kèm đã ký** (đáng tin hơn regex trên docx),
  và gắn trạng thái toàn vẹn (cột "Toàn Vẹn" trên bảng + Excel + cảnh báo tab 2):
  - **Hợp lệ** — chữ ký đúng, docx nguyên trạng;
  - **Docx đã bị sửa sau khi tạo** — chữ ký đúng nhưng file .docx đã đổi (dùng dữ liệu JSON gốc, cần lưu ý);
  - **Chữ ký SAI - nghi bị giả mạo** — xếp ngay mức Nguy cấp để soát lại;
  - **Không có file kèm** — biên bản cũ/thủ công, không kiểm chứng được nguồn gốc.

> Đã kiểm chứng cả 4 trạng thái. Lưu ý: khoá nhúng trong .exe chỉ chống sửa từ người dùng thông thường,
> không phải chữ ký số pháp lý (PKI). Nếu cần giá trị pháp lý cao hơn, giai đoạn sau có thể thay HMAC bằng
> ký số bằng chứng thư số của đơn vị.

### 3.2. (Đã xử lý ở giai đoạn 3) Toàn vẹn biên bản
Xem mục 2c. Hướng nâng cao còn lại: thay HMAC bằng chữ ký số PKI để có giá trị pháp lý đầy đủ.

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
- *(Thuộc công cụ kiểm tra, ghi lại để tham khảo)*: điều kiện `startswith("- mã độc")` trong `fill_form` khớp cả mục II.2
  "- Mã độc hoặc phần mềm độc hại…", nên kết quả quét mã độc của máy bị ghi sai sang mục thiết bị khác. Công cụ tổng hợp
  hiện chỉ lấy lần khớp đầu tiên nên không bị ảnh hưởng.

## 4. Lộ trình đề xuất

| Giai đoạn | Nội dung | Ghi chú |
|---|---|---|
| **1 – Đúng dữ liệu** | Mục 2 | **Đã thực hiện** |
| **2 – Tin cậy dữ liệu** | Mục 2b (FixedBuild/UBR, KEV, lọc IOC, kiểm tra trước build, ngày dữ liệu, manifest, giao diện) | **Đã thực hiện** — sửa cả 2 công cụ |
| **3 – Toàn vẹn biên bản** | Mục 2c (file kèm .attt.json + HMAC, khoá nhúng khi build, phát hiện sửa/giả mạo) | **Đã thực hiện** — sửa cả 2 công cụ |
| **4 – Quản lý theo thời gian** | 3.3 (SQLite, so sánh đợt), 3.4 (danh mục, độ phủ, chống trùng) | Chỉ sửa công cụ tổng hợp |
| **5 – Văn bản đầu ra** | 3.5 (báo cáo cấp trên, thông báo khắc phục từng đơn vị) | Chỉ sửa công cụ tổng hợp |
| 6 – Mở rộng tiêu chí | Tiêu chí mới do công cụ kiểm tra thu thập: tường lửa, SMBv1, RDP, BitLocker, ngày cập nhật Windows gần nhất, tuổi bản mẫu nhận diện của Defender, tài khoản quản trị | Công cụ tổng hợp chỉ cần thêm quy tắc chấm điểm |

Giai đoạn 4 và 5 tiếp theo (lịch sử qua các đợt, danh mục tài sản, văn bản đầu ra) chỉ cần sửa công cụ tổng hợp.

## 5. Quy trình chuẩn trước mỗi đợt kiểm tra (bảo đảm dữ liệu mới và tính pháp lý)

1. Mở công cụ **TỔNG HỢP** → tab "3. Cập nhật dữ liệu & Build".
2. Chọn đường dẫn file CVE, IOC, mã nguồn, mẫu docx, Python (có Nuitka), thư mục xuất (chỉ cần làm 1 lần, tự nhớ).
3. **Tải CVE**: nhập tháng mốc, chọn số tháng (mặc định 12), bấm "Tải CVE" → xem lại → "Lưu". Tick "chỉ lỗ hổng đã bị khai thác"
   nếu muốn danh sách gọn, đúng trọng tâm.
4. **Tải IOC**: nhập Auth-Key, đặt độ tin cậy ≥ 75% và mốc loại IP cũ → "Tải IOC" → xem lại → "Lưu".
5. Bấm **Build**. Công cụ tự kiểm tra dữ liệu; nếu có lỗi sẽ dừng và báo. Build xong sinh `auto_fill_bien_ban.exe` + `manifest.json`.
6. Chép cả thư mục xuất (exe + manifest.json) sang USB, mang đi kiểm tra.
7. Trên mỗi máy: chạy exe (nên "Run as administrator"), thanh trạng thái hiển thị ngày dữ liệu để xác nhận là bản mới.
   Mỗi máy sinh ra biên bản `.docx` **và file kèm `.attt.json`** (chữ ký toàn vẹn) — **thu về cả hai file, giữ cạnh nhau**.
8. Thu biên bản về, dùng tab 1/2 của công cụ TỔNG HỢP để phân tích, kiểm tra cột "Toàn Vẹn" và xuất Excel.

> Lưu ý pháp lý: biên bản sẽ tự ghi "đối chiếu bằng bộ dữ liệu cập nhật đến ngày …". `manifest.json` lưu lại
> phiên bản công cụ + mã băm để đối chứng đợt kiểm tra đã dùng bộ dữ liệu nào.
