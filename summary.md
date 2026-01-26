# Báo Cáo Đánh Giá Mã Backend

## 1. Đánh Giá Kiến Trúc Tổng Thể

Hệ thống backend CA là ứng dụng cơ quan chứng thực và chữ ký số dựa trên Django với các đặc điểm sau:

- **Framework**: Django 6.0 với mẫu lớp dịch vụ tùy chỉnh (không sử dụng Django REST Framework)
- **Cơ sở dữ liệu**: SQLite (phù hợp với phát triển, không đủ cho sản xuất)
- **Lĩnh vực cốt lõi**: PKI nội bộ với cấp phát chứng chỉ, lưu trữ, ký PDF và xác thực
- **Kiểu kiến trúc**: Ứng dụng Django monolithic với các lớp dịch vụ cho các hoạt động mã hóa
- **Xác thực**: Xác thực tích hợp Django + cơ chế dựa trên phiên/POST
- **Các lớp chính**:
  - Ứng dụng: `usermanage` (quản lý người dùng/quản trị), `usercerts` (lưu trữ chứng chỉ), `signing` (hoạt động PDF)
  - Dịch vụ: `CertificateService` (tìm kiếm/giải mã chứng chỉ), `PDFSigner` (ký), `PDFVerifier` (xác thực)
  - Tiện ích: mã hóa dựa trên Fernet, tích hợp pyHanko để xử lý PDF

Kiến trúc tuân theo mẫu hướng dịch vụ đơn giản nhưng thiếu các quy ước REST chính thức và cho thấy dấu hiệu phát triển tùy tiện trong các lĩnh vực bảo mật quan trọng.

---

## 2. Điểm Mạnh

### Tách Biệt Mối Quan Tâm Một Cách Rõ Ràng
- Các hoạt động chứng chỉ cô lập trong lớp `CertificateService`
- Ký/xác thực PDF được đóng gói trong các dịch vụ `PDFSigner` và `PDFVerifier` riêng biệt
- Tiện ích mã hóa tập trung trong `utils.py`
- Các hàm view rõ ràng ủy thác cho các lớp dịch vụ

### Quản Lý Chứng Chỉ Thực Tế
- Phát hiện chứng chỉ từ nhiều nguồn: bản ghi cơ sở dữ liệu với dự phòng hệ thống tệp
- Cấp phát chứng chỉ tự động trong khi đăng ký (thông qua script `issue_cert.py`)
- Hỗ trợ lưu trữ PKCS#12 được mã hóa bằng Fernet
- Mẫu trình quản lý bối cảnh (`__enter__`/`__exit__`) để làm sạch tệp tạm thời an toàn trong `PDFSigner`

### Triển Khai Ký PDF Mạnh Mẽ
- Tích hợp với thư viện pyHanko theo tiêu chuẩn ngành
- Hỗ trợ giao diện chữ ký tùy chỉnh với kiểu dáng chuyên nghiệp
- Định vị trường chữ ký trên các trang PDF cụ thể
- Tích hợp TSA (Cơ quan Dấu Thời Gian) để dấu thời gian đáng tin cậy
- Xem xét tuân thủ PAdES trong siêu dữ liệu chữ ký

### Xác Thực PDF Toàn Diện
- Tải các gốc tin cậy (Root CA + Intermediate CA) từ hệ thống tệp
- Thiết lập ngữ cảnh xác thực với cả gốc tin cậy và chứng chỉ trung gian
- Xử lý dự phòng cho các phiên bản API pyHanko khác nhau
- Trích xuất chữ ký chi tiết với thông tin người ký, dấu thời gian và trạng thái

### Mã Hóa Có Nhận Thức Bảo Mật
- Mã hóa Fernet (AES-128 đối xứng) cho PKCS#12 và mật khẩu
- Phái sinh khóa từ `SECRET_KEY` Django bằng SHA256
- Mã hóa được áp dụng cho cả tệp chứng chỉ và mật khẩu
- Các tệp được mã hóa lưu trữ trên hệ thống tệp với theo dõi đường dẫn tương đối trong cơ sở dữ liệu

### Kiểm Soát Truy Cập Dựa Trên Vai Trò (RBAC)
- Các hoạt động quản trị được bảo vệ bằng cờ `is_staff`
- Cô lập người dùng: người dùng không phải nhân viên chỉ thấy chứng chỉ của họ
- Nhân viên có thể quản lý kích hoạt người dùng, nâng cao đặc quyền và đặt lại mật khẩu
- Kiểm tra quyền rõ ràng trong các view trước các hoạt động nhạy cảm

### Hỗ Trợ Tệp Tiện Ích
- Cấu hình tiện ích V3 để keyUsage chứng chỉ và extendedKeyUsage thích hợp
- Tạo tệp tiện ích tự động với các mặc định hợp lý
- Áp dụng trong khi ký chứng chỉ bằng openssl

---

## 3. Điểm Yếu

### Vấn Đề Bảo Mật Quan Trọng

#### 1. **Bí Mật Được Mã Hóa Cứng trong Cài Đặt**
- **Vị trí**: `backend/settings.py:24`
- **Vấn đề**: `SECRET_KEY = 'django-insecure-@p3_#!xc_1tzxlm2o4$ngmwb7zs-9b^y^4z!3^7eyvva0=o6yt'` được tiết lộ trong mã nguồn
- **Tác động**: Các khóa mã hóa Fernet được lấy từ SECRET_KEY này bị xâm phạm; kẻ tấn công có thể giải mã tất cả các chứng chỉ P12 và mật khẩu đã lưu trữ
- **Nguyên nhân gốc**: Thiết lập phát triển Django không an toàn được kiểm tra vào kiểm soát phiên bản
- **Giải pháp**: Di chuyển sang biến môi trường ngay lập tức; xoay tất cả các thông tin đã mã hóa

#### 2. **DEBUG = True trong Cấu Hình Sản Xuất**
- **Vị trí**: `backend/settings.py:28`
- **Tác động**: Dấu vết ngăn xếp được tiết lộ trong lỗi; phục vụ tệp tĩnh được bật; truy vấn SQL hiển thị; cho phép gỡ lỗi mẫu
- **Mức độ nghiêm trọng**: CAO - Lỗ hổng tiết lộ thông tin

#### 3. **Miễn Trừ CSRF Ở Khắp Nơi**
- **Tệp**: `signing/views.py`, `signing/upload.py`, `usermanage/auth.py`, `usercerts/views.py`
- **Mẫu**: Mỗi điểm cuối được trang trí bằng `@csrf_exempt`
- **Vấn đề**: Hệ thống dễ bị tấn công CSRF trừ khi frontend rõ ràng quản lý các token CSRF
- **Nguyên nhân gốc**: Dường như là giải pháp thay thế cho xác thực dựa trên POST thay vì triển khai quản lý phiên một cách thích hợp
- **Tác động**: Các trang web địch thù có thể kích hoạt các hành động không mong muốn thay mặt người dùng đã xác thực

#### 4. **Xử Lý Mật Khẩu Văn Bản Rõ**
- **Vị trí**: Nhiều vị trí (ví dụ: `usercerts/views.py:issue_cert`, `usermanage/auth.py:issue_cert`)
- **Vấn đề**: Mật khẩu nhận qua POST, ghi nhật ký trong các lệnh gọi quy trình con, và giữ trong bộ nhớ mà không xóa an toàn
- **Ví dụ mẫu**: `subprocess.run([..., f'pass:{passphrase}'], ...)` được tiết lộ trong danh sách quy trình
- **Thiếu**: Mô-đun Python `secrets` để tạo mật khẩu; cơ chế xóa; giao tiếp quy trình con an toàn
- **Rủi ro**: Mật khẩu bị xâm phạm qua: danh sách quy trình, hoán đổi, nhật ký, xả lưu trữ bộ nhớ

#### 5. **Xác Thực Đầu Vào Không Đủ**
- **Tham số URL**: Không có xác thực trên `<str:username>` trong định tuyến URL usermanage - cho phép các nỗ lực duyệt đường dẫn
- **Vị trí chữ ký**: Xác thực vị trí trong `PDFSigner.parse_position()` thiếu kiểm tra giới hạn cho số trang và tọa độ
- **Tải lên tệp**: Không có xác thực loại MIME; không có giới hạn kích thước tệp; chấp nhận tải lên nhị phân tùy ý

#### 6. **Tiếp Xúc Khóa Riêng tư trong Lệnh Gọi Quy Trình Con**
- **Vị trí**: `usercerts/views.py`, `usermanage/auth.py`, `scripts/issue_cert.py`
- **Vấn đề**: Các tệp khóa riêng tư được chuyển qua các đối số dòng lệnh cho openssl
- **Mẫu**: `subprocess.run(['openssl', 'x509', '-req', '-in', str(csr_path), '-CA', str(interm_cert), '-CAkey', str(interm_key), ...], check=True)`
- **Vấn đề**: Đường dẫn tệp hiển thị trong `/proc/[pid]/cmdline` cho tất cả người dùng trên hệ thống
- **Thực hành tốt hơn**: Sử dụng chuyển hướng stdin/stdout hoặc thư viện mã hóa Python

#### 7. **Lưu Trữ Khóa Riêng tư Không Được Mã Hóa**
- **Vị trí**: Thư mục người dùng (`users/{username}/{username}.key`)
- **Vấn đề**: Các khóa riêng tư RSA được tạo được lưu trữ dưới dạng văn bản rõ ràng trên đĩa
- **Vòng đời**: Được tạo, sử dụng để ký CSR, sau đó bị bỏ lại trên hệ thống tệp không được mã hóa
- **Khuyến nghị**: Xóa sau khi xuất P12; không bao giờ lưu trữ các khóa riêng tư không được mã hóa lâu dài

---

### Vấn Đề Kiến Trúc

#### 1. **Cơ Sở Dữ Liệu SQLite trong Sản Xuất**
- **Tệp**: `backend/settings.py:96-100`
- **Vấn đề**: SQLite không phù hợp cho các môi trường đa người dùng, không hỗ trợ ghi đồng thời, không có phục hồi thảm họa thích hợp
- **Mô hình người dùng**: Dựa hoàn toàn trên mô hình `User` tích hợp Django mà không có tiện ích cụ thể theo lĩnh vực
- **Khuyến nghị**: PostgreSQL hoặc tương tự với chiến lược sao lưu thích hợp

#### 2. **Lôgic Cấp Phát Chứng Chỉ Monolithic**
- **Vấn đề**: Lôgic cấp phát chứng chỉ được lặp lại:
  - `usermanage/auth.py:issue_cert()` (dự phòng trong luồng ký)
  - `usercerts/views.py:issue_cert()` (điểm cuối rõ ràng)
  - `scripts/issue_cert.py` (công cụ CLI)
- **Bảo trì**: Ba triển khai độc lập có nghĩa là các bản sửa lỗi phải được áp dụng ba lần
- **Thử nghiệm**: Không có bài kiểm tra đơn vị cho lôgic tạo chứng chỉ

#### 3. **Thiết Kế Mô Hình Người Dùng Yếu**
- **Tệp**: `usermanage/models.py`
- **Mô hình**: `UserProfile` với các trường điện thoại/phòng ban
- **Vấn đề**: Không được sử dụng nhất quán; hầu hết mã hoạt động trên Django `User` trực tiếp
- **Vấn đề**: Không có định nghĩa vai trò ngoài boolean `is_staff`
- **Thiếu**: Các loại người dùng thích hợp (Sinh viên, Giáo viên, Nhân viên, Quản trị viên) được tham chiếu trong tạo chứng chỉ nhưng không được mô hình hóa

#### 4. **Không Có Dấu Vết Kiểm Toán**
- **Vấn đề**: Không ghi nhật ký các hoạt động chứng chỉ, sự kiện ký hoặc mẫu truy cập
- **Tác động**: Không thể điều tra: ai đã ký cái gì, khi nào thu hồi xảy ra, hoặc kiểm toán hoạt động CA
- **Trạng thái hiện tại**: Chỉ có các câu lệnh in ra stdout (bị mất khi triển khai sản xuất)

#### 5. **Không Nhất Quán Trong Xử Lý Lỗi**
- **Mẫu**: Một số điểm cuối trả về JsonResponse với khóa `error`; những điểm khác trả về khóa `details`
- **Ví dụ Không Nhất Quán**:
  - `sign_file`: Trả về `{'error': '...', 'details': '...'}` (trạng thái 500)
  - `verify_pdf`: Trả về `{'error': '...', 'valid': False, ...}` (trạng thái 500)
  - `list_certs`: Trả về `{'error': '...'}` (trạng thái 401)
- **Tác động**: Frontend phải xử lý nhiều định dạng phản hồi lỗi

#### 6. **Phiên Bản Trình Xác Thực Toàn Cục trong PDFVerifier**
- **Tệp**: `signing/pdf_verifier.py:__init__`
- **Vấn đề**: Gốc tin cậy được tải một lần khi nhập mô-đun; cập nhật chứng chỉ CA yêu cầu khởi động lại
- **Mẫu**: `_load_ca_certificates()` trong `__init__` tạo liên kết chặt với hệ thống tệp
- **Khuyến nghị**: Tải chứng chỉ theo yêu cầu hoặc thông qua quản lý cấu hình

---

### Vấn Đề Chất Lượng Mã

#### 1. **Trình Bao Hàm Hàm Không Được Dùng Nữa**
- **Vị trí**: Nhiều tệp (ví dụ: `usermanage/auth.py:13`, `usercerts/views.py:15`, `signing/views.py:14`)
- **Mẫu**:
  ```python
  def _derive_key():
      """DEPRECATED: Use signing.utils.derive_encryption_key() instead"""
      return derive_encryption_key()
  ```
- **Vấn đề**: Mã chết sẽ bị xóa; gây nhầm lẫn về hàm nào để gọi

#### 2. **Xử Lý Đường Dẫn Không Nhất Quán Pathlib**
- **Các Phương Pháp Hỗn Hợp**:
  - `usercerts/views.py:issue_cert()` sử dụng `pathlib.Path` (hiện đại, an toàn)
  - `usermanage/auth.py:issue_cert()` sử dụng nối chuỗi với `os.path.join()` (không nhất quán)
- **Rủi ro**: Đường dẫn dựa trên chuỗi dễ bị vấn đề chuẩn hóa; các đối tượng Path ngăn chặn các cuộc tấn công duyệt

#### 3. **Thiếu Cấu Hình Môi Trường**
- **Tệp**: `backend/settings.py` mã hóa cứng nhiều đường dẫn
- **Vấn đề**: Không tách biệt cấu hình cụ thể môi trường (phát triển vs sản xuất)
- **Ví dụ**:
  - `ALLOWED_HOSTS = ["localhost", "127.0.0.1", "www.dut.local", "10.10.53.104"]` mã hóa cứng
  - Đường dẫn `PYHANKO_CLI` mã hóa cứng
  - `DEFAULT_SIGNER_P12` mã hóa cứng
  - Không có ghi đè biến ENV

#### 4. **Ghi Nhật Ký Không Đủ**
- **Hiện Tại**: Câu lệnh in gỡ lỗi phân tán (ví dụ: `print(f"[SIGN] Signing PDF with field: ...")`)
- **Vấn Đề Sản Xuất**: Đầu ra `print()` bị mất; không có tập hợp nhật ký; không có nhật ký có cấu trúc
- **Thiếu**: Ghi nhật ký yêu cầu, theo dõi lỗi, ghi nhật ký sự kiện bảo mật

#### 5. **Thông Báo Lỗi Không Hoàn Chỉnh**
- **Mẫu**: Lỗi chung chung như "Ký không thành công" mà không có chi tiết có thể thực hiện
- **Ví dụ**: `JsonResponse({'error': 'Signing failed'}, status=500)` ẩn nguyên nhân cơ bản với frontend
- **Tác động của Người Dùng**: Người dùng không thể khắc phục sự cố; nhà phát triển không thể điều tra từ các báo cáo frontend

#### 6. **Chuỗi Magic và Hằng Số Bị Thiếu**
- **Vấn đề**: Các giá trị được mã hóa cứng phân tán trong mã
- **Ví dụ**:
  - `reason='Signed'` (ký các view)
  - `'changeit'` mặc định mật khẩu (nhiều vị trí)
  - `'-'` tên trường (siêu dữ liệu chữ ký)
  - Giá trị OU `'Student'` mã hóa cứng trong `scripts/issue_cert.py:74`

#### 7. **Tài Liệu Không Đầy Đủ**
- **Nhận Xét Mã**: Nhận xét tiếng Việt trộn lẫn với tiếng Anh; không nhất quán
- **Docstrings**: Các lớp dịch vụ có docstrings, nhưng các view thiếu tài liệu tham số
- **Không Có Tài Liệu Kiến Trúc**: Không có README giải thích vòng đời chứng chỉ, mô hình bảo mật hoặc triển khai
- **Tài Liệu API Bị Thiếu**: Không có OpenAPI/Swagger cho các điểm cuối backend

---

### Khoảng Chức Năng

#### 1. **Không Có Quy Trình Thu Hồi Chứng Chỉ**
- **Vị trí**: `usercerts/views.py:revoke_cert()` chỉ đánh dấu chứng chỉ `active=False` trong cơ sở dữ liệu
- **Thiếu**:
  - Không tạo CRL (Danh Sách Thu Hồi Chứng Chỉ)
  - Không có responder OCSP
  - Không có lan truyền trạng thái thu hồi cho xác thực PDF
  - `PDFVerifier` không kiểm tra trạng thái thu hồi trong quá trình xác thực
- **Tác động**: Các PDF được ký bằng chứng chỉ bị thu hồi vẫn xác thực như chính xác

#### 2. **Không Có Quản Lý Vòng Đời Chứng Chỉ**
- **Thiếu**:
  - Theo dõi hết hạn (chứng chỉ có giá trị 365 ngày)
  - Quy trình gia hạn (thông báo sắp hết hạn)
  - Lưu trữ tự động các chứng chỉ đã hết hạn
  - Không theo dõi các số sê-ri chứng chỉ để kiểm toán

#### 3. **Kết Quả Xác Thực PDF Không Hoàn Chỉnh**
- **Tệp**: `signing/pdf_verifier.py`
- **Trả Về Hiện Tại**: Sự tồn tại của chữ ký và xác thực cơ bản
- **Thiếu**:
  - Chi tiết xác thực chuỗi chứng chỉ
  - Kết quả xác thực dấu thời gian (xác minh responder TSA)
  - Xác thực tiện ích sử dụng khóa
  - Kiểm tra trạng thái thu hồi
  - Chi tiết đường dẫn tin cậy (CA gốc nào đã cấp người ký)

#### 4. **Không Có Hoạt Động Hàng Loạt**
- **Vấn đề**: Chỉ hoạt động chứng chỉ/tệp duy nhất
- **Thiếu**:
  - Cấp phát chứng chỉ hàng loạt
  - Ký tệp hàng loạt
  - Xác thực hàng loạt (xử lý tài liệu)
  - Quản lý người dùng hàng loạt của quản trị viên

#### 5. **Tích Hợp Cơ Quan Dấu Thời Gian (TSA) Không Hoàn Chỉnh**
- **Vị trí**: `signing/pdf_signer.py:_get_timestamper()`
- **Hiện Tại**: Cố gắng sử dụng nhiều máy chủ TSA công khai mà không có dự phòng; âm thầm không thành công nếu tất cả đều không thể tiếp cận
- **Thiếu**:
  - Cấu hình TSA trong cài đặt
  - Lôgic thử lại với backoff theo cấp số nhân
  - Báo cáo lỗi khi TSA không có sẵn
  - Dự phòng cho dấu thời gian cục bộ (không đáng tin cậy)

#### 6. **Không Hỗ Trợ Chứng Chỉ Di Động**
- **Vấn đề**: Chỉ hỗ trợ chứng chỉ PKCS#12 trên máy tính để bàn
- **Thiếu**:
  - Hỗ trợ mã thông báo phần cứng (USB HSM)
  - Tích hợp Cloud HSM
  - Chứng chỉ ký di động
  - Tích hợp thẻ thông minh

---

### Các Mối Quan Tâm về Hiệu Năng & Khả Năng Mở Rộng

#### 1. **Cấp Phát Chứng Chỉ Đồng Bộ**
- **Vấn đề**: Các điểm cuối `issue_cert()` chặn các lệnh gọi quy trình con đến openssl
- **Thời gian Điển Hình**: 2-5 giây mỗi chứng chỉ (RSA 2048, SHA256, ký)
- **Tác động**: Trong khi tăng đột biến đăng ký người dùng, hết thời gian 504 nhanh chóng trong các yêu cầu đồng thời
- **Khuyến nghị**: Hàng đợi tác vụ không đồng bộ (Celery) với theo dõi công việc nền

#### 2. **Xác Thực PDF Chặn I/O**
- **Vấn đề**: Tải chứng chỉ và phân tích cú pháp PDF là đồng bộ trong trình xử lý yêu cầu
- **Tệp**: `signing/pdf_verifier.py`
- **Mẫu**: `_load_ca_certificates()` được gọi mỗi yêu cầu; có thể được tối ưu hóa bằng bộ nhớ cache

#### 3. **Không Có Giới Hạn Kích Thước Tệp**
- **Vấn đề**: Các điểm cuối tải lên chấp nhận kích thước tệp tùy ý
- **Rủi ro**: DoS thông qua tải lên tệp lớn tiêu thụ đĩa và bộ nhớ
- **Thiếu**: Cấu hình Django `FILE_UPLOAD_MAX_MEMORY_SIZE`, `DATA_UPLOAD_MAX_MEMORY_SIZE`

#### 4. **Xây Dựng Đường Dẫn Chứng Chỉ Không Hiệu Quả**
- **Vấn đề**: Tải gốc tin cậy được lặp lại ở nhiều vị trí:
  - `PDFSigner._load_trust_roots()`
  - `PDFVerifier._load_ca_certificates()`
- **Khuyến nghị**: Kho chứng chỉ tập trung, được lưu vào bộ nhớ cache

---

## 4. Đánh Giá Bảo Mật

### Xác Thực & Ủy Quyền
- **Quản Lý Phiên**: Sử dụng khung phiên Django nhưng cũng chấp nhận thông tin đăng nhập POST
- **Rủi Ro**: Tên người dùng/mật khẩu trong POST trên HTTP dễ bị bắt qua nắm bắt mạng
- **Yêu Cầu HTTPS**: Không bắt buộc trong cài đặt (thiếu `SECURE_SSL_REDIRECT`)
- **Triển Khai RBAC**: Cơ bản (nhân viên vs không phải nhân viên); thiếu mô hình quyền chi tiết
- **Vấn đề**: Người dùng không thể phân biệt truy cập vào chứng chỉ của những người khác mà không có hệ thống vai trò

### Mã Hóa & Quản Lý Khóa
- **Thuật Toán Mã Hóa**: Fernet (AES-128) - phù hợp cho mã hóa đối xứng
- **Phái Sinh Khóa**: SHA256 của Django SECRET_KEY - không chuẩn; nên sử dụng PBKDF2
- **Lưu Trữ Khóa**: Trong bộ nhớ trong quá trình xử lý yêu cầu; không có chính sách hết hạn hoặc xoay khóa
- **Xử Lý Khóa Riêng Tư**: Lưu trữ văn bản rõ ràng và tiếp xúc quy trình con (quan trọng)
- **Bảo Mật Mật Khẩu**: Nhận trong POST, giữ trong bộ nhớ, ghi nhật ký trong quy trình con; không có xóa an toàn

### Hoạt Động Cơ Quan Chứng Thực
- **Mô Hình Tin Cậy**: Tin tưởng ngầm vào chứng chỉ từ thư mục `/certs`; không có xác thực PKI
- **Xác Thực CSR**: Không xác thực chủ đề/tiện ích được yêu cầu trước khi ký
- **Ràng Buộc Chứng Chỉ**: Không có ràng buộc độ dài đường dẫn; chứng chỉ lá có thể cấp phát các chứng chỉ khác
- **Kích Thước Khóa**: RSA 2048 - đủ (không phải công nghệ tiên tiến; 3072+ được khuyến nghị cho thời gian dài)
- **Thuật Toán Hash**: SHA256 - an toàn

### Ký & Xác Thực PDF
- **Định Dạng Chữ Ký**: Tương thích PAdES; tiêu chuẩn ngành
- **Hỗ Trợ Dấu Thời Gian**: Tích hợp TSA hiện tại nhưng dễ vỡ (dự phòng không đáng tin cậy)
- **Mạnh Mẽ Xác Thực**: Không xác thực thu hồi; chấp nhận CA tự ký
- **Giao Diện Chữ Ký**: Kiểu dáng chuyên nghiệp; dấu thời gian được hiển thị
- **Rủi Ro**: Các tài liệu được ký không thể được chứng minh bị thu hồi (không tích hợp CRL/OCSP)

### Bảo Mật API
- **CSRF**: Tất cả các điểm cuối POST được đánh dấu `@csrf_exempt` - dễ bị CSRF
- **HTTPS**: Không bắt buộc; thông tin đăng nhập được gửi trong POST văn bản rõ ràng
- **Giới Hạn Tỷ Lệ**: Không có; các điểm cuối dễ bị tấn công vũ phu (xác thực) và DoS (tải lên)
- **Xác Thực Đầu Vào**: Tối thiểu; các tham số tên người dùng/đường dẫn không được kiểm tra
- **Tiêm SQL**: Được bảo vệ bằng ORM; không có truy vấn thô được phát hiện

### Tuân Thủ & Tiêu Chuẩn
- **Tiêu Chuẩn PKI**: Theo định dạng chứng chỉ X.509; sử dụng tiêu chuẩn openssl
- **Tiêu Chuẩn Chữ Ký PDF**: Cố gắng tuân thủ PAdES; không có đề cập đến các tiêu chuẩn khác (XAdES, CAdES)
- **Dấu Vết Kiểm Toán**: Không có; không thể chứng minh tuân thủ các yêu cầu pháp lý
- **Bảo Vệ Dữ Liệu**: Mã hóa được áp dụng nhưng quản lý khóa yếu; không có nhật ký kiểm toán kiểm soát truy cập

---

## 5. Các Tính Năng Bị Thiếu Hoặc Không Hoàn Chỉnh

### Các Tính Năng PKI Cần Thiết
- **Tạo CRL (Danh Sách Thu Hồi Chứng Chỉ)**: Chưa triển khai
- **Responder OCSP**: Chưa triển khai
- **Xác Thực Máy Khách OCSP**: Chưa triển khai (xác thực PDF bỏ qua thu hồi)
- **Gia Hạn Chứng Chỉ**: Không có điểm cuối gia hạn hoặc quy trình làm việc
- **Lưu Trữ Khóa**: Không có cơ chế lưu trữ sao lưu khóa lịch sử
- **Escrow Khóa**: Không áp dụng (chứng chỉ người dùng duy nhất), nhưng không xem xét các kịch bản phục hồi

### Vòng Đời Chứng Chỉ
- **Quản Lý Hết Hạn**: Không theo dõi giá trị 365 ngày; không có thông báo hết hạn trước đó
- **Hoạt Động Hàng Loạt**: Không cấp phát chứng chỉ hàng loạt hoặc thu hồi hàng loạt
- **Lịch Sử Chứng Chỉ**: Mô hình UserCert chỉ theo dõi chứng chỉ hiện tại; không có phiên bản cho các chứng chỉ trong quá khứ
- **Theo Dõi Số Sê-ri**: Không lưu trữ số sê-ri chứng chỉ tường minh hoặc xác thực

### Tính Năng Quản Trị & Hoạt Động
- **Tìm Kiếm Chứng Chỉ**: Chỉ theo người dùng; không tìm kiếm CN, chủ đề hoặc giá trị
- **Xuất Chứng Chỉ**: Tải P12 được mã hóa tồn tại, nhưng không xuất PEM/DER để tích hợp hệ thống
- **Sao Lưu/Phục Hồi Khóa CA**: Không có quy trình sao lưu được tài liệu cho các khóa CA trung gian
- **Xoay Khóa**: Không có quy trình xoay khóa CA trung gian được lên lịch
- **Kế Hoạch Khôi Phục Thảm Họa**: Không được tài liệu; quy trình khôi phục không rõ ràng nếu mất khóa

### Quản Lý Người Dùng
- **Mô Hình Vai Trò**: Chỉ nhân viên/không phải nhân viên; không theo dõi vai trò Sinh viên/Giáo viên/Nhân viên/Quản trị viên
- **Hồ Sơ Người Dùng**: Mô hình tồn tại nhưng hầu như không sử dụng; các trường điện thoại/phòng ban không được thu thập/xác thực
- **Nhập Người Dùng Hàng Loạt**: Không có nhập CSV cho đăng ký người dùng hàng loạt
- **Gia Hạn Chứng Chỉ Tự Phục Vụ**: Không gia hạn tự phục vụ (chỉ cấp phát qua đăng ký)

### Tích Hợp & Tương Thích
- **Trình Điều Khiển Cơ Sở Dữ Liệu**: Chỉ SQLite; không có hỗ trợ PostgreSQL/MySQL được tài liệu
- **Tích Hợp LDAP/AD**: Không có; tất cả xác thực thủ công
- **Đăng Nhập Duy Nhất (SSO)**: Không tích hợp; OAuth2/SAML vắng mặt
- **API Ứng Dụng Di Động**: Không có hỗ trợ máy khách di động được tài liệu
- **Tin Tưởng Bên Thứ Ba**: Không có cơ chế tin tưởng chứng chỉ CA nước ngoài

### Giám Sát & Khả Quan Sát
- **Kiểm Tra Sức Khỏe**: Không có điểm cuối `/health` hoặc `/status` để kiểm tra trình cân bằng tải
- **Chỉ Số**: Không tích hợp Prometheus/CloudWatch; chỉ có các câu lệnh in
- **Tracing**: Không tracing yêu cầu qua các ranh giới dịch vụ
- **Cảnh Báo**: Không có cảnh báo cho hết hạn chứng chỉ, xâm phạm khóa CA hoặc lỗi ký

---

## 6. Khuyến Nghị cho Phát Triển Tiếp Theo

### Tức Thì (Quan Trọng Bảo Mật, Ngày 1-3)

1. **Di Chuyển Bí Mật sang Biến Môi Trường**
   - Xóa `SECRET_KEY` được mã hóa cứng từ mã nguồn ngay lập tức
   - Sử dụng `python-dotenv` hoặc bí mật Docker
   - Tạo lại tất cả các khóa Fernet và mã hóa lại các tệp P12 được lưu trữ
   ```python
   import os
   SECRET_KEY = os.environ.get('SECRET_KEY')
   DEBUG = os.environ.get('DEBUG', 'False') == 'True'
   ```

2. **Bật HTTPS & Bảo Vệ CSRF**
   - Đặt `SECURE_SSL_REDIRECT = True`
   - Đặt `SESSION_COOKIE_SECURE = True`
   - Xóa tất cả các bộ trang trí `@csrf_exempt`
   - Triển khai xác thực dựa trên phiên thích hợp (xóa thông tin đăng nhập POST)
   - Thêm middleware token CSRF cho frontend

3. **Bảo Mật Xử Lý Mật Khẩu**
   - Sử dụng mô-đun `secrets` của Python để tạo mật khẩu:
     ```python
     passphrase = secrets.token_urlsafe(16)
     ```
   - Tránh chuyển mật khẩu qua quy trình con; sử dụng đầu vào tệp
   - Triển khai xóa chuỗi an toàn trước khi kết thúc quy trình
   - Không bao giờ ghi nhật ký mật khẩu; che kín từ thông báo lỗi

4. **Mã Hóa Khóa Riêng Tư**
   - Mã hóa các tệp khóa riêng tư bằng cơ chế Fernet tương tự như P12
   - Xóa các khóa riêng tư văn bản rõ ràng sau khi xuất P12
   - Hoặc tốt hơn: Không lưu trữ các khóa riêng tư cục bộ; sử dụng HSM

### Ngắn Hạn (Kiến Trúc, Tuần 1-2)

5. **Hợp Nhất Lôgic Cấp Phát Chứng Chỉ**
   - Tạo lớp `CertificateAuthority` duy nhất:
     ```python
     class CertificateAuthority:
         def issue_user_certificate(self, username, cn, passphrase) -> Tuple[bytes, bytes]:
             """Returns (p12_data, password_data)"""
     ```
   - Tái sử dụng từ auth, views và scripts
   - Thêm bài kiểm tra đơn vị cho mỗi bước (tạo CSR, ký, xuất P12)

6. **Triển Khai Kiểm Soát Truy Cập Dựa Trên Vai Trò Thích Hợp**
   - Mở rộng mô hình Django User với các vai trò rõ ràng:
     ```python
     class UserRole(models.TextChoices):
         STUDENT = 'student'
         FACULTY = 'faculty'
         STAFF = 'staff'
         ADMIN = 'admin'
     
     class UserProfile(models.Model):
         user = models.OneToOneField(User, on_delete=models.CASCADE)
         role = models.CharField(choices=UserRole.choices, default='student')
     ```
   - Sử dụng Django Permissions hoặc django-guardian để kiểm soát quyền cấp độ đối tượng
   - Thực thi kiểm tra vai trò trong các view chứng chỉ

7. **Thêm Ghi Nhật Ký Kiểm Toán**
   - Triển khai mô hình kiểm toán:
     ```python
     class AuditLog(models.Model):
         timestamp = models.DateTimeField(auto_now_add=True)
         actor = models.ForeignKey(User, on_delete=models.CASCADE)
         action = models.CharField()  # 'sign', 'verify', 'issue', 'revoke'
         resource = models.CharField()  # 'certificate', 'pdf'
         status = models.CharField()  # 'success', 'failure'
         details = models.TextField()
     ```
   - Ghi nhật ký tất cả các hoạt động ký, xác thực và chứng chỉ
   - Cung cấp bảng điều khiển kiểm toán cho quản trị viên

8. **Triển Khai Thu Hồi Chứng Chỉ**
   - Thêm `revocation_date` vào mô hình `UserCert`
   - Tạo điểm cuối tạo CRL:
     ```python
     POST /api/admin/crl/generate/
     Returns: .crl file
     ```
   - Tích hợp kiểm tra CRL vào `PDFVerifier._verify_signature()`
   - Phân phối CRL thông qua OCSP hoặc kho HTTP

9. **Thay Thế SQLite bằng PostgreSQL**
   - Tài liệu thiết lập PostgreSQL cho phát triển và sản xuất
   - Thêm di chuyển cho gộp kết nối (pgBouncer)
   - Triển khai thủ tục sao lưu và khôi phục được tài liệu trong README

### Trung Hạn (Tính Năng, Tuần 2-4)

10. **Xử Lý Tác Vụ Không Đồng Bộ**
    - Triển khai Celery cho công việc nền:
      - Cấp phát chứng chỉ (lệnh gọi openssl chặn)
      - Xác thực PDF trên các tệp lớn
      - Tạo CRL
      - Thông báo hết hạn chứng chỉ
    - Thêm API theo dõi trạng thái tác vụ

11. **Nâng Cao Xác Thực PDF**
    - Kết quả xác thực chuỗi trình bày chi tiết
    - Tích hợp trạng thái thu hồi (CRL/OCSP)
    - Xác thực chứng chỉ cơ quan dấu thời gian
    - Trả về thông tin đường dẫn tin cậy
    - Hỗ trợ các tiêu chuẩn chữ ký PDF khác (PAdES, XAdES)

12. **Triển Khai Quy Trình Gia Hạn Chứng Chỉ**
    - Thêm điểm cuối yêu cầu gia hạn 30 ngày trước khi hết hạn
    - Quản trị viên phê duyệt yêu cầu gia hạn
    - Cấp phát chứng chỉ mới với số sê-ri mới
    - Thông báo cho người dùng qua email

13. **Thêm Tài Liệu API**
    - Tạo lược đồ OpenAPI cho tất cả các điểm cuối
    - Phục vụ Swagger UI tại `/api/docs/`
    - Tài liệu luồng xác thực và mã lỗi
    - Cung cấp SDK/thư viện máy khách

14. **Xác Thực & Vệ Sinh Đầu Vào**
    - Xác thực định dạng tên người dùng (chỉ chữ và số)
    - Xác thực kích thước tệp PDF (tối đa 50MB)
    - Xác thực giới hạn vị trí chữ ký
    - Thêm trình xác thực Django cho các trường UserProfile

### Dài Hạn (Cấp Độ Doanh Nghiệp, Tuần 4+)

15. **Tích Hợp Mô-đun Bảo Mật Phần Cứng (HSM)**
    - Truy cập lưu trữ chứng chỉ vào phần cứng có thể cắm:
      ```python
      class CertificateBackend(ABC):
          def load_certificate(self, cert_id) -> CertificateData: ...
          def sign_data(self, data) -> Signature: ...
      
      class LocalFileBackend(CertificateBackend): ...
      class HSMBackend(CertificateBackend): ...
      ```
    - Hỗ trợ CloudHSM, Thales HSM hoặc YubiHSM
    - Không bao giờ xuất khóa riêng từ HSM

16. **Hỗ Trợ Multi-CA**
    - Cho phép nhiều CA trung gian
    - Các yêu cầu cấp phát tuyến đến CA thích hợp
    - Hỗ trợ cập nhật chuỗi chứng chỉ CA

17. **Tính Năng Chữ Ký Nâng Cao**
    - Hỗ trợ Long-Term Validation (LTV) (nhúng CRL/OCSP trong chữ ký)
    - Tích hợp Cơ Quan Dấu Thời Gian (TSA) với xử lý lỗi thích hợp
    - Hỗ trợ chữ ký đối chứng
    - Nhiều người ký trên một tài liệu

18. **Tuân Thủ & Tiêu Chuẩn**
    - Triển khai tuân thủ eIDAS cho chữ ký điện tử
    - Hỗ trợ định dạng chữ ký XAdES và CAdES
    - Triển khai xác thực PKIX theo RFC 5280
    - Ma trận tuân thủ tài liệu

19. **Tính Khả Dụng Cao & Khôi Phục Thảm Họa**
    - Sao chép cơ sở dữ liệu (phát sóng trực tuyến PostgreSQL)
    - Trình cân bằng tải để mở rộng ngang
    - Kiểm tra sao lưu và khôi phục tự động
    - Mục tiêu RTO/RPO được tài liệu

---

## 7. Kết Luận

Hệ thống backend CA thể hiện sự hiểu biết vững chắc về các nguyên tắc cơ bản của chứng chỉ và mã hóa PDF, với việc sử dụng thích hợp các thư viện được thiết lập (pyHanko, pyhanko-certvalidator) và kiến trúc hướng dịch vụ được suy nghĩ kỹ. Triển khai ký PDF là khả năng sản xuất với tuân thủ PAdES và hỗ trợ TSA.

Tuy nhiên, hệ thống **không sẵn sàng cho sản xuất** ở trạng thái hiện tại do:

1. **Vấn đề bảo mật quan trọng**: Bí mật được mã hóa cứng, lỗ hổng CSRF, xử lý mật khẩu yếu, khóa riêng tư không được mã hóa
2. **Thiếu các nguyên tắc cơ bản của PKI**: Không thu hồi chứng chỉ, không CRL/OCSP, không dấu vết kiểm toán
3. **Xác thực yếu**: Thông tin đăng nhập dựa trên POST, các điểm cuối miễn trừ CSRF, không bắt buộc HTTPS
4. **Cơ sở dữ liệu không đủ**: SQLite không đủ cho các hệ thống đa người dùng
5. **Quản lý vòng đời không hoàn chỉnh**: Không gia hạn, không theo dõi hết hạn hoặc khôi phục thảm họa

### Lộ Trình Ưu Tiên:
- **Tuần 1**: Sửa quản lý bí mật, bật HTTPS/CSRF, bảo mật mật khẩu
- **Tuần 2-3**: Hợp nhất lôgic chứng chỉ, thêm ghi nhật ký kiểm toán, triển khai thu hồi
- **Tuần 3+**: Xử lý không đồng bộ, xác thực nâng cao, các tính năng doanh nghiệp

Cơ sở mã cung cấp một nền tảng tuyệt vời cho một hệ thống PKI an toàn nếu các vấn đề bảo mật được xác định được giải quyết một cách có hệ thống. Nhóm phát triển nên ưu tiên quản lý bí mật và bảo vệ CSRF trước bất kỳ triển khai sản xuất nào, sau đó dần dần triển khai các tính năng PKI bị thiếu để đáp ứng các yêu cầu tuân thủ doanh nghiệp.

### Chỉ Số Thành Công cho Sản Xuất:
- Không có bí mật được mã hóa cứng trong kho lưu trữ
- 100% HTTPS với ghim chứng chỉ
- Dấu vết kiểm toán hoàn chỉnh của tất cả các hoạt động
- Thực thi thu hồi CRL/OCSP trong xác thực
- Thủ tục khôi phục thảm họa được tài liệu
- Bài kiểm tra xâm nhập với 0 phát hiện quan trọng
