# LFS — Local File Share

Máy chủ chia sẻ tệp cho mạng nội bộ và Internet, có cấp quyền bằng chữ ký số Ed25519.

## Yêu cầu

- Node.js 18 trở lên

## Cài đặt

```bash
git clone https://github.com/Jaycelation/LFS.git
cd LFS
npm install
```

## Khởi chạy

```bash
node server [PORT] [THƯ_MỤC]
```

| Lệnh | Mô tả |
|---|---|
| `npm start` | Chạy ở cổng 8080, lưu tệp tại `./storage` |
| `node server 8000 D:\Share` | Chạy ở cổng 8000, chia sẻ thư mục `D:\Share` |
| `npm run cert` | Tạo chứng chỉ tự ký; lần khởi chạy sau máy chủ dùng HTTPS |

Khi khởi động, máy chủ in ra địa chỉ truy cập và fingerprint khóa máy chủ:

```
  Local File Share  —  mode: INTERNAL
  → http://localhost:8000
  → http://192.168.1.10:8000

  Server key fingerprint (compare on clients for 2-way auth):
    AB7A:45A4:DC7C:F3F6:AB56:5887:1187:7B43
```

Người dùng truy cập địa chỉ trên bằng trình duyệt. Tài khoản đăng ký đầu tiên được cấp quyền quản trị.

## Sử dụng giao diện web

### Đăng ký và đăng nhập

1. Chọn **Tạo danh tính**, nhập tên người dùng và mật khẩu. Cặp khóa được tạo và lưu trên trình duyệt.
2. So sánh fingerprint hiển thị ở mục **Máy chủ** với fingerprint in trên console của máy chủ.
3. Những lần sau, nhập mật khẩu và chọn **Mở khóa & đăng nhập**.

Tùy chọn **Xác thực 2 chiều** (bật mặc định) kiểm tra chữ ký của máy chủ khi đăng nhập. Nếu tắt, chỉ máy chủ xác thực người dùng.

Để dùng danh tính trên máy khác, vào **Danh tính → Tải file sao lưu danh tính**, sau đó chọn **Nhập danh tính** trên máy mới.

### Tải tệp lên

1. Vào **Tệp → Tải tệp lên**, chọn hoặc kéo thả tệp.
2. Thiết lập quyền tải xuống:
   - **Yêu cầu khóa khi tải xuống**: bỏ chọn để tệp ở chế độ công khai.
   - **Người phê duyệt** và **Số chữ ký cần (M)**: số người phải ký trước khi khóa tải xuống có hiệu lực.
   - **Hiển thị**: hiển thị trong danh sách hoặc ẩn.
3. Chọn **Ký & tải lên**.

Quản trị viên tải lên trực tiếp. Người dùng thường cần nhập **Mã Khóa tải lên** do quản trị viên cấp.

### Tải tệp xuống

Màu của mỗi ô tệp thể hiện quyền của bạn:

| Màu | Ý nghĩa |
|---|---|
| Xanh lá | Được phép tải |
| Vàng | Đã có khóa, đang chờ ký |
| Xám đậm | Cần khóa |

- **Tệp công khai**: tải tại trang **Tệp công khai**, không cần đăng nhập.
- **Tệp cần khóa**: mở tệp, nhập mã khóa nhận được và chọn **Ký & mở**. Khi khóa đủ chữ ký, tệp được tải về.

Để kiểm tra tính toàn vẹn của tệp đã tải, mở tệp và vào tab **Chi tiết & xác minh**.

### Cấp quyền tải xuống

1. Mở tệp và chọn **Tạo khóa**, hoặc vào **Khóa & quyền → Tạo khóa**.
2. Chọn người nhận, số lần dùng và thời hạn. Chọn **Bất kỳ ai có mã** nếu chưa biết tài khoản người nhận.
3. Chọn **Ký & tạo khóa** và gửi mã `XXXX-XXXX-XXXX-XXXX` cho người nhận.
4. Người nhận nhập mã và ký nhận.
5. Nếu tệp yêu cầu nhiều người phê duyệt, những người còn lại mở mã tại **Khóa & quyền** và chọn **Đồng ký phê duyệt**.

Khóa có hiệu lực khi đủ M chữ ký phê duyệt và chữ ký của người nhận. Người phê duyệt hoặc người nhận có thể **Thu hồi** khóa bất cứ lúc nào.

### Cấp quyền tải lên

Quản trị viên vào **Khóa & quyền → Tạo khóa**, chọn loại **Khóa tải lên** và đặt dung lượng tối đa mỗi tệp. Người nhận ký nhận khóa, sau đó nhập mã khi tải tệp lên.

### Quản trị

Trang **Quản trị** dùng để kích hoạt, vô hiệu hóa, cấp hoặc gỡ quyền quản trị cho người dùng, và xem nhật ký hoạt động.

## Sử dụng dòng lệnh (CLI)

```bash
npm link          # cài lệnh `lfs`; hoặc dùng: node cli/lfs.js <lệnh>
```

### Thiết lập

```bash
lfs init <tên>                                      # tạo danh tính
lfs server http://192.168.1.10:8000 --fingerprint <FP>
lfs register
lfs login                                           # --one-way: xác thực 1 chiều
```

### Lệnh

| Lệnh | Mô tả |
|---|---|
| `lfs ls` | Liệt kê tệp |
| `lfs upload <tệp> [--public] [--approvers a,b] [--threshold N] [--key MÃ]` | Tải tệp lên |
| `lfs download <id> [--key MÃ] [-o đường_dẫn]` | Tải tệp xuống và kiểm tra tính toàn vẹn |
| `lfs access <id> public\|protected` | Đổi chế độ tải xuống của tệp |
| `lfs rm <id>` | Xóa tệp |
| `lfs grant download <id> --to <người\|*> [--uses N] [--hours H]` | Tạo khóa tải xuống |
| `lfs grant upload --to <người> [--max-mb M]` | Tạo khóa tải lên (quản trị viên) |
| `lfs key <MÃ>` | Xem khóa và trạng thái chữ ký |
| `lfs accept <MÃ>` | Ký nhận khóa |
| `lfs approve <MÃ>` | Đồng ký phê duyệt |
| `lfs revoke <MÃ>` | Thu hồi khóa |
| `lfs keys` | Liệt kê khóa liên quan |
| `lfs users` | Liệt kê người dùng |
| `lfs admin <người> status active\|disabled` | Kích hoạt hoặc vô hiệu hóa người dùng |
| `lfs admin <người> role admin\|user` | Cấp hoặc gỡ quyền quản trị |
| `lfs audit` | Xem nhật ký hoạt động |

| Biến môi trường | Mô tả |
|---|---|
| `LFS_PASSPHRASE` | Mật khẩu danh tính, dùng cho script |
| `LFS_HOME` | Thư mục hồ sơ (mặc định `~/.lfs`) |

### Ví dụ

```bash
# Máy A
lfs upload report.pdf --approvers carol --threshold 2
lfs grant download 3f2a9c… --to bob

# Máy C (người phê duyệt thứ hai)
lfs approve 8F3K-2QX9-MA71-ZK4D

# Máy B
lfs accept 8F3K-2QX9-MA71-ZK4D
lfs download 3f2a9c…
```

## Cấu hình

Cấu hình được đọc theo thứ tự ưu tiên: tham số dòng lệnh, biến môi trường, rồi `config.json` (tạo từ `config.example.json`).

| Biến môi trường | Mặc định | Mô tả |
|---|---|---|
| `PORT` | `8080` | Cổng lắng nghe |
| `HOST` | `0.0.0.0` | Địa chỉ lắng nghe |
| `NETWORK_MODE` | `internal` | `internal`: chỉ chấp nhận IP nội bộ. `external`: chấp nhận mọi IP |
| `TRUST_PROXY` | `false` | Bật khi chạy sau reverse proxy hoặc tunnel |
| `STORAGE_DIR` | `storage` | Thư mục lưu tệp |
| `KEYS_DIR` | `keys` | Thư mục lưu khóa máy chủ và danh sách người dùng |
| `DOWNLOAD_AUTH` | `true` | Giá trị mặc định của tùy chọn “Yêu cầu khóa khi tải xuống” |
| `OPEN_REGISTRATION` | `true` | `false`: tài khoản mới cần quản trị viên kích hoạt |
| `UPLOAD_KEY_THRESHOLD` | `1` | Số chữ ký quản trị viên cần cho một khóa tải lên |
| `MAX_UPLOAD_MB` | `4096` | Dung lượng tệp tối đa |
| `MAX_GRANT_DAYS` | `30` | Thời hạn tối đa của khóa |
| `SESSION_TTL_MIN` | `480` | Thời gian hiệu lực của phiên đăng nhập |
| `LFS_NAME` | `Local File Share` | Tên hiển thị của máy chủ |

## Truy cập từ Internet

Đặt `NETWORK_MODE=external` và chọn một trong các cách sau:

| Cách | Thiết lập |
|---|---|
| Mở cổng trên router | Chuyển tiếp cổng tới máy chủ, chạy `npm run cert` để dùng HTTPS |
| Cloudflare Tunnel | `cloudflared tunnel --url http://localhost:8080`, đặt `TRUST_PROXY=true` |
| Tailscale / ZeroTier | Giữ `NETWORK_MODE=internal` (dải 100.64.0.0/10 được xem là nội bộ) |

Khi truy cập qua Internet, nên dùng HTTPS để mã hóa nội dung tệp khi truyền.

## Lưu ý

- Tệp được lưu với tên gốc trong thư mục chia sẻ. Danh sách người dùng nằm tại `keys/authorized_keys`.
- Khóa cấp quyền và phiên đăng nhập chỉ lưu trong bộ nhớ. Khởi động lại máy chủ sẽ hủy toàn bộ khóa đang có.
- Sao lưu file danh tính. Mất file danh tính đồng nghĩa với mất tài khoản.

## Kiểm thử

```bash
npm test
```
