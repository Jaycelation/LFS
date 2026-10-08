# Local File Share

Chia sẻ tệp trong mạng nội bộ (LAN) hoặc qua Internet. Dùng đơn giản như `python -m http.server`, nhưng có thêm **xác thực bằng chữ ký số Ed25519** để không phải ai cũng tải được.

- Không dùng database: tệp nằm nguyên tên gốc trong một thư mục, người dùng lưu trong 1 file text kiểu `authorized_keys`.
- Giao diện web lấy cảm hứng từ **CTFd**, có hai ngôn ngữ **VI / EN**. Có thêm **CLI** để dùng trong script.
- Chạy được cả trên `http://192.168.x.x` (không cần HTTPS), vì phần mật mã viết bằng JS thuần, không phụ thuộc WebCrypto.

```bash
npm install
node server 8000 ./thu-muc-chia-se
```

Mở `http://<ip-máy-bạn>:8000`. Người dùng đầu tiên đăng ký sẽ là **admin**.

---

## Tính năng

| # | Tính năng | Cách hoạt động |
|---|---|---|
| 1 | **Upload \*** | Người tải lên ký metadata của tệp (tên, kích thước, SHA-256). Server tính lại SHA-256 khi nhận và từ chối nếu không khớp. Admin tự ký là đủ; người dùng thường cần một **Khóa tải lên** do admin cấp. |
| 2 | **Download \*** | Người tải xuống ký một yêu cầu mới (nonce + timestamp). Server trả về link dùng **1 lần, sống 60 giây**. Tải xong, CLI và web kiểm tra lại SHA-256 cùng chữ ký của người tải lên. **Xác thực khi tải là tùy chọn theo từng tệp** (xem bên dưới). |
| 3 | **Generate Key, xác thực 1 / 2 / N chiều** | **1 chiều:** server kiểm tra chữ ký của bạn trên challenge ngẫu nhiên. **2 chiều:** bạn cũng kiểm tra chữ ký của server bằng khóa đã ghim (TOFU), chống giả mạo server. **N chiều:** một khóa cần chữ ký của M trong N người phê duyệt, cộng chữ ký của người nhận. |
| 4 | **Cấp quyền cho hành động \*** | A tạo khóa → gửi mã `XXXX-XXXX-XXXX-XXXX` cho B → B **ký** khóa → (nếu cần, các người phê duyệt khác **đồng ký**) → B được phép tải. Khóa có giới hạn số lần dùng, thời hạn, và có thể **thu hồi**. |

### Xác thực khi tải xuống là tùy chọn

Mỗi tệp chọn 1 trong 2 chế độ (ô *"Yêu cầu khóa khi tải xuống"* lúc upload; chủ tệp đổi được bất cứ lúc nào):

- **Công khai**: ai vào `ip:port` cũng thấy và tải được, **không cần đăng nhập**, giống `python -m http.server`. Link trực tiếp có dạng `/f/<id>/<tên-tệp>`.
- **Cần khóa** (mặc định): áp dụng luồng ký khóa ở mục 4.

Đổi giá trị mặc định bằng `DOWNLOAD_AUTH=false`.

### Luồng cấp quyền tải (ví dụ 2-of-2)

```
alice upload report.pdf, chọn người phê duyệt [alice, carol], cần 2 chữ ký
alice  ── Tạo khóa cho bob ──►  mã 8F3K-2QX9-…   (chữ ký 1/2)
alice  ── gửi mã (chat, Zalo…) ─► bob
bob    ── Ký nhận khóa ─────────►  chờ đồng ký
carol  ── Đồng ký ──────────────►  2/2 ✔ → khóa ACTIVE
bob    ── ký yêu cầu tải ───────►  link 1 lần → tải → kiểm tra SHA-256 + chữ ký alice ✔
```

Trên web, B chỉ cần mở tệp và dán mã vào ô nhập khóa (giống ô nộp flag trong CTFd). Trình duyệt tự kiểm tra chữ ký, ký nhận rồi tải về.

---

## Dữ liệu lưu ở đâu (không có DB)

```
storage/                 tệp chia sẻ, giữ nguyên tên gốc
storage/.lfs/<id>.json   "file chữ ký" của từng tệp: SHA-256, khóa công khai người tải lên, chữ ký, chính sách
keys/server.key          khóa Ed25519 của server (dùng cho xác thực 2 chiều)
keys/authorized_keys     danh sách người dùng, mỗi dòng 1 người — sửa tay được
```

**Khóa cấp quyền, phiên đăng nhập và nhật ký chỉ nằm trong RAM.** Khởi động lại server thì mọi khóa đang có tự hết hiệu lực. Người dùng và tệp vẫn được giữ.

Khóa bí mật của người dùng **không bao giờ rời máy họ**: trên web được mã hóa bằng mật khẩu (PBKDF2-SHA256 + XSalsa20-Poly1305) trong `localStorage`; với CLI thì nằm trong `~/.lfs/identity.json`. Có thể xuất file danh tính từ web và dùng cho CLI (`lfs import`), hoặc ngược lại.

---

## Chạy server

```bash
npm install
npm start                          # cổng 8080, thư mục ./storage
node server 8000 D:\Share          # giống "python -m http.server 8000", chia sẻ D:\Share
npm run cert                       # (tùy chọn) tạo chứng chỉ tự ký → server tự chuyển sang HTTPS
npm test                           # 22 test end-to-end
```

Khi khởi động, console in ra các địa chỉ LAN và **fingerprint khóa server**. Người dùng so fingerprint này ở màn hình đăng nhập để chắc chắn đang nói chuyện với đúng server.

### Cấu hình

Theo thứ tự ưu tiên: tham số dòng lệnh > biến môi trường > `config.json` (xem `config.example.json`).

| Biến môi trường | Mặc định | Ý nghĩa |
|---|---|---|
| `PORT` / `HOST` | `8080` / `0.0.0.0` | |
| `NETWORK_MODE` | `internal` | `internal`: chỉ nhận IP nội bộ (10.x, 172.16-31.x, 192.168.x, 100.64/10 Tailscale, loopback), đồng thời chặn request đi qua proxy hay tunnel. `external`: nhận mọi IP. |
| `TRUST_PROXY` | `false` | Bật khi chạy sau reverse proxy hoặc tunnel do bạn kiểm soát. |
| `STORAGE_DIR` / `KEYS_DIR` | `storage` / `keys` | |
| `DOWNLOAD_AUTH` | `true` | Giá trị mặc định của ô "Yêu cầu khóa khi tải xuống". |
| `OPEN_REGISTRATION` | `true` | `false`: tài khoản mới phải được admin kích hoạt. |
| `UPLOAD_KEY_THRESHOLD` | `1` | Số chữ ký admin cần cho một Khóa tải lên. |
| `MAX_UPLOAD_MB` | `4096` | |
| `MAX_GRANT_DAYS` | `30` | Thời hạn tối đa của một khóa. |
| `SESSION_TTL_MIN` | `480` | |

### Dùng qua Internet (External)

Đặt `NETWORK_MODE=external`, sau đó chọn một trong các cách:

- **Port forwarding** trên router, kèm `npm run cert` để có HTTPS.
- **Cloudflare Tunnel**: chạy `cloudflared tunnel --url http://localhost:8080`, đặt `TRUST_PROXY=true`.
- **Tailscale / ZeroTier**: giữ nguyên `internal`, vì dải 100.64.0.0/10 của Tailscale được coi là nội bộ.

Tính toàn vẹn và quyền truy cập được bảo vệ bằng chữ ký, kể cả khi chạy HTTP. Tuy vậy, **nội dung tệp chỉ được mã hóa khi chạy HTTPS**, nên trên Internet hãy luôn dùng HTTPS.

---

## CLI

```bash
npm link                                   # hoặc: node cli/lfs.js …
lfs init alice                             # tạo danh tính
lfs server http://192.168.1.10:8080 --fingerprint AB7A:45A4:…   # ghim server
lfs register && lfs login                  # --one-way để bỏ kiểm tra server

lfs upload report.pdf --approvers carol --threshold 2      # cần khóa, 2-of-2
lfs upload readme.txt --public                            # công khai
lfs access <fileId> public|protected
lfs ls
lfs grant download <fileId> --to bob --uses 1 --hours 24  # in ra mã khóa
lfs grant upload --to bob --max-mb 500                     # (admin)
lfs key <CODE> | accept <CODE> | approve <CODE> | revoke <CODE> | keys
lfs download <fileId> [-o out]             # tự kiểm tra SHA-256 + chữ ký
lfs admin bob status disabled | lfs audit
```

`LFS_PASSPHRASE` dùng để bỏ qua bước hỏi mật khẩu. `LFS_HOME` (hoặc `--home`) dùng để chọn hồ sơ khác.

---

## Bảo mật: tóm tắt thiết kế

- Mọi chữ ký đều ký lên `LFS-v1\n<mục đích>\n<JSON chuẩn hóa>`. Vì phần *mục đích* (`upload`, `download`, `grant`, `grant-accept`…) nằm trong nội dung được ký, chữ ký của hành động này không dùng lại được cho hành động khác.
- Mọi yêu cầu đã ký đều có `nonce` + `ts` (lệch tối đa 5 phút), và nonce đã dùng sẽ bị từ chối, nên không thể **replay**.
- Khóa tải xuống gắn với **SHA-256 của tệp**: nếu tệp bị thay, khóa không còn khớp.
- Đăng ký phải kèm chữ ký chứng minh sở hữu khóa, và chữ ký đó gắn với khóa của server này.
- Trình duyệt tự kiểm tra lại mọi chữ ký của khóa trước khi cho bạn ký nhận, nên server không thể giả mạo chữ ký của người phê duyệt.
- Link tải dùng 1 lần, sống 60 giây. Có CSP chặt và không có inline script.

Những điểm chưa có: đổi khóa (key rotation) cho người dùng, mã hóa đầu-cuối nội dung tệp.

## Cấu trúc

```
server/   index.js (API + static), store.js (file thuần), config.js
shared/   lfs-crypto.js — mật mã dùng chung cho server, CLI và trình duyệt
public/   giao diện web (vanilla JS, không cần build)
cli/      lfs.js
scripts/  gen-cert.js
test/     e2e.js
```
