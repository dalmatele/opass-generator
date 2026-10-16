# OMEN Generator

Generator C đọc model `IP.level`, `CP.level` và `config.txt` của pcfg-go/OMEN,
sau đó stream password candidate ra `stdout`. Có thể ghi output ra file hoặc
nối vào một chương trình khác qua pipe.

> Chỉ sử dụng candidate và Hashcat với dữ liệu/hash mà bạn được phép kiểm tra
> hoặc khôi phục.

## Yêu cầu

- Compiler C hỗ trợ C11 (`cc`, GCC hoặc Clang).
- `make` tương thích POSIX (GNU Make hoặc BSD Make).
- Model OMEN gồm `IP.level`, `CP.level` và `config.txt` có khai báo `ngram`.

Generator hỗ trợ build native trên Windows bằng MinGW-w64, cũng như build
trong các môi trường tương thích POSIX như MSYS2 MSYS và Cygwin.

### Build trên Windows bằng MSYS2

1. Cài MSYS2 từ [msys2.org](https://www.msys2.org/).
2. Mở terminal **MSYS2 MINGW64**.
3. Cập nhật MSYS2:

   ```sh
   pacman -Syu
   ```

   Nếu được yêu cầu đóng và mở lại terminal, hãy làm theo hướng dẫn rồi cài
   GNU Make và compiler MinGW-w64 cho MINGW64:

   ```sh
   pacman -S --needed base-devel mingw-w64-x86_64-gcc
   ```

4. Trong terminal MINGW64, chuyển đến thư mục dự án và build:

   ```sh
   cd /e/Projects/github/opass-generator
   make
   ```

   Thay đường dẫn bằng vị trí bạn đã clone dự án. Build tạo ra
   `omen-generator.exe` và `omen-level-check.exe`. Khi build bằng MinGW-w64,
   đây là executable Windows native và không cần MSYS2 runtime. Nếu MinGW và
   GNU Make đã có trong `PATH`, bạn cũng có thể chạy `make` từ môi trường đó.

## Build

Trong thư mục dự án:

```sh
make
```

Lệnh này tạo:

- `omen-generator`: đọc model và sinh candidate.
- `omen-level-check`: kiểm tra định dạng các file model.

Có thể chọn compiler/flags:

```sh
make CC=clang
make CC=gcc CFLAGS="-O2 -Wall -Wextra -Wpedantic -std=c11"
```

Xóa binary đã build:

```sh
make clean
```

## Kiểm tra model

Kiểm tra cấu trúc và số record bằng generator:

```sh
./omen-generator \
  --ip data/IP.level \
  --cp data/CP.level \
  --config data/config.txt \
  --check
```

Hoặc dùng checker độc lập:

```sh
./omen-level-check \
  --ip data/IP.level \
  --cp data/CP.level \
  --config data/config.txt
```

Checker là công cụ kiểm tra riêng; nếu model có ký tự đặc biệt như dấu cách
trong token, dùng `omen-generator --check` để xác nhận model mà generator sẽ
đọc được.

## Chạy generator

Ví dụ sinh candidate từ độ dài 8 đến 16 ký tự rồi ghi vào file:

```sh
./omen-generator \
  --ip data/IP.level \
  --cp data/CP.level \
  --config data/config.txt \
  --min-len 8 \
  --max-len 16 \
  > candidates.txt
```

Các tuỳ chọn:

- `--min-len N`: độ dài tối thiểu, tính theo ký tự UTF-8. Mặc định là
  `ngram - 1`; giá trị thấp hơn prefix tối thiểu này được nâng lên.
- `--max-len N`: độ dài tối đa. Nếu không chỉ định, generator tiếp tục tăng
  độ dài cho đến khi bị dừng.
- `--session FILE`: đường dẫn checkpoint; mặc định là `omen.session`.
- `--no-session`: tắt checkpoint.
- `--check`: chỉ kiểm tra model, không sinh candidate.
- `--help`: in trợ giúp.

Generator phát candidate qua `stdout`; thông tin tiến độ/lỗi được ghi ra
`stderr`. Mỗi độ dài được duyệt theo tổng OMEN level tăng dần. Thứ tự này
được áp dụng riêng trong từng độ dài.

## Dùng với Hashcat

Có thể nối output trực tiếp đến Hashcat ở chế độ stdin:

```sh
./omen-generator \
  --ip data/IP.level \
  --cp data/CP.level \
  --config data/config.txt \
  --min-len 8 \
  --max-len 16 \
  --session omen.session |
hashcat -m <hash-mode> -a 0 hashes.txt
```

Thay `<hash-mode>` bằng mode phù hợp với định dạng hash của bạn. Tránh ghi
candidate ra file nếu không cần thiết; pipe giúp không lưu toàn bộ wordlist
trên đĩa.

## Session và restore

Khi bật session (mặc định), generator tạo hoặc cập nhật file `omen.session`.
Checkpoint lưu model fingerprint, giới hạn độ dài, độ dài hiện tại, IP line
và tổng OMEN level. File được ghi qua file tạm rồi thay checkpoint cũ để giảm
nguy cơ checkpoint dở dang.

Checkpoint được cập nhật định kỳ khoảng 5 giây và khi bắt đầu độ dài mới.
Dừng generator bằng `Ctrl+C` hoặc `SIGTERM` để yêu cầu lưu trạng thái trước
khi thoát. Khi chạy lại, dùng đúng model, session và khoảng độ dài:

```sh
./omen-generator \
  --ip data/IP.level \
  --cp data/CP.level \
  --config data/config.txt \
  --min-len 8 \
  --max-len 16 \
  --session omen.session \
  --resume
```

Generator kiểm tra fingerprint của các file model và từ chối resume nếu model
đã thay đổi. Các tuỳ chọn `--min-len`/`--max-len` phải khớp với checkpoint.
Khi không dùng `--max-len`, giữ nguyên trạng thái không giới hạn đó lúc resume.
Sau khi hoàn tất, session được đánh dấu hoàn thành và không thể resume tiếp;
bỏ hoặc đổi tên session nếu muốn bắt đầu lượt mới.

### Resume khi dùng pipe với Hashcat

`--resume` khôi phục **generator**, không khôi phục nguồn stdin của Hashcat.
Nếu pipeline bị dừng, khởi chạy lại cả lệnh generator và Hashcat như một phiên
mới, thêm `--resume` cho generator. Không dùng `--restore` của Hashcat để khôi
phục candidate stream từ generator.

Checkpoint không lưu vị trí chính xác bên trong một nhánh candidate; sau khi
resume, một phần candidate tại vị trí đang xử lý có thể được phát lại. Nếu cần
tránh candidate trùng tuyệt đối sau khi dừng/khởi động lại, cần tạo và lưu
wordlist hoàn chỉnh rồi quản lý offset riêng; stdin pipeline không cung cấp
đảm bảo đó.

## Tốc độ và bộ nhớ

Tốc độ tham khảo với Hashcat mode `32500`:

| Phần cứng | Tốc độ |
|---|---:|
| NVIDIA GeForce RTX 2060 6 GB | 250K candidate/giây |
| MacBook Pro 15-inch (2019) | 30K candidate/giây |
| NVIDIA Tesla T4 | 215K candidates/giây |

Đây là số liệu ghi nhận trên các cấu hình nêu trên; tốc độ thực tế có thể
thay đổi tùy model, thiết lập và cấu hình hệ thống.

Generator nạp model và chỉ mục vào RAM một lần, nhưng không giữ tất cả
candidate trong bộ nhớ. Candidate được stream ra ngay. Buffer tạm tỷ lệ với
độ dài đang sinh; đặt `--max-len` để giới hạn phạm vi và bộ nhớ tạm. Khi pipe
đến Hashcat, tốc độ đầu-cuối chịu giới hạn bởi bên xử lý chậm hơn.
