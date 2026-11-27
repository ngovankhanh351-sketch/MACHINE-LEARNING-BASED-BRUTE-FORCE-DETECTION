# BruteForceML: Phát hiện tấn công brute-force SSH/FTP bằng học máy

Ba mô hình (Decision Tree, Random Forest, XGBoost) được huấn luyện trên dataset **CIC-IDS2017 (Tuesday)**, sau đó cùng dự đoán trên lưu lượng mạng thật. Khi phát hiện brute-force, hệ thống gửi thông báo Discord gồm kết quả của **mô hình chính**, tức mô hình có Recall tấn công cao nhất, hoà thì xét F1-macro (hiện là XGBoost), kèm kết quả của 2 mô hình còn lại để tham khảo.

## Cấu trúc

```
src/01…05_*.py          Pipeline huấn luyện: khảo sát → tiền xử lý → chia dữ liệu → train 3 model → phân tích
src/06_*.py             Kiểm thử detector trên tập X_test (phải khớp confusion matrix của bước 04)
src/07_*.py             Tổng hợp kết quả kiểm thử thật (Kali) thành bảng 3 model × các kịch bản
src/08_*.py             So phân phối đặc trưng dataset ↔ pcap thật (KS-test), tìm đặc trưng lệch
src/dung_chung.py       Đường dẫn dùng chung, lấy từ detector/config.py
detector/               Hệ thống phát hiện (chạy thật)
  flow_tracker.py         Gom gói tin thành luồng theo quy tắc CICFlowMeter (Java)
  features.py             Đổi đặc trưng cicflowmeter (Python) → 78 cột CIC-IDS2017, tính lại
                          độ dài/header/IAT theo công thức bản Java (java_style_features)
  predictor.py            Nạp 3 model, xếp hạng theo Recall tấn công rồi F1-macro, dự đoán đồng thời
  notifier.py             Discord webhook + gom cảnh báo theo IP tấn công
  cli.py                  Lệnh: live | pcap | test-discord
scripts/                Script bash cho Ubuntu
  kiem_thu.sh             Chạy 1 kịch bản: ghi pcap → (Kali tấn công) → phân tích, đặt tên cố định
Results/kiem_thu/       pcap đã phân tích + bảng đánh giá từng kịch bản + bảng tổng hợp
models/                 Model đã train + bảng xếp hạng ket_qua_so_sanh.csv
  metadata.json           Phiên bản thư viện, danh sách đặc trưng, cách chia dữ liệu lúc train
  *_feature_importance.csv  Độ quan trọng đặc trưng của từng model
  thi_nghiem_bo_port.csv  Kết quả thí nghiệm huấn luyện lại không có Destination Port
Results/                Biểu đồ, kết quả, nhật ký live, kết quả phân tích pcap
Results/lech_mien/      Kết quả bước 08 (đặc trưng lệch giữa dataset và pcap thật)
```

> `models/` và `detector/` phải luôn đi cùng nhau: model hiện tại dùng 66 đặc trưng (đã bỏ 12 cột cờ TCP)
> và cách tính đặc trưng mới. Khi chép sang Ubuntu, chép cả hai thư mục (cùng `src/` và README).

## Mô hình lab

```
 Kali Linux (tấn công)                 Ubuntu (nạn nhân + IDS)
 192.168.56.101  ── mạng host-only ──► 192.168.56.20
 hydra / patator / medusa              :22 OpenSSH   :21 vsftpd
                                       sudo ./scripts/run_live.sh -i enp0s8 ──► Discord
```

Hai máy ảo dùng chung một mạng **Host-only** (VirtualBox) hoặc **LAN segment** (VMware). IP ở trên chỉ là ví dụ, xem IP thật bằng `ip -brief address`.

## Cài đặt trên Ubuntu (24.04 trở lên)

> Cần Python ≥ 3.12 (yêu cầu của `cicflowmeter` 0.5.0). Ubuntu 22.04 chỉ có Python 3.10.

```bash
cd BruteForceML
chmod +x scripts/*.sh
./scripts/setup_ubuntu.sh --services   # cài thư viện, .venv, OpenSSH server và vsftpd
nano .env                              # điền DISCORD_WEBHOOK_URL
./scripts/test_discord.sh              # kiểm tra: kênh Discord nhận được tin nhắn thử
```

Lấy webhook: Discord, mở **Server Settings → Integrations → Webhooks → New Webhook → Copy Webhook URL**. Không chia sẻ file `.env`.

Tạo tài khoản làm mục tiêu: `sudo adduser victim`. Nếu có `fail2ban` thì tắt nó trong lúc kiểm thử, vì nó sẽ chặn Kali.

## Chế độ 1: giám sát thời gian thực (mặc định)

```bash
sudo ./scripts/run_live.sh -i enp0s8            # enp0s8 = interface nối với Kali
sudo ./scripts/run_live.sh -i enp0s8 --quiet    # chỉ in luồng tấn công
```

- Mỗi luồng bị đánh giá là tấn công được in ra màn hình kèm kết quả của 3 model (`*` đánh dấu mô hình chính).
- **Discord:** mỗi đợt tấn công, tính theo cặp (IP tấn công, dịch vụ), nhận một cảnh báo chi tiết ngay khi phát hiện. Sau đó cứ mỗi `--cooldown` giây (mặc định 60) có một tin tổng hợp số luồng tấn công thêm, đếm theo từng model.
- Tất cả dự đoán được ghi vào `Results/live_log_<thời gian>.csv` để đánh giá sau.
- Một luồng được đóng và dự đoán khi gặp gói FIN, khi không có gói mới sau 30 giây (`--idle-timeout`), hoặc khi đã kéo dài 120 giây.
- Tùy chọn khác: `--primary-model "Random Forest"`, `--all-ports`, `--no-discord`. Xem đầy đủ: `./scripts/run_live.sh --help`.
- Mô hình chính mặc định lấy theo bảng xếp hạng lúc train. Sau khi kiểm thử bằng Kali, nên dùng model mà `src/07` gợi ý (xếp hạng trên lưu lượng thật): `--primary-model "<tên>"`.
- Cảnh báo đến chậm vài giây so với lúc bắt đầu tấn công vì luồng chỉ được dự đoán khi đã đóng — đây không phải lỗi.

## Chế độ 2: phân tích file pcap

```bash
./scripts/analyze_pcap.sh capture.pcap
./scripts/analyze_pcap.sh capture.pcap --attacker-ip 192.168.56.101   # thêm Recall/Precision từng model
./scripts/analyze_pcap.sh capture.pcap --notify                       # gửi tóm tắt lên Discord
```

Kết quả gồm số luồng BENIGN / FTP-Patator / SSH-Patator theo từng model, kết luận theo mô hình chính, số luồng cả 3 model đồng ý và danh sách IP tấn công. Dự đoán từng luồng được lưu ở `Results/pcap_<tên>_<thời gian>.csv`.

Khi có `--attacker-ip`, mọi luồng từ IP đó tới cổng 21/22 được coi là tấn công, còn lại là bình thường. Từ đó chương trình tính TP, FN, FP, Recall, Precision và tỉ lệ báo nhầm cho từng model, rồi lưu thêm file `*_danh_gia.csv`.

Mặc định phần đánh giá **chỉ tính trên các luồng mở kết nối thật** (luồng có gói SYN), bỏ qua các mảnh luồng vụn sinh ra khi đóng kết nối (gói FIN tách thành luồng riêng 1–2 gói, không mang dấu hiệu brute-force). Nhờ vậy số luồng tấn công khớp với số kết nối mà Kali thực sự mở — bằng số gói SYN đếm bằng:

```bash
tcpdump -r capture.pcap -nn 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and dst port 22 and src host <IP_Kali>' | wc -l
```

Nếu các mảnh vụn này cũng bị tính là tấn công thì Recall sẽ bị kéo xuống một cách giả tạo. Thêm cờ `--count-fragments` nếu muốn quay lại cách tính cũ (tính cả mảnh vụn). File CSV kết quả có thêm cột `n_packets` và `has_syn` để bạn tự kiểm tra từng luồng.

## Kịch bản kiểm thử bằng Kali

> Chỉ tấn công máy trong lab của bạn.

Chuẩn bị wordlist nhỏ trên Kali và cho mật khẩu đúng của `victim` vào cuối danh sách:

```bash
sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz
head -n 300 /usr/share/wordlists/rockyou.txt > pass.txt && echo 'MatKhauDung' >> pass.txt
```

Mỗi kịch bản làm **một lần**, trên Ubuntu chạy `scripts/kiem_thu.sh` để nó tự ghi pcap →
chờ bạn tấn công → dừng ghi → phân tích và lưu kết quả với tên cố định:

```bash
# cú pháp: sudo ./scripts/kiem_thu.sh <interface> <tên_kịch_bản> <IP_Kali | --benign>
sudo ./scripts/kiem_thu.sh enp0s8 03_hydra_ssh 192.168.56.101
```

Script bắt đầu ghi gói tin rồi dừng lại chờ. Lúc đó **sang máy Kali chạy đúng một lệnh**
ở bảng dưới, chạy xong quay lại Ubuntu nhấn Enter — script dừng ghi, đếm số gói SYN và in
bảng Recall/Precision từng model. Kết quả vào `pcaps/<tên>.pcap`,
`Results/kiem_thu/<tên>.csv` và `Results/kiem_thu/<tên>_danh_gia.csv`.

| Tên kịch bản | Máy chạy | Lệnh trên Kali |
|---|---|---|
| `01_patator_ssh` | Kali | `patator ssh_login host=192.168.56.20 user=victim password=FILE0 0=pass.txt -x ignore:mesg='Authentication failed.'` |
| `02_patator_ftp` | Kali | `patator ftp_login host=192.168.56.20 user=victim password=FILE0 0=pass.txt -x ignore:mesg='Login incorrect.'` |
| `03_hydra_ssh` | Kali | `hydra -l victim -P pass.txt -t 4 ssh://192.168.56.20` |
| `04_hydra_ftp` | Kali | `hydra -l victim -P pass.txt -t 4 ftp://192.168.56.20` |
| `05_medusa_ssh` | Kali | `medusa -h 192.168.56.20 -u victim -P pass.txt -M ssh` (và `06_medusa_ftp` với `-M ftp`) |
| `07_ncrack` | Kali | `ncrack -p 21,22 --user victim -P pass.txt 192.168.56.20` |
| `08_binh_thuong` | Kali | Đăng nhập **đúng**: `ssh victim@…`, `scp`, `sftp`, tải file FTP (`curl ftp://victim:MatKhauDung@192.168.56.20/`) |

Với kịch bản tấn công, đưa IP Kali làm tham số thứ 3. Với kịch bản bình thường thì dùng `--benign`:

```bash
sudo ./scripts/kiem_thu.sh enp0s8 08_binh_thuong --benign
```

Kịch bản bình thường rất quan trọng: thiếu nó thì không đo được tỉ lệ báo nhầm.

Sau khi chạy đủ các kịch bản, gom tất cả bảng đánh giá thành bảng so sánh 3 model × kịch bản:

```bash
.venv/bin/python src/07_tong_hop_kiem_thu.py
# -> Results/kiem_thu/tong_hop_recall.csv, tong_hop_bao_nham.csv, tong_hop.csv
```

> Vẫn có thể làm thủ công: `scripts/capture_pcap.sh` để ghi pcap, rồi
> `scripts/analyze_pcap.sh <file> --attacker-ip <IP>` (hoặc `--benign`) để phân tích.

Kiểm tra **lệch miền đặc trưng** giữa dataset và pcap thật (cần chạy trên máy có pcap):

```bash
.venv/bin/python src/08_kiem_tra_lech_mien.py pcaps/01_patator_ssh.pcap pcaps/02_patator_ftp.pcap \
    --attacker-ip 192.168.56.101 --benign pcaps/08_binh_thuong.pcap
# -> Results/lech_mien/dac_trung_lech.csv: KS từng đặc trưng + % độ quan trọng của mỗi model nằm trên đặc trưng lệch
.venv/bin/python src/04_huan_luyen_mo_hinh.py --bo-co-tcp --bo-cot-lech   # huấn luyện lại không dùng đặc trưng lệch
```

## Quy trình đầy đủ sau khi cập nhật model

Model hiện tại (chia theo thời gian, bỏ cờ TCP, đặc trưng kiểu Java) **chưa được kiểm thử lại bằng Kali**. Thứ tự nên làm trên Ubuntu:

1. Chép `detector/`, `src/`, `models/`, `README.md` sang; chạy `./scripts/test_discord.sh`.
2. Chạy các kịch bản Kali bằng `scripts/kiem_thu.sh` (mục trên) — có ít nhất 1 kịch bản SSH, 1 FTP và `08_binh_thuong`.
3. `src/07_tong_hop_kiem_thu.py` → bảng 3 model × kịch bản + gợi ý `--primary-model`.
4. `src/08_kiem_tra_lech_mien.py` với các pcap đó → danh sách đặc trưng lệch.
5. Nếu bước 4 còn đặc trưng lệch quan trọng: `src/04_huan_luyen_mo_hinh.py --bo-co-tcp --bo-cot-lech`, rồi `src/06` để kiểm tra, rồi lặp lại bước 2–3.
6. Chạy phát hiện: dùng chế độ pcap kèm `--attacker-ip` để lấy số liệu cho báo cáo, sau đó demo bằng chế độ live:

```bash
sudo ./scripts/run_live.sh -i enp0s8 --quiet --primary-model "XGBoost"   # Ubuntu
hydra -l victim -P pass.txt -t 4 ssh://192.168.56.20                     # Kali
```

### Đọc kết quả

| Hiện tượng | Ý nghĩa / việc cần làm |
|---|---|
| Cả 3 model báo tấn công, Discord có cảnh báo | Hệ thống hoạt động đúng |
| Mô hình chính bỏ sót nhưng model khác bắt được | Đổi `--primary-model` theo `Results/kiem_thu/xep_hang_that.csv` |
| Cả 3 model bỏ sót | Chạy `src/08` với pcap đó; huấn luyện lại với `--bo-cot-lech` |
| Kịch bản `--benign` bị báo tấn công | Báo nhầm — xem cột `so_mo_hinh_bao_tan_cong` trong file CSV kết quả |

## Lưu ý về độ chính xác khi chạy thật

1. **Công cụ trích đặc trưng khác nhau.** CIC-IDS2017 được tạo bằng CICFlowMeter bản **Java**, còn hệ thống dùng bản **Python** (`cicflowmeter` 0.5.0). `detector/features.py` sửa các khác biệt: tên cột, giây → micro giây, `Init_Win_bytes = -1`, và **tính lại** các đặc trưng độ dài/header/IAT theo công thức Java (độ dài = payload TCP thay vì cả gói, header = TCP header, std mẫu n−1, IAT khi chỉ có 1 khoảng, gói đầu tính 2 lần ở thống kê cấp luồng, Down/Up chia nguyên). Các công thức này đã đối chiếu khớp 100% với dataset. 12 cột cờ TCP của dataset là artefact không tái tạo được, nên model hiện tại được huấn luyện với `--bo-co-tcp`. Đặc trưng còn lệch thì dùng `src/08` để tìm.
2. **Phụ thuộc vào cổng đích.** Decision Tree dựa ~99% vào `Destination Port`. Bước 04 tự chạy thí nghiệm bỏ cột này (`models/thi_nghiem_bo_port.csv`); muốn model không dựa vào cổng thì huấn luyện với `--bo-port`.
3. **Công cụ khác Patator.** Dataset chỉ có tấn công bằng Patator. Hydra, Medusa, Ncrack có nhịp gửi khác, và đó là điểm đáng so sánh trong báo cáo.
4. Nếu kết quả thật kém, có thể dùng chính các file pcap đã gán nhãn từ lab để huấn luyện lại hoặc bổ sung dữ liệu.

## Huấn luyện lại

```bash
.venv/bin/python src/01_khao_sat_du_lieu.py   # … lần lượt tới 05
.venv/bin/python src/06_kiem_thu_he_thong.py  # detector phải cho kết quả giống bước 04
```

- **Bước 03** mặc định chia train/test **theo thời gian** cho từng nhãn (80% luồng đầu → train, 20% cuối → test). Chia ngẫu nhiên (`--chia ngau_nhien`) làm điểm test gần 100% vì các luồng patator gần như giống hệt nhau nằm ở cả hai tập.
- **Bước 04** tuỳ chọn: `--bo-co-tcp`, `--bo-port`, `--bo-cot-lech` (đọc kết quả bước 08), `--bo-cot "Tên cột" ...`. Ghi thêm `*_feature_importance.csv`, `thi_nghiem_bo_port.csv`, `metadata.json` (phiên bản thư viện, đặc trưng, cách chia).
- **Bước 05** vẽ thêm biểu đồ độ quan trọng đặc trưng (`Results/<model>_feature_importance.png`), in số luồng tấn công bị bỏ sót và bảng thí nghiệm bỏ port.
- **Xếp hạng mô hình** theo `Recall_Attack` (recall trung bình của các lớp tấn công), hoà thì xét `F1_Macro` — quy tắc ở `RANKING_COLUMNS` trong `detector/config.py`, detector và bước 05 dùng chung. Bước 07 xếp hạng thêm trên lưu lượng thật (`Results/kiem_thu/xep_hang_that.csv`) và gợi ý `--primary-model`.

Kết quả hiện tại trên tập test (chia theo thời gian, `--bo-co-tcp`, 66 đặc trưng):

| Model | Recall tấn công | Luồng tấn công bỏ sót | Báo nhầm |
|---|---|---|---|
| XGBoost (chính) | 0.9860 | 18 | 0 |
| Decision Tree | 0.9822 | 27 | 0 |
| Random Forest | 0.9667 | 47 | 0 |

Thí nghiệm bỏ `Destination Port`: số luồng XGBoost bỏ sót tăng từ 18 lên 39 — model vẫn học được dấu hiệu brute-force, không chỉ dựa vào cổng. Bản sao lưu trước khi sửa nằm ở `backup_truoc_sua_20261119/`.

Các script dùng đường dẫn tương đối theo thư mục project nên chạy được ở bất kỳ đâu. Tên file model, bảng xếp hạng và thư mục kết quả chỉ được khai báo trong `detector/config.py`, nên bước huấn luyện và hệ thống phát hiện luôn khớp nhau. `requirements.txt` cố định `scikit-learn==1.9.1`, đúng phiên bản đã dùng để lưu model.
