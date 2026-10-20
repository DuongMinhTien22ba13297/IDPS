# Kế hoạch kiểm thử runtime 21 features bằng traffic kiểu CICIDS2017

Ngày nghiên cứu: 2026-09-09. Đây là đề xuất; chưa chạy các lệnh dưới đây, chưa cài công cụ hay thay đổi VM.

## 1. Công cụ nào thực sự được dùng?

| Nhóm | Công cụ/môi trường gốc | Áp dụng cho model hiện tại |
|---|---|---|
| Benign | B-Profile; HTTP, HTTPS, FTP, SSH, email | Đo false positive |
| FTP/SSH brute force | Patator | Brute Force |
| DoS | Slowloris, SlowHTTPTest, HULK, GoldenEye | DoS/DDoS |
| Port scan | Nmap, nhiều chế độ quét | PortScan |
| Web | DVWA; Selenium tự động hóa XSS và web brute force | Web Attack |
| DDoS | Trang UNB ghi “DDoS LOIT”, ba máy Windows | DoS/DDoS; ưu tiên PCAP gốc |
| Bot / Infiltration / Heartbleed | ARES / Metasploit / Heartleech | Ngoài các lớp đã giữ lại |

Nguồn: [trang CICIDS2017 của UNB](https://www.unb.ca/cic/datasets/ids-2017.html) và [bài báo gốc, mục 4](https://www.scitepress.org/PublishedPapers/2018/66398/pdf/index.html). DVWA là ứng dụng đích, không phải công cụ sinh traffic. CICFlowMeter là công cụ trích xuất flow, không phải bộ phát tấn công.

Tên LOIC thường được dùng để chỉ Low Orbit Ion Cannon; ở đây giữ nguyên cách ghi LOIT của trang dữ liệu, không suy ra một CLI lịch sử chưa xác minh. Không nhầm công cụ của CICIDS2017 với CSE-CIC-IDS2018.

Các tham số bên dưới do tôi đề xuất cho lab, KHÔNG phải các lệnh nguyên bản năm 2017. Tài liệu đã đọc không cung cấp đủ phiên bản, wordlist, toàn bộ CLI và cấu hình server để tái lập từng packet. Đổi Hydra thành Patator không bảo đảm score tăng.

## 2. Hai mục tiêu kiểm thử phải tách biệt

1. Kiểm tra pipeline: đọc PCAP gốc hoặc PCAP lab bằng chính extractor 21 features và model hiện hành. Không phát packet trở lại mạng. Không đưa CSV CICFlowMeter nguyên bản vào model NFStream chỉ vì tên cột giống nhau.
2. Kiểm tra tổng quát hóa và bảo vệ live: sinh traffic mới, ghi PCAP, log công cụ và log server; đánh giá ML riêng, sau đó đánh giá nhánh hybrid/block riêng.

PCAP thuộc dữ liệu đã huấn luyện chỉ có giá trị regression, không phải test độc lập. Muốn báo cáo chất lượng trên corpus, giữ đúng tập holdout đã khóa và phép gán nhãn/split tương ứng. Không gán nhãn tấn công cho mọi packet trong một file theo ngày.

Lab đã kiểm tra: Kali `172.16.1.10` → Ubuntu `172.16.1.2`; quản trị `192.168.226.151`; NFStream nghe `ens33`. Port 80 redirect HTTPS, 443 là Nginx reverse proxy, 3001 đi thẳng Juice Shop HTTP. Đối chiếu cấu hình/log tại [báo cáo chẩn đoán](../experiments/20260909_live_score_diagnosis/diagnosis_report.md).

Lab DoS gốc dùng Apache trên Ubuntu 16.04, khác Nginx/Juice Shop hiện tại. Chạy HTTP 3001 giúp có ca plaintext để phân tích, nhưng vẫn không tái tạo Apache. HTTPS 443 là một ca kiểm thử khác; không gộp phân bố features hai đường đi. [Bài báo gốc](https://www.scitepress.org/PublishedPapers/2018/66398/pdf/index.html).

## 3. Chuẩn bị trên Kali

Chỉ sử dụng các IP lab đã nêu. Giữ một đường quản trị qua mạng 192.168.226.x; dừng test nếu mất quản trị, dịch vụ không hồi phục hoặc VM thiếu tài nguyên. Chạy từng ca riêng, không chạy cả tài liệu như một script.

```bash
# Nếu còn thiếu công cụ; đây là lệnh cài đề xuất, chưa được thực hiện.
sudo apt update
sudo apt install patator slowhttptest nmap curl git python3

TARGET=172.16.1.2
RUN=$(mktemp -d -p "$PWD" cicids17-test.XXXXXX)
printf '%s\n' "$RUN"
date -u --iso-8601=seconds
ip route get "$TARGET"
dpkg-query -W patator slowhttptest nmap curl > "$RUN/tool_versions.txt"

# Kiểm tra endpoint trước cửa sổ attack; không dùng -L để che redirect.
curl --max-time 5 -sS -o /dev/null -w 'HTTP80 %{http_code}\n' "http://$TARGET/"
curl --max-time 5 -sS -o /dev/null -w 'HTTP3001 %{http_code}\n' "http://$TARGET:3001/"
curl -k --max-time 5 -sS -o /dev/null -w 'HTTPS443 %{http_code}\n' "https://$TARGET/"
```

Cú pháp cài và module Patator: [Kali](https://www.kali.org/tools/patator/). Cờ SlowHTTPTest: [tài liệu tác giả](https://github.com/shekyan/slowhttptest/wiki/InstallationAndUsage).

Trước mỗi ca, tạo lại RUN bằng mktemp để không ghi đè kết quả. Ghi cùng một run_id ở Kali và Ubuntu, thời điểm bắt đầu/kết thúc UTC, lệnh đầy đủ, IP nguồn thực tế, endpoint, phiên bản công cụ và trạng thái firewall. Ghi cả exit code; timeout 124 có thể chỉ là kết thúc theo giới hạn thời gian, không tự chứng minh lỗi công cụ hay thành công tấn công.

## 4. Các lệnh ưu tiên

### A. Benign HTTP: đối chứng bắt buộc

```bash
for i in $(seq 1 60); do
  date -u --iso-8601=seconds
  curl --max-time 5 -sS -o /dev/null \
    -w 'code=%{http_code} seconds=%{time_total}\n' \
    "http://$TARGET:3001/rest/products/search?q=apple"
  sleep 1
done > "$RUN/benign_http.log" 2>&1
```

Đây chỉ là baseline HTTP đơn giản, không tái tạo toàn bộ B-Profile. Bổ sung duyệt web thật, đăng nhập FTP/SSH hợp lệ bằng tài khoản test, tải file lab nhỏ và một vài lần nhập sai mật khẩu đơn lẻ. Chạy riêng baseline trên HTTPS. Không mặc định tất cả lần đăng nhập sai đều là brute force.

### B. FTP-Patator và Hydra đối chứng

Dùng cùng hai wordlist lab cho cả hai công cụ. Khởi đầu tối đa khoảng 200 tổ hợp, chỉ chứa tài khoản/mật khẩu thử nghiệm; không dùng tài khoản quản trị. Không chia sẻ log chứa mật khẩu thật. Cú pháp FILE0/FILE1 theo [Patator Usage](https://github.com/lanjelot/patator/wiki/Usage).

```bash
timeout --signal=INT --kill-after=5s 120s \
  patator ftp_login host="$TARGET" port=21 \
  user=FILE0 password=FILE1 \
  0=bruteforce_usernames.txt 1=bruteforce_passwords.txt \
  --threads 4 --max-retries 0 > "$RUN/ftp_patator.log" 2>&1
```

Ca riêng để so với công cụ đang dùng:

```bash
timeout --signal=INT --kill-after=5s 120s \
  hydra -L bruteforce_usernames.txt -P bruteforce_passwords.txt \
  -t 4 -vV "ftp://$TARGET" > "$RUN/ftp_hydra.log" 2>&1
```

Không lọc bỏ phản hồi sai mật khẩu: cần giữ 530 và số lần thử thực tế. Connection refused, timeout và lỗi kết nối không được tính như đăng nhập đã thử. Giới hạn thời gian có thể khiến hai công cụ hoàn thành số tổ hợp khác nhau; báo cáo số thực tế, không chỉ số dòng wordlist.

### C. SSH-Patator, chỉ khi lab bật password authentication

```bash
timeout --signal=INT --kill-after=5s 120s \
  patator ssh_login host="$TARGET" port=22 \
  user=FILE0 password=FILE1 \
  0=bruteforce_usernames.txt 1=bruteforce_passwords.txt \
  --threads 2 --max-retries 0 > "$RUN/ssh_patator.log" 2>&1
```

Đối chiếu failed authentication trong journal/auth log. Không bật password authentication trên dịch vụ quản trị chỉ để hoàn thành ca này; nếu chưa có dịch vụ test phù hợp, đánh dấu chưa đủ điều kiện. Không coi lỗi thương lượng SSH là brute force hoàn chỉnh.

### D. SlowHTTPTest: tách slow headers và slow body

Ca slow headers:

```bash
slowhttptest -H -c 100 -r 10 -i 5 -l 120 \
  -t GET -u "http://$TARGET:3001/" -x 24 -p 3 \
  -g -o "$RUN/slow_headers" > "$RUN/slow_headers.log" 2>&1
```

Ca slow body, chạy riêng:

```bash
slowhttptest -B -c 100 -r 10 -i 5 -l 120 \
  -t POST -u "http://$TARGET:3001/rest/user/login" \
  -s 8192 -x 24 -p 3 \
  -g -o "$RUN/slow_body" > "$RUN/slow_body.log" 2>&1
```

`-H` gửi chậm header, `-B` gửi chậm body, `-l` giới hạn thời gian, `-p` là timeout của probe. Hai chế độ là ca lab đề xuất, không khẳng định cấu hình Slowhttptest lịch sử là `-B`. [SlowHTTPTest](https://github.com/shekyan/slowhttptest/wiki/InstallationAndUsage).

Endpoint POST có thể từ chối request theo parser/content type; kiểm tra số socket thật sự giữ mở và phản hồi server, không chỉ số `-c` yêu cầu. So sánh tiếp với URL `https://172.16.1.2/` trong ca riêng. Nếu công cụ lỗi TLS/chứng chỉ, ghi lỗi và dừng ca, không gán đó là model miss.

Giữ lệnh cũ vào port 80 làm đối chứng, thêm `-l 120 -g -o ...` để có giới hạn và bằng chứng. Sau vòng nhỏ, nếu VM ổn định và cần sweep tải, định trước các mức 100/300/1000 kết nối; không tăng tải hoặc sửa header TCP cho tới khi đạt một score mong muốn.

### E. Nmap: một biến thay đổi mỗi lần

Giữ sáu cổng hiện tại, đổi sang nhịp mặc định T3:

```bash
sudo nmap -n -Pn -sS -T3 \
  -p 22,80,443,3000,3001,8080 --reason \
  --host-timeout 180s -oA "$RUN/nmap_syn6" "$TARGET"
```

Ca riêng, cùng sáu cổng nhưng TCP connect:

```bash
nmap -n -Pn -sT -T3 \
  -p 22,80,443,3000,3001,8080 --reason \
  --host-timeout 180s -oA "$RUN/nmap_connect6" "$TARGET"
```

Ca riêng, mở rộng phạm vi cổng có giới hạn tốc độ:

```bash
sudo nmap -n -Pn -sS -T3 --max-rate 100 \
  -p 1-1024 --reason --host-timeout 180s \
  -oA "$RUN/nmap_syn1024" "$TARGET"
```

Lặp lại lệnh `-T1 --scan-delay 500ms` ban đầu trong ca khác và lưu `-oA`. Phân biệt open/closed/filtered, host-timeout và số cổng thực sự đã thử. Các chế độ dựa trên [Nmap scan techniques](https://nmap.org/book/man-port-scanning-techniques.html), giới hạn theo [Nmap timing](https://nmap.org/book/man-performance.html).

21 features hiện là thống kê từng flow, không có số cổng khác nhau trên một IP/cửa sổ. Vì thế tăng số cổng không bảo đảm từng flow có score cao; thử cả nhịp chậm để đo giới hạn này.

### F. HTTP flood bằng GoldenEye: ca bổ sung

```bash
git clone https://github.com/jseidl/GoldenEye.git "$RUN/GoldenEye"
git -C "$RUN/GoldenEye" rev-parse HEAD > "$RUN/goldeneye_commit.txt"

timeout --signal=INT --kill-after=5s 60s \
  python3 "$RUN/GoldenEye/goldeneye.py" "http://$TARGET:3001/" \
  -w 2 -s 10 -m get > "$RUN/goldeneye.log" 2>&1
```

Chỉ hai worker, mười socket/worker; đây không phải giới hạn request/giây. Cần quan sát tài nguyên và dừng sớm khi cần. Đây là DoS từ một nguồn, không phải phép thử DDoS phân tán. Cờ và script Python theo [repository tác giả](https://github.com/jseidl/GoldenEye).

HULK và DDoS gốc nên được kiểm tra trước bằng PCAP gốc; không đưa ra lệnh của một bản port bất kỳ rồi gọi đó là tái lập năm 2017. SlowHTTPTest `-H` đã cung cấp phép thử slow-headers; không cần thêm một bản Slowloris khác trong vòng chẩn đoán đầu tiên.

### G. Web Attack: chỉ smoke test traffic, chưa là benchmark đầy đủ

```bash
curl --max-time 5 --get --data-urlencode "q=' OR 1=1--" \
  -D "$RUN/web_probe.headers" -o "$RUN/web_probe.body" \
  "http://$TARGET:3001/rest/products/search"
```

Đây là request chứa mẫu SQLi để xác minh packet/log, không chứng minh khai thác thành công và không đủ để tính recall cả lớp Web Attack. Muốn ca tương ứng corpus: dựng DVWA riêng, xác minh endpoint/session/security level, dùng Selenium thực hiện web brute force/XSS và lưu bằng chứng trình duyệt. Không suy ra payload SQLi/XSS của DVWA tương đương Juice Shop.

Cảnh báo script hiện có `tests/scenarios/04_web_attack.sh`: những lệnh curl với `/#/search?...` không gửi phần fragment sau `#` tới server. Không dùng các dòng này làm bằng chứng đã truyền XSS qua mạng; curl cũng không thực thi JavaScript. Script còn chứa payload phá dữ liệu và thao tác reset/unblock, nên không chạy nguyên bộ cho đánh giá có kiểm soát. Quy tắc fragment: [RFC 3986, mục 3.5](https://www.rfc-editor.org/rfc/rfc3986#section-3.5).

## 5. Capture và bằng chứng trên Ubuntu

Mở terminal trên Ubuntu, chuẩn bị riêng từng ca. Biến OBS ở Ubuntu khác RUN ở Kali. Bắt capture trước khi chạy công cụ ít nhất 10 giây; chờ ít nhất 60 giây sau khi công cụ dừng, rồi Ctrl+C tcpdump. Có giới hạn 300 giây để tránh capture vô hạn; tăng giới hạn nếu ca được định trước dài hơn.

```bash
OBS=$(mktemp -d -p /home/dmtien cicids17-observe.XXXXXX)
START_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf '%s\n' "$START_UTC" > "$OBS/start_utc.txt"
sudo timeout --signal=INT --kill-after=5s 300s \
  tcpdump -i ens33 -nn -s 0 -U -w "$OBS/traffic.pcap" \
  'host 172.16.1.10 and host 172.16.1.2'

# Sau khi capture kết thúc, dùng lại đúng terminal/biến OBS.
END_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf '%s\n' "$END_UTC" > "$OBS/end_utc.txt"
sudo docker logs --timestamps --since "$START_UTC" --until "$END_UTC" \
  autodefense > "$OBS/autodefense.log" 2>&1
sudo docker logs --timestamps --since "$START_UTC" --until "$END_UTC" \
  reverse-proxy > "$OBS/nginx.log" 2>&1
sudo journalctl -u ssh --since "$START_UTC" --until "$END_UTC" \
  --no-pager > "$OBS/ssh.log"
```

Nếu IP nguồn thực tế không phải .10, sửa capture filter trước ca. Không capture trên `any` để rồi vô tình đếm trùng traffic qua interface/bridge. Với dịch vụ FTP, lưu auth log đúng daemon đang chạy; với Suricata, lưu đoạn EVE JSON tương ứng cửa sổ trên từ log hiện hành. Không chỉ lấy docker stdout vì EVE thường là file riêng. Lưu thống kê dropped packets của tcpdump.

Cần xem cả `docker stats`, tình trạng socket và probe HTTP trong cửa sổ test. Chạy probe từ máy quan sát khác sẽ dễ tách khỏi attack flows; nếu cùng Kali, gán nhãn riêng cho probe. HTTPS trên ens33 là traffic mã hóa; Suricata nghe bridge sau TLS termination có thể có plaintext nhưng là điểm quan sát khác, phải ghi rõ.

## 6. Chấm PCAP thụ động bằng runtime hiện hành

Ví dụ đề xuất trên Ubuntu sau capture, sử dụng đúng image của autodefense và mount source/model chỉ đọc. Container mới không có mạng, không chạy daemon/firewall. Chưa thực thi snippet này trong lượt nghiên cứu.

```bash
PROJ=/home/dmtien/IDPS
PCAP="$OBS/traffic.pcap"
IMAGE_ID=$(sudo docker inspect --format '{{.Image}}' autodefense)
test -f "$PCAP" && test -d "$PROJ/src" || exit 1
sudo docker run --rm -i --network none --cap-drop ALL \
  --read-only --tmpfs /tmp \
  -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONPATH=/app/src \
  -v "$PCAP:/input/test.pcap:ro" \
  -v "$PROJ/src:/app/src:ro" \
  -v "$PROJ/models:/app/models:ro" \
  -v "$PROJ/configs:/app/configs:ro" \
  --entrypoint python3 "$IMAGE_ID" - \
  > "$OBS/scores.jsonl" 2> "$OBS/scoring_stderr.log" <<'PY'
import json
from realtime_extractor import create_streamer, extract_features
from threat_evaluator import ThreatEvaluator

if __name__ == "__main__":
    evaluator = ThreatEvaluator("/app/models", "/app/configs")
    print(json.dumps({"kind": "metadata", **evaluator.get_model_info()}))
    for flow in create_streamer(interface="/input/test.pcap", n_meters=1):
        vector = extract_features(flow, feature_names=evaluator.feature_names)
        record = {
            "kind": "flow", "src_ip": flow.src_ip, "src_port": flow.src_port,
            "dst_ip": flow.dst_ip, "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "first_seen_ms": flow.bidirectional_first_seen_ms,
            "last_seen_ms": flow.bidirectional_last_seen_ms,
            "features": dict(zip(evaluator.feature_names, vector.tolist())),
            "ml": evaluator.evaluate(vector),
        }
        print(json.dumps(record), flush=True)
PY
```

Kiểm tra exit code và stderr trước khi dùng kết quả. Snippet trả điểm từng flow, không tự gán nhãn, không tự tính recall và không tái hiện quyết định hybrid. Lưu hash source/model/PCAP cùng kết quả. Nếu rootless Docker/quyền file không tương thích, sửa quyền truy cập file test cụ thể; không mở toàn bộ project cho mọi người.

Lưu ý quan trọng: chấm lại PCAP đã bị IPS chặn giữa chừng vẫn là chấm traffic bị cắt ngắn, không biến nó thành một thí nghiệm ML-only hoàn chỉnh. Muốn đo ML-only không bị ảnh hưởng cần capture trên lab quan sát thụ động riêng, hoặc triển khai chế độ monitor-only thực sự sau khi được duyệt. Runtime hiện chưa có công tắc monitor-only được xác minh. `SURICATA_ONLY_MODE` không thay thế chế độ đó; whitelist IP còn bỏ qua inference.

## 7. Cách đọc kết quả và thứ tự thực hiện

- Đầu tiên: benign → FTP Patator/Hydra → Nmap cùng sáu cổng → SlowHTTP H/B → GoldenEye → Web đầy đủ sau khi chuẩn bị target.
- Mỗi ca ít nhất ba lần, tách session; đảo thứ tự các ca sau vòng đầu để giảm ảnh hưởng warm-up. Chờ dịch vụ hồi phục và xác minh block TTL đã hết trước ca tiếp theo; không chỉ sleep rồi giả định đã sạch.
- Giữ nguyên model, 21 features và threshold trong cả vòng. Không hạ ngưỡng sau khi xem test. Dữ liệu dùng để sửa model/threshold trở thành development, cần một lượt test mới chưa đụng tới.
- Ghi số flow gán nhãn, binary score, multiclass probabilities, confidence ML, alert Suricata và quyết định block thành các mục riêng. Runtime dùng `max(binary_score, multi_score)` làm confidence; đây không mặc nhiên là xác suất đã hiệu chỉnh.
- Với attack flows đã xác minh: báo cáo tỷ lệ vượt ngưỡng alert và block của đúng phiên bản code, nhầm lớp, và ca bỏ sót. Code hiện dùng so sánh `>` tại các ngưỡng ML 0.60/0.85. Phân biệt recall per-flow với phát hiện ít nhất một flow trong một lượt tấn công.
- Với benign: đo false-positive rate và số IP bị chặn nhầm. Với DoS: đo thêm lỗi/độ trễ dịch vụ, số socket và CPU/RAM; score cao không chứng minh đã bảo vệ được ứng dụng.
- Độ trễ phát hiện đo từ packet tấn công đầu tiên tới alert/block thật, không dùng thời gian một lần predict thay thế. Flow timeout hiện là idle 10 giây, active 30 giây, cộng trễ hàng đợi/xử lý thực tế.
- Ground truth dựa trên packet và phản hồi server. Không tính health probe của SlowHTTPTest hoặc mọi flow từ IP attacker là malicious một cách tự động.

Nếu Patator vẫn thấp như Hydra nhưng PCAP được trích xuất đúng, đó là bằng chứng cần cải thiện tính tổng quát hóa của model. Chẩn đoán trước đã thấy mọi mẫu Brute Force development có TCP window 29200 trong khi FTP live quan sát có 64240; không được sửa window hoặc feature đầu vào để làm đẹp điểm. Bổ sung quy tắc hành vi và dữ liệu đa môi trường là hướng xử lý riêng, không phải thay đổi thầm trong benchmark.
