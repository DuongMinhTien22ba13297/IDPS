# CHƯƠNG 1: GIỚI THIỆU ĐỀ TÀI

---

# 1.1. Đặt vấn đề và Tính cấp thiết của đề tài

## 1.1.1. Sự thay đổi hệ hình (Paradigm Shift) trong bối cảnh an ninh mạng toàn cầu

Trong thập kỷ vừa qua, bối cảnh an ninh mạng toàn cầu đã trải qua một cuộc chuyển dịch hệ hình (paradigm shift) sâu sắc, từ mô hình phòng thủ phản ứng (reactive defense) sang yêu cầu bức thiết về phòng thủ chủ động (proactive defense). Sự chuyển dịch này không đến từ một sự kiện đơn lẻ, mà là hệ quả tất yếu của ba xu thế hội tụ đồng thời: sự bùng nổ lưu lượng mạng, sự tinh vi hóa của các vector tấn công, và sự trì trệ nội tại của các cơ chế phòng thủ truyền thống.

**Về mặt khối lượng**, lưu lượng mạng toàn cầu đã tăng theo cấp số nhân. Theo báo cáo *Cisco Annual Internet Report (2018–2023)* [1], tổng lưu lượng IP toàn cầu đã đạt **4.8 zettabyte mỗi năm** vào cuối năm 2022, với khoảng 29.3 tỷ thiết bị kết nối mạng. Mỗi giây, hàng trăm triệu gói tin (packet) đi qua các nút mạng doanh nghiệp, tạo ra một dòng chảy dữ liệu mà bất kỳ hệ thống phân tích thủ công nào cũng bất lực trong việc xử lý. Quan trọng hơn, lưu lượng mạng ngày nay không chỉ tăng về mặt khối lượng mà còn trở nên **dị biệt về mặt hành vi**: sự pha trộn giữa các luồng HTTP/HTTPS hợp lệ, lưu lượng IoT không đồng nhất, các kết nối API microservices, và lưu lượng mã hóa TLS 1.3 end-to-end tạo ra một bề mặt tấn công (attack surface) đa tầng mà việc phân tích nội dung (payload inspection) trở nên ngày càng kém hiệu quả.

**Về mặt tài chính**, thiệt hại do tội phạm mạng đã đạt mức **10.5 nghìn tỷ USD mỗi năm** vào năm 2025 theo ước tính của Cybersecurity Ventures [2] — biến nó thành nền kinh tế tội phạm có quy mô lớn thứ ba thế giới, chỉ sau GDP của Hoa Kỳ và Trung Quốc. Con số này không chỉ phản ánh giá trị tài sản bị đánh cắp trực tiếp, mà còn bao gồm chi phí khắc phục sự cố, mất uy tín thương hiệu, gián đoạn kinh doanh, rò rỉ dữ liệu cá nhân, và các khoản phạt vi phạm quy định bảo mật dữ liệu (GDPR, PDPA).

**Về mặt thời gian phản ứng**, dữ liệu từ báo cáo *IBM Cost of a Data Breach Report 2023* [3] cho thấy một con số đáng báo động: trung bình thời gian để phát hiện và ngăn chặn một vụ xâm nhập dữ liệu (data breach) là **277 ngày** — trong đó 204 ngày để phát hiện và 73 ngày để kiểm soát thiệt hại. Khoảng thời gian "cửa sổ tấn công" kéo dài này cho phép kẻ tấn công thực hiện các hoạt động di chuyển ngang (lateral movement), leo thang đặc quyền (privilege escalation), và trích xuất dữ liệu nhạy cảm (data exfiltration) mà hoàn toàn không bị phát hiện bởi các hệ thống phòng thủ truyền thống.

**Tại Việt Nam**, theo báo cáo của Cục An toàn thông tin (Bộ Thông tin và Truyền thông), năm 2023 ghi nhận hơn **13,900 cuộc tấn công mạng** nhằm vào các hệ thống thông tin tại Việt Nam [4], trong đó có hàng trăm nghìn địa chỉ IP bị ảnh hưởng. Đặc biệt, các cuộc tấn công bằng mã độc tống tiền (ransomware) tăng hơn **300%** so với năm trước, và phần lớn các tổ chức vừa và nhỏ vẫn chưa có hệ thống phòng thủ tự động, chủ yếu dựa vào các công cụ bảo mật cơ bản hoặc kinh nghiệm chủ quan của quản trị viên.

## 1.1.2. Điểm yếu cố hữu của Hệ thống Phát hiện Xâm nhập dựa trên Chữ ký (Signature-based NIDS)

Trong kiến trúc phòng thủ mạng nhiều lớp (defense-in-depth), Hệ thống Phát hiện Xâm nhập Mạng (Network Intrusion Detection System — NIDS) đóng vai trò như tuyến phòng vệ đầu tiên và cũng là quan trọng nhất. Hai đại diện tiêu biểu — **Snort** (do Martin Roesch phát triển từ năm 1998 [5]) và **Suricata** (do Open Information Security Foundation phát hành từ năm 2009 [6]) — đã được triển khai rộng rãi trên toàn thế giới nhờ khả năng so khớp chữ ký (signature matching) mạnh mẽ và hệ sinh thái quy tắc phong phú. Tuy nhiên, chính từ đặc điểm thiết kế cốt lõi dựa trên so khớp chữ ký mà các hệ thống này đã bộc lộ **bốn điểm yếu nội tại** (intrinsic limitations) không thể khắc phục hoàn toàn bằng cách mở rộng tập quy tắc.

### Điểm yếu thứ nhất: Sự phụ thuộc tuyệt đối vào cơ chế so khớp chữ ký (Signature-based Detection)

Nguyên lý hoạt động cốt lõi của Snort và Suricata là so khớp tuần tự (pattern matching) tải trọng (payload) của từng gói tin với hàng chục nghìn quy tắc (rules) trong cơ sở dữ liệu chữ ký. Về mặt lý thuyết hình thức (formal theory), phương pháp này tương đương với việc kiểm tra tư cách thành viên của một chuỗi ký tự trong một ngôn ngữ chính quy (regular language) được định nghĩa bởi tập hợp các biểu thức chính quy trong rule set — tức là, hệ thống chỉ có thể nhận diện những gì nó **đã biết trước** [7].

Hệ quả trực tiếp là: khi một lỗ hổng mới (zero-day vulnerability) được phát hiện và bị khai thác, quy trình phản ứng truyền thống diễn ra theo chuỗi tuần tự:

```
Phát hiện lỗ hổng → Phân tích mẫu tấn công → Viết rule mới → Kiểm thử 
→ Phát hành bản cập nhật → Quản trị viên tải về và áp dụng
```

Toàn bộ chuỗi này có thể kéo dài từ **vài giờ đến vài ngày**, tạo ra một "cửa sổ lỗ hổng" (vulnerability window) trong suốt thời gian đó hệ thống hoàn toàn **mù lòa** trước cuộc tấn công mới. Nghiên cứu của Bilge & Dumitras tại *ACM CCS 2012* [8] chỉ ra rằng trung bình một lỗ hổng zero-day tồn tại **312 ngày** trước khi được công bố công khai, và khoảng thời gian từ khi lỗ hổng bị khai thác "trong tự nhiên" (in the wild) đến khi có bản vá (patch) trung bình là **30 ngày**. Trong khoảng trống thời gian này, mọi hệ thống NIDS dựa trên chữ ký đều hoàn toàn vô hiệu.

### Điểm yếu thứ hai: Sự bất lực trước các kỹ thuật trốn tránh (Evasion Techniques)

Kẻ tấn công hiện đại không còn sử dụng các payload thô sơ dễ bị nhận diện. Theo phân loại của Ptacek & Newsham trong nghiên cứu kinh điển *"Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection"* [9], có bốn nhóm kỹ thuật trốn tránh chính:

1. **Phân mảnh gói tin (IP Fragmentation):** Chia nhỏ payload tấn công thành nhiều fragment nhỏ hơn MTU, mỗi fragment riêng lẻ không chứa đủ chuỗi đặc trưng để kích hoạt rule. Khi đích tái lắp ráp (reassemble), payload hoàn chỉnh mới mang tính nguy hại.
2. **Chồng chéo phân đoạn TCP (TCP Segmentation Overlap):** Gửi các TCP segment chồng lấn nhau với nội dung khác nhau; hệ thống IDS và hệ thống đích có thể chọn phiên bản khác nhau khi reassemble, dẫn đến IDS "nhìn" một nội dung khác với nội dung thực tế mà server nhận được.
3. **Mã hóa payload (Payload Encoding):** Sử dụng Base64, URL encoding, Unicode normalization, hoặc mã hóa đa tầng (multi-layer encoding) để biến đổi cấu trúc cú pháp của payload mà không thay đổi ngữ nghĩa tấn công.
4. **Tấn công "Low and Slow":** Giảm tốc độ tấn công xuống dưới ngưỡng phát hiện thống kê bất thường — ví dụ, thực hiện brute force SSH với chỉ 1 lần thử mỗi 30 giây thay vì hàng trăm lần mỗi giây.

Một cuộc tấn công SQL Injection qua HTTP POST với payload được mã hóa Base64, chèn xen kẽ các ký tự Unicode vô nghĩa, và phân mảnh qua nhiều gói tin TCP sẽ hoàn toàn hợp lệ với một IDS dựa trên so khớp chữ ký đơn thuần, vì bản thân payload ở tầng gói tin không chứa bất kỳ chuỗi đặc trưng nào (như `' OR 1=1 --`) để so khớp.

### Điểm yếu thứ ba: Suricata không được thiết kế làm công cụ đo lường thống kê luồng mạng (Flow Meter)

Đây là một phát hiện quan trọng trong quá trình nghiên cứu sâu của đề tài, và cũng là điểm mà nhiều nghiên cứu liên quan đã bỏ qua hoặc không giải quyết triệt để.

Phân tích chi tiết đầu ra EVE JSON (Extensible Event Format) của Suricata cho thấy nó chỉ cung cấp khoảng **6 đến 8 đặc trưng mạng cơ bản**: địa chỉ IP nguồn/đích (`src_ip`, `dest_ip`), cổng nguồn/đích (`src_port`, `dest_port`), giao thức (`proto`), tổng byte gửi/nhận (`bytes_toserver`, `bytes_toclient`), thời gian bắt đầu/kết thúc flow, và danh sách alert. Theo nghiên cứu của Sharafaldin *et al.* tại CIC (Canadian Institute for Cybersecurity) [10], một mô hình phát hiện xâm nhập dựa trên học máy hiệu quả cần tối thiểu **28-30 đặc trưng thống kê bậc cao** (higher-order statistical features) phản ánh bản chất toán học của luồng mạng, bao gồm:

- **Đặc trưng thời gian liên gói (Inter-Arrival Time — IAT):** Mean, standard deviation, min, max của khoảng thời gian giữa các gói tin liên tiếp theo cả hai chiều (forward/backward).
- **Đặc trưng kích thước gói tin (Packet Length Statistics):** Mean, standard deviation, min, max của kích thước gói tin theo từng chiều.
- **Đặc trưng tốc độ (Rate Features):** Flow Bytes/s, Flow Packets/s, Fwd Packets/s.
- **Đặc trưng cờ TCP (TCP Flag Features):** SYN, FIN, RST, PSH, ACK flag count.
- **Đặc trưng cửa sổ TCP (TCP Window Features):** Initial Window Size forward/backward.

Bản chất thiết kế của Suricata là một **Deep Packet Inspection (DPI) engine** tối ưu cho việc so khớp payload ở tầng ứng dụng (L7), không phải một **flow meter** tối ưu cho việc tính toán thống kê trên trường thời gian của luồng. Mỗi công cụ có mục tiêu kiến trúc riêng biệt, và việc ép buộc một công cụ đảm nhiệm cả hai vai trò đồng thời sẽ tạo ra một giải pháp nửa vời ở cả hai mặt.

### Điểm yếu thứ tư: Mô hình phản ứng "Phát hiện rồi Cảnh báo" (Detect-then-Alert) và sự phụ thuộc vào con người

Các hệ thống NIDS truyền thống hoạt động theo nguyên lý **"phát hiện rồi cảnh báo"** (detect-then-alert): hệ thống có thể phát hiện một cuộc tấn công và phát ra cảnh báo (alert), nhưng bản thân công cụ không tự thực thi hành động ngăn chặn (prevention). Quy trình phản ứng truyền thống đòi hỏi sự can thiệp của con người (human-in-the-loop):

```
Hệ thống phát cảnh báo → Quản trị viên đọc log → Xác nhận tình huống 
→ Thảo luận quyết định → Cập nhật tường lửa thủ công
```

Theo nghiên cứu của Alahmadi *et al.* (2020) [11], thời gian phản ứng trung bình của quy trình thủ công này có thể kéo dài từ **15 phút đến vài giờ**, tùy thuộc vào quy mô tổ chức và tính sẵn sàng của đội ngũ SOC (Security Operations Center). Trong bối cảnh một cuộc tấn công DDoS SYN Flood với tốc độ hàng chục nghìn gói tin mỗi giây, hoặc một cuộc tấn công brute force SSH với hàng triệu lần thử đăng nhập, sự chậm trễ này tạo ra một **nút thắt cổ chai vận hành** (operational bottleneck) cho phép kẻ tấn công gây thiệt hại đáng kể trong khoảng thời gian chờ đợi phản ứng.

## 1.1.3. Phát hiện xâm nhập dựa trên Bất thường (Anomaly-based Detection) và vai trò của Học máy

Trước những hạn chế cố hữu của phương pháp dựa trên chữ ký, cộng đồng nghiên cứu an ninh mạng đã chuyển hướng sang cách tiếp cận **phát hiện dựa trên sự bất thường hành vi (Anomaly-based Detection)**. Sự thay đổi này phản ánh một chuyển dịch triết học quan trọng: thay vì hỏi *"gói tin này có chứa mẫu tấn công đã biết hay không?"* (câu hỏi của signature-based), hệ thống anomaly-based hỏi *"luồng mạng này có hành vi thống kê giống như những luồng tấn công đã học hay không?"*. Phương pháp này có tiềm năng phát hiện các cuộc tấn công chưa từng được biết đến (unknown attacks) vì nó dựa trên **mô hình hành vi** thay vì **mẫu cú pháp**.

Tuy nhiên, các hệ thống anomaly-based truyền thống (trước kỷ nguyên ML) cũng gặp một vấn đề nghiêm trọng: **tỷ lệ báo động giả cao (high False Positive Rate — FPR)**. Hệ thống cần xây dựng một đường cơ sở hành vi "bình thường" (behavioral baseline) từ một lượng lớn dữ liệu lịch sử, và bất kỳ sự sai lệch nào khỏi đường cơ sở này đều bị coi là bất thường. Trong thực tế, hành vi người dùng hợp lệ thường xuyên thay đổi (thói quen làm việc mới, ứng dụng mới, lưu lượng tải đợt cuối tháng), dẫn đến hai rủi ro đối lập:

- **Hệ thống quá nhạy** → Phát sinh quá nhiều cảnh báo giả → "Alert fatigue" (mệt mỏi cảnh báo) → Đội ngũ SOC bỏ sót cảnh báo thực sự.
- **Hệ thống quá bảo thủ** → Giảm FPR nhưng tăng False Negative Rate (FNR) → Bỏ lọt tấn công.

**Công nghệ học máy (Machine Learning)** mang đến giải pháp tối ưu cho bài toán cân bằng FPR-FNR này. Các thuật toán học máy có khả năng học các ranh giới quyết định (decision boundaries) phức tạp, phi tuyến tính trong không gian đặc trưng đa chiều, phân biệt được giữa hành vi bình thường và hành vi tấn công ngay cả khi không có chữ ký cụ thể. Đặc biệt, các thuật toán **ensemble learning** dựa trên cây quyết định tăng cường (gradient boosting decision trees) như XGBoost [12], LightGBM [13], và CatBoost đã chứng minh hiệu quả vượt trội trên các tập dữ liệu mạng chuẩn (benchmark datasets).

Nghiên cứu hệ thống của Ferrag *et al.* (2020) [14] — một bài khảo sát toàn diện về ứng dụng học sâu trong phát hiện xâm nhập — đã phân tích hơn 100 công trình và kết luận rằng **các mô hình ensemble tree-based** (Random Forest, XGBoost, LightGBM) thường đạt hiệu suất tương đương hoặc vượt trội so với các mô hình học sâu (CNN, LSTM, Autoencoder) trên dữ liệu dạng bảng (tabular data) như network flow statistics, đồng thời có ưu thế lớn về **tốc độ suy luận** (inference speed) và **hiệu quả bộ nhớ** (memory footprint) — hai yếu tố sống còn cho hệ thống thời gian thực.

## 1.1.4. Triết lý Zero-touch Network Security: Đóng vòng lặp phòng thủ tự động

Một trong những xu hướng chiến lược quan trọng nhất trong lĩnh vực an ninh mạng hiện đại là **Zero-touch Network Security** — triết lý phòng thủ mạng hoàn toàn tự động, trong đó hệ thống có khả năng tự nhận thức (self-aware), tự quyết định (self-deciding), và tự thực thi (self-executing) mà không đòi hỏi sự can thiệp thủ công của con người trong vòng lặp phản ứng sự cố (incident response loop).

Khái niệm này bắt nguồn từ lý thuyết điều khiển học (control theory), cụ thể là nguyên lý **vòng lặp khép kín (closed-loop control)** [15]:

```
Sense → Analyze → Decide → Act → Monitor → Sense → ...
```

Trong ngữ cảnh an ninh mạng, vòng lặp khép kín được hiện thực hóa như sau:
- **Sense:** Thu thập lưu lượng mạng thô từ card mạng vật lý (raw packet capture).
- **Analyze:** Trích xuất vector đặc trưng thống kê từ luồng mạng (feature extraction).
- **Decide:** Suy luận qua mô hình ML để phân loại và tính toán độ tin cậy (ML inference).
- **Act:** Tự động thực thi hành động ngăn chặn ở tầng nhân hệ điều hành (kernel-level firewall update).
- **Monitor:** Ghi nhận kết quả, cập nhật trạng thái, và phản hồi vào hệ thống giám sát (logging & dashboard).

Theo báo cáo *Gartner Top Strategic Technology Trends 2024* [16], tự động hóa an ninh mạng (security automation and orchestration) được xếp vào nhóm ưu tiên cao nhất, với dự báo rằng đến năm 2027, hơn **75% tổ chức** sẽ tái cấu trúc SOC của mình để tích hợp các quy trình phản ứng tự động. Lý do rất rõ ràng: với hàng tỷ sự kiện bảo mật (security events) xảy ra mỗi ngày trên một hệ thống mạng doanh nghiệp trung bình, việc phụ thuộc vào con người để phân loại, phân tích và phản ứng là **không thể mở rộng** (unscalable) và **không bền vững** (unsustainable).

Giao thoa giữa học máy và tự động hóa Zero-touch tạo ra một lớp phòng thủ có khả năng hoạt động **với tốc độ của máy móc nhưng vẫn đảm bảo độ chính xác của trí tuệ**. Đây chính là nền tảng triết học cho hệ thống IDPS được phát triển trong đề tài này.

## 1.1.5. Tổng hợp: Khoảng trống nghiên cứu và Giá trị cốt lõi của đề tài

Tổng hợp bốn điểm yếu đã phân tích ở trên, có thể xác định rõ ràng **khoảng trống nghiên cứu** (research gap) mà đề tài nhắm đến:

| Vấn đề của giải pháp hiện hành | Giải pháp đề xuất trong đề tài |
|:---|:---|
| Phụ thuộc chữ ký → Mù lòa trước Zero-day | Bổ sung lớp ML phát hiện bất thường hành vi (anomaly-based detection) |
| Chỉ cung cấp 6-8 đặc trưng cơ bản → Không đủ cho ML | Sử dụng NFStream làm flow meter chuyên dụng, trích xuất 30 đặc trưng thống kê bậc cao |
| Mô hình "Detect-then-Alert" → Phụ thuộc con người | Hiện thực hóa vòng lặp khép kín Zero-touch: ML inference → auto iptables DROP |
| Thiếu kiến trúc cô lập an toàn → Rủi ro bảo mật cho chính hệ thống phòng thủ | Containerization bằng Docker: mỗi thành phần chạy trong container riêng biệt |

Điểm khác biệt cốt lõi của đề tài nằm ở việc **nhận ra và giải quyết triệt để bài toán "đặc trưng mạng"** mà phần lớn các nghiên cứu NIDS dựa trên ML thường bỏ qua. Thay vì cố gắng ép buộc Suricata — một công cụ DPI — đồng thời đóng vai trò flow meter (một bài toán vi phạm nguyên tắc *Single Responsibility Principle*), đề tài đề xuất **kiến trúc kết hợp hai tầng**:

- **Tầng 1 (Suricata):** Hoạt động như cảm biến DPI tiền phương, phát hiện tấn công đã biết thông qua so khớp chữ ký L7, đặc biệt hiệu quả với các custom rules nhắm đến lưu lượng plaintext (SQL Injection, XSS qua HTTP).
- **Tầng 2 (NFStream + XGBoost):** Hoạt động như lớp phát hiện bất thường hành vi, trích xuất 30 đặc trưng thống kê bậc cao và sử dụng mô hình XGBoost để phân loại luồng — có khả năng phát hiện các tấn công mà Suricata bỏ sót (DoS/DDoS pattern, PortScan thầm lặng, Botnet C&C communication).

Hai tầng này được **hợp nhất thông qua Correlation Engine** — một module fusion kết hợp kết quả từ cả Suricata alerts và ML predictions để đưa ra quyết định cuối cùng với độ tin cậy tổng hợp (fused confidence score). Kiến trúc này tạo ra một hệ thống phòng thủ có chiều sâu thực sự: phát hiện được cả tấn công đã biết lẫn tấn công chưa biết, đồng thời tự động phản ứng với tốc độ ở cấp mili-giây.

---

# 1.2. Mục tiêu Nghiên cứu và Phát triển

## 1.2.1. Mục tiêu tổng quát

Thiết kế, hiện thực hóa và đánh giá một **Hệ thống Phát hiện và Ngăn chặn Xâm nhập Mạng (Intrusion Detection and Prevention System — IDPS)** tự động hoàn toàn (Zero-touch), sử dụng kỹ thuật học máy để nhận diện hành vi bất thường trên lưu lượng mạng thời gian thực. Hệ thống phải đáp ứng đồng thời ba tiêu chí kỹ thuật cốt lõi:

1. **Độ chính xác cao:** Tỷ lệ phát hiện (Detection Rate / Recall) ≥ 99%, kết hợp với tỷ lệ báo động giả (False Positive Rate) ≤ 0.2%, đảm bảo hệ thống không chặn nhầm lưu lượng hợp lệ.
2. **Độ trễ siêu thấp:** Toàn bộ vòng lặp phản ứng từ thời điểm bắt gói tin (T₀) đến thời điểm nhân Linux xác nhận lệnh DROP (T₁) phải hoàn thành **dưới 100 mili-giây (100ms)**.
3. **Khả năng triển khai linh hoạt:** Toàn bộ hệ thống được đóng gói dưới dạng container Docker, cho phép triển khai nhanh chóng trên bất kỳ máy chủ Linux nào.

## 1.2.2. Các mục tiêu kỹ thuật cụ thể

Để đạt được hệ thống vĩ mô trên, dự án phân rã thành **bốn mục tiêu kỹ thuật cốt lõi**, mỗi mục tiêu tương ứng với một module trong kiến trúc tổng thể:

### Mục tiêu 1: Phát triển mô hình phân loại tấn công mạng có độ chính xác cao

Xây dựng pipeline xử lý dữ liệu hoàn chỉnh và huấn luyện hai mô hình XGBoost chuyên biệt trên tập dữ liệu chuẩn **CIC-IDS-2017** [10]:

- **Active Model (Binary Classification):** Trả lời nhanh câu hỏi nhị phân *"Luồng này có phải tấn công hay không?"* — tối ưu cho tốc độ suy luận. XGBoost binary sử dụng thuật toán `tree_method='hist'` (histogram-based gradient boosting), cho phép suy luận cực nhanh với **inference latency chỉ 0.73 µs/packet** — nhanh hơn 4x so với Random Forest (3.02 µs/packet) và 2x so với LightGBM (1.50 µs/packet) theo kết quả benchmark trên tập test 503,073 mẫu.

- **Classification Model (Multi-class Classification):** Định danh cụ thể loại tấn công thuộc 7 danh mục: BENIGN, DoS/DDoS, Brute Force, Web Attack, PortScan, Botnet, Exploitation/Rare.

Pipeline xử lý dữ liệu phải giải quyết bài toán **mất cân bằng dữ liệu nghiêm trọng** (severe class imbalance): phân tích phân bố nhãn trên tập test cho thấy lớp BENIGN chiếm **83.08%**, trong khi các lớp tấn công hiếm gặp như Web Attack chỉ chiếm **0.09%** (428 mẫu) và Exploitation/Rare chỉ vỏn vẹn **0.00%** (9 mẫu). Kỹ thuật **SMOTE (Synthetic Minority Over-sampling Technique)** [17] được áp dụng để tạo mẫu tổng hợp cho các lớp thiểu số, tăng tập train từ 2,012,289 mẫu lên 2,107,968 mẫu.

Tiêu chí thành công: Recall ≥ 99.9%, FPR ≤ 0.15%, F1-Score ≥ 0.995 trên tập test 20%.

### Mục tiêu 2: Xây dựng kiến trúc trích xuất đặc trưng mạng chuyên sâu thời gian thực

Thiết kế module trích xuất đặc trưng (feature extraction) sử dụng thư viện **NFStream** [18] — một framework Python/C hiệu suất cao cho phân tích luồng mạng thời gian thực — để sinh ra **vector 30 đặc trưng thống kê** tương thích hoàn toàn với không gian đặc trưng đã dùng khi huấn luyện trên CIC-IDS-2017.

NFStream được lựa chọn thay vì CICFlowMeter (công cụ gốc của Canadian Institute for Cybersecurity) vì các lý do kỹ thuật:
- **Backend C tốc độ cao:** NFStream sử dụng nDPI và libpcap ở tầng dưới, tối ưu cho live traffic capture với overhead tối thiểu.
- **Plugin architecture mở rộng:** Cho phép viết **NFPlugin tùy chỉnh bằng Python** để trích xuất đặc trưng nâng cao mà phiên bản mặc định không cung cấp. Cụ thể, đề tài tự thiết kế **TCPWindowPlugin** để trích xuất Init_Win_bytes_forward/backward (kích thước cửa sổ TCP ban đầu) và **ConnectionRatePlugin** để tính tốc độ kết nối theo cổng đích — những đặc trưng nhạy cảm nhất để phân biệt giữa hành vi duyệt web bình thường với PortScan (Nmap SYN scan) hay DDoS.
- **Hỗ trợ native 48 đặc trưng thống kê bậc cao** thông qua tham số `statistical_analysis=True`, bao gồm mean, std, min, max của IAT và packet length theo cả hai chiều.

### Mục tiêu 3: Hiện thực hóa cơ chế phòng vệ chủ động Zero-touch với độ trễ siêu thấp

Thiết lập logic tự động cập nhật quy tắc tường lửa **iptables** của nhân Linux ngay khi mô hình học máy đưa ra dự đoán có dấu hiệu tấn công với độ tin cậy (fused confidence score) vượt ngưỡng. Triết lý Zero-touch được hiện thực hóa thông qua hệ thống ra quyết định tự động hoạt động theo nguyên tắc **ngưỡng hành động có trọng số (Weighted Action Threshold)** với ba tầng:

| Tầng | Ngưỡng Confidence | Hành động |
|:---|:---|:---|
| **Monitor** | < 0.60 | Ghi log, phân loại BENIGN, không hành động |
| **Alert** | 0.60 – 0.85 | Đánh dấu SUSPICIOUS, ghi log chi tiết, chưa chặn |
| **Auto-Block** | > 0.85 | Tự động chèn rule `iptables -I INPUT -s {IP} -j DROP` ở tầng nhân |

Điểm ngưỡng auto-block **0.85** (85% confidence) là kết quả của quá trình phân tích **đường cong đánh đổi Detection Rate — FPR** (trade-off curve): với ngưỡng mặc định 0.5, mô hình có thể chặn nhầm người dùng hợp pháp với xác suất quá cao; với ngưỡng 0.85, FPR giảm xuống mức cực thấp **0.106%** (443/417,947 benign bị báo nhầm) trong khi Detection Rate vẫn đạt **99.94%** (85,074/85,126 tấn công phát hiện được).

Lệnh `iptables -I INPUT` (insert, không phải append) đảm bảo rule mới được chèn lên **đỉnh bảng INPUT**, bóp nghẹt luồng tấn công **ngay tức khắc từ tầng kernel**, trước khi bất kỳ dịch vụ ứng dụng nào (Nginx, SSH, Database) trên máy chủ nhận được gói tin.

### Mục tiêu 4: Đóng gói hệ thống dưới dạng vi dịch vụ (Containerization) và giám sát toàn diện

Hiện đại hóa quy trình triển khai bằng cách đóng gói toàn bộ hệ thống thành **6 vi dịch vụ (microservices)** chạy song song thông qua Docker Compose, đảm bảo tính cô lập tài nguyên, bảo mật cho chính hệ thống phòng thủ, và khả năng mở rộng nhanh chóng:

| Container | Vai trò | Network Mode | Lý do |
|:---|:---|:---|:---|
| **suricata** | Cảm biến DPI L7, so khớp chữ ký | host | Cần truy cập raw socket trên card mạng vật lý |
| **autodefense** | Core daemon: NFStream + XGBoost + iptables | host | Cần truy cập card mạng và quyền NET_ADMIN cho iptables |
| **nginx** | Reverse proxy, điều phối HTTP/HTTPS | bridge (idps_net) | Tiếp nhận traffic HTTP/S và chuyển tiếp đến backend |
| **juice-shop** | Web app mục tiêu (OWASP Juice Shop) | bridge (idps_net) | Ứng dụng web giả lập để kiểm thử tấn công |
| **loki** | Lưu trữ log tốc độ cao (Grafana Loki) | bridge | Giao tiếp nội bộ với autodefense qua logging-loki API |
| **grafana** | Dashboard giám sát trực quan | bridge | Hiển thị Live Attack Map, Flow Rate, Top Attacker IPs |

Kiến trúc mạng được thiết kế có chủ đích: Suricata và autodefense chạy ở **host network** vì cần "nhìn thấy" toàn bộ traffic thực; các container còn lại sử dụng **bridge network** riêng biệt (`br-idps`) để cách ly khỏi mạng bên ngoài, giảm thiểu bề mặt tấn công nếu bất kỳ container nào bị khai thác.

---

# 1.3. Phạm vi và Giới hạn của Đề tài

## 1.3.1. Giới hạn về môi trường triển khai

Hệ thống được phát triển và thử nghiệm trên môi trường máy ảo **Ubuntu Server 22.04 LTS** (kernel 5.15+), giám sát giao diện mạng `ens33` và các giao thức ở **tầng giao vận** (Transport Layer — TCP/UDP) và **tầng mạng** (Network Layer — IP/ICMP). Môi trường lab mô phỏng một máy chủ web tiêu chuẩn với các dịch vụ SSH, HTTP/HTTPS, cho phép kiểm thử phản ứng Zero-touch trước các công cụ tấn công phổ biến (Nmap, Hydra, hping3, LOIC).

Việc triển khai trên môi trường production thực tế (cloud infrastructure, hybrid multi-cloud, multi-interface load balancing) nằm ngoài phạm vi hiện tại và sẽ đòi hỏi nghiên cứu bổ sung về cấu hình tài nguyên, high availability (HA), và horizontal scaling.

## 1.3.2. Giới hạn về thuật toán Học máy

Đề tài sử dụng thuật toán **XGBoost** (eXtreme Gradient Boosting) [12] thuộc nhóm **Học máy truyền thống** (Traditional/Classical ML), không triển khai các mô hình **Học sâu** (Deep Learning) như CNN, RNN, LSTM, GCN. Lựa chọn này được bảo vệ dựa trên ba yếu tố thực tiễn:

1. **Tốc độ suy luận (Inference Speed):** XGBoost sử dụng thuật toán `tree_method='hist'` (histogram-based splitting) cho phép suy luận cực nhanh — **0.73 µs/packet**, thấp hơn nhiều bậc so với yêu cầu latency budget 100ms của hệ thống thời gian thực. Các mô hình Deep Learning (CNN, LSTM) thường có inference latency ở mức mili-giây đến chục mili-giây, tiêu tốn phần lớn latency budget.

2. **Hiệu quả bộ nhớ (Memory Footprint):** File mô hình XGBoost binary chỉ **0.61 MB** (`active_model.pkl`) và multiclass chỉ **2.64 MB** (`classification_model.pkl`), phù hợp để chạy trong container Docker với tài nguyên hạn chế. So sánh: mô hình Random Forest tương đương có kích thước **90 MB** (file `best_eval_randomforest.pkl` = 90.2 MB) — lớn gấp 148 lần.

3. **Hiệu suất trên dữ liệu dạng bảng (Tabular Data):** Theo khảo sát hệ thống của Grinsztajn *et al.* (NeurIPS 2022) [19] — *"Why do tree-based models still outperform deep learning on tabular data?"* — các mô hình tree-based vẫn đạt hiệu suất vượt trội so với deep learning trên dữ liệu dạng bảng (tabular data) như network flow statistics. XGBoost đặc biệt hiệu quả vì tự động xử lý được missing values, non-linear interactions, và không yêu cầu feature scaling phức tạp.

## 1.3.3. Giới hạn về phạm vi nhận diện tấn công

Khả năng phân loại của mô hình bị giới hạn bởi **không gian mẫu (sample space)** của tập dữ liệu huấn luyện **CIC-IDS-2017** [10]. Hệ thống có khả năng nhận diện 6 danh mục tấn công chính (được gộp từ 15 nhãn gốc theo tính tương đồng phương thức):

| Danh mục gộp | Nhãn gốc CIC-IDS-2017 | Số mẫu test |
|:---|:---|:---|
| DoS/DDoS | DoS Hulk, DDoS, DoS GoldenEye, DoS Slowloris, DoS Slowhttptest | 64,330 |
| PortScan | PortScan | 18,139 |
| Brute Force | FTP-Patator, SSH-Patator | 1,830 |
| Web Attack | Web Attack – Brute Force, XSS, SQL Injection | 428 |
| Botnet | Bot | 390 |
| Exploitation/Rare | Infiltration, Heartbleed | 9 |

**Hạn chế quan trọng:** Các vector tấn công hoàn toàn mới, chưa từng xuất hiện trong tập huấn luyện (true zero-day attacks sử dụng kỹ thuật chưa biết) vẫn nằm ngoài khả năng nhận diện trực tiếp của mô hình ML. Lớp Exploitation/Rare chỉ có **38 mẫu train** và **9 mẫu test** — quá ít để đánh giá hiệu suất đáng tin cậy theo tiêu chuẩn thống kê. Đề tài bù đắp hạn chế này bằng cách kết hợp Suricata custom rules cho các tấn công L7 hiếm gặp thông qua **Correlation Engine** (module `suricata_correlator.py`).

## 1.3.4. Giới hạn về kiến trúc triển khai

Đề tài tập trung vào **kiến trúc đơn nút (single-node architecture)** với 6 container chạy trên cùng một máy chủ. Mô hình triển khai phân tán đa nút (multi-node federated deployment) phục vụ hệ thống doanh nghiệp quy mô lớn với nhiều chi nhánh sẽ được đề cập như hướng phát triển tương lai.

Ngoài ra, sự phổ biến ngày càng tăng của mã hóa lưu lượng end-to-end (**TLS 1.3**, QUIC) làm giảm đáng kể khả năng trích xuất ngữ nghĩa (semantic inspection) ở tầng payload — cả Suricata lẫn NFStream đều chỉ có thể phân tích được **metadata** của kết nối mã hóa (IP, port, certificate fingerprint, JA3 hash) mà không thể giải mã nội dung. Đây là hạn chế chung của tất cả các hệ thống IDS/NIDS thụ động (passive monitoring), và việc triển khai TLS inspection proxy nằm ngoài phạm vi của đề tài hiện tại.

---

## Tài liệu tham khảo

[1] Cisco Systems, *"Cisco Annual Internet Report (2018–2023) White Paper,"* Cisco, 2020. [Online]. Available: https://www.cisco.com/c/en/us/solutions/collateral/executive-perspectives/annual-internet-report/white-paper-c11-741490.html

[2] S. Morgan, *"2025 Cybercrime Report,"* Cybersecurity Ventures, 2024.

[3] IBM Security, *"Cost of a Data Breach Report 2023,"* IBM Corporation, 2023.

[4] Cục An toàn thông tin (AIS), Bộ Thông tin và Truyền thông, *"Báo cáo tình hình an toàn thông tin mạng Việt Nam năm 2023,"* 2024.

[5] M. Roesch, *"Snort — Lightweight Intrusion Detection for Networks,"* in Proc. USENIX LISA Conference, 1999.

[6] Open Information Security Foundation (OISF), *"Suricata — Open Source IDS/IPS/NSM Engine,"* https://suricata.io/

[7] R. Sommer and V. Paxson, *"Outside the Closed World: On Using Machine Learning for Network Intrusion Detection,"* in Proc. IEEE Symposium on Security and Privacy (S&P), 2010, pp. 305–316.

[8] L. Bilge and T. Dumitras, *"Before We Knew It: An Empirical Study of Zero-Day Attacks in the Real World,"* in Proc. ACM CCS, 2012, pp. 833–844.

[9] T. H. Ptacek and T. N. Newsham, *"Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection,"* Secure Networks, Inc., Technical Report, 1998.

[10] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, *"Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization,"* in Proc. 4th International Conference on Information Systems Security and Privacy (ICISSP), 2018, pp. 108–116.

[11] B. A. Alahmadi *et al.*, *"99% False Positives: A Qualitative Study of SOC Analysts' Perspectives on Security Alarms,"* in Proc. USENIX Security Symposium, 2022.

[12] T. Chen and C. Guestrin, *"XGBoost: A Scalable Tree Boosting System,"* in Proc. ACM SIGKDD International Conference on Knowledge Discovery and Data Mining, 2016, pp. 785–794.

[13] G. Ke *et al.*, *"LightGBM: A Highly Efficient Gradient Boosting Decision Tree,"* in Advances in Neural Information Processing Systems (NeurIPS), 2017, pp. 3146–3154.

[14] M. A. Ferrag *et al.*, *"Deep Learning for Cyber Security Intrusion Detection: Approaches, Datasets, and Comparative Study,"* Journal of Information Security and Applications, vol. 50, 2020.

[15] K. J. Åström and R. M. Murray, *Feedback Systems: An Introduction for Scientists and Engineers,* Princeton University Press, 2nd ed., 2020.

[16] Gartner, Inc., *"Top Strategic Technology Trends 2024,"* Gartner Research, 2023.

[17] N. V. Chawla *et al.*, *"SMOTE: Synthetic Minority Over-sampling Technique,"* Journal of Artificial Intelligence Research, vol. 16, pp. 321–357, 2002.

[18] Z. Aouini and A. Pekar, *"NFStream: A Flexible Network Data Analysis Framework,"* Computer Networks, vol. 204, 2022.

[19] L. Grinsztajn, E. Oyallon, and G. Varoquaux, *"Why do tree-based models still outperform deep learning on typical tabular data?"* in Advances in Neural Information Processing Systems (NeurIPS), 2022.

---

*Nội dung Chương 1 được xây dựng dựa trên: (a) phân tích kiến trúc mã nguồn thực tế của hệ thống IDPS — bao gồm các module `autodefense_daemon.py`, `realtime_extractor.py`, `threat_evaluator.py`, `auto_firewall.py`, `suricata_correlator.py`; (b) kết quả đánh giá mô hình trên tập test 503,073 mẫu từ `evaluate.txt`; (c) cấu hình hệ thống từ `docker-compose.yml` và `thresholds.json`; (d) các công trình nghiên cứu học thuật có phản biện (peer-reviewed) được trích dẫn trực tiếp.*
