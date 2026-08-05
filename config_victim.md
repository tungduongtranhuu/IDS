Để xây dựng một máy Ubuntu Victim (Nạn nhân) toàn diện, đóng vai trò là "mục tiêu hoàn hảo" cho dự án IDS tự viết bằng Python + Scapy, bạn cần cấu hình máy này theo 3 tầng: Phần cứng, Dịch vụ mạng hệ thống và Ứng dụng Web lỗi.
Khi hoàn thành bộ cấu hình này, phòng Lab của bạn sẽ cực kỳ chuyên nghiệp và ăn điểm tuyệt đối trong CV. Dưới đây là hướng dẫn chi tiết:
------------------------------
## Tầng 1: Cấu hình Phần cứng & Mạng (Trên VirtualBox)
Sau khi bạn đã cài đặt xong hệ điều hành Ubuntu thành công (vượt qua dòng treo), hãy tắt máy ảo đi để bật lại chế độ "nghe lén" mạng:

   1. Số nhân CPU: Giữ nguyên 2 vCPU và RAM 2GB (để máy chạy ổn định).
   2. Cấu hình mạng: Vào Settings -> Network -> Attached to: NAT Network -> Name: NatNetwork.
   3. Bật lại Promiscuous Mode: Vào mục Advanced, chuyển dòng Promiscuous Mode từ Deny thành Allow All. (Bước này bắt buộc phải làm để máy IDS có thể "hít" được gói tin đi ra/vào từ máy Victim này).

------------------------------
## Tầng 2: Cấu hình các dịch vụ hệ thống lỗi (System Services)
Bật các máy ảo lên và đăng nhập vào Ubuntu Victim. Chúng ta sẽ mở các dịch vụ mạng cơ bản để làm mục tiêu cho kịch bản tấn công Quét cổng (Port Scan) và Dò mật khẩu (Brute Force).
## 1. Cài đặt và mở dịch vụ SSH (Cổng 22)
Hacker rất thích bẻ khóa SSH. Hãy cài nó bằng lệnh:

sudo apt update && sudo apt install openssh-server -y

(Sau khi cài xong, dịch vụ sẽ tự động chạy ở cổng 22).
## 2. Tạo một tài khoản có mật khẩu yếu (Để làm mục tiêu Brute Force)
Để máy Kali Linux có thể tấn công dò mật khẩu thành công và kích hoạt cảnh báo trên IDS, hãy tạo một user tên là testuser với mật khẩu siêu dễ đoán (ví dụ: 123456):

sudo adduser testuser

(Hệ thống sẽ bảo bạn nhập mật khẩu mới, hãy gõ 123456).
------------------------------
## Tầng 3: Cấu hình Ứng dụng Web lỗi toàn diện (Ứng dụng Docker)
Để IDS của bạn có thể soi được các loại traffic phức tạp ở tầng ứng dụng (như SQL Injection, XSS, Command Injection), cách tốt nhất và sạch sẽ nhất là chạy các app lỗi thông qua Docker.
## 1. Cài đặt Docker trên Ubuntu Victim
Chạy lệnh sau để cài đặt môi trường chạy Container:

sudo apt install docker.io -y
sudo systemctl enable --now docker

## 2. Kích hoạt ứng dụng DVWA (Damn Vulnerable Web Application)
Đây là ứng dụng web dính lỗi kinh điển nhất thế giới bảo mật. Bạn cho nó chạy ngầm ở cổng 80 bằng lệnh:

sudo docker run -d --name lab-dvwa -p 80:80 --restart always vulnerables/web-dvwa

## 3. Kích hoạt thêm ứng dụng OWASP Juice Shop (Cổng 3000)
Nếu muốn Lab hoành tráng hơn, bạn có thể cài thêm một ứng dụng Web lỗi hiện đại viết bằng Node.js ở cổng 3000:

sudo docker run -d --name lab-juiceshop -p 3000:3000 --restart always bkimminich/juice-shop

------------------------------
## Bước Cuối: Kiểm tra "Thành quả" toàn diện
Bây giờ máy Ubuntu Victim của bạn đã mở đồng thời 3 cổng dịch vụ cực kỳ phổ biến: 22 (SSH), 80 (HTTP DVWA), và 3000 (HTTP Juice Shop).

   1. Trên máy Victim, gõ lệnh ip a để lấy địa chỉ IP (Ví dụ: 10.0.2.5).
   2. Ngồi bên máy Kali Linux, mở trình duyệt web lên và truy cập:
   * http://10.0.2.5 -> Giao diện DVWA hiện ra (Đăng nhập mặc định: admin / password).
      * http://10.0.2.5:3000 -> Giao diện Juice Shop hiện ra.
   3. Cũng từ máy Kali, mở Terminal và gõ lệnh quét thử:
   * nmap 10.0.2.5 -> Bạn sẽ thấy các cổng 22, 80, 3000 đều đang mở ở trạng thái open.
   
Môi trường nạn nhân như thế này là đã đạt chuẩn Toàn diện (Production-grade Lab) để làm dự án CV.
Bạn đã chuẩn bị cấu hình xong đến bước này chưa? Hãy báo cho tôi biết để chúng ta chuyển hẳn sang máy IDS và bắt đầu viết script Python Scapy cấu hình bộ bắt gói tin đầu tiên nhé!


Chúc mừng bạn, cấu hình ứng dụng web lỗi DVWA trên máy victim-ubuntu như trong ảnh là đã hoàn thành thành công 100% và cực kỳ chuẩn bài!
Nhìn vào các dòng thông báo cuối cùng:

* Hệ thống báo Pull complete cho tất cả các tầng dữ liệu (layers).
* Dòng Digest: sha256:... chứng minh Docker đã tải xong bản mới nhất từ Internet.
* Dấu nhắc lệnh đã quay trở lại trạng thái chờ ubuntu@victim-ubuntu:~$ mà không có bất kỳ dòng báo lỗi (Error) nào.

------------------------------
## 🛠️ Một bước nhỏ để kiểm tra xem nó có đang chạy ngầm hay không
Để chắc chắn ứng dụng container này đang hoạt động ổn định ở chế độ chạy ngầm (-d), bạn hãy gõ lệnh sau trên máy Victim rồi ấn Enter:

sudo docker ps

Kết quả chuẩn: Bạn sẽ thấy một bảng hiện ra, trong đó cột STATUS ghi chữ Up ... (about a minute) và cột NAMES ghi đúng tên lab-dvwa.
------------------------------
## 🚀 Bước tiếp theo: Kiểm tra từ máy tấn công (Kali Linux)
Bây giờ "mồi ngon" đã được bày ra. Bạn hãy kiểm tra xem card mạng nội bộ đã thông suốt chưa bằng cách:

   1. Gõ lệnh ip a trên máy victim-ubuntu này để xem chính xác địa chỉ IP hiện tại của nó (Ví dụ: 10.0.2.x).
   2. Ngồi sang máy Kali Linux, mở trình duyệt web (Firefox) và gõ địa chỉ IP đó vào thanh URL (Ví dụ: http://10.0.2.x).
   3. Nếu màn hình hiện ra giao diện đăng nhập của DVWA, bạn nhập tài khoản mặc định:
   * Username: admin
      * Password: password
   
Nếu mọi thứ trơn tru, môi trường nạn nhân coi như đã đóng hòm xong xuôi! Bạn đã sẵn sàng chuyển sang máy IDS để viết file Python Scapy hứng trọn traffic này chưa?
