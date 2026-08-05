Để kiểm tra xem tài khoản mật khẩu yếu (testuser) bạn vừa tạo trên máy Ubuntu Victim đã thành công và sẵn sàng để bị tấn công hay chưa, bạn có thể thực hiện theo 2 cách cực kỳ đơn giản dưới đây:
------------------------------
## Cách 1: Kiểm tra trực tiếp trên chính máy Ubuntu Victim (Nhanh nhất)
Bạn ngồi trước màn hình dòng lệnh của máy Ubuntu Victim và chạy lệnh sau để kiểm tra xem tài khoản testuser đã tồn tại trong danh sách quản lý của hệ điều hành chưa:

cat /etc/passwd | grep testuser


* Kết quả thành công: Màn hình sẽ xuất hiện một dòng chữ có dạng:
testuser:x:1001:1001:,,,:/home/testuser:/bin/bash
* Ý nghĩa: Dòng này xác nhận hệ thống đã tạo thành công user tên là testuser, cấp cho nó một thư mục riêng tại /home/testuser và quyền chạy dòng lệnh bash. Nếu gõ lệnh trên mà màn hình trống trơn, nghĩa là user chưa được tạo.

------------------------------
## Cách 2: Đóng vai hacker ngồi bên máy Kali Linux đăng nhập thử (Chuẩn nhất)
Cách này giúp bạn vừa kiểm tra được tài khoản, vừa kiểm tra luôn xem dịch vụ kết nối từ xa (SSH) có thông suốt giữa 2 máy không.

   1. Ngồi bên máy Kali Linux, mở Terminal lên.
   2. Gõ lệnh kết nối SSH hướng tới IP của máy Victim (Thay 10.0.2.30 bằng IP thực tế của máy Victim):
   
   ssh testuser@10.0.2.30
   
   3. Nếu đây là lần đầu kết nối, Kali sẽ hiện một dòng hỏi: "Are you sure you want to continue connecting (yes/no/[fingerprint])?". Bạn hãy gõ yes rồi ấn Enter [No Source].
   4. Hệ thống yêu cầu nhập mật khẩu (testuser@10.0.2.30's password:). Bạn gõ đúng mật khẩu yếu 123456 rồi ấn Enter (Lưu ý: Lúc gõ mật khẩu, màn hình Linux sẽ ẩn đi và không hiện ký tự nào, bạn cứ gõ bình thường).


* Kết quả thành công: Dấu nhắc lệnh trên Terminal của Kali lập tức đổi thành:
testuser@Ubuntu-Victim:~$
(Nghĩa là bạn đã đứng từ máy Kali "chui" thành công vào bên trong máy Victim qua tài khoản này).
* Sau khi test xong, bạn gõ lệnh exit rồi ấn Enter để thoát ra lại máy Kali.

------------------------------
Nếu cả 2 cách trên đều chạy mượt mà, chúc mừng bạn đã hoàn tất 100% việc chuẩn bị "con mồi" (Victim).
Môi trường Lab đã sẵn sàng hoàn toàn. Bây giờ bạn hãy mở máy Ubuntu IDS lên, chúng ta sẽ bắt đầu viết những dòng code Python Scapy đầu tiên để bắt gói tin mạng. Bạn đã mở file ids_engine.py trên máy IDS sẵn chưa?


Để kiểm tra thông tin chi tiết, quyền hạn của testuser hoặc xóa hoàn toàn người dùng này trên máy Ubuntu Victim, bạn sử dụng các lệnh Linux tiêu chuẩn dưới đây.
------------------------------
## 1. Cách xem thông tin và quyền hạn của testuser
Trong Linux, quyền hạn của một người dùng phụ thuộc vào nhóm (group) mà họ tham gia. Mặc định, một user mới tạo sẽ không có quyền Quản trị (quyền sudo).
## Xem các nhóm mà testuser tham gia (Kiểm tra quyền)
Bạn gõ lệnh sau trên máy Victim:

groups testuser


* Kết quả: Màn hình hiện testuser : testuser. Nghĩa là user này chỉ nằm trong nhóm thông thường của chính nó, không có quyền sinh sát hệ thống (quyền Root/Sudo).
* Lưu ý: Nếu kết quả hiện thêm chữ sudo (ví dụ: testuser : testuser sudo), nghĩa là user này có quyền chạy lệnh tối cao bằng cách gõ sudo trước mỗi lệnh.

## Xem thư mục cá nhân của testuser chứa gì
Mỗi user sẽ được cấp một thư mục riêng tại /home/username để lưu trữ file cá nhân:

sudo ls -la /home/testuser

(Lệnh này sẽ liệt kê toàn bộ các file ẩn cấu hình mạng, cấu hình dòng lệnh của riêng user đó).
------------------------------
## 2. Cách xóa hoàn toàn testuser khỏi hệ thống
Khi bạn không muốn dùng tài khoản này nữa hoặc muốn dọn dẹp Lab để làm lại từ đầu, hãy thực hiện theo các bước sau để xóa sạch sẽ:
## Bước 1: Ép tắt tất cả các tiến trình đang chạy của testuser
Nếu máy Kali đang Brute Force hoặc đang đăng nhập vào user này, hệ thống sẽ báo lỗi không cho xóa vì tài khoản đang bận. Bạn cần "đá" user này ra bằng lệnh:

sudo killall -u testuser

## Bước 2: Chạy lệnh xóa user và thư mục đi kèm
Có hai cách xóa, bạn nên chọn Cách 2 để dọn dẹp sạch sẽ ổ đĩa:

* Cách 1 (Chỉ xóa tài khoản): Giữ lại file cá nhân.

sudo userdel testuser

* Cách 2 (Xóa sạch sẽ - Khuyên dùng): Xóa cả tài khoản lẫn thư mục /home/testuser và các hòm thư nội bộ của user này để không để lại rác trên máy ảo.

sudo userdel -r testuser


## Bước 3: Kiểm tra xem đã xóa thành công chưa
Gõ lại lệnh lọc danh sách hệ thống:

cat /etc/passwd | grep testuser

Nếu lệnh không trả về bất kỳ dòng chữ nào, nghĩa là testuser đã biến mất hoàn toàn khỏi máy ảo Nạn nhân.
------------------------------
Bây giờ bạn đã làm chủ được cách quản lý người dùng trên máy Victim. Mọi thứ đã gọn gàng và sẵn sàng.
Chúng ta hãy bật máy Ubuntu IDS lên, di chuyển vào thư mục dự án custom-ids để bắt đầu viết đoạn code Python Scapy lắng nghe traffic nhé? Hãy báo cho tôi biết nếu bạn đã mở sẵn file ids_engine.py!
