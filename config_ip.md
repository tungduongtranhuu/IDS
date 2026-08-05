
------------------------------
## 📋 Bản Quy Hoạch Mạng Tĩnh (Internal Network)

* Tên Mạng Nội Bộ (Đặt trên VirtualBox): intnet [No Source]
* Dải IP Hệ Thống: 192.168.10.0/24 [No Source]
* Máy Kali Linux (Attacker): 192.168.10.20
* Máy Ubuntu Victim (Nạn nhân): 192.168.10.30
* Máy Ubuntu IDS (Giám sát): 192.168.10.40 (Dùng phương án Dual-NIC để vừa hít mạng nội bộ vừa có Internet kéo Git) [No Source].

------------------------------
## 🛠️ Bước chuẩn bị phần cứng (Trên giao diện VirtualBox)
Trước khi vào cấu hình bên trong máy, bạn tắt cả 3 máy ảo đi và chỉnh card mạng trên VirtualBox chính xác như sau:

   1. Máy Kali: Settings -> Network -> Adapter 1 -> Attached to: Internal Network -> Name: Đặt tên là intnet. Vào Advanced -> Promiscuous Mode: Allow All [No Source].
   2. Máy Victim: Settings -> Network -> Adapter 1 -> Attached to: Internal Network -> Name: Đặt tên là intnet. Vào Advanced -> Promiscuous Mode: Allow All [No Source].
   3. Máy IDS (2 Card mạng):
   * Adapter 1 (Mạng hít log): Attached to: Internal Network -> Name: Đặt tên là intnet. Vào Advanced -> Promiscuous Mode: Allow All [No Source].
      * Adapter 2 (Mạng Internet ngoài để push/pull Git): Attached to: NAT [No Source].
   
------------------------------
## 1. Cấu hình IP tĩnh cho máy Ubuntu Victim (192.168.10.30)
Bật máy Victim lên, mở file cấu hình Netplan bằng lệnh:

sudo nano /etc/netplan/00-installer-config.yaml

Xóa toàn bộ file cũ và thay bằng nội dung sau (⚠️ Lưu ý: Bắt buộc dùng phím cách Space để thụt lề, không dùng phím Tab):

network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: no
      addresses:
        - 192.168.10.30/24

(Do mạng Internal Network không có Internet nên cấu hình này không cần điền dòng gateway hay nameservers) [No Source].
Lưu và áp dụng: Nhấn Ctrl + O -> Enter -> Ctrl + X. Sau đó gõ lệnh:

sudo netplan apply

------------------------------
## 2. Cấu hình IP tĩnh cho máy Ubuntu IDS (192.168.10.40)
Bật máy IDS lên, mở file cấu hình Netplan (kiểm tra kỹ tên card mạng bằng ip a, ở đây ví dụ card nội bộ là enp0s3, card Internet NAT ngoài là enp0s8):

sudo nano /etc/netplan/00-installer-config.yaml

Xóa nội dung cũ và điền chính xác cấu hình 2 card mạng song song:

network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: no
      addresses:
        - 192.168.10.40/24
    enp0s8:
      dhcp4: yes

(Card enp0s3 đứng im hứng traffic nội bộ dải 192.168, card enp0s8 tự nhận IP từ VirtualBox để giúp bạn kết nối ra Internet phục vụ Git) [No Source].
Lưu và áp dụng: Nhấn Ctrl + O -> Enter -> Ctrl + X. Sau đó gõ lệnh:

sudo netplan apply

Bật chế độ nghe lén trên OS: Gõ lệnh ép card nội bộ mở cổng thu dữ liệu:

sudo ip link set enp0s3 promisc on

------------------------------
## 3. Cấu hình IP tĩnh cho máy Kali Linux (192.168.10.20)
Vì Kali có giao diện đồ họa, bạn click chuột để cài đặt cho nhanh và chính xác:

   1. Click chuột phải vào Biểu tượng mạng ở góc trên bên phải màn hình Kali -> Chọn Edit Connections...
   2. Bấm đúp chuột vào tên mạng đang kết nối (Ví dụ: Wired connection 1).
   3. Chuyển sang tab IPv4 Settings.
   4. Tại mục Method, bấm chọn đổi thành Manual (Thủ công).
   5. Tại mục Addresses ở dưới, bấm nút Add ở bên phải rồi điền:
   * Address: 192.168.10.20
      * Netmask: 24
      * Gateway: Để trống (Vì mạng Internal không có Gateway) [No Source].
   6. Mục DNS servers: Để trống.
   7. Bấm nút Save để lưu lại.
   8. Click chuột trái vào biểu tượng mạng -> Chọn Disconnect, sau đó chọn Connect lại mạng đó để Kali nhận dải IP mới.

------------------------------
## 🧪 Bài kiểm tra thông mạng tổng thể
Bật cả 3 máy lên và thực hiện các lệnh kiểm tra chéo từ máy Kali Linux (192.168.10.20):

* Gõ ping 192.168.10.30 (Ping sang máy Victim) -> Phải có tín hiệu phản hồi.
* Gõ ping 192.168.10.40 (Ping sang máy IDS) -> Phải có tín hiệu phản hồi.

Hạ tầng mạng cô lập an toàn đã thiết lập xong vĩnh viễn. Khi các máy đã ping thông suốt nhau thành công, hãy báo cho tôi biết để chúng ta bắt đầu viết script Python Scapy thu giữ gói tin đầu tiên trên máy IDS nhé!


## enp0s3: Interface for internal network 
## enp0s8: Interface for NAT and connect with Internet