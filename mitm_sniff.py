
from scapy.all import sniff, IP, TCP, Raw, get_if_hwaddr

# Lấy MAC của h2 để nhận diện gói tin do mình gửi ra
MY_MAC = get_if_hwaddr("h2-eth0")

def process_packet(pkt):
    # CHỐT CHẶN: Nếu MAC nguồn là của mình, thì đây là gói tin đang đi ra -> Bỏ qua
    if pkt.src == MY_MAC:
        return

    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        if pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode(errors='ignore').strip()
                if payload:
                    print(f"[*] [NGHE LÉN] {pkt[IP].src} -> {pkt[IP].dst}: {payload}")
            except:
                pass

print("[+] Dang nghe len (da loc goi trung)...")
sniff(iface="h2-eth0", filter="tcp port 8080", prn=process_packet, store=0)
        