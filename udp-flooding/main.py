import scapy.all


dest = "192.168.0.102"


while True:
    scapy.all.send(scapy.all.IP(dst=dest)/scapy.all.fuzz(scapy.all.UDP())/"hello", loop=1)
