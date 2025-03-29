from scapy.all import *

def start_sniffing(interface):
    sniff(iface=interface, store=False, prn=process_packet)
    
def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered[0][1].hwsrc

def process_packet(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP Response
        real_mac = get_mac(packet[ARP].psrc)
        response_mac = packet[ARP].hwsrc
        if real_mac != response_mac:
            print("[!] ARP Spoofing Attack Detected!")

if __name__ == '__main__':
    start_sniffing("enp0s3")
