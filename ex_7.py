import pcapy
import datetime

# Lista todas as interfaces disponíveis
interfaces = pcapy.findalldevs()
print("Available interfaces are:")
for interface in interfaces:
    print(interface)

# Escolhe uma interface
interface = input("Enter interface name to sniff and inject packets: ")
print("Using interface:", interface)

# Abre a interface para captura e envio
cap = pcapy.open_live(interface, 65536, 1, 0)

# Pacote de exemplo (broadcast ARP request)
packet = b"\xff\xff\xff\xff\xff\xff" + b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x08\x06" + b"\x00" * 42

# Injeta o pacote na rede
cap.sendpacket(packet)
print(f"{datetime.datetime.now()}: Packet injected successfully!")

# Captura pacotes
print("Listening for packets...")
while True:
    (header, payload) = cap.next()
    print(f"{datetime.datetime.now()}: Captured {header.getlen()} bytes")
