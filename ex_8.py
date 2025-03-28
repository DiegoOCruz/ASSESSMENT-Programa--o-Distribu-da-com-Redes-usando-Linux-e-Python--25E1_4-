from scapy.all import *

def capturar_pacote():
    print("Capturando um pacote...")
    pacotes = sniff(count=1)
    pacote = pacotes[0]
    print("Pacote capturado:")
    pacote.show()
    return pacote

def modificar_pacote(pacote):
    print("Modificando pacote...")
    if IP in pacote:
        pacote[IP].ttl = 99  # Altera o TTL
    return pacote

def injetar_pacote(pacote):
    print("Injetando pacote modificado...")
    send(pacote)

def main():
    pacote = capturar_pacote()
    pacote_modificado = modificar_pacote(pacote)
    injetar_pacote(pacote_modificado)

if __name__ == "__main__":
    main()