from scapy.all import IP, TCP, UDP, Ether, wrpcap
import time

pakiety = []
t0 = time.time()

# 1. Normalny ruch TCP (50 pakietów co 0.1s)
for i in range(50):
    pkt = Ether()/IP(src="192.168.1.10", dst="10.0.0.5")/TCP(sport=50000, dport=443, flags="PA", seq=1000+i*100)/("X"*100)
    pkt.time = t0 + i * 0.1
    pakiety.append(pkt)

# 2. Ruch UDP - np. zapytania DNS i strumień danych (40 pakietów)
for i in range(40):
    pkt = Ether()/IP(src="192.168.1.15", dst="8.8.8.8")/UDP(sport=40000+i, dport=53)/("D"*60)
    pkt.time = t0 + 2.0 + i * 0.05
    pakiety.append(pkt)

# 3. Retransmisje TCP (ten sam numer sekwencyjny seq=2000 wysłany 4 razy)
for i in range(4):
    pkt = Ether()/IP(src="192.168.1.10", dst="10.0.0.5")/TCP(sport=50000, dport=443, flags="PA", seq=2000)/("X"*100)
    pkt.time = t0 + 5.0 + i * 0.2
    pakiety.append(pkt)

# 4. Anomalia: Skanowanie portów TCP SYN (1 host skanuje 80 różnych portów w 1 sekundę)
for port in range(20, 100):
    pkt = Ether()/IP(src="192.168.1.99", dst="192.168.1.10")/TCP(sport=12345, dport=port, flags="S")
    pkt.time = t0 + 7.0 + (port - 20) * 0.01
    pakiety.append(pkt)

wrpcap("idealny_test.pcap", pakiety)
print("Gotowe! Zapisano", len(pakiety), "pakietów.")