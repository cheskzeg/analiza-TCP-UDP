# Analizator ruchu sieciowego PCAP (TCP/UDP)

Narzędzie napisane w języku C dla systemu Linux, analizujące pliki `.pcap` przy użyciu biblioteki `libpcap` oraz generujące wykresy statystyczne (`gnuplot`) i raport końcowy w formacie PDF (`libharu`).

## Wymagane zależności (Ubuntu / Debian)

```bash
sudo apt update && sudo apt install -y build-essential libpcap-dev gnuplot libhpdf-dev
```

## Kompilacja i uruchomienie

```bash
make
./analyzer <sciezka_do_pliku.pcap>
```

## Wynik działania programu

Po zakończeniu analizy w katalogu roboczym generowane są:
* `raport_analizy.pdf` – wielostronicowy raport zawierający statystyki ruchu, wykryte anomalie (m.in. skanowanie portów TCP SYN, retransmisje TCP) oraz osadzone wykresy,
* `wykres_ruch_czas.png` – natężenie ruchu TCP i UDP w czasie,
* `wykres_protokoly.png` – podział liczby pakietów według protokołu,
* `wykres_top_ip.png` – zestawienie 5 najbardziej aktywnych źródłowych adresów IP.