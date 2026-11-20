# Analizator ruchu sieciowego PCAP (TCP/UDP)

Narzędzie napisane w języku C dla systemu Linux, służące do analizy ruchu sieciowego z plików `.pcap` (oraz prostych plików `.pcapng`). Program dekoduje nagłówki warstw Ethernet, IPv4 oraz TCP/UDP, wykrywa wybrane anomalie (skanowanie portów TCP SYN, retransmisje pakietów), generuje zestaw wykresów w formacie PNG oraz składa kompletny raport w pliku PDF.

## Wykorzystane technologie i zależności

Projekt opiera się na standardowych nagłówkach sieciowych systemu Linux (`<netinet/...>`) oraz lekkich bibliotekach systemowych:
* `libpcap` – odczyt i parsowanie pakietów z plików `.pcap`,
* `gnuplot` – generowanie wykresów statystycznych `.png`,
* `libharu` (`libhpdf`) – natywne generowanie wielostronicowego dokumentu `.pdf` z poziomu języka C.

## 1. Instalacja wymaganych zależności (Ubuntu / Debian / WSL2)

Przed pierwszą kompilacją zainstaluj kompilator oraz wymagane biblioteki:

```bash
sudo apt update && sudo apt install -y build-essential libpcap-dev gnuplot libhpdf-dev
```

## 2. Kompilacja programu

W katalogu głównym projektu uruchom polecenie `make`, które skompiluje kod źródłowy `analyzer.c` do pliku wykonywalnego `analyzer`:

```bash
make
```

## 3. Uruchamianie i wybór pliku `.pcap`

Program przyjmuje jako jedyny argument wiersza poleceń ścieżkę do pliku `.pcap`, który ma zostać przeanalizowany:

```bash
./analyzer <sciezka_do_pliku.pcap>
```

### Przykłady użycia w zależności od lokalizacji pliku:

* **Plik znajduje się w tym samym folderze co program:**
  ```bash
  ./analyzer idealny_test.pcap
  ```

* **Plik znajduje się w innym katalogu w systemie Linux (ścieżka względna lub bezwzględna):**
  ```bash
  ./analyzer ~/Pobrane/zrzut_sieci.pcap
  ```

* **Korzystasz z WSL2 na Windowsie i plik leży w folderze Pobrane na dysku `C:`:**
  ```bash
  ./analyzer /mnt/c/Users/<Twoja_Nazwa_Uzytkownika>/Downloads/plik.pcap
  ```

> **Uwaga:** Program obsługuje pliki z nagłówkami warstwy łącza typu Ethernet (`DLT_EN10MB`). W przypadku podania błędnej ścieżki lub uszkodzonego pliku program wyświetli stosowny komunikat błędu w konsoli.

## 4. Generowanie syntetycznych danych testowych (opcjonalnie)

Jeśli nie masz pod ręką własnego pliku `.pcap`, możesz wygenerować plik testowy `idealny_test.pcap` za pomocą dołączonego skryptu w Pythonie (`generuj_pcap.py`). Tworzy on zrzut zawierający normalny ruch TCP, ruch UDP (DNS), retransmisje TCP oraz symulację skanowania portów TCP SYN:

```bash
sudo apt install -y python3-scapy
python3 generuj_pcap.py
./analyzer idealny_test.pcap
```

## 5. Wyniki analizy (pliki wyjściowe)

Po zakończeniu działania program zapisuje w bieżącym katalogu roboczym następujące pliki:
* `raport_analizy.pdf` – główny, 2-stronicowy raport zawierający podsumowanie liczbowe, alerty o wykrytych anomaliach, tabelę Top 5 najbardziej aktywnych adresów IP oraz osadzone wykresy,
* `wykres_ruch_czas.png` – wykres liniowy natężenia ruchu TCP i UDP w oknach 1-sekundowych,
* `wykres_protokoly.png` – wykres słupkowy udziału poszczególnych protokołów (TCP, UDP, inne),
* `wykres_top_ip.png` – zestawienie 5 najbardziej aktywnych źródłowych adresów IP z wyróżnieniem pakietów `TCP SYN`.

*(Dodatkowo program tworzy tymczasowe pliki robocze `.csv` oraz `plot.gp`, wykorzystywane przez Gnuplota do wyrysowania wykresów).*

### Podgląd wygenerowanego raportu PDF:
* **Na natywnym Linuksie z pulpitem:** `xdg-open raport_analizy.pdf`
* **W środowisku WSL2 (otwarcie w przeglądarce Windows):** `explorer.exe raport_analizy.pdf`

## 6. Czyszczenie plików roboczych i binariów

Aby usunąć skompilowany plik wykonywalny oraz wszystkie wygenerowane raporty, wykresy i pliki tymczasowe, użyj polecenia:

```bash
make clean
```
