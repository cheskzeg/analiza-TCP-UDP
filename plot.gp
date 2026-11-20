set datafile separator ';'
set grid
set term pngcairo size 900,500 enhanced font 'Sans,10'

# Wykres 1: Ruch w czasie
set output 'wykres_ruch_czas.png'
set title 'Natezenie ruchu sieciowego w czasie (pakiety/s)'
set xlabel 'Czas od poczatku zrzutu [s]'
set ylabel 'Liczba pakietow'
plot 'traffic_time.csv' using 1:2 with linespoints lw 2 pt 7 title 'TCP', \
     'traffic_time.csv' using 1:3 with linespoints lw 2 pt 5 title 'UDP'

# Wykres 2: Udzial protokolow
set output 'wykres_protokoly.png'
set title 'Liczba pakietow wedlug protokolu'
set xlabel 'Protokol'
set ylabel 'Liczba pakietow'
set style data histograms
set style fill solid 0.8 border -1
set boxwidth 0.5
set yrange [0:*]
plot 'protocols.csv' using 2:xtic(1) notitle lc rgb '#2b5c8f'

# Wykres 3: Top 5 najbardziej aktywnych adresow IP
set output 'wykres_top_ip.png'
set title 'Top 5 najbardziej aktywnych zrodlowych adresow IP'
set xlabel 'Adres IP'
set ylabel 'Liczba pakietow'
plot 'top_hosts.csv' using 2:xtic(1) title 'Wszystkie pakiety' lc rgb '#388e3c', \
     'top_hosts.csv' using 3:xtic(1) title 'Pakiety TCP SYN' lc rgb '#d32f2f'
