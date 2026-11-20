#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <hpdf.h>

#define MAX_HOSTS 1024
#define RETRANS_WINDOW 1024

typedef struct {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t tcp_packets;
    uint64_t tcp_bytes;
    uint64_t udp_packets;
    uint64_t udp_bytes;
    uint64_t other_packets;
    uint64_t tcp_syn_only;
    uint64_t tcp_retransmissions;
    double first_ts;
    double last_ts;
} TrafficStats;

typedef struct {
    uint64_t tcp_pkts;
    uint64_t udp_pkts;
    uint64_t tcp_bytes;
    uint64_t udp_bytes;
} TimeBucket;

typedef struct {
    uint32_t ip;
    uint64_t packets;
    uint64_t bytes;
    uint64_t syn_count;
} HostStats;

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint16_t payload_len;
} TcpPacketRecord;

void pdf_error_handler(HPDF_STATUS error_no, HPDF_STATUS detail_no, void *user_data) {
    (void)user_data;
    fprintf(stderr, "Blad libharu: error_no=%04X, detail_no=%u\n",
            (unsigned int)error_no, (unsigned int)detail_no);
}

HostStats* get_host(HostStats *hosts, size_t *host_count, uint32_t ip) {
    for (size_t i = 0; i < *host_count; i++) {
        if (hosts[i].ip == ip) return &hosts[i];
    }
    if (*host_count < MAX_HOSTS) {
        HostStats *h = &hosts[(*host_count)++];
        memset(h, 0, sizeof(HostStats));
        h->ip = ip;
        return h;
    }
    return NULL;
}

int cmp_hosts(const void *a, const void *b) {
    const HostStats *ha = (const HostStats *)a;
    const HostStats *hb = (const HostStats *)b;
    if (hb->packets > ha->packets) return 1;
    if (hb->packets < ha->packets) return -1;
    return 0;
}

void generate_charts(const TrafficStats *stats, const TimeBucket *buckets, size_t num_buckets,
                     const HostStats *hosts, size_t host_count) {
    FILE *f_time = fopen("traffic_time.csv", "w");
    if (f_time) {
        fprintf(f_time, "Sekunda;TCP_pakiety;UDP_pakiety;TCP_KB;UDP_KB\n");
        for (size_t i = 0; i < num_buckets; i++) {
            fprintf(f_time, "%zu;%lu;%lu;%.2f;%.2f\n",
                    i, buckets[i].tcp_pkts, buckets[i].udp_pkts,
                    buckets[i].tcp_bytes / 1024.0, buckets[i].udp_bytes / 1024.0);
        }
        fclose(f_time);
    }

    FILE *f_proto = fopen("protocols.csv", "w");
    if (f_proto) {
        fprintf(f_proto, "Protokol;Pakiety\n");
        fprintf(f_proto, "TCP;%lu\n", stats->tcp_packets);
        fprintf(f_proto, "UDP;%lu\n", stats->udp_packets);
        fprintf(f_proto, "Inne;%lu\n", stats->other_packets);
        fclose(f_proto);
    }

    FILE *f_hosts = fopen("top_hosts.csv", "w");
    if (f_hosts) {
        fprintf(f_hosts, "IP;Pakiety;SYN\n");
        size_t limit = host_count < 5 ? host_count : 5;
        char ip_str[INET_ADDRSTRLEN];
        for (size_t i = 0; i < limit; i++) {
            inet_ntop(AF_INET, &hosts[i].ip, ip_str, sizeof(ip_str));
            fprintf(f_hosts, "%s;%lu;%lu\n", ip_str, hosts[i].packets, hosts[i].syn_count);
        }
        fclose(f_hosts);
    }

    FILE *gp = fopen("plot.gp", "w");
    if (!gp) return;

    fprintf(gp,
        "set datafile separator ';'\n"
        "set grid\n"
        "set term pngcairo size 900,450 enhanced font 'Sans,10'\n"
        "set output 'wykres_ruch_czas.png'\n"
        "set title 'Natezenie ruchu sieciowego w czasie (pakiety/s)'\n"
        "set xlabel 'Czas od poczatku zrzutu [s]'\n"
        "set ylabel 'Liczba pakietow'\n"
        "plot 'traffic_time.csv' using 1:2 with linespoints lw 2 pt 7 title 'TCP', \\\n"
        "     'traffic_time.csv' using 1:3 with linespoints lw 2 pt 5 title 'UDP'\n"
        "set output 'wykres_protokoly.png'\n"
        "set title 'Liczba pakietow wedlug protokolu'\n"
        "set xlabel 'Protokol'\n"
        "set ylabel 'Liczba pakietow'\n"
        "set style data histograms\n"
        "set style fill solid 0.8 border -1\n"
        "set boxwidth 0.5\n"
        "set yrange [0:*]\n"
        "plot 'protocols.csv' using 2:xtic(1) notitle lc rgb '#2b5c8f'\n"
        "set output 'wykres_top_ip.png'\n"
        "set title 'Top 5 najbardziej aktywnych zrodlowych adresow IP'\n"
        "set xlabel 'Adres IP'\n"
        "set ylabel 'Liczba pakietow'\n"
        "plot 'top_hosts.csv' using 2:xtic(1) title 'Wszystkie pakiety' lc rgb '#388e3c', \\\n"
        "     'top_hosts.csv' using 3:xtic(1) title 'Pakiety TCP SYN' lc rgb '#d32f2f'\n"
    );
    fclose(gp);

    if (system("gnuplot plot.gp") != 0) {
        fprintf(stderr, "Ostrzezenie: problem z wywolaniem gnuplot.\n");
    }
}

void pdf_write_line(HPDF_Page page, HPDF_Font font, float size, float x, float y, const char *text) {
    HPDF_Page_BeginText(page);
    HPDF_Page_SetFontAndSize(page, font, size);
    HPDF_Page_TextOut(page, x, y, text);
    HPDF_Page_EndText(page);
}

void generate_pdf_report(const char *pcap_filename, const TrafficStats *stats,
                         const HostStats *hosts, size_t host_count) {
    HPDF_Doc pdf = HPDF_New(pdf_error_handler, NULL);
    if (!pdf) {
        fprintf(stderr, "Nie mozna zainicjowac dokumentu PDF.\n");
        return;
    }

    HPDF_Font font_reg = HPDF_GetFont(pdf, "Helvetica", NULL);
    HPDF_Font font_bold = HPDF_GetFont(pdf, "Helvetica-Bold", NULL);

    // === STRONA 1: Statystyki, Top Hosty, Anomalie i Wykres 1 ===
    HPDF_Page page1 = HPDF_AddPage(pdf);
    HPDF_Page_SetSize(page1, HPDF_PAGE_SIZE_A4, HPDF_PAGE_PORTRAIT);
    float width = HPDF_Page_GetWidth(page1);
    float y = HPDF_Page_GetHeight(page1) - 50;

    char buf[256];
    pdf_write_line(page1, font_bold, 18, 50, y, "RAPORT ANALIZY RUCHU SIECIOWEGO (PCAP)");
    y -= 22;
    snprintf(buf, sizeof(buf), "Analizowany plik: %s", pcap_filename);
    pdf_write_line(page1, font_reg, 11, 50, y, buf);
    y -= 15;

    // Linia oddzielajaca
    HPDF_Page_MoveTo(page1, 50, y);
    HPDF_Page_LineTo(page1, width - 50, y);
    HPDF_Page_Stroke(page1);
    y -= 25;

    // Sekcja 1: Podsumowanie ogolne
    pdf_write_line(page1, font_bold, 13, 50, y, "1. Ogolne statystyki ruchu");
    y -= 18;

    double duration = stats->last_ts - stats->first_ts;
    double tcp_pct = stats->total_packets ? (100.0 * stats->tcp_packets / stats->total_packets) : 0.0;
    double udp_pct = stats->total_packets ? (100.0 * stats->udp_packets / stats->total_packets) : 0.0;

    snprintf(buf, sizeof(buf), "- Czas trwania zrzutu: %.3f s", duration);
    pdf_write_line(page1, font_reg, 10, 60, y, buf); y -= 15;

    snprintf(buf, sizeof(buf), "- Laczna liczba pakietow: %lu (wolumen: %lu bajtow)",
             stats->total_packets, stats->total_bytes);
    pdf_write_line(page1, font_reg, 10, 60, y, buf); y -= 15;

    snprintf(buf, sizeof(buf), "- Ruch TCP: %lu pakietow (%.1f%%) | %lu bajtow",
             stats->tcp_packets, tcp_pct, stats->tcp_bytes);
    pdf_write_line(page1, font_reg, 10, 60, y, buf); y -= 15;

    snprintf(buf, sizeof(buf), "- Ruch UDP: %lu pakietow (%.1f%%) | %lu bajtow",
             stats->udp_packets, udp_pct, stats->udp_bytes);
    pdf_write_line(page1, font_reg, 10, 60, y, buf); y -= 15;

    snprintf(buf, sizeof(buf), "- Inne protokoly (np. ARP, ICMP): %lu pakietow", stats->other_packets);
    pdf_write_line(page1, font_reg, 10, 60, y, buf); y -= 25;

    // Sekcja 2: Wykryte nieprawidlowosci
    pdf_write_line(page1, font_bold, 13, 50, y, "2. Wykryte nieprawidlowosci i anomalie");
    y -= 18;

    snprintf(buf, sizeof(buf), "- Retransmisje TCP (zduplikowane numery SEQ): %lu", stats->tcp_retransmissions);
    pdf_write_line(page1, font_reg, 10, 60, y, buf); y -= 15;

    int alerts_found = 0;
    char ip_str[INET_ADDRSTRLEN];
    for (size_t i = 0; i < host_count; i++) {
        if (hosts[i].syn_count >= 10) {
            inet_ntop(AF_INET, &hosts[i].ip, ip_str, sizeof(ip_str));
            snprintf(buf, sizeof(buf),
                     "[ALERT] Podejrzenie skanowania portow TCP SYN z IP %s (%lu pakietow SYN)",
                     ip_str, hosts[i].syn_count);
            HPDF_Page_SetRGBFill(page1, 0.8, 0.1, 0.1);
            pdf_write_line(page1, font_bold, 10, 60, y, buf);
            HPDF_Page_SetRGBFill(page1, 0.0, 0.0, 0.0);
            y -= 15;
            alerts_found++;
        }
    }
    if (alerts_found == 0) {
        pdf_write_line(page1, font_reg, 10, 60, y, "- Nie wykryto skanowania portow TCP SYN.");
        y -= 15;
    }
    y -= 10;

    // Sekcja 3: Top 5 zrodlowych adresow IP
    pdf_write_line(page1, font_bold, 13, 50, y, "3. Top 5 najbardziej aktywnych adresow IP");
    y -= 18;
    size_t limit = host_count < 5 ? host_count : 5;
    for (size_t i = 0; i < limit; i++) {
        inet_ntop(AF_INET, &hosts[i].ip, ip_str, sizeof(ip_str));
        snprintf(buf, sizeof(buf), "%zu. %-16s | Pakiety: %-6lu | Bajty: %-8lu | SYN-only: %lu",
                 i + 1, ip_str, hosts[i].packets, hosts[i].bytes, hosts[i].syn_count);
        pdf_write_line(page1, font_reg, 10, 60, y, buf);
        y -= 14;
    }
    y -= 15;

    // Osadzenie Wykresu 1 na dole strony 1
    HPDF_Image img1 = HPDF_LoadPngImageFromFile(pdf, "wykres_ruch_czas.png");
    if (img1) {
        float img_w = 490;
        float img_h = 245;
        HPDF_Page_DrawImage(page1, img1, 50, y - img_h, img_w, img_h);
    }

    // === STRONA 2: Pozostale wykresy ===
    HPDF_Page page2 = HPDF_AddPage(pdf);
    HPDF_Page_SetSize(page2, HPDF_PAGE_SIZE_A4, HPDF_PAGE_PORTRAIT);
    float y2 = HPDF_Page_GetHeight(page2) - 50;

    pdf_write_line(page2, font_bold, 14, 50, y2, "4. Rozklad protokolow oraz aktywnosc hostow");
    y2 -= 20;

    HPDF_Image img2 = HPDF_LoadPngImageFromFile(pdf, "wykres_protokoly.png");
    if (img2) {
        HPDF_Page_DrawImage(page2, img2, 50, y2 - 250, 490, 245);
        y2 -= 275;
    }

    HPDF_Image img3 = HPDF_LoadPngImageFromFile(pdf, "wykres_top_ip.png");
    if (img3) {
        HPDF_Page_DrawImage(page2, img3, 50, y2 - 250, 490, 245);
    }

    if (HPDF_SaveToFile(pdf, "raport_analizy.pdf") == HPDF_OK) {
        printf("Wygenerowano raport PDF: raport_analizy.pdf\n");
    } else {
        fprintf(stderr, "Blad zapisu pliku raport_analizy.pdf\n");
    }

    HPDF_Free(pdf);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Uzycie: %s <plik.pcap>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (!handle) {
        fprintf(stderr, "Blad otwarcia pliku pcap: %s\n", errbuf);
        return 1;
    }

    TrafficStats stats = {0};
    HostStats hosts[MAX_HOSTS];
    size_t host_count = 0;

    size_t bucket_cap = 64;
    size_t num_buckets = 0;
    TimeBucket *buckets = calloc(bucket_cap, sizeof(TimeBucket));

    TcpPacketRecord history[RETRANS_WINDOW] = {0};
    size_t hist_idx = 0;
    size_t hist_count = 0;

    struct pcap_pkthdr *header;
    const u_char *packet;
    int res;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue;

        double ts = header->ts.tv_sec + header->ts.tv_usec / 1e6;
        if (stats.total_packets == 0) stats.first_ts = ts;
        stats.last_ts = ts;

        size_t sec_idx = (size_t)(ts - stats.first_ts);
        if (sec_idx >= bucket_cap) {
            size_t new_cap = sec_idx + 64;
            buckets = realloc(buckets, new_cap * sizeof(TimeBucket));
            memset(buckets + bucket_cap, 0, (new_cap - bucket_cap) * sizeof(TimeBucket));
            bucket_cap = new_cap;
        }
        if (sec_idx + 1 > num_buckets) num_buckets = sec_idx + 1;

        stats.total_packets++;
        stats.total_bytes += header->len;

        if (header->caplen < sizeof(struct ethhdr)) {
            stats.other_packets++;
            continue;
        }
        const struct ethhdr *eth = (const struct ethhdr *)packet;
        if (ntohs(eth->h_proto) != ETH_P_IP) {
            stats.other_packets++;
            continue;
        }

        size_t ip_offset = sizeof(struct ethhdr);
        if (header->caplen < ip_offset + sizeof(struct iphdr)) {
            stats.other_packets++;
            continue;
        }
        const struct iphdr *ip = (const struct iphdr *)(packet + ip_offset);
        size_t ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < 20 || header->caplen < ip_offset + ip_hdr_len) {
            stats.other_packets++;
            continue;
        }

        HostStats *src_host = get_host(hosts, &host_count, ip->saddr);
        if (src_host) {
            src_host->packets++;
            src_host->bytes += header->len;
        }

        size_t l4_offset = ip_offset + ip_hdr_len;
        uint16_t ip_tot_len = ntohs(ip->tot_len);

        if (ip->protocol == IPPROTO_TCP) {
            if (header->caplen < l4_offset + sizeof(struct tcphdr)) {
                stats.other_packets++;
                continue;
            }
            const struct tcphdr *tcp = (const struct tcphdr *)(packet + l4_offset);
            size_t tcp_hdr_len = tcp->doff * 4;
            uint16_t payload_len = (ip_tot_len > ip_hdr_len + tcp_hdr_len)
                                   ? (ip_tot_len - ip_hdr_len - tcp_hdr_len) : 0;

            stats.tcp_packets++;
            stats.tcp_bytes += header->len;
            buckets[sec_idx].tcp_pkts++;
            buckets[sec_idx].tcp_bytes += header->len;

            if (tcp->syn == 1 && tcp->ack == 0) {
                stats.tcp_syn_only++;
                if (src_host) src_host->syn_count++;
            }

            uint32_t seq_num = ntohl(tcp->seq);
            if (payload_len > 0) {
                for (size_t i = 0; i < hist_count; i++) {
                    if (history[i].src_ip == ip->saddr &&
                        history[i].dst_ip == ip->daddr &&
                        history[i].sport == tcp->source &&
                        history[i].dport == tcp->dest &&
                        history[i].seq == seq_num &&
                        history[i].payload_len == payload_len) {
                        stats.tcp_retransmissions++;
                        break;
                    }
                }
                history[hist_idx] = (TcpPacketRecord){
                    ip->saddr, ip->daddr, tcp->source, tcp->dest, seq_num, payload_len
                };
                hist_idx = (hist_idx + 1) % RETRANS_WINDOW;
                if (hist_count < RETRANS_WINDOW) hist_count++;
            }
        }
        else if (ip->protocol == IPPROTO_UDP) {
            if (header->caplen < l4_offset + sizeof(struct udphdr)) {
                stats.other_packets++;
                continue;
            }
            stats.udp_packets++;
            stats.udp_bytes += header->len;
            buckets[sec_idx].udp_pkts++;
            buckets[sec_idx].udp_bytes += header->len;
        }
        else {
            stats.other_packets++;
        }
    }

    pcap_close(handle);
    qsort(hosts, host_count, sizeof(HostStats), cmp_hosts);

    generate_charts(&stats, buckets, num_buckets, hosts, host_count);
    generate_pdf_report(argv[1], &stats, hosts, host_count);

    free(buckets);
    return 0;
}