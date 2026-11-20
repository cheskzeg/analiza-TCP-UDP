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

// Znajduje lub dodaje wpis dla adresu IP
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

// Sortowanie hostow malejaco po liczbie pakietow
int cmp_hosts(const void *a, const void *b) {
    const HostStats *ha = (const HostStats *)a;
    const HostStats *hb = (const HostStats *)b;
    if (hb->packets > ha->packets) return 1;
    if (hb->packets < ha->packets) return -1;
    return 0;
}

// Zapis danych CSV i wywolanie Gnuplota
void generate_charts(const TrafficStats *stats, const TimeBucket *buckets, size_t num_buckets,
                     const HostStats *hosts, size_t host_count) {
    // 1. Zapis szeregu czasowego
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

    // 2. Zapis podzialu protokolow
    FILE *f_proto = fopen("protocols.csv", "w");
    if (f_proto) {
        fprintf(f_proto, "Protokol;Pakiety\n");
        fprintf(f_proto, "TCP;%lu\n", stats->tcp_packets);
        fprintf(f_proto, "UDP;%lu\n", stats->udp_packets);
        fprintf(f_proto, "Inne;%lu\n", stats->other_packets);
        fclose(f_proto);
    }

    // 3. Zapis Top 5 hostow
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

    // 4. Skrypt Gnuplota generujacy 3 pliki PNG
    FILE *gp = fopen("plot.gp", "w");
    if (!gp) {
        perror("Nie mozna utworzyc skryptu plot.gp");
        return;
    }

    fprintf(gp,
        "set datafile separator ';'\n"
        "set grid\n"
        "set term pngcairo size 900,500 enhanced font 'Sans,10'\n"
        "\n"
        "# Wykres 1: Ruch w czasie\n"
        "set output 'wykres_ruch_czas.png'\n"
        "set title 'Natezenie ruchu sieciowego w czasie (pakiety/s)'\n"
        "set xlabel 'Czas od poczatku zrzutu [s]'\n"
        "set ylabel 'Liczba pakietow'\n"
        "plot 'traffic_time.csv' using 1:2 with linespoints lw 2 pt 7 title 'TCP', \\\n"
        "     'traffic_time.csv' using 1:3 with linespoints lw 2 pt 5 title 'UDP'\n"
        "\n"
        "# Wykres 2: Udzial protokolow\n"
        "set output 'wykres_protokoly.png'\n"
        "set title 'Liczba pakietow wedlug protokolu'\n"
        "set xlabel 'Protokol'\n"
        "set ylabel 'Liczba pakietow'\n"
        "set style data histograms\n"
        "set style fill solid 0.8 border -1\n"
        "set boxwidth 0.5\n"
        "set yrange [0:*]\n"
        "plot 'protocols.csv' using 2:xtic(1) notitle lc rgb '#2b5c8f'\n"
        "\n"
        "# Wykres 3: Top 5 najbardziej aktywnych adresow IP\n"
        "set output 'wykres_top_ip.png'\n"
        "set title 'Top 5 najbardziej aktywnych zrodlowych adresow IP'\n"
        "set xlabel 'Adres IP'\n"
        "set ylabel 'Liczba pakietow'\n"
        "plot 'top_hosts.csv' using 2:xtic(1) title 'Wszystkie pakiety' lc rgb '#388e3c', \\\n"
        "     'top_hosts.csv' using 3:xtic(1) title 'Pakiety TCP SYN' lc rgb '#d32f2f'\n"
    );
    fclose(gp);

    int ret = system("gnuplot plot.gp");
    if (ret == 0) {
        printf("Wygenerowano wykresy: wykres_ruch_czas.png, wykres_protokoly.png, wykres_top_ip.png\n");
    } else {
        fprintf(stderr, "Blad podczas uruchamiania gnuplot (kod: %d)\n", ret);
    }
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

            // Wykrywanie retransmisji (powtorzony seq z danymi dla tego samego polaczenia)
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

    printf("=== PODSUMOWANIE ANALIZY ===\n");
    printf("Czas trwania      : %.3f s\n", stats.last_ts - stats.first_ts);
    printf("Pakiety razem     : %lu (%lu B)\n", stats.total_packets, stats.total_bytes);
    printf("TCP / UDP / Inne  : %lu / %lu / %lu\n",
           stats.tcp_packets, stats.udp_packets, stats.other_packets);
    printf("Retransmisje TCP  : %lu\n", stats.tcp_retransmissions);
    printf("Pakiety SYN-only  : %lu\n", stats.tcp_syn_only);

    char ip_str[INET_ADDRSTRLEN];
    for (size_t i = 0; i < host_count; i++) {
        if (hosts[i].syn_count >= 10) {
            inet_ntop(AF_INET, &hosts[i].ip, ip_str, sizeof(ip_str));
            printf("[!] ALERT: Podejrzenie skanowania portow z IP %s (%lu pakietow SYN)\n",
                   ip_str, hosts[i].syn_count);
        }
    }

    generate_charts(&stats, buckets, num_buckets, hosts, host_count);

    free(buckets);
    return 0;
}