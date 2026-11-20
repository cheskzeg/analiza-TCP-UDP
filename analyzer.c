#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

typedef struct {
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t tcp_packets;
    uint64_t tcp_bytes;
    uint64_t udp_packets;
    uint64_t udp_bytes;
    uint64_t tcp_syn_only; // Potencjalne skanowanie portów
    uint64_t other_packets;
    double first_ts;
    double last_ts;
} TrafficStats;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Uzycie: %s <plik.pcap>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Blad otwarcia pliku pcap: %s\n", errbuf);
        return 1;
    }

    // Sprawdzamy, czy warstwa lacza to standardowy Ethernet (14 bajtow)
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Ostrzezenie: Plik nie uzywa standardowych ramek Ethernet (DLT_EN10MB).\n");
    }

    TrafficStats stats = {0};
    struct pcap_pkthdr *header;
    const u_char *packet;
    int res;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue; // Timeout (nie dotyczy plikow, ale dobra praktyka)

        double ts = header->ts.tv_sec + header->ts.tv_usec / 1e6;
        if (stats.total_packets == 0) {
            stats.first_ts = ts;
        }
        stats.last_ts = ts;

        stats.total_packets++;
        stats.total_bytes += header->len;

        // 1. Warstwa 2: Ethernet
        if (header->caplen < sizeof(struct ethhdr)) {
            stats.other_packets++;
            continue;
        }
        const struct ethhdr *eth = (const struct ethhdr *)packet;

        // Interesuje nas tylko IPv4 (0x0800)
        if (ntohs(eth->h_proto) != ETH_P_IP) {
            stats.other_packets++;
            continue;
        }

        // 2. Warstwa 3: IPv4
        size_t ip_offset = sizeof(struct ethhdr);
        if (header->caplen < ip_offset + sizeof(struct iphdr)) {
            stats.other_packets++;
            continue;
        }
        const struct iphdr *ip = (const struct iphdr *)(packet + ip_offset);
        size_t ip_hdr_len = ip->ihl * 4; // Dlugosc naglowka IP w bajtach (zwykle 20B, ale moze byc wiecej)

        if (ip_hdr_len < 20 || header->caplen < ip_offset + ip_hdr_len) {
            stats.other_packets++;
            continue;
        }

        size_t l4_offset = ip_offset + ip_hdr_len;

        // 3. Warstwa 4: TCP lub UDP
        if (ip->protocol == IPPROTO_TCP) {
            if (header->caplen < l4_offset + sizeof(struct tcphdr)) {
                stats.other_packets++;
                continue;
            }
            const struct tcphdr *tcp = (const struct tcphdr *)(packet + l4_offset);

            stats.tcp_packets++;
            stats.tcp_bytes += header->len;

            // Wykrywanie czystych pakietow SYN (bez ACK) - charakterystyczne dla skanowania portow
            if (tcp->syn == 1 && tcp->ack == 0) {
                stats.tcp_syn_only++;
            }
        } 
        else if (ip->protocol == IPPROTO_UDP) {
            if (header->caplen < l4_offset + sizeof(struct udphdr)) {
                stats.other_packets++;
                continue;
            }
            const struct udphdr *udp = (const struct udphdr *)(packet + l4_offset);
            (void)udp; // Na razie nie uzywamy pol portow, wyciszamy ostrzezenie kompilatora

            stats.udp_packets++;
            stats.udp_bytes += header->len;
        } 
        else {
            stats.other_packets++;
        }
    }

    if (res == -1) {
        fprintf(stderr, "Blad podczas czytania pakietu: %s\n", pcap_geterr(handle));
    }

    pcap_close(handle);

    // Wypisanie podsumowania
    double duration = stats.last_ts - stats.first_ts;
    printf("=== PODSUMOWANIE ANALIZY PCAP ===\n");
    printf("Czas trwania zrzutu : %.3f s\n", duration);
    printf("Wszystkie pakiety   : %lu (%lu bajtow)\n", stats.total_packets, stats.total_bytes);
    printf("Pakiety TCP         : %lu (%lu bajtow)\n", stats.tcp_packets, stats.tcp_bytes);
    printf("Pakiety UDP         : %lu (%lu bajtow)\n", stats.udp_packets, stats.udp_bytes);
    printf("Inne (ARP/ICMP itp.): %lu\n", stats.other_packets);
    printf("Pakiety TCP SYN-only: %lu\n", stats.tcp_syn_only);

    return 0;
}