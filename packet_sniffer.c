/*
 * Packet Sniffer Monitor - Network Security Tool
 * Monitors network traffic and alerts on potential threats
 * Author: Security Monitoring Tool
 * License: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>

/* Color codes for terminal output */
#define COLOR_RED     "\x1b[31m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_RESET   "\x1b[0m"

/* Threat detection thresholds */
#define MAX_PACKET_SIZE 1500
#define SUSPICIOUS_PACKET_SIZE 1400
#define PORT_SCAN_THRESHOLD 10
#define TIME_WINDOW 60

/* Statistics structure */
struct packet_stats {
    unsigned long total_packets;
    unsigned long tcp_packets;
    unsigned long udp_packets;
    unsigned long icmp_packets;
    unsigned long other_packets;
    unsigned long threat_alerts;
};

/* Port scan detection structure */
struct port_scan_tracker {
    char src_ip[INET_ADDRSTRLEN];
    int port_count;
    time_t first_seen;
};

/* Global variables */
struct packet_stats stats = {0};
struct port_scan_tracker scan_tracker[100];
int tracker_count = 0;
pcap_t *handle = NULL;

/* Suspicious ports (common attack vectors) */
int suspicious_ports[] = {
    21,    // FTP
    23,    // Telnet
    135,   // MS RPC
    139,   // NetBIOS
    445,   // SMB
    1433,  // MS SQL
    3306,  // MySQL
    3389,  // RDP
    5900,  // VNC
    6667,  // IRC
    31337, // Back Orifice
    12345, // NetBus
    0
};

/* Function prototypes */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void process_ip_packet(const u_char *packet, int size);
void process_tcp_packet(const u_char *packet, int size, struct iphdr *iph);
void process_udp_packet(const u_char *packet, int size, struct iphdr *iph);
void process_icmp_packet(const u_char *packet, int size, struct iphdr *iph);
void detect_threats(struct iphdr *iph, int src_port, int dest_port, int protocol);
int is_suspicious_port(int port);
void check_port_scan(char *src_ip, int dest_port);
void print_threat_alert(const char *type, const char *details);
void print_statistics();
void signal_handler(int signum);
void print_banner();

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;
    struct bpf_program fp;
    bpf_u_int32 net, mask;

    print_banner();

    /* Check for root privileges */
    if (getuid() != 0) {
        fprintf(stderr, COLOR_RED "[ERROR] This program requires root privileges!\n" COLOR_RESET);
        fprintf(stderr, "Please run with sudo: sudo %s\n", argv[0]);
        return 1;
    }

    /* Set up signal handler for clean exit */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Find network device */
    if (argc > 1) {
        dev = argv[1];
    } else {
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, COLOR_RED "[ERROR] Couldn't find default device: %s\n" COLOR_RESET, errbuf);
            return 2;
        }
    }

    printf(COLOR_GREEN "[INFO] Monitoring device: %s\n" COLOR_RESET, dev);

    /* Get network number and mask */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, COLOR_YELLOW "[WARNING] Couldn't get netmask for device %s: %s\n" COLOR_RESET,
                dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* Open device for sniffing */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, COLOR_RED "[ERROR] Couldn't open device %s: %s\n" COLOR_RESET, dev, errbuf);
        return 2;
    }

    /* Verify Ethernet headers */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, COLOR_RED "[ERROR] Device %s doesn't provide Ethernet headers\n" COLOR_RESET, dev);
        pcap_close(handle);
        return 2;
    }

    printf(COLOR_GREEN "[INFO] Packet capture started. Press Ctrl+C to stop.\n" COLOR_RESET);
    printf(COLOR_CYAN "[INFO] Monitoring for potential threats...\n\n" COLOR_RESET);

    /* Start packet capture loop */
    pcap_loop(handle, 0, packet_handler, NULL);

    /* Cleanup */
    pcap_close(handle);
    print_statistics();

    return 0;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    stats.total_packets++;

    /* Process IP packet */
    process_ip_packet(packet, header->len);

    /* Print stats every 100 packets */
    if (stats.total_packets % 100 == 0) {
        printf(COLOR_CYAN "[STATS] Packets: %lu | Threats: %lu | TCP: %lu | UDP: %lu | ICMP: %lu\n" COLOR_RESET,
               stats.total_packets, stats.threat_alerts, stats.tcp_packets,
               stats.udp_packets, stats.icmp_packets);
    }
}

void process_ip_packet(const u_char *packet, int size) {
    struct iphdr *iph = (struct iphdr *)(packet + sizeof(struct ethhdr));

    /* Check for oversized packets */
    if (size > SUSPICIOUS_PACKET_SIZE) {
        char details[256];
        snprintf(details, sizeof(details), "Oversized packet detected: %d bytes", size);
        print_threat_alert("SUSPICIOUS_SIZE", details);
    }

    /* Process based on protocol */
    switch (iph->protocol) {
        case IPPROTO_TCP:
            stats.tcp_packets++;
            process_tcp_packet(packet, size, iph);
            break;

        case IPPROTO_UDP:
            stats.udp_packets++;
            process_udp_packet(packet, size, iph);
            break;

        case IPPROTO_ICMP:
            stats.icmp_packets++;
            process_icmp_packet(packet, size, iph);
            break;

        default:
            stats.other_packets++;
            break;
    }
}

void process_tcp_packet(const u_char *packet, int size, struct iphdr *iph) {
    unsigned short iphdrlen = iph->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr *)(packet + iphdrlen + sizeof(struct ethhdr));

    int src_port = ntohs(tcph->source);
    int dest_port = ntohs(tcph->dest);

    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    /* Detect SYN scan (SYN flag set, ACK flag not set) */
    if (tcph->syn && !tcph->ack) {
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &source.sin_addr, src_ip, INET_ADDRSTRLEN);
        check_port_scan(src_ip, dest_port);
    }

    /* Check for NULL scan (all flags off) */
    if (!tcph->syn && !tcph->ack && !tcph->fin && !tcph->rst && !tcph->psh && !tcph->urg) {
        char details[256];
        snprintf(details, sizeof(details), "NULL scan detected from %s",
                 inet_ntoa(source.sin_addr));
        print_threat_alert("NULL_SCAN", details);
    }

    /* Check for XMAS scan (FIN, PSH, URG flags set) */
    if (tcph->fin && tcph->psh && tcph->urg) {
        char details[256];
        snprintf(details, sizeof(details), "XMAS scan detected from %s",
                 inet_ntoa(source.sin_addr));
        print_threat_alert("XMAS_SCAN", details);
    }

    /* Check for threats */
    detect_threats(iph, src_port, dest_port, IPPROTO_TCP);
}

void process_udp_packet(const u_char *packet, int size, struct iphdr *iph) {
    unsigned short iphdrlen = iph->ihl * 4;
    struct udphdr *udph = (struct udphdr *)(packet + iphdrlen + sizeof(struct ethhdr));

    int src_port = ntohs(udph->source);
    int dest_port = ntohs(udph->dest);

    /* Check for threats */
    detect_threats(iph, src_port, dest_port, IPPROTO_UDP);
}

void process_icmp_packet(const u_char *packet, int size, struct iphdr *iph) {
    unsigned short iphdrlen = iph->ihl * 4;
    struct icmphdr *icmph = (struct icmphdr *)(packet + iphdrlen + sizeof(struct ethhdr));

    struct sockaddr_in source;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    /* Detect ICMP flood (too many ICMP packets) */
    static unsigned long icmp_count = 0;
    static time_t last_check = 0;
    time_t now = time(NULL);

    icmp_count++;

    if (now - last_check >= 10) {
        if (icmp_count > 100) {
            char details[256];
            snprintf(details, sizeof(details),
                     "Possible ICMP flood: %lu packets in 10 seconds", icmp_count);
            print_threat_alert("ICMP_FLOOD", details);
        }
        icmp_count = 0;
        last_check = now;
    }
}

void detect_threats(struct iphdr *iph, int src_port, int dest_port, int protocol) {
    struct sockaddr_in source, dest;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    /* Check for suspicious destination ports */
    if (is_suspicious_port(dest_port)) {
        char details[256];
        snprintf(details, sizeof(details),
                 "%s traffic to suspicious port %d from %s to %s",
                 protocol == IPPROTO_TCP ? "TCP" : "UDP",
                 dest_port,
                 inet_ntoa(source.sin_addr),
                 inet_ntoa(dest.sin_addr));
        print_threat_alert("SUSPICIOUS_PORT", details);
    }

    /* Check for suspicious source ports */
    if (is_suspicious_port(src_port)) {
        char details[256];
        snprintf(details, sizeof(details),
                 "%s traffic from suspicious port %d (%s to %s)",
                 protocol == IPPROTO_TCP ? "TCP" : "UDP",
                 src_port,
                 inet_ntoa(source.sin_addr),
                 inet_ntoa(dest.sin_addr));
        print_threat_alert("SUSPICIOUS_PORT", details);
    }
}

int is_suspicious_port(int port) {
    for (int i = 0; suspicious_ports[i] != 0; i++) {
        if (port == suspicious_ports[i]) {
            return 1;
        }
    }
    return 0;
}

void check_port_scan(char *src_ip, int dest_port) {
    time_t now = time(NULL);
    int found = 0;

    /* Check if source IP is already being tracked */
    for (int i = 0; i < tracker_count; i++) {
        if (strcmp(scan_tracker[i].src_ip, src_ip) == 0) {
            found = 1;

            /* Check if within time window */
            if (now - scan_tracker[i].first_seen <= TIME_WINDOW) {
                scan_tracker[i].port_count++;

                /* Alert if threshold exceeded */
                if (scan_tracker[i].port_count >= PORT_SCAN_THRESHOLD) {
                    char details[256];
                    snprintf(details, sizeof(details),
                             "Port scan detected from %s (%d ports in %ld seconds)",
                             src_ip, scan_tracker[i].port_count,
                             now - scan_tracker[i].first_seen);
                    print_threat_alert("PORT_SCAN", details);

                    /* Reset counter after alert */
                    scan_tracker[i].port_count = 0;
                    scan_tracker[i].first_seen = now;
                }
            } else {
                /* Reset if outside time window */
                scan_tracker[i].port_count = 1;
                scan_tracker[i].first_seen = now;
            }
            break;
        }
    }

    /* Add new tracker if not found and space available */
    if (!found && tracker_count < 100) {
        strncpy(scan_tracker[tracker_count].src_ip, src_ip, INET_ADDRSTRLEN);
        scan_tracker[tracker_count].port_count = 1;
        scan_tracker[tracker_count].first_seen = now;
        tracker_count++;
    }
}

void print_threat_alert(const char *type, const char *details) {
    time_t now;
    struct tm *timeinfo;
    char timestamp[80];

    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

    stats.threat_alerts++;

    printf(COLOR_RED "[THREAT ALERT] " COLOR_RESET);
    printf("[%s] %s: %s\n", timestamp, type, details);
}

void print_statistics() {
    printf("\n" COLOR_CYAN "=== Packet Capture Statistics ===" COLOR_RESET "\n");
    printf("Total Packets:   %lu\n", stats.total_packets);
    printf("TCP Packets:     %lu\n", stats.tcp_packets);
    printf("UDP Packets:     %lu\n", stats.udp_packets);
    printf("ICMP Packets:    %lu\n", stats.icmp_packets);
    printf("Other Packets:   %lu\n", stats.other_packets);
    printf(COLOR_RED "Threat Alerts:   %lu\n" COLOR_RESET, stats.threat_alerts);
    printf(COLOR_CYAN "=================================" COLOR_RESET "\n");
}

void signal_handler(int signum) {
    printf("\n" COLOR_YELLOW "[INFO] Caught signal %d, stopping capture...\n" COLOR_RESET, signum);

    if (handle != NULL) {
        pcap_breakloop(handle);
    }
}

void print_banner() {
    printf(COLOR_GREEN "\n");
    printf("╔═══════════════════════════════════════════════════════╗\n");
    printf("║     Packet Sniffer Monitor - Security Tool v1.0      ║\n");
    printf("║     Network Threat Detection & Monitoring            ║\n");
    printf("╚═══════════════════════════════════════════════════════╝\n");
    printf(COLOR_RESET "\n");
}
