#include "parse_data.h"

int parse_data(const u_char * packet, u_int length) {
    int i = 0; // iterator
    int count = 0;

    // fills Eth_header
    struct Eth_header *eth_header = (struct Eth_header*)packet;

    if (ntohs(eth_header->ether_type) != 0x0800){
        printf("not ip protocol!!\n");
        return -1;
    }

    // fills IP_header
    struct IP_header *ip_header = (struct IP_header*)(packet + ETH_HEADER_LEN);

    if (ip_header->protocol != 0x06){
        printf("not tcp protocol!!\n");
        return -2;
    }

    count += ETH_HEADER_LEN + (ip_header->header_len & 0B00001111) * 4;

    // fills TCP_header
    struct TCP_header *tcp_header = (struct TCP_header*)(packet + count);

    count += (tcp_header->header_len >> 4) * 4;

    // print datas
    // print Eth_header
    printf(">>> Ethernet Header <<<\n");
    printf("Source MAC Address : ");
    for (i = 0; i < MAC_ADDR_LEN; i++) {
        printf("%02x", eth_header->saddr_MAC[i]);
        if (i != MAC_ADDR_LEN - 1){
            printf(".");
        }
        else {
            printf("\n");
        }
    }

    printf("Destination MAC Address : ");
    for (i = 0; i < MAC_ADDR_LEN; i++) {
        printf("%02x", eth_header->daddr_MAC[i]);
        if (i != MAC_ADDR_LEN - 1) {
            printf(".");
        }
        else {
            printf("\n\n");
        }
    }

    // print IP_header
    printf(">>> IP Header <<<\n");
    printf("Source IP Address : ");
    for (i = 0; i < IP_ADDR_LEN; i++) {
        printf("%d", ip_header->saddr_IP[i]);
        if (i != IP_ADDR_LEN - 1) {
            printf(".");
        }
        else {
            printf("\n");
        }
    }

    printf("Destination IP Address : ");
    for (i = 0; i < IP_ADDR_LEN; i++) {
        printf("%d", ip_header->daddr_IP[i]);
        if (i != IP_ADDR_LEN - 1) {
            printf(".");
        }
        else {
            printf("\n\n");
        }
    }

    // print TCP_header
    printf(">>> TCP Header <<<\n");
    printf("Source Port : ");
    printf("%d\n", ntohs(tcp_header->s_Port));
    
    printf("Destination Port : ");
    printf("%d\n\n", ntohs(tcp_header->d_Port));


    printf(">>> TCP Payloads <<<\n");
    if ((u_int)count == length) {
        printf("No Data\n\n");
    }
    else{
        for (i = count; i < count + 10; i++) {
	if ((u_int)i == length) {
		break;
	}
        printf("%02x ", *(packet + i));
    }
    printf("\n\n\n");
    }
    
    return 0;
}

int parse_UDP_data(const u_char * UDP_packet) {
    int count = 0;
    int i = 0;
    int j = 0;
    int mod = 0;
    
    // init headers
    struct Eth_header *eth_header = (struct Eth_header*)UDP_packet;
    if (ntohs(eth_header->ether_type) != 0x0800){
        return -1;
    }

    struct IP_header *ip_header = (struct IP_header*)(UDP_packet + ETH_HEADER_LEN);
    if (ip_header->protocol != 0x11){
        return -2;
    }

    count += ETH_HEADER_LEN + (ip_header->header_len & 0B00001111) * 4;
    mod = count % 16;

    struct UDP_header *udp_header = (struct UDP_header*)(UDP_packet + count);

    udp_header->UDP_length = ntohs(udp_header->UDP_length);
    for (i = count + 8; i <= count + udp_header->UDP_length; i++) {
        
        printf("%02x ", *(UDP_packet + i));
        
        if (i % 16 == mod) {
            printf("  :bin|string:  ");

            for (j = i - 15; j <= i; j++) {
                printf("%c", *(UDP_packet + j));
            }
        }
    }

    return 0;
}
