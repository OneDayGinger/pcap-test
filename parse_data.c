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
    struct IP_header *ip_header = (struct IP_header*)(packet + 14);

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
