#include <pcap.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#pragma once

#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ETH_HEADER_LEN 14

struct Eth_header {
	u_char daddr_MAC[MAC_ADDR_LEN];
	u_char saddr_MAC[MAC_ADDR_LEN];
	u_short ether_type; // has to be 08 00
};

struct IP_header{
    u_char header_len; // bit calculation needed (45 -> 5), 15
	u_char dummy1;
    u_short total_len; // 17, 18
	u_char dummy2[5];
    u_char protocol; // has to be 06, 24
	u_char dummy3[2];
	u_char saddr_IP[IP_ADDR_LEN]; // 27~30
	u_char daddr_IP [IP_ADDR_LEN]; // 31~34
};

struct TCP_header{
	u_short s_Port; // 35, 36
	u_short d_Port; // 37, 38
	u_char dummy4[8];
	u_char header_len; // bit calculation needed (50 -> 5), 47
};

// payload location = 14 + IP_header->header_len + TCP_header->header_len

int parse_data(const u_char * packet, u_int length);
// function parse_data(packet) filles data in stuctures.