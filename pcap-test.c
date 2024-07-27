#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include "libnet-headers.h"
#include <arpa/inet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		// 1. Ethernet header
		struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*) packet;
		
		u_int8_t* s_mac = eth_hdr->ether_shost;
		u_int8_t* d_mac = eth_hdr->ether_dhost;
		u_int16_t type = eth_hdr->ether_type;

		if(type != 8) {
			printf("==============================\n");
			continue;
		}

		// 2. IP header
		struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*) (packet + 14);
		u_int8_t ip_hdr_len = (ip_hdr->ip_hl) * 4;
		u_int16_t total_len = ntohs(ip_hdr->ip_len);
		u_int8_t protocol = ip_hdr->ip_p;
		struct in_addr s_ip = ip_hdr->ip_src;
		struct in_addr d_ip = ip_hdr->ip_dst;

		if (protocol != 6) {
			printf("==============================\n");
			continue;
		}

		// 3. TCP header
		struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*) (packet + 14 + ip_hdr_len); 
		// 포인터 자료형의 크기만큼 더하고 빼기 때문에 packet은 char 단위로 연산 가능하지만 ip_hdr은 struct libnet_ipv4_hdr 단위
		// 따라서 packet에 대해 연산해야.
		u_int16_t s_port = ntohs(tcp_hdr->th_sport);
		u_int16_t d_port = ntohs(tcp_hdr->th_dport);
		u_int8_t data_offset = (tcp_hdr->th_off) * 4;


		// 4. HTTP header
		u_int8_t* data = (u_int8_t*)(packet + 14 + ip_hdr_len + data_offset);
		u_int16_t data_len = total_len - ip_hdr_len - data_offset;

		// 5. Print
		printf("[-- Src MAC addr --]\n");
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n", s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5]);
		printf("[-- Dst MAC addr --]\n");
		printf("%02x:%02x:%02x:%02x:%02x:%02x\n", d_mac[0], d_mac[1], d_mac[2], d_mac[3], d_mac[4], d_mac[5]);

		printf("[-- Src IP addr --]\n");
		printf("%s\n", inet_ntoa(s_ip));
		printf("[-- Dst IP addr --]\n");
		printf("%s\n", inet_ntoa(d_ip));

		printf("[-- Src Port --]\n");
		printf("%d\n", s_port);
		printf("[-- Dst Port --]\n");
		printf("%d\n", d_port);

		printf("[-- Payload --]\n");
		for (int i=0; i<data_len && i<20; i++) {
			printf("%x", data[i]);
		}
		printf(" (Data Len : %d)\n", data_len);
		printf("==============================\n");

	}

	pcap_close(pcap);
}
