/* simple-web-server: Simple WEB Server using DPDK
   james@ustc.edu.cn 2018.01.03

*/

/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <signal.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_tcp.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "webserverV2"

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

//#define NUM_MBUFS 	8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 	32

#define TCPMSS 1200
#define MAXIPLEN 64000

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

#define TTL 64

//#define DEBUGPACKET
//#define DEBUGARP
//#define DEBUGICMP
//#define DEBUGTCP

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN},
	.txmode = {.mq_mode = ETH_MQ_TX_NONE},
};
struct state_info {
        struct rte_mempool *pktmbuf_pool;
        uint16_t nf_destination;
        uint32_t *source_ips;
        int print_flag;
};

struct state_info *state_info;

/* shared data structure containing host port info */
extern struct port_info *ports;

struct rte_mempool *mbuf_pool;	// ?? for multicore

struct rte_ether_addr my_eth_addr;	// My ethernet address
uint32_t my_ip;			// My IP Address in network order
uint16_t tcp_port;		// listen tcp port in network order

volatile int got_signal = 0;
#define STATS_PKTS 100000

uint32_t tcp_syn_random = 0;	// simple random sent_seq
uint64_t recv_pkts = 0;
uint64_t process_pkts = 0;
uint64_t drop_pkts = 0;
uint64_t recv_arp_pkts = 0;
uint64_t send_arp_pkts = 0;
uint64_t recv_icmp_pkts = 0;
uint64_t send_icmp_pkts = 0;
uint64_t recv_tcp_syn_pkts = 0;
uint64_t recv_tcp_data_pkts = 0;
uint64_t send_tcp_data_pkts = 0;
uint64_t send_tcp_data_multi_pkts = 0;
uint64_t recv_tcp_fin_pkts = 0;

void sig_handler_hup(int signo);
void sig_handler_hup(int signo __attribute__ ((unused)))
{
	got_signal = 1;
}

/*Prints a usage message */
static void
usage(const char *progname) {
        printf("Usage:\n");
        printf("%s [EAL args] -- [NF Lib args] -- -d <destination_id> -s <source_ip> [-p enable printing]\n", progname);
        printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]>\n\n", progname);
        printf("Flags:\n");
        printf(
            " - `-d <destination_id>`: the NF will send non-ARP packets to the NF at this service ID, e.g. `-d 2` "
            "sends packets to service ID 2\n");
        printf(
            " - `-s <source_ip_list>`: the NF will map each comma separated IP (no spaces) to the corresponding port. "
            "Example: `-s 10.0.0.31,11.0.0.31` maps port 0 to 10.0.0.31, and port 1 to 11.0.0.31. If 0.0.0.0 is "
            "inputted, the IP will be 0. If too few IPs are inputted, the remaining ports will be ignored.\n");
        printf(" - `-p`: Enables printing of log information\n");
}

static inline int user_init_func(int, char *[]);
static inline char *INET_NTOA(uint32_t ip);
static inline void swap_2bytes(unsigned char *a, unsigned char *b);
static inline void swap_4bytes(unsigned char *a, unsigned char *b);
static inline void swap_6bytes(unsigned char *a, unsigned char *b);
static inline void swap_16bytes(unsigned char *a, unsigned char *b);
static inline void dump_packet(unsigned char *buf, int len);
static inline void dump_arp_packet(struct rte_ether_hdr *eh);
static inline int process_arp(struct rte_ether_hdr *eh, int len);
static inline int process_icmp(struct rte_ether_hdr *eh, struct rte_ipv4_hdr *iph,
			       int ipv4_hdrlen, int len);
static inline int process_tcp(struct rte_mbuf *mbuf, struct rte_ether_hdr *eh, struct rte_ipv4_hdr *iph,
			      int ipv4_hdrlen, int len, struct onvm_nf *nf);
static inline int process_http(int ip_version, void *iph, struct rte_tcp_hdr *tcph,
			       unsigned char *http_req, int req_len, unsigned char *http_resp,
			       int *resp_len, int *resp_in_req);

static inline char *INET_NTOA(uint32_t ip)	// ip in network order
{
	static char buf[100];
	sprintf(buf, "%d.%d.%d.%d", (int)(ip & 0xff), (int)((ip >> 8) & 0xff),
		(int)((ip >> 16) & 0xff), (int)((ip >> 24) & 0xff));
	return buf;
}

static inline void swap_2bytes(unsigned char *a, unsigned char *b)
{
	uint16_t t;
	t = *((uint16_t *) a);
	*((uint16_t *) a) = *((uint16_t *) b);
	*((uint16_t *) b) = t;
}

static inline void swap_4bytes(unsigned char *a, unsigned char *b)
{
	uint32_t t;
	t = *((uint32_t *) a);
	*((uint32_t *) a) = *((uint32_t *) b);
	*((uint32_t *) b) = t;
}

static inline void swap_6bytes(unsigned char *a, unsigned char *b)
{
	swap_4bytes(a, b);
	swap_2bytes(a + 4, b + 4);
}

static inline void swap_16bytes(unsigned char *a, unsigned char *b)
{
	swap_4bytes(a, b);
	swap_4bytes(a + 4, b + 4);
	swap_4bytes(a + 8, b + 8);
	swap_4bytes(a + 12, b + 12);
}

/* Parse how many IPs are in the input string */
static int
get_ip_count(char *input_string, const char *delim) {
        int ip_count = 0;
        char *token = NULL;
        char *buffer = NULL;
        char *ip_string = NULL;
        size_t length = sizeof(input_string);

        if (input_string == NULL || delim == NULL) {
                return -1;
        }

        ip_string = rte_calloc("Copy of IP String", sizeof(input_string), sizeof(char), 0);
        if (ip_string == NULL) {
                RTE_LOG(INFO, APP, "Unable to allocate space for IP string");
                return -1;
        }

        strncpy(ip_string, input_string, length);
        token = strtok_r(ip_string, delim, &buffer);

        while (token != NULL) {
                ++ip_count;
                token = strtok_r(NULL, delim, &buffer);
        }

        return ip_count;
}

/*Parses through app args, crashes if the 2 required args aren't set */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c = -1;
        //int dst_flag = 0;
        int ip_flag = 0;
        int num_ips = 0;
        int current_ip = 0;
        int result = 0;
        const char delim[2] = ",";
        char *token;
        char *buffer;
        state_info->print_flag = 0;
        state_info->source_ips = rte_calloc("Array of decimal IPs", ports->num_ports, sizeof(uint32_t), 0);
        if (state_info->source_ips == NULL) {
                RTE_LOG(INFO, APP, "Unable to initialize source IP array\n");
                return -1;
        }

        while ((c = getopt(argc, argv, "d:s:p")) != -1) {
                switch (c) {
/*                        case 'd':
                                state_info->nf_destination = strtoul(optarg, NULL, 10);
                                dst_flag = 1;
                                RTE_LOG(INFO, APP, "Sending packets to service ID %d\n", state_info->nf_destination);
                                break;*/
                        case 's':
                                num_ips = get_ip_count(optarg, delim);
                                if (num_ips > ports->num_ports) {
                                        RTE_LOG(INFO, APP, "Too many IPs were entered!\n");
                                        return -1;
                                }

                                if (num_ips < 0) {
                                        RTE_LOG(INFO, APP, "Invalid IP pointer\n");
                                        return -1;
                                }

                                token = strtok_r(optarg, delim, &buffer);
                                while (token != NULL) {
                                        result = onvm_pkt_parse_ip(token, &state_info->source_ips[current_ip]);
                                        if (result < 0) {
                                                RTE_LOG(INFO, APP, "Invalid IP entered");
                                                return -1;
                                        }
                                        ++current_ip;
                                        token = strtok_r(NULL, delim, &buffer);
                                }

                                ip_flag = 1;
                                break;
                        case 'p':
                                state_info->print_flag = 1;
                                break;
                        case '?':
                                usage(progname);
                                if (optopt == 'd')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument\n", optopt);
                                else if (optopt == 'd')
                                        RTE_LOG(INFO, APP, "Option -%c requires an argument\n", optopt);
                                else
                                        RTE_LOG(INFO, APP, "Unknown option character\n");

                                return -1;
                        default:
                                usage(progname);
                                return -1;
                }
        }

/*        if (!dst_flag) {
                RTE_LOG(INFO, APP, "ARP Response NF needs a destination NF service ID with the -d flag\n");
                return -1;
        }
*/
        if (!ip_flag) {
                RTE_LOG(INFO, APP, "webserver NF needs comma separated IPs with the -s flag\n");
                return -1;
        }

        return optind;
}
static inline void dump_packet(unsigned char *buf, int len)
{
	printf("+++++++++++++++++++++++++++++++++++++++\n");
	printf("packet buf=%p len=%d\n", buf, len);
	int i, j;
	unsigned char c;
	for (i = 0; i < len; i++) {
		printf("%02X", buf[i]);
		if (i % 16 == 7)
			printf("  ");
		if ((i % 16) == 15 || (i == len - 1)) {
			if (i % 16 < 7)
				printf("  ");
			for (j = 0; j < 15 - (i % 16); j++)
				printf("  ");
			printf(" | ");
			for (j = (i - (i % 16)); j <= i; j++) {
				c = buf[j];
				if ((c > 31) && (c < 127))
					printf("%c", c);
				else
					printf(".");
			}
			printf("\n");
		}
	}
}

static inline void dump_arp_packet(struct rte_ether_hdr *eh)
{
	struct rte_arp_hdr *ah;
	ah = (struct rte_arp_hdr *)((unsigned char *)eh + RTE_ETHER_HDR_LEN);
	printf("+++++++++++++++++++++++++++++++++++++++\n");
	printf("ARP PACKET: %p \n", eh);
	printf("ETHER DST MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
	       eh->d_addr.addr_bytes[0], eh->d_addr.addr_bytes[1],
	       eh->d_addr.addr_bytes[2], eh->d_addr.addr_bytes[3], eh->d_addr.addr_bytes[4],
	       eh->d_addr.addr_bytes[5]);
	printf("ETHER SRC MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n", eh->s_addr.addr_bytes[0],
	       eh->s_addr.addr_bytes[1], eh->s_addr.addr_bytes[2], eh->s_addr.addr_bytes[3],
	       eh->s_addr.addr_bytes[4], eh->s_addr.addr_bytes[5]);
	printf("H/D TYPE : %x PROTO TYPE : %X \n", ah->arp_hardware, ah->arp_protocol);
	printf("H/D LEN  : %x PROTO LEN  : %X \n", ah->arp_hlen, ah->arp_plen);
	printf("OPERATION : %x \n", ah->arp_opcode);
	printf("SENDER MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
	       ah->arp_data.arp_sha.addr_bytes[0], ah->arp_data.arp_sha.addr_bytes[1],
	       ah->arp_data.arp_sha.addr_bytes[2], ah->arp_data.arp_sha.addr_bytes[3],
	       ah->arp_data.arp_sha.addr_bytes[4], ah->arp_data.arp_sha.addr_bytes[5]);
	printf("SENDER IP address : %d.%d.%d.%d\n",
	       ((unsigned)((unsigned char *)&(ah->arp_data.arp_sip))[0]),
	       ((unsigned)((unsigned char *)&(ah->arp_data.arp_sip))[1]),
	       ((unsigned)((unsigned char *)&(ah->arp_data.arp_sip))[2]),
	       ((unsigned)((unsigned char *)&(ah->arp_data.arp_sip))[3]));
	printf("TARGET MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
	       ah->arp_data.arp_tha.addr_bytes[0], ah->arp_data.arp_tha.addr_bytes[1],
	       ah->arp_data.arp_tha.addr_bytes[2], ah->arp_data.arp_tha.addr_bytes[3],
	       ah->arp_data.arp_tha.addr_bytes[4], ah->arp_data.arp_tha.addr_bytes[5]);
	printf("TARGET IP address : %d.%d.%d.%d\n",
	       ((unsigned)((unsigned char *)&(ah->arp_data.arp_tip))[0]),
	       ((unsigned)((unsigned char *)&(ah->arp_data.arp_tip))[1]),
	       ((unsigned)((unsigned char *)&(ah->arp_data.arp_tip))[2]),
	       ((unsigned)((unsigned char *)&(ah->arp_data.arp_tip))[3]));
}

static inline int process_arp(struct rte_ether_hdr *eh, int len)
{
	struct rte_arp_hdr *ah = (struct rte_arp_hdr *)((unsigned char *)eh + RTE_ETHER_HDR_LEN);
#ifdef DEBUGARP
	dump_arp_packet(eh);
#endif
	recv_arp_pkts++;
	if (len < (int)(sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr))) {
#ifdef DEBUGICMP
		printf("len = %d is too small for arp packet??\n", len);
#endif
		return 0;
	}
	if (rte_cpu_to_be_16(ah->arp_opcode) != RTE_ARP_OP_REQUEST) {	// ARP request
		return 0;
	}
	if (my_ip == ah->arp_data.arp_tip) {
#ifdef DEBUGARP
		printf("ARP asking me....\n");
#endif
		rte_memcpy((unsigned char *)&eh->d_addr, (unsigned char *)&eh->s_addr, 6);
		rte_memcpy((unsigned char *)&eh->s_addr, (unsigned char *)&my_eth_addr, 6);
		ah->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
		ah->arp_data.arp_tha = ah->arp_data.arp_sha;
		rte_memcpy((unsigned char *)&ah->arp_data.arp_sha, (unsigned char *)&my_eth_addr,
			   6);
		ah->arp_data.arp_tip = ah->arp_data.arp_sip;
		ah->arp_data.arp_sip = my_ip;
#ifdef DEBUGARP
		printf("I will reply following \n");
		dump_arp_packet(eh);
#endif
		send_arp_pkts++;
		return 1;
	}
	return 0;
}

static inline int process_icmp(struct rte_ether_hdr *eh, struct rte_ipv4_hdr *iph,
			       int ipv4_hdrlen, int len)
{
	struct rte_icmp_hdr *icmph = (struct rte_icmp_hdr *)((unsigned char *)(iph) + ipv4_hdrlen);
#ifdef DEBUGICMP
	printf("icmp type=%d, code=%d\n", icmph->icmp_type, icmph->icmp_code);
#endif
	recv_icmp_pkts++;
	if (len < (int)(sizeof(struct rte_ether_hdr) + sizeof(struct rte_icmp_hdr))) {
#ifdef DEBUGICMP
		printf("len = %d is too small for icmp packet??\n", len);
#endif
		return 0;
	}
	if ((icmph->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) && (icmph->icmp_code == 0)) {	// ICMP echo req
		rte_memcpy((unsigned char *)&eh->d_addr, (unsigned char *)&eh->s_addr, 6);
		rte_memcpy((unsigned char *)&eh->s_addr, (unsigned char *)&my_eth_addr, 6);
		iph->dst_addr = iph->src_addr;
		iph->src_addr = my_ip;
		iph->time_to_live = TTL;
		iph->hdr_checksum = 0;
		iph->hdr_checksum = rte_ipv4_cksum(iph);
		icmph->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
		icmph->icmp_cksum = 0;
		icmph->icmp_cksum = ~rte_raw_cksum(icmph, len - RTE_ETHER_HDR_LEN - ipv4_hdrlen);
#ifdef DEBUGICMP
		printf("I will send reply\n");
		dump_packet(rte_pktmbuf_mtod(mbuf, unsigned char *), len);
#endif
		send_icmp_pkts++;
		return 1;
	}
	return 0;
}

static inline int process_tcp(struct rte_mbuf *mbuf, struct rte_ether_hdr *eh, struct rte_ipv4_hdr *iph,
			      int ipv4_hdrlen, int len, struct onvm_nf *nf)
{
	struct rte_tcp_hdr *tcph = (struct rte_tcp_hdr *)((unsigned char *)(iph) + ipv4_hdrlen);
	int pkt_len;
	struct onvm_pkt_meta *pmeta = NULL;
#ifdef DEBUGTCP
	printf("TCP packet, dport=%d\n", rte_be_to_cpu_16(tcph->dst_port));
	printf("TCP flags=%d\n", tcph->tcp_flags);
#endif
	if (len < (int)(sizeof(struct rte_ether_hdr) + ipv4_hdrlen + sizeof(struct rte_tcp_hdr))) {
#ifdef DEBUGICMP
		printf("len = %d is too small for tcp packet??\n", len);
#endif
		return 0;
	}
	if (tcph->dst_port != tcp_port)
		return 0;

	if ((tcph->tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) {	// SYN packet, send SYN+ACK
#ifdef DEBUGTCP
		printf("SYN packet\n");
#endif
		recv_tcp_syn_pkts++;

		swap_6bytes((unsigned char *)&eh->s_addr, (unsigned char *)&eh->d_addr);
		swap_4bytes((unsigned char *)&iph->src_addr, (unsigned char *)&iph->dst_addr);
		swap_2bytes((unsigned char *)&tcph->src_port, (unsigned char *)&tcph->dst_port);
		tcph->tcp_flags = TCP_ACK | TCP_SYN;
		tcph->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->sent_seq) + 1);
		tcph->sent_seq =
		    rte_cpu_to_be_32(*(uint32_t *) & iph->src_addr +
				     *(uint32_t *) & iph->dst_addr +
				     *(uint16_t *) & tcph->src_port +
				     *(uint16_t *) & tcph->dst_port + tcp_syn_random);
		tcph->data_off = (sizeof(struct rte_tcp_hdr) / 4) << 4;
		tcph->cksum = 0;
		pkt_len = ipv4_hdrlen + sizeof(struct rte_tcp_hdr);
		iph->total_length = rte_cpu_to_be_16(pkt_len);
		iph->hdr_checksum = 0;
		iph->time_to_live = TTL;
		rte_pktmbuf_data_len(mbuf) = rte_pktmbuf_pkt_len(mbuf) = pkt_len + RTE_ETHER_HDR_LEN;

		tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);
		iph->hdr_checksum = rte_ipv4_cksum(iph);
#ifdef DEBUGTCP
		printf("I will reply following:\n");
		dump_packet((unsigned char *)eh, rte_pktmbuf_data_len(mbuf));
#endif
		pmeta = onvm_get_pkt_meta(mbuf);
		pmeta->destination = mbuf->port;
                pmeta->action = ONVM_NF_ACTION_OUT;
		return 1;
#ifdef DEBUGTCP
		//printf("send tcp packet return %d\n", ret);
#endif
	} else if (tcph->tcp_flags & TCP_FIN) {	// FIN packet, send ACK
#ifdef DEBUGTCP
		fprintf(stderr, "FIN packet\n");
#endif
		recv_tcp_fin_pkts++;
		swap_6bytes((unsigned char *)&eh->s_addr, (unsigned char *)&eh->d_addr);
		swap_4bytes((unsigned char *)&iph->src_addr, (unsigned char *)&iph->dst_addr);
		swap_2bytes((unsigned char *)&tcph->src_port, (unsigned char *)&tcph->dst_port);
		swap_4bytes((unsigned char *)&tcph->sent_seq, (unsigned char *)&tcph->recv_ack);
		tcph->tcp_flags = TCP_ACK;
		tcph->recv_ack = rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->recv_ack) + 1);
		tcph->data_off = (sizeof(struct rte_tcp_hdr) / 4) << 4;
		tcph->cksum = 0;
		pkt_len = ipv4_hdrlen + sizeof(struct rte_tcp_hdr);
		iph->total_length = rte_cpu_to_be_16(pkt_len);
		iph->hdr_checksum = 0;
		iph->time_to_live = TTL;
		rte_pktmbuf_data_len(mbuf) = rte_pktmbuf_pkt_len(mbuf) = pkt_len + RTE_ETHER_HDR_LEN;

		tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);
		iph->hdr_checksum = rte_ipv4_cksum(iph);
#ifdef DEBUGTCP
		printf("I will reply following:\n");
		dump_packet((unsigned char *)eh, rte_pktmbuf_data_len(mbuf));
#endif
                pmeta = onvm_get_pkt_meta(mbuf);
                pmeta->destination = mbuf->port;
                pmeta->action = ONVM_NF_ACTION_OUT;
		return 1;
#ifdef DEBUGTCP
		//fprintf(stderr, "send tcp packet return %d\n", ret);
#endif
	} else if ((tcph->tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_ACK) {	// ACK packet, send DATA
		pkt_len = rte_be_to_cpu_16(iph->total_length);
		int tcp_payload_len = pkt_len - ipv4_hdrlen - (tcph->data_off >> 4) * 4;
		int ntcp_payload_len = MAXIPLEN;
		unsigned char *tcp_payload;
		unsigned char buf[MAXIPLEN + sizeof(struct rte_tcp_hdr)];	// http_response
		int resp_in_req = 0;
		recv_tcp_data_pkts++;
#ifdef DEBUGTCP
		printf("ACK pkt len=%d(inc ether) ip len=%d\n", rte_pktmbuf_data_len(mbuf),
		       pkt_len);
		printf("tcp payload len=%d\n", tcp_payload_len);
#endif
		if (tcp_payload_len <= 5) {
#ifdef DEBUGTCP
			printf("tcp payload len=%d too small, ignore\n", tcp_payload_len);
#endif
			return 0;
		}
		if (tcph->recv_ack !=
		    rte_cpu_to_be_32(*(uint32_t *) & iph->src_addr +
				     *(uint32_t *) & iph->dst_addr +
				     *(uint16_t *) & tcph->src_port +
				     *(uint16_t *) & tcph->dst_port + tcp_syn_random + 1)) {
#ifdef DEBUGTCP
			printf("ack_seq error\n");
#endif
			return 0;
		}
		tcp_payload = (unsigned char *)iph + ipv4_hdrlen + (tcph->data_off >> 4) * 4;
		if (process_http
		    (4, iph, tcph, tcp_payload, tcp_payload_len, buf + sizeof(struct rte_tcp_hdr),
		     &ntcp_payload_len, &resp_in_req) == 0)
			return 0;
#ifdef DEBUGTCP
		printf("http return new payload len=%d\n", ntcp_payload_len);
#endif
		uint32_t ack_seq =
		    rte_cpu_to_be_32(rte_be_to_cpu_32(tcph->sent_seq) + tcp_payload_len);
		swap_6bytes((unsigned char *)&eh->s_addr, (unsigned char *)&eh->d_addr);
		swap_4bytes((unsigned char *)&iph->src_addr, (unsigned char *)&iph->dst_addr);
		swap_2bytes((unsigned char *)&tcph->src_port, (unsigned char *)&tcph->dst_port);
		tcph->tcp_flags = TCP_ACK | TCP_PSH | TCP_FIN;
		tcph->sent_seq = tcph->recv_ack;
		tcph->recv_ack = ack_seq;
		tcph->cksum = 0;
		iph->hdr_checksum = 0;
		iph->time_to_live = TTL;

		if (ntcp_payload_len <= TCPMSS) {	// tcp packet fit in one IP packet
			if (!resp_in_req)
				rte_memcpy(tcp_payload, buf + sizeof(struct rte_tcp_hdr),
					   ntcp_payload_len);
			pkt_len = ntcp_payload_len + ipv4_hdrlen + (tcph->data_off >> 4) * 4;
			iph->total_length = rte_cpu_to_be_16(pkt_len);
			iph->fragment_offset = 0;
#ifdef DEBUGTCP
			fprintf(stderr, "new pkt len=%d\n", pkt_len);
#endif
			rte_pktmbuf_data_len(mbuf) = rte_pktmbuf_pkt_len(mbuf) =
			    pkt_len + RTE_ETHER_HDR_LEN;
			
			tcph->cksum = rte_ipv4_udptcp_cksum(iph, tcph);
			iph->hdr_checksum = rte_ipv4_cksum(iph);
#ifdef DEBUGTCP
			printf("I will reply following:\n");
			dump_packet((unsigned char *)eh, rte_pktmbuf_data_len(mbuf));
#endif
                        pmeta = onvm_get_pkt_meta(mbuf);
                        pmeta->destination = mbuf->port;
                        pmeta->action = ONVM_NF_ACTION_OUT;
			send_tcp_data_pkts++;
			return 1;
#ifdef DEBUGTCP
			//fprintf(stderr, "send tcp packet return %d\n", ret);
#endif
		} else {	// tcp packet could not fit in one IP packet, I will send one by one
			struct rte_mbuf *frag;
			struct rte_ether_hdr *neh;
			struct rte_ipv4_hdr *niph;
			struct rte_tcp_hdr *ntcph;
			int left = ntcp_payload_len + sizeof(struct rte_tcp_hdr);
			uint32_t offset = 0;
			if (resp_in_req) {
				printf("BIG TCP packet, must returned in my buf\n");
				return 0;
			}
			iph->total_length = rte_cpu_to_be_16(left + sizeof(struct rte_ipv4_hdr));
			iph->fragment_offset = 0;
			iph->packet_id = tcph->dst_port;
			tcph->data_off = (sizeof(struct rte_tcp_hdr) / 4) << 4;
			ntcph = (struct rte_tcp_hdr *)buf;
			rte_memcpy(ntcph, tcph, sizeof(struct rte_tcp_hdr));	// copy tcp header to begin of buf
			ntcph->cksum = rte_ipv4_udptcp_cksum(iph, ntcph);	// trick but works, now eth/ip header in mbuf, tcp packet in buf
			while (left > 0) {
				len = left < TCPMSS ? left : (TCPMSS & 0xfff0);
				left -= len;
#ifdef DEBUGTCP
				printf("offset=%d len=%d\n", offset, len);
#endif
				frag = rte_pktmbuf_alloc(state_info->pktmbuf_pool);
				if (!frag) {
					printf("mutli packet alloc error\n");
					return 0;
				}
				neh = rte_pktmbuf_mtod(frag, struct rte_ether_hdr *);
				rte_memcpy(neh, eh, RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr));	// copy eth/ip header
				niph = (struct rte_ipv4_hdr *)((unsigned char *)(neh) + RTE_ETHER_HDR_LEN);
				ntcph =
				    (struct rte_tcp_hdr *)((unsigned char *)(niph) +
						       sizeof(struct rte_ipv4_hdr));
				rte_memcpy(ntcph, buf + offset, len);

				pkt_len = len + sizeof(struct rte_ipv4_hdr);
				niph->total_length = rte_cpu_to_be_16(pkt_len);
				niph->fragment_offset = rte_cpu_to_be_16(offset >> 3);
				if (left > 0)
					niph->fragment_offset |= rte_cpu_to_be_16(RTE_IPV4_HDR_MF_FLAG);
#ifdef DEBUGTCP
				fprintf(stderr, "frag offset %d, pkt len=%d\n", offset, pkt_len);
#endif
				rte_pktmbuf_data_len(frag) = rte_pktmbuf_pkt_len(frag) =
				    pkt_len + RTE_ETHER_HDR_LEN;
				
				niph->hdr_checksum = rte_ipv4_cksum(niph);

#ifdef DEBUGTCP
                                printf("I will reply following:\n");
                                dump_packet((unsigned char *)neh, rte_pktmbuf_data_len(frag));
#endif
				pmeta = onvm_get_pkt_meta(frag);
				pmeta->destination = mbuf->port;
			        pmeta->action = ONVM_NF_ACTION_OUT;

				send_tcp_data_multi_pkts++;
				offset += len;
				onvm_nflib_return_pkt(nf, frag);
			}
			rte_pktmbuf_free(mbuf);
			return 1;
		}
	}
	return 0;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
//static __attribute__ ((noreturn))
//void lcore_main(void)
static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
               __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx)
{
	int len = rte_pktmbuf_data_len(pkt);
	struct rte_ether_hdr *eh = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	recv_pkts++;
	meta->action = ONVM_NF_ACTION_DROP; // drop on default
	if (eh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {	// IPv4 protocol
		struct rte_ipv4_hdr *iph;
		iph = (struct rte_ipv4_hdr *)((unsigned char *)(eh) + RTE_ETHER_HDR_LEN);
		int ipv4_hdrlen = (iph->version_ihl & RTE_IPV4_HDR_IHL_MASK) << 2;
		if (((iph->version_ihl & 0xF0) == 0x40) && ((iph->fragment_offset & rte_cpu_to_be_16(RTE_IPV4_HDR_OFFSET_MASK)) == 0) && (iph->dst_addr == my_ip)) {	// ipv4
			if (iph->next_proto_id == 6) {	// TCP
				process_pkts++;
				if (process_tcp(pkt, eh, iph, ipv4_hdrlen, len, nf_local_ctx->nf)) {
					meta->action = ONVM_NF_ACTION_OUT;
					return 0;
				}
				else {
					//meta->action = ONVM_NF_ACTION_DROP;
					return 0;
				}
			} else if (iph->next_proto_id == 1) {	// ICMP
				process_pkts++;
				if (process_icmp(eh, iph, ipv4_hdrlen, len)) {
					meta->destination = pkt->port;
                                        meta->action = ONVM_NF_ACTION_OUT;
					return 0;
                                }
                                else {
                                        //meta->action = ONVM_NF_ACTION_DROP;
					return 0;
				}
			}
			//meta->action = ONVM_NF_ACTION_DROP;
			//return 0;
		}
		//meta->action = ONVM_NF_ACTION_DROP;
		//return 0;
	} else if (eh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {	// ARP protocol
		process_pkts++;
		if (process_arp(eh, len)) {
			meta->destination = pkt->port;
                        meta->action = ONVM_NF_ACTION_OUT;
			return 0;
                }
                else {
                        //meta->action = ONVM_NF_ACTION_DROP;
			return 0;
		}
	}
	//meta->action = ONVM_NF_ACTION_DROP;
	return 0;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[])
{
        int arg_offset;
        struct onvm_nf_local_ctx *nf_local_ctx;
        struct onvm_nf_function_table *nf_function_table;
        const char *progname = argv[0];

        nf_local_ctx = onvm_nflib_init_nf_local_ctx();
        onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

        nf_function_table = onvm_nflib_init_nf_function_table();
        nf_function_table->pkt_handler = &packet_handler;

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                if (arg_offset == ONVM_SIGNAL_TERMINATION) {
                        printf("Exiting due to user termination\n");
                        return 0;
                } else {
                        rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
                }
        }

        argc -= arg_offset;
        argv += arg_offset;

	tcp_port = rte_cpu_to_be_16(80);
	signal(SIGHUP, sig_handler_hup);
	user_init_func(argc, argv);

	srand(time(NULL));
	tcp_syn_random = rand();

        state_info = rte_calloc("state", 1, sizeof(struct state_info), 0);
        if (state_info == NULL) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Unable to initialize NF state");
        }

        state_info->pktmbuf_pool = rte_mempool_lookup(PKTMBUF_CLONE_POOL_NAME);
        if (state_info->pktmbuf_pool == NULL) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
        }

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop(nf_local_ctx);
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments");
        }
	my_ip = rte_cpu_to_be_32(state_info->source_ips[ports->id[0]]);
	printf("My IP is: %s, port is %d\n", INET_NTOA(my_ip), rte_be_to_cpu_16(tcp_port));
	my_eth_addr = ports->mac[0];
        printf("My ether addr is: %02X:%02X:%02X:%02X:%02X:%02X\n",
               my_eth_addr.addr_bytes[0], my_eth_addr.addr_bytes[1],
               my_eth_addr.addr_bytes[2], my_eth_addr.addr_bytes[3], my_eth_addr.addr_bytes[4],
               my_eth_addr.addr_bytes[5]);
        onvm_nflib_run(nf_local_ctx);

        onvm_nflib_stop(nf_local_ctx);

        if (state_info)
                rte_free(state_info);

        printf("If we reach here, program is ending\n");
	return 0;
}
