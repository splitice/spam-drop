/*
Purpose: Filtering Process for SMTP (Interception & Parsing). Everything is brought together here.
*/
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/linux_nfnetlink_queue.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <sys/time.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <stdio.h>
#include <stdint.h>
#include <map>
#include <cstring>
#include "filter.h"
#include "debug.h"
#include "read_buffer.h"
#include "ip_address.h"

timeval cur_time;
struct nfq_handle *handle;
struct nfq_q_handle *queue;
struct nfnl_handle *netlink_handle;

//Structure of an IP packet
struct ipv4_header {
	u_int8_t        ip_vhl;          /* header length, version    */
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)   ((ip)->ip_vhl & 0x0f)
	u_int8_t        ip_tos;          /* type of service           */
	u_int16_t       ip_len;          /* total length              */
	u_int16_t       ip_id;           /* identification            */
	u_int16_t       ip_off;          /* fragment offset field     */
#define IP_DF 0x4000                 /* dont fragment flag        */
#define IP_MF 0x2000                 /* more fragments flag       */
#define IP_OFFMASK 0x1fff            /* mask for fragmenting bits */
	u_int8_t        ip_ttl;          /* time to live              */
	u_int8_t        ip_p;            /* protocol                  */
	u_int16_t       ip_sum;          /* checksum                  */
	struct  ipv4_address ip_src, ip_dst;  /* source and dest address   */
};

struct ipv6_header
{
	uint32_t        ip_vtcfl;	/* version then traffic class and flow label */
#define IP6_V(ip)		(ntohl((ip)->ip_vtcfl) >> 28)
	uint16_t length;
	uint8_t  next_header;
	uint8_t  hop_limit;
	struct ipv6_address src;
	struct ipv6_address dst;
};

struct tcp_header {
	u_short th_sport; /* source port            */
	u_short th_dport; /* destination port       */
	uint32_t th_seq;   /* sequence number        */
	uint32_t th_ack;   /* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int th_x2 : 4,    /* (unused)    */
	th_off : 4;         /* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN
	u_int th_off : 4,   /* data offset */
	th_x2 : 4;          /* (unused)    */
#endif
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
	u_short th_win; /* window */
	u_short th_sum; /* checksum */
	u_short th_urp; /* urgent pointer */
};


struct flow_entry {
	struct ip_address src;
	struct ip_address dst;
	uint16_t srcport;
	uint16_t dstport;
};

struct cmp_flow_entry
{
	bool operator()(struct flow_entry* a, struct flow_entry* b)
	{
		return std::memcmp(a, b, sizeof(struct flow_entry)) < 0;
	}
};

struct flow_state {
	timeval last_action;
	uint16_t last_seq;
};

struct out_of_order_key {

};


typedef std::map<struct flow_entry*, struct flow_state, struct cmp_flow_entry> ConnectionsMap;
typedef std::pair<struct flow_entry*, struct flow_state> ConnectionsPair;

ConnectionsMap connections;

void nfq_verdict_drop(struct nfq_q_handle *qh, int id){
	nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

void nfq_verdict_accept(struct nfq_q_handle *qh, int id){
	nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}



void flow_bump(ConnectionsMap::iterator it){
	it->second.last_action = cur_time;
}

ConnectionsPair flow_create(struct ip_address& src, struct ip_address& dst, uint16_t sport, uint16_t dport, uint16_t seq){
	//Create the flow object
	struct flow_entry* flow = (struct flow_entry*)malloc(sizeof(struct flow_entry));
	flow->dst = dst;
	flow->src = src;
	flow->dstport = dport;
	flow->srcport = sport;

	//Search for an already existing connection, if so return it
	ConnectionsMap::iterator it = connections.find(flow);
	if (it != connections.end()){
		free(flow);
		flow_bump(it);
		return *it;
	}

	//Create the new connection
	struct flow_state state;
	state.last_action = cur_time;
	state.last_seq = seq;
	ConnectionsPair pair(flow, state);
	connections.insert(pair);

	return pair;
}

bool flow_destroy(flow_entry* flow){
	ConnectionsMap::iterator it = connections.find(flow);
	if (it != connections.end()){
		free(it->first);
		connections.erase(it);
		return true;
	}
	return false;
}

ConnectionsPair flow_get(struct ip_address src, struct ip_address dst, uint16_t sport, uint16_t dport){
	struct flow_entry flow;
	flow.dst = dst;
	flow.src = src;
	flow.dstport = dport;
	flow.srcport = sport;

	ConnectionsMap::iterator it = connections.find(&flow);
	if (it == connections.end()){
		return ConnectionsPair(NULL, {});
	}

	flow_bump(it);

	return *it;
}

void tcp_filter_payload(ConnectionsPair& flow_pair, unsigned char* payload, uint16_t payload_length, struct nfq_q_handle *qh, int id){

}

void tcp_filter(struct ip_address& src, struct ip_address& dst, const struct tcp_header* tcp, uint16_t payload_length, struct nfq_q_handle *qh, int id){
	ConnectionsPair flow_pair;
	unsigned char* payload;
	uint16_t seq = ntohs(tcp->th_seq);

	if (tcp->th_flags & TH_SYN){
		DEBUG("[#] SYN Flag set attemping to create flow\n");
		flow_pair = flow_create(src, dst, tcp->th_sport, tcp->th_dport, seq);
	}
	else{
		DEBUG("[#] Attemping to lookup flow\n");
		flow_pair = flow_get(src, dst, tcp->th_sport, tcp->th_dport);
	}

	//Check if we couldnt find a valid flow
	if (flow_pair.first == NULL){
		DEBUG("[#] No flow found, packet accepted by default\n");
		//ACCEPT by default
		nfq_verdict_accept(qh, id);
		return;
	}

	//Handle SEQ
	if (!(tcp->th_flags & TH_SYN)){
		if (flow_pair.second.last_seq <= seq){
			//ACCEPT resend by default
			nfq_verdict_accept(qh, id);
			return;
		}

		if ((flow_pair.second.last_seq + 1) != seq){
			//Out of order
			DEBUG("[#] Out of order packet received, expected %d got %d\n", flow_pair.second.last_seq + 1, seq);
		}
	}

	//Handle any data
	if (payload_length){
		DEBUG("[#] Packet has payload, attempting to filter\n");
		payload = ((unsigned char*)tcp) + sizeof(struct tcp_header);
		tcp_filter_payload(flow_pair, payload, payload_length, qh, id);
	}
	else{
		nfq_verdict_accept(qh, id);
	}

	//Destroy the flow if needed
	if (tcp->th_flags & TH_RST || tcp->th_flags & TH_FIN){
		DEBUG("[#] Destroying flow, end of connection.\n");
		flow_destroy(flow_pair.first);
	}
}

void ipv4_filter(struct ipv4_header* ip, struct nfq_q_handle *qh, int id){
	unsigned char* payload = (unsigned char*)ip;
	uint8_t header_length = (IP_HL(ip) >> 4);
	uint16_t payload_length = ip->ip_len;
	struct ip_address src;
	struct ip_address dst;

	if (ip->ip_p == htons(6)){
		tcp_filter(src, dst, (struct tcp_header*)(((char*)ip) + header_length),payload_length,qh,id);
	}
	else{
		nfq_verdict_accept(qh, id);
	}
}

/* Return true if packet is to be accepted */
void ip_filter(const struct iphdr* ip, struct nfq_q_handle *qh, int id){
	u_int version;               /*  version                 */
	u_int16_t len;               /* length holder            */
	len = ntohs(ip->tot_len); /* get packet length */

	//Check IP version
	if (ip->version == 4){
		ipv4_filter((struct ipv4_header*)ip, qh, id);
	}
	else if (ip->version == 6){
		//Extract TCP
	}
}

static int manage_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data2)
{
	unsigned char *payload;
	int id = -1;
	struct nfqnl_msg_packet_hdr *packetHeader;


	if (nfq_get_timestamp(nfa, &cur_time) != 0){
		gettimeofday(&cur_time, NULL);
	}

	if ((packetHeader = nfq_get_msg_packet_hdr(nfa)) != NULL){
		id = ntohl(packetHeader->packet_id);
	}


#pragma GCC diagnostic push
#pragma GCC diagnostic warning "-fpermissive"

	nfq_get_payload(nfa, &payload);
#pragma GCC diagnostic pop

	struct iphdr *iphdr = (struct iphdr *) payload;

	ip_filter(iphdr, qh, id);

	return id;
}

void smtp_filter_close(){
	DEBUG("[#] Cleaning up NFQUEUE\n");

	// Free the mallocs
	if (queue != NULL)
	{
		nfq_destroy_queue(queue);
	}
	if (handle != NULL)
	{
		nfq_close(handle);
	}
}

int smtp_filter_setup(uint16_t qnum)
{
	int nfqueue_fd;

	// NF_QUEUE initializing
	handle = nfq_open();
	if (!handle)
	{
		PFATAL("Error: during nfq_open()");
		goto end;
	}

	if (nfq_unbind_pf(handle, AF_INET) < 0)
	{
		PFATAL("Error: during nfq_unbind_pf()");
		goto end;
	}

	if (nfq_bind_pf(handle, AF_INET) < 0)
	{
		PFATAL("Error: during nfq_bind_pf()");
		goto end;
	}

	queue = nfq_create_queue(handle, qnum, &manage_packet, NULL);
	if (!queue)
	{
		PFATAL("Error: during nfq_create_queue()");
		goto end;
	}

	nfq_set_queue_maxlen(queue, 1000);

	if (nfq_set_mode(queue, NFQNL_COPY_PACKET, 150) < 0)
	{
		PFATAL("Error: can't set packet_copy mode");
		goto end;
	}

	netlink_handle = nfq_nfnlh(handle);

	nfnl_rcvbufsiz(netlink_handle, 1000 * 1500);
	// End of NF_QUEUE initializing

	printf("# End of NF_QUEUE initializing. Listening on queue: %d\n", qnum);


	nfqueue_fd = nfnl_fd(netlink_handle);

	return nfqueue_fd;

end:
	smtp_filter_close();
}

void smtp_filter_process(int nfqueue_fd){
	char buf[4096] __attribute__((aligned));
	int received;
	received = recv(nfqueue_fd, buf, sizeof(buf), 0);
	if (received == -1)
	{
		PFATAL("Error receiving packet");
	}
	// Call the handle
	nfq_handle_packet(handle, buf, received);
}