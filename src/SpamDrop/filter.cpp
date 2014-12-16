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
#include "debug.h"
#include "read_buffer.h"
#include "khash.h"

timeval cur_time;
struct nfq_handle *handle;
struct nfq_q_handle *queue;
struct nfnl_handle *netlink_handle;

struct connection_entry {
	struct in_addr src;
	struct in_addr dst;
	uint16_t srcport;
	uint16_t dstport;
	int state;//TODO: state enum
};

KHASH_MAP_INIT_INT(connection, struct connection_entry*);
khash_t(connection) *connections;

char _ip_buffer[17];
const char* ip_format(uint32_t ip){
	snprintf(_ip_buffer, 16, "%d.%d.%d.%d", (ip >> 24) & 0xFF,
		(ip >> 16) & 0xFF,
		(ip >> 8) & 0xFF,
		ip & 0xFF);
	return _ip_buffer;
}

bool tcp_filter(const struct tcphdr tcp){

}

/* Return true if packet is to be accepted */
bool ip_filter(const struct iphdr* ip){
	u_int version;               /*  version                 */
	u_int16_t len;               /* length holder            */
	len = ntohs(ip->tot_len); /* get packet length */

	//Check IP version
	if (ip->version == 4){
		//Extract TCP
	}
	else if (ip->version == 6){
		//Extract TCP
	}

	return true;
}

static int manage_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data2)
{
	char *payload;
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

	if (!ip_filter(iphdr)){
		printf("drop %d\n", id);
		nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		return id;
	}

	nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
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

int smtp_filter_setup(u_int16_t qnum)
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