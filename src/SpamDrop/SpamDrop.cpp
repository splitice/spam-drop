#include <sys/epoll.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/linux_nfnetlink_queue.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */

#include <libmnl/libmnl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include "filter.h"
#include "debug.h"

bool stop_soon = false;

void process(int nl){
	struct epoll_event ev;
	struct epoll_event events[5];
	int pcap_fd = mnl_socket_get_fd(nl);
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int res;

	DEBUG("[#] netlink fd: %d\n", pcap_fd);

	//Initial epoll setup
	int epfd = epoll_create(10);

	//add PCAP fd
	ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
	ev.data.fd = pcap_fd;
	res = epoll_ctl(epfd, EPOLL_CTL_ADD, pcap_fd, &ev);
	if (res != 0){
		PFATAL("epoll_ctl() failed.");
	}

	SAYF("[+] Entered main event loop.\n\n");

	//Main loop
	while (!stop_soon) {
		int nfds = epoll_wait(epfd, events, 5, -1);
		int n = 0;
		while (n < nfds) {
			int fd = events[n].data.fd;
			if (fd == pcap_fd){
				//Handle PCAP event
				if (events[n].events & EPOLLIN){
					res = mnl_socket_recvfrom(nl, buf, sizeof(buf));
					if (res == -1) {
						PFATAL("mnl_socket_recvfrom");
					}
					//res = mnl_cb_run(buf, res, 0, portid, parse_packet, NULL);
					if (res < 0){
						PFATAL("mnl_cb_run");
					}
				}
				else if (events[n].events & EPOLLERR || events[n].events & EPOLLHUP){
					FATAL("Packet capture interface is down.");
				}
			}

			//Increment n (like a for loop!)
			++n;
		}
	}

	close(epfd);
}

int main(int argc, char *argv[])
{
	int nl = smtp_filter_setup(666);

	smtp_filter_close();
}