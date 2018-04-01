#ifndef OPS_NET_H
#define OPS_NET_H

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <signal.h>
#include <assert.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h> 
#include <arpa/inet.h>
#include "ops_mq.h"

#define SOCKET_PATH_WWW	"/tmp/uds.www"
#define MAX_CLIENT_WWW	5

struct ops_net_t {
	void (*init) (void);
	void (*show_all) (void);
	int (*uds_server_create)();
	uint32_t (*uds_server_send)(int socket_fd, struct msg_t *msg, struct sockaddr_un* cli_addr, socklen_t cli_addr_len);
	uint32_t (*uds_server_recv)(int socket_fd, struct msg_t *msg, struct sockaddr_un* cli_addr, socklen_t* cli_addr_len);
	int (*uds_client_send_and_recv)(struct msg_t* req, struct msg_t* res);
	void (*uds_close)(int socket_fd);

	int (*udp_server_create)(uint8_t* bind_interface, uint16_t bind_port);
	uint32_t (*udp_server_send)(int socket_fd, struct msg_t *msg, struct sockaddr_in* cli_addr, socklen_t cli_addr_len);
	uint32_t (*udp_server_recv)(int socket_fd, struct msg_t *msg, struct sockaddr_in* cli_addr, socklen_t* cli_addr_len);
	int (*udp_client_send_and_recv)(uint8_t* serverip_str, uint16_t server_port, struct msg_t* req, struct msg_t* res);
	void (*udp_close)(int socket_fd);
};

struct ops_net_t *get_net_instance();
void del_net_instance();
#endif
