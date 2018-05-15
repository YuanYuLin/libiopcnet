#include <sys/socket.h>
#include <sys/epoll.h>
#include <signal.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>

#include "ops_mq.h"
#include "ops_log.h"
#include "ops_net.h"

static int uds_server_create()
{
	int socket_fd = -1;
	struct sockaddr_un addr;
	struct ops_log_t* log = get_log_instance();
	
	socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(socket_fd < 0) {
		log->error(0x01, "socket error : %s\n", strerror(errno));
		return -1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	log->debug(0x01, "serv create socket path: %s\n", SOCKET_PATH_WWW);
	strncpy(addr.sun_path, SOCKET_PATH_WWW, sizeof(addr.sun_path)-1);
	unlink(SOCKET_PATH_WWW);
	if(bind(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		log->error(0x01, "bind error : %s\n", strerror(errno));
		return -2;
	}

	return socket_fd;
}

static int udp_server_create(uint8_t* bind_interface, uint16_t bind_port)
{
	int socket_fd = -1;
	struct sockaddr_in addr;
	struct ops_log_t* log = get_log_instance();
	
	socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(socket_fd < 0) {
		log->error(0x01, "socket error : %s\n", strerror(errno));
		return -1;
	}
	setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, bind_interface, strlen(bind_interface));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(bind_port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	log->debug(0x01, "serv create socket :%s %ld\n", bind_interface, bind_port);
	//strncpy(addr.sun_path, SOCKET_PATH_WWW, sizeof(addr.sun_path)-1);
	//unlink(SOCKET_PATH_WWW);
	if(bind(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		log->error(0x01, "bind error : %s\n", strerror(errno));
		return -2;
	}

	return socket_fd;
}

static uint32_t uds_server_send(int socket_fd, struct msg_t *msg, struct sockaddr_un* cli_addr, socklen_t cli_addr_len)
{
	int32_t wc = 0;
	struct ops_log_t* log = get_log_instance();
	uint16_t msg_size = sizeof(struct msg_t) - MAX_MSG_DATA_SIZE + msg->data_size;
	
	wc = sendto(socket_fd, (void*)msg, msg_size, 0, (struct sockaddr*)cli_addr, cli_addr_len);
	if(((int32_t)wc) <0)
		log->error(0x01, "uds send error %s\n", strerror(errno));
	return (uint32_t)wc;
}

static uint32_t udp_server_send(int socket_fd, struct msg_t *msg, struct sockaddr_in* cli_addr, socklen_t cli_addr_len)
{
	int32_t wc = 0;
	struct ops_log_t* log = get_log_instance();
	uint16_t msg_size = sizeof(struct msg_t) - MAX_MSG_DATA_SIZE + msg->data_size;
	wc = sendto(socket_fd, (void*)msg, msg_size, 0, (struct sockaddr*)cli_addr, cli_addr_len);
	if(((int32_t)wc) <0)
		log->error(0x01, "udp send error %s\n", strerror(errno));
	return (uint32_t)wc;
}

static uint32_t uds_server_recv(int socket_fd, struct msg_t *msg, struct sockaddr_un* cli_addr, socklen_t* cli_addr_len)
{
	uint32_t rc = 0;
	rc = recvfrom(socket_fd, msg, sizeof(struct msg_t), 0, (struct sockaddr*)cli_addr, cli_addr_len);
	return rc;
}

static uint32_t udp_server_recv(int socket_fd, struct msg_t *msg, struct sockaddr_in* cli_addr, socklen_t* cli_addr_len)
{
	uint32_t rc = 0;
	rc = recvfrom(socket_fd, msg, sizeof(struct msg_t), 0, (struct sockaddr*)cli_addr, cli_addr_len);
	return rc;
}

static void close_socket(int socket_fd) 
{
	if(socket_fd < 0) {
	} else {
		close(socket_fd);
	}
}

static volatile uint8_t cli_cnt = 0;
static int uds_client_send_and_recv(struct msg_t* req, struct msg_t* res)
{
	struct sockaddr_un addr;
	struct ops_log_t* log = get_log_instance();
	uint32_t wc = 0;
	uint32_t rc = 0;
	//uint32_t i = 0;
	int socket_fd = -1;
        struct sockaddr_un cli_addr;
        socklen_t cli_addr_len;
	uint8_t cli_path[30] = {0};
	memset(&cli_path[0], 0, sizeof(cli_path));

	socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (socket_fd == -1) {
		log->error(0x01, "cli socket: %s\n", strerror(errno));
		return -1;
	}

	memset(&cli_addr, 0, sizeof(struct sockaddr_un));
	cli_addr.sun_family = AF_UNIX;
	sprintf(cli_path, "%s.cli_%x", SOCKET_PATH_WWW, cli_cnt++);
	strcpy(cli_addr.sun_path, cli_path);

	log->debug(0x01, "bind path: %s\n", cli_addr.sun_path);

	if(bind(socket_fd, (struct sockaddr*)&cli_addr, sizeof(struct sockaddr_un)) < 0) {
		log->error(0x01, "cli bind error : %s\n", strerror(errno));
		return -2;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, SOCKET_PATH_WWW);
	log->debug(0x01, "cli sending to %s\n", addr.sun_path);
	wc = uds_server_send(socket_fd, req, &addr, sizeof(struct sockaddr_un));
	//wc = sendto(socket_fd, (void*)req, msg_size, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_un));
	log->debug(0x01, "cli write count = %ld\n", wc);

	rc = uds_server_recv(socket_fd, res, &cli_addr, &cli_addr_len);
	//rc = recvfrom(socket_fd, (void*)res, msg_size, 0, NULL, NULL);
	log->debug(0x01, "uds cli read count = %ld\n", rc);

	close_socket(socket_fd);
	log->debug(0x01, "cli reading from %s\n", cli_path);
	unlink(cli_path);
	return 0;
}

static int udp_client_send_and_recv(uint8_t* server_ip_str, uint16_t server_port, struct msg_t* req, struct msg_t* res)
{
	struct sockaddr_in addr;
	struct ops_log_t* log = get_log_instance();
	uint32_t wc = 0;
	uint32_t rc = 0;
	//uint32_t i = 0;
	int socket_fd = -1;
        struct sockaddr_in cli_addr;
        socklen_t cli_addr_len;
	//struct hostent* server_ip;

	socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_fd == -1) {
		log->error(0x01, "cli socket: %s\n", strerror(errno));
		return -1;
	}

	memset(&cli_addr, 0, sizeof(struct sockaddr_in));
	cli_addr.sin_family = AF_INET;
	cli_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	cli_addr.sin_port = htons(0);

	if(bind(socket_fd, (struct sockaddr*)&cli_addr, sizeof(struct sockaddr_in)) < 0) {
		log->error(0x01, "cli bind error : %s\n", strerror(errno));
		return -2;
	}

	memset(&addr, 0, sizeof(struct sockaddr_in));
	//server_ip = gethostbyname(server_ip_str);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(server_port);
	inet_pton(AF_INET, server_ip_str, &(addr.sin_addr));
	//strcpy(addr.sun_path, SOCKET_PATH_WWW);
	log->debug(0x01, "cli sending to %s\n", server_ip_str);
	wc = udp_server_send(socket_fd, req, &addr, sizeof(struct sockaddr_in));
	//wc = sendto(socket_fd, (void*)req, msg_size, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_un));
	log->debug(0x01, "cli write count = %ld\n", wc);

	rc = udp_server_recv(socket_fd, res, &cli_addr, &cli_addr_len);
	//rc = recvfrom(socket_fd, (void*)res, msg_size, 0, NULL, NULL);
	log->debug(0x01, "udp cli read count = %ld\n", rc);

	close_socket(socket_fd);
	//log->debug(0x01, "cli reading from %s\n", cli_addr.sun_path);
	//unlink(cli_addr.sun_path);
	return 0;
}

static void init(void)
{
}

static void show_all(void)
{
}

static struct ops_net_t *obj;
struct ops_net_t *get_net_instance()
{
	if (!obj) {
		obj = malloc(sizeof(struct ops_net_t));
		obj->init = init;
		obj->show_all = show_all;

		obj->uds_server_create = uds_server_create;
		obj->uds_server_send = uds_server_send;
		obj->uds_server_recv = uds_server_recv;
		obj->uds_client_send_and_recv = uds_client_send_and_recv;
		obj->uds_close = close_socket;

		obj->udp_server_create = udp_server_create;
		obj->udp_server_send = udp_server_send;
		obj->udp_server_recv = udp_server_recv;
		obj->udp_client_send_and_recv = udp_client_send_and_recv;
		obj->udp_close = close_socket;
	}

	return obj;
}

void del_net_instance()
{
	if (obj)
		free(obj);
}
