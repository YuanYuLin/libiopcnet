#include <errno.h>
#include <pty.h>

#include "ops_log.h"
#include "ops_shell.h"
#include "ops_net.h"

static int destroy()
{
	return 0;
}

static void init()
{
}

static void show_all()
{
}

static int create_sh(uint8_t idx)
{
    struct ops_net_t* net = get_net_instance();
    struct ops_log_t* log = get_log_instance();
    struct msg_t req;
    struct msg_t res;
    struct shell_cmd_t *req_cmd = (struct shell_cmd_t*)&req.data;
    struct shell_cmd_t *res_cmd = (struct shell_cmd_t*)&res.data;
    memset(&req, 0, sizeof(struct msg_t));
    memset(&res, 0, sizeof(struct msg_t));
    sprintf(&req_cmd->cmd[0], "/bin/sh");
    req.fn = 0xFF;
    req.cmd = 0xFF;
    req.data_size = sizeof(struct shell_cmd_t);
    req_cmd->cmdlen = strlen(req_cmd->cmd);
    req_cmd->action = SHELL_ACTION_CREATE;
    req_cmd->type = SHELL_TYPE_CMDSH;
    req_cmd->instance = idx;
    net->uds_client_send_and_recv(SOCKET_PATH_SHELL, &req, &res);
    log->info(0x01, __FILE__, __func__, __LINE__, "res %d, %d, %d\n", res_cmd->action, res_cmd->type, res_cmd->instance);
    return 0;
}

static int create_qemu(uint8_t idx)
{
    struct ops_net_t* net = get_net_instance();
    struct ops_log_t* log = get_log_instance();
    struct msg_t req;
    struct msg_t res;
    struct shell_cmd_t *req_cmd = (struct shell_cmd_t*)&req.data;
    struct shell_cmd_t *res_cmd = (struct shell_cmd_t*)&res.data;
    memset(&req, 0, sizeof(struct msg_t));
    memset(&res, 0, sizeof(struct msg_t));
    sprintf(&req_cmd->cmd[0], "/bin/sh");
    req.fn = 0xFF;
    req.cmd = 0xFF;
    req.data_size = sizeof(struct shell_cmd_t);
    req_cmd->cmdlen = strlen(req_cmd->cmd);
    req_cmd->action = SHELL_ACTION_CREATE;
    req_cmd->type = SHELL_TYPE_CMDQEMU;
    req_cmd->instance = idx;
    net->uds_client_send_and_recv(SOCKET_PATH_SHELL, &req, &res);
    log->info(0x01, __FILE__, __func__, __LINE__, "res %d, %d, %d\n", res_cmd->action, res_cmd->type, res_cmd->instance);
    return 0;
}

static int send_sh(uint8_t idx, uint8_t cmdlen, uint8_t* cmd)
{
    struct ops_net_t* net = get_net_instance();
    struct ops_log_t* log = get_log_instance();
    struct msg_t req;
    struct msg_t res;
    struct shell_cmd_t *req_cmd = (struct shell_cmd_t*)&req.data;
    struct shell_cmd_t *res_cmd = (struct shell_cmd_t*)&res.data;
    memset(&req, 0, sizeof(struct msg_t));
    memset(&res, 0, sizeof(struct msg_t));
    req.fn = 0xFF;
    req.cmd = 0xFF;
    req.data_size = sizeof(struct shell_cmd_t);
    req_cmd->cmdlen = cmdlen;
    req_cmd->action = SHELL_ACTION_EXECUTE;
    req_cmd->type = SHELL_TYPE_CMDSH;
    req_cmd->instance = idx;
    memcpy(&req_cmd->cmd[0], cmd, cmdlen);
    net->uds_client_send_and_recv(SOCKET_PATH_SHELL, &req, &res);
    log->info(0x01, __FILE__, __func__, __LINE__, "res %d, %d, %d\n", res_cmd->action, res_cmd->type, res_cmd->instance);
    return 0;
}

static int create_and_send_sh(uint8_t idx, uint8_t cmdlen, uint8_t* cmd)
{
    create_sh(idx);
    send_sh(idx, cmdlen, cmd);
}

static int send_qemu(uint8_t idx, uint8_t cmdlen, uint8_t* cmd)
{
    struct ops_net_t* net = get_net_instance();
    struct ops_log_t* log = get_log_instance();
    struct msg_t req;
    struct msg_t res;
    struct shell_cmd_t *req_cmd = (struct shell_cmd_t*)&req.data;
    struct shell_cmd_t *res_cmd = (struct shell_cmd_t*)&res.data;
    memset(&req, 0, sizeof(struct msg_t));
    memset(&res, 0, sizeof(struct msg_t));
    req.fn = 0xFF;
    req.cmd = 0xFF;
    req.data_size = sizeof(struct shell_cmd_t);
    req_cmd->cmdlen = cmdlen;
    req_cmd->action = SHELL_ACTION_EXECUTE;
    req_cmd->type = SHELL_TYPE_CMDSH;
    req_cmd->instance = idx;
    memcpy(&req_cmd->cmd[0], cmd, cmdlen);
    net->uds_client_send_and_recv(SOCKET_PATH_SHELL, &req, &res);
    log->info(0x01, __FILE__, __func__, __LINE__, "res %d, %d, %d\n", res_cmd->action, res_cmd->type, res_cmd->instance);
    return 0;
}

static int create_and_send_qemu(uint8_t idx, uint8_t cmdlen, uint8_t* cmd)
{
    create_qemu(idx);
    send_qemu(idx, cmdlen, cmd);
}

static struct ops_shell_t *obj = NULL;
struct ops_shell_t *get_shell_instance()
{
	if (!obj) {
		obj = malloc(sizeof(struct ops_shell_t));
		obj->init = init;
		obj->show_all = show_all;

		obj->create_sh = create_sh;
		obj->send_sh = create_and_send_sh;
		obj->create_qemu = create_qemu;
		obj->send_qemu = create_and_send_qemu;

		obj->destroy = destroy;
	}
	return obj;
}

void del_shell_instance()
{
	if (obj)
		free(obj);
}
