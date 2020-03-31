#ifndef OPS_SHELL_H
#define OPS_SHELL_H

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "ops_mq.h"
#include "ops_misc.h"

#define MAX_SHELL_CMDLEN	CMDLEN
#define MAX_PTY_NAME		32
#define MAX_PTY_BUFF		1024
#define MAX_SHELL_INSTANCE	0x10

#define SHELL_ACTION_UNKNOWN	0x00
#define SHELL_ACTION_CREATE	0x01
#define SHELL_ACTION_EXECUTE	0x02
#define SHELL_ACTION_TERMINATE	0x10

#define SHELL_TYPE_UNKNOWN	0x00
#define SHELL_TYPE_CMDSH	0x01
#define SHELL_TYPE_CMDQEMU	0x02

#define SHELL_INSTANCE		0x01
/*
 */
struct shell_cmd_t {
	uint8_t action;
	uint8_t type;
	uint8_t instance;
	uint8_t cmdlen;
	uint8_t cmd[MAX_SHELL_CMDLEN];
} __attribute__ ((packed));

struct ops_shell_t {
	void (*init) (void);
	void (*show_all) (void);
	int (*create_sh) (uint8_t idx);
	int (*create_qemu) (uint8_t idx);
	int (*send_sh)(uint8_t idx, uint8_t cmdlen, uint8_t* cmd);
	int (*send_qemu)(uint8_t idx, uint8_t cmdlen, uint8_t* cmd);

	int (*destroy) (void);
};

struct ops_shell_t *get_shell_instance();
void del_shell_instance();
#endif
