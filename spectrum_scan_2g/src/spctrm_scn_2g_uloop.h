#ifndef _SPCTRM_SCN_2G_ULOOP_H_
#define _SPCTRM_SCN_2G_ULOOP_H_
#include <signal.h>
#include <semaphore.h>
#include <unistd.h>
#include <signal.h>
#include <libubox/blobmsg_json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <libubus.h>
#include <json-c/json.h>
#include "spctrm_scn_2g_dev.h"
#include "spctrm_scn_2g_ubus.h"
#include "lib_unifyframe.h"
#include "spctrm_scn_2g_rlog.h"
#include "spctrm_scn_2g_config.h"
#include "was_sdk.h"
#include "spctrm_scn_2g_redbs.h"

int spctrm_scn_2g_uloop(struct ubus_context *ctx);
void spctrm_scn_2g_close();
#endif
