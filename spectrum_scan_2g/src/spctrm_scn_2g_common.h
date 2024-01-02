/* spctrm_scn_2g_common.h */
#ifndef _SPCTRM_SCN_2G_COMMON_H_
#define _SPCTRM_SCN_2G_COMMON_H_

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
#include <uci.h>
#include "spctrm_scn_2g_config.h"
#include <sys/ioctl.h>
#include "was_sdk.h"
#include <linux/wireless.h>

#define RTPRIV_IOCTL_SET (SIOCIWFIRSTPRIV + 0x02)

void spctrm_scn_2g_common_dump_packet(unsigned char *src, unsigned int len);
int spctrm_scn_2g_common_mac_2_nodeadd(unsigned char *mac_src,__u32 *instant);
char spctrm_scn_2g_common_read_file(char *name,char *buf,int len);
int spctrm_scn_2g_common_cmd(char *cmd,char **rbuf);
void spctrm_scn_2g_common_get_sn(char *sn);
int spctrm_scn_2g_common_uci_anonymous_get(char *file, char *type, char *name, char *option, char *buf, int len);
int spctrm_scn_2g_common_iwpriv_set(char *ifname,char *data,size_t data_size);

#endif
