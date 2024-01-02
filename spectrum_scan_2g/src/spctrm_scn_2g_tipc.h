/* spctrm_scn_2g_tipc.h */
#ifndef _SPCTRM_SCN_2G_TIPC_H_
#define _SPCTRM_SCN_2G_TIPC_H_

#include <stdio.h>
#include <errno.h>
#include <linux/tipc.h>
#include <time.h>
#include <fcntl.h>
#include <semaphore.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <pthread.h>
#include "spctrm_scn_2g_dev.h"
#include "libubus.h"
#include "spctrm_scn_2g_config.h"
#include "spctrm_scn_2g_ubus.h"

#define SPCTRM_SCN_2G_SERVER_TYPE  115 
#define PROTOCAL_TYPE_SCAN    17888
#define PROTOCAL_TYPE_SCAN_ACK    17887
#define PROTOCAL_TYPE_CPE_REPORT_ACK     112
#define PROTOCAL_TYPE_CPE_REPORT     17886

#define SERVER_INST  17
#define BUF_SIZE 40

typedef struct spctrm_scn_2g_tipc_scan_ack_pkt {
    uint8_t band_support;
} spctrm_scn_2g_tipc_scan_ack_pkt_t;

typedef struct spctrm_scn_2g_tipc_recv_packet_head {
    unsigned int type;
    size_t payload_size;
    unsigned int instant;
} spctrm_scn_2g_tipc_recv_packet_head_t;

int spctrm_scn_2g_common_mac_2_nodeadd(unsigned char *mac_src,__u32 *instant);
int spctrm_scn_2g_tipc_send(__u32 dst_instance,__u32 type,size_t payload_size,char *payload);
int spctrm_scn_2g_tipc_send_recv(__u32 dst_instance,__u32 type,size_t payload_size,char *payload,char*rbuf);
void spctrm_scn_2g_tipc_task();
void tipc_close();
#endif
