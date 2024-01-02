/* spctrm_scn_2g_ubus.h*/
#ifndef _SPCTRM_SCN_2G_UBUS_H_
#define _SPCTRM_SCN_2G_UBUS_H_

/* 
 ubus call spctrm_scn_2g set '{"band":5}'
 ubus call spctrm_scn_2g set '{"band":2}'
 ubus call spctrm_scn_2g get
**/

/* ubus call spctrm_scn_2g set '{"band":5,"channel_list":[36,40,44,48]}' */
/* cat /etc/spectrum_scan/spctrm_scn_2g_device_info.json */
#include <unistd.h>
#include <signal.h>
#include <semaphore.h>
#include <json-c/json.h>
#include <libubox/blobmsg_json.h>
#include "libubus.h"
#include "spctrm_scn_2g_wireless.h"
#include "spctrm_scn_2g_dev.h"
#include "spctrm_scn_2g_tipc.h"
#include "spctrm_scn_2g_config.h"
#include "spctrm_scn_2g_redbs.h"
#include "bitmap.h"

#define MAX_BW_NUM 5
#define MAX_CHANNEL_NUM 200 
#define CHANNEL_BITMAP_ARRAY_DEPTH 2
#define UBUS_DEFER_REQUEST
enum {
    SPCTRM_SCN_BAND,
    SPCTRM_SCN_CHANNEL_LIST,
    SPCTRM_SCN_BW_LIST,
    SPCTRM_SCN_SCAN_TIME,
    __SPCTRM_SCN_SCAN_MAX
};

enum {
    SPCTRM_SCN_INSTANT,
    SPCTRM_SCN_MSG_TYPE,
    SPCTRM_SCN_PAYLOAD,
    __SPCTRM_SCN_TIPC_SEND_MAX
};

struct spctrm_scn_2g_ubus_set_request
{
    struct ubus_request_data req;
    struct uloop_timeout timeout;
    unsigned long int channel_bitmap[3][CHANNEL_BITMAP_ARRAY_DEPTH];
    uint8_t bw_bitmap;
    unsigned long int channel_num;
    uint8_t scan_time;
    uint8_t band;
    struct spctrm_scn_2g_device_info spctrm_scn_2g_device_info;
    int fd;
    int idx;
    int channel_index;
    int spctrm_scn_2g_tipc_wait_cpe_retry;
};

void spctrm_scn_2g_ubus_task(struct ubus_context *ctx);
void spctrm_scn_2g_ubus_send_notify(uint32_t msg_type,char *payload);
int spctrm_scn_2g_ubus_add_blobmsg(struct blob_buf *buf,struct spctrm_scn_2g_device_list *spctrm_scn_2g_device_list,struct spctrm_scn_2g_ubus_set_request *hreq);
#endif
