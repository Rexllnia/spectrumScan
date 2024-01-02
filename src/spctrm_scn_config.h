/* spctrm_scn_config.h */
#ifndef _SPCTRM_SCN_CONFIG_H_
#define _SPCTRM_SCN_CONFIG_H_

#include <libdebug/libdebug.h>
#include "spctrm_scn_common.h"
#include "spctrm_scn_debug.h"

#define SN_LEN 14

#define MIN_SCAN_TIME 15
#define MAX_SCAN_TIME 60
#define BITS_PER_BYTE 8
#define EXPIRE_TIME 14

#define POPEN_CMD_ENABLE
#define BRIDGE_PLATFORM
#define UDP_FUNCTION

#define ETH_ALEN 6

#define UNKNOW     0
#define SUPPORT_5G 1
#define SUPPORT_2G 1<<1

#define MAX_DEVICE_NUM  32
#define MAX_POPEN_BUFFER_SIZE   81920

#define BW_20   20
#define BW_40   40
#define BW_80   80
#define BW_160  160

#define SCAN_BUSY       1
#define SCAN_IDLE       2
#define SCAN_NOT_START  0
#define SCAN_TIMEOUT  	3
#define SCAN_ERR        -1

#define FAIL       -1
#define SUCCESS    0

#define MAX_BAND_5G_CHANNEL_NUM 36

#define BAND_2G 2
#define BAND_5G 5

#define PLATFORM_5G     5
#define PLATFORM_2G     2
#define PLATFORM_BOTH   0

#define AP_MODE  0
#define CPE_MODE 1
unsigned char g_mode;

struct user_input {
    uint64_t channel_bitmap;
    int band;
    int channel_num;
    int scan_time;
};

struct channel_info {
    int channel;
    int floornoise;
    int utilization;
    int bw;
    int obss_util;
    int tx_util;
    int rx_util;
    double score;
    double rate;
};

#endif
