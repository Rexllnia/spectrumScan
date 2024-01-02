/* spctrm_scn_2g_config.h */
#ifndef _SPCTRM_SCN_2G_CONFIG_H_
#define _SPCTRM_SCN_2G_CONFIG_H_

#include "spctrm_scn_2g_common.h"
#include "spctrm_scn_debug.h"
#define SN_LEN 14

#define SCAN_INTERVAL 500
#define DEFAULT_SCAN_TIME 5
#define MIN_SCAN_TIME 10 
#define MAX_SCAN_TIME 60
#define EXPIRE_TIME 14

#define ETH_ALEN 6

#define POPEN_BUFFER_MAX_SIZE   8192

#define _20MHZ 20
#define _40MHZ 40
#define _80MHZ 80

#define BAND_5G_BW_20_MAX_RATE 200
#define BAND_5G_BW_40_MAX_RATE 400
#define BAND_5G_BW_80_MAX_RATE 800

#define BAND_2G_BW_20_MAX_RATE 150
#define BAND_2G_BW_40_MAX_RATE 300

#define SPCTRM_SCN_2G_BW_20   1
#define SPCTRM_SCN_2G_BW_40   (1 << 1)
#define SPCTRM_SCN_2G_BW_80   (1 << 2)
#define SPCTRM_SCN_2G_BW_160  (1 << 3) 

#define BW_BITMAP_SIZE          4
#define BW_BITMAP_20MHZ_INDEX   0
#define BW_BITMAP_40MHZ_INDEX   1
#define BW_BITMAP_80MHZ_INDEX   2

#define SPCTRM_SCN_2G_SCAN_BUSY             1
#define SPCTRM_SCN_2G_SCAN_IDLE             2
#define SPCTRM_SCN_2G_SCAN_NOT_START        0
#define SPCTRM_SCN_2G_SCAN_TIMEOUT          3
#define SPCTRM_SCN_2G_SCAN_ERROR            -1

#define FAIL       -1
#define SUCCESS    0

#define SPCTRM_SCN_2G_MAX_DEVICE_NUM 5
#define BAND_5G_MAX_CHANNEL_NUM 36

#define BAND_5G     5
#define BAND_2G     2

#define AP_MODE  0
#define CPE_MODE 1

#define CHANNEL_BITMAP_SIZE 64
#define CHANNEL_BITMAP_ARRAY_DEPTH 2

#define ROLE_STR_LEN 4
#define FINISHED 	1
#define NOT_FINISH	0

#define SPCTRM_SCN_2G_DEV_LIST_JSON_PATH "/etc/spectrum_scan/spctrm_scn_2g_device_list.json"

uint8_t g_spctrm_scn_2g_mode;
uint8_t g_band_support;

#define debug(...)

struct spctrm_scn_2g_channel_info {
    uint8_t channel;
    int8_t floornoise;
    uint8_t utilization;
    uint8_t obss_util;
    uint8_t tx_util;
    uint8_t rx_util;
    int bw;
    double score;
    double rate;
};


struct spctrm_scn_2g_device_info {
    char series_no[SN_LEN];
    unsigned char mac[20];
    char role[ROLE_STR_LEN];
    int status;
    struct spctrm_scn_2g_channel_info bw20_channel_info[BAND_5G_MAX_CHANNEL_NUM];
    struct spctrm_scn_2g_channel_info bw40_channel_info[BAND_5G_MAX_CHANNEL_NUM];
    struct spctrm_scn_2g_channel_info bw80_channel_info[BAND_5G_MAX_CHANNEL_NUM];
    unsigned char finished_flag;
    unsigned char band_support;
    time_t timestamp;
};

struct spctrm_scn_2g_device_list {
    int list_len;
    struct spctrm_scn_2g_device_info device[32];
};

#endif
