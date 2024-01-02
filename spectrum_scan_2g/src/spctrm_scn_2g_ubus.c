/*
 * Copyright (C) 2011-2014 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "spctrm_scn_2g_ubus.h"

static int spctrm_scn_2g_ubus_set(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg);
static int spctrm_scn_2g_ubus_get(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg);
static int spctrm_scn_2g_ubus_tipc_send(struct ubus_context *ctx, struct ubus_object *obj,
              struct ubus_request_data *req, const char *method,
              struct blob_attr *msg);
struct spctrm_scn_2g_ubus_get_request
{
    struct ubus_request_data req;
    struct uloop_timeout timeout;
    int fd;
    int idx;
    char data[];
};

extern char g_2g_ext_ifname[IFNAMSIZ];
extern char g_5g_ext_ifname[IFNAMSIZ];
static struct ubus_connect_ctx *g_ctx;
struct spctrm_scn_2g_device_list g_spctrm_scn_2g_device_list;
int8_t g_spctrm_scn_2g_status;
uint8_t g_spctrm_scn_2g_scan_schedule,g_total_channel;
long long int g_timestamp;

const char g_bw_name_array[10][10] = {"bw_20","bw_40","bw_80"};
const char g_bw_name_array2[10][10] = {"bw20","bw40","bw80"};


static const struct blobmsg_policy spctrm_scn_2g_ubus_set_policy[] = {
    [SPCTRM_SCN_BAND] = {.name = "band", .type = BLOBMSG_TYPE_INT32},
    [SPCTRM_SCN_CHANNEL_LIST] = {.name = "channel_list", .type = BLOBMSG_TYPE_ARRAY},
    [SPCTRM_SCN_BW_LIST] = {.name = "bw_list", .type = BLOBMSG_TYPE_ARRAY},
    [SPCTRM_SCN_SCAN_TIME] = {.name = "scan_time", .type = BLOBMSG_TYPE_INT32},
};

static const struct blobmsg_policy spctrm_scn_2g_ubus_tipc_send_policy[] = {
    [SPCTRM_SCN_INSTANT] = {.name = "instant", .type = BLOBMSG_TYPE_INT32},
    [SPCTRM_SCN_MSG_TYPE] = {.name = "msg_type", .type = BLOBMSG_TYPE_INT32},
    [SPCTRM_SCN_PAYLOAD] = {.name = "payload", .type = BLOBMSG_TYPE_STRING},
};
static const struct ubus_method spctrm_scn_2g_methods[] = {
    UBUS_METHOD_NOARG("get", spctrm_scn_2g_ubus_get),
    UBUS_METHOD("set", spctrm_scn_2g_ubus_set, spctrm_scn_2g_ubus_set_policy),
    UBUS_METHOD("tipc_send", spctrm_scn_2g_ubus_tipc_send, spctrm_scn_2g_ubus_tipc_send_policy),
};
static struct ubus_object_type spctrm_scn_2g_object_type =
    UBUS_OBJECT_TYPE("spctrm_scn_2g", spctrm_scn_2g_methods);

static struct ubus_object spctrm_scn_2g_object = {
    .name = "spctrm_scn_2g",
    .type = &spctrm_scn_2g_object_type,
    .methods = spctrm_scn_2g_methods,
    .n_methods = ARRAY_SIZE(spctrm_scn_2g_methods),
};

static void add_score_list_blobmsg(struct blob_buf *buf, unsigned long int *channel_bitmap, struct spctrm_scn_2g_channel_info *channel_info_list,int band)
{
    int bit;
    uint8_t channel;
    char temp[128];
    void *const score_list = blobmsg_open_array(buf, "score_list");
    void *score_list_elem;
    bit = 0;

    SPCTRM_SCN_IS_ZERO_WARN(channel_info_list[0].floornoise,"channel_info_list[0].floornoise is zero");
    SPCTRM_SCN_IS_ZERO_WARN(channel_info_list[0].floornoise,"channel_info_list[0].obss_util is zero");
    SPCTRM_SCN_DBG("floornoise %d \r\n",channel_info_list[0].floornoise);
    SPCTRM_SCN_DBG("obss_util %d \r\n",channel_info_list[0].obss_util);
    for_each_set_bit(bit,channel_bitmap,CHANNEL_BITMAP_SIZE) {
        score_list_elem = blobmsg_open_table(buf,"");

        if (bitset_to_channel(bit,&channel,band) == FAIL) {
            SPCTRM_SCN_ERR("bitset_to_channel error");
            return;
        }

        sprintf(temp,"%d",channel);
        blobmsg_add_string(buf,"channel",temp);
        sprintf(temp,"%f",channel_info_list[bit].score);
        blobmsg_add_string(buf,"score",temp);
        blobmsg_close_table(buf,score_list_elem);
    }

    blobmsg_close_array(buf, score_list);
}

static inline void add_bw_blobmsg(struct blob_buf *buf, struct spctrm_scn_2g_device_info *device,
                struct spctrm_scn_2g_ubus_set_request *hreq,int bw_index)
{
    
    void *bw_table;
    char temp[128];
    unsigned long int channel_bitmap[2];

    bw_table = blobmsg_open_table(buf, g_bw_name_array[bw_index]);
    spctrm_scn_2g_wireless_get_group_channel_bitmap(hreq->channel_bitmap[bw_index],channel_bitmap,hreq->band,SET_BIT_TO_BW(bw_index));
    
    if (SET_BIT_TO_BW(bw_index) == _40MHZ) {
        add_score_list_blobmsg(buf,channel_bitmap,device->bw40_channel_info,hreq->band);
    } else if (SET_BIT_TO_BW(bw_index) == _20MHZ) {
        add_score_list_blobmsg(buf,channel_bitmap,device->bw20_channel_info,hreq->band);
    } else if (SET_BIT_TO_BW(bw_index) == _80MHZ) {
        add_score_list_blobmsg(buf,channel_bitmap,device->bw80_channel_info,hreq->band);
    }

    blobmsg_close_table(buf, bw_table);
}

static void add_timestamp_blobmsg(struct blob_buf *buf, time_t *timestamp)
{
    char temp[256];   
    sprintf(temp, "%ld", *timestamp);
    blobmsg_add_string(buf, "timestamp", temp);
}


struct best_channel {
    int bit;         /* set bit in channel bitmap  */
    double score;
    double rate;
};
struct best_channel best_channel[3];
static void add_avg_score_list_blobmsg(struct blob_buf *buf,
                struct spctrm_scn_2g_ubus_set_request *hreq,
                struct spctrm_scn_2g_device_list *list) 
{
    struct spctrm_scn_2g_device_info *p;
    void *avg_score_list,*avg_score_list_elem;
    uint8_t channel;
    int i,bit,bw_index,finished_device_num;
    double avg_score = 0,rate = 0;
    char tmp[128];

    double ratio_max_rate[10];
    __u32 channel_bitmap[2];

    memset(ratio_max_rate,0,sizeof(ratio_max_rate));
    /* ratio_max_rate init */
    if (hreq->band == BAND_5G) {
        ratio_max_rate[0] = BAND_5G_BW_20_MAX_RATE;
        ratio_max_rate[1] = BAND_5G_BW_40_MAX_RATE;
        ratio_max_rate[2] = BAND_5G_BW_80_MAX_RATE;
    } else if (hreq->band == BAND_2G) {
        ratio_max_rate[0] = BAND_2G_BW_20_MAX_RATE;
        ratio_max_rate[1] = BAND_2G_BW_40_MAX_RATE;
    }


    memset(best_channel,0,sizeof(best_channel));
    bit = 0;
    channel = 0;
    bw_index = 0;
    for_each_set_bit(bw_index,&hreq->bw_bitmap,BW_BITMAP_SIZE) {
#ifdef NEW_FIELD
        avg_score_list = blobmsg_open_array(buf,g_bw_name_array[bw_index]);
#else
        avg_score_list = blobmsg_open_array(buf,g_bw_name_array2[bw_index]);
#endif
        SPCTRM_SCN_INFO("bw_index %d\r\n",bw_index);
        memset(channel_bitmap,0,sizeof(channel_bitmap));
        spctrm_scn_2g_wireless_get_group_channel_bitmap(hreq->channel_bitmap[bw_index],
                                        channel_bitmap,hreq->band,SET_BIT_TO_BW(bw_index));
        for_each_set_bit(bit,channel_bitmap,CHANNEL_BITMAP_SIZE) {
            /* devices average score and max rate */
            avg_score = 0.0;
            finished_device_num = 0;
            rate = 0.0;
            list_for_each_device(p,i,list) {
                if (p->finished_flag == FINISHED) {
                    finished_device_num++;
                    if (SET_BIT_TO_BW(bw_index) == _20MHZ) {
                        avg_score += p->bw20_channel_info[bit].score;
                    } else if (SET_BIT_TO_BW(bw_index) == _40MHZ) {
                        avg_score += p->bw40_channel_info[bit].score;
                    } else if (SET_BIT_TO_BW(bw_index) == _80MHZ) {
                        avg_score += p->bw80_channel_info[bit].score;
                    }
                }
            }
            SPCTRM_SCN_INFO("avg_score %f finished_device_num %d \r\n",avg_score,finished_device_num);
            avg_score /= finished_device_num;
            rate = avg_score * ratio_max_rate[bw_index] / 100.0;
            SPCTRM_SCN_INFO("channel bit set %d\r\n",bit);
            SPCTRM_SCN_INFO("rate %f\r\n",rate);

            /* find best channel each bw */
            if (best_channel[bw_index].score < avg_score) {
                best_channel[bw_index].score = avg_score;
                best_channel[bw_index].bit = bit;
                best_channel[bw_index].rate = rate;
            }

            /* create avg_score blobmsg */
            avg_score_list_elem = blobmsg_open_table(buf,"");
            bitset_to_channel(bit,&channel,hreq->band);
            memset(tmp,0,sizeof(tmp));
            sprintf(tmp,"%d",channel);
            blobmsg_add_string(buf,"channel",tmp);
            memset(tmp,0,sizeof(tmp));
            sprintf(tmp,"%f",avg_score);

            blobmsg_add_string(buf,"avg_score",tmp);
            memset(tmp,0,sizeof(tmp));
            sprintf(tmp,"%f",rate);
#ifdef NEW_FIELD
            blobmsg_add_string(buf,"rate",tmp);
#else 
            blobmsg_add_string(buf,"avg_rate",tmp);
#endif
            blobmsg_close_table(buf,avg_score_list_elem);
        }
        blobmsg_close_array(buf,avg_score_list);
    }
    
}

static void add_best_channel_blobmsg(struct blob_buf *buf,struct spctrm_scn_2g_ubus_set_request *hreq)
{
    int bw_index,channel;
    void *best_channel_table,*best_channel_table_elem,*bw_table;
    char tmp[128];

    bw_index = 0;
    channel = 0;

    best_channel_table = blobmsg_open_table(buf, "best_channel");
    for_each_set_bit(bw_index,&hreq->bw_bitmap,BW_BITMAP_SIZE) {
        bw_table = blobmsg_open_table(buf,g_bw_name_array[bw_index]);
        bitset_to_channel(best_channel[bw_index].bit,&channel,hreq->band);
        memset(tmp,0,sizeof(tmp));
        sprintf(tmp,"%d",channel);
        blobmsg_add_string(buf,"channel",tmp);
        memset(tmp,0,sizeof(tmp));
        sprintf(tmp,"%f",best_channel[bw_index].score);
        blobmsg_add_string(buf,"score",tmp);
        memset(tmp,0,sizeof(tmp));
        sprintf(tmp,"%f",best_channel[bw_index].rate); /* xxx */
        blobmsg_add_string(buf,"rate",tmp);
        blobmsg_close_table(buf,bw_table);
    }
    blobmsg_close_table(buf, best_channel_table);
}

int spctrm_scn_2g_ubus_add_blobmsg(struct blob_buf *buf,struct spctrm_scn_2g_device_list *spctrm_scn_2g_device_list,struct spctrm_scn_2g_ubus_set_request *hreq)
{
    struct spctrm_scn_2g_device_info *p;
    int i,bw_index=0;
    void *scan_list,*avg_score_table,*bw_table;
    void *scan_list_elem;
    void *band_obj;
    char tmp[128];

    __u32 channel_bitmap[2];

    if (buf == NULL || spctrm_scn_2g_device_list == NULL || hreq == NULL) {
        return FAIL;
    }
    memset(channel_bitmap,0,sizeof(channel_bitmap));
    memset(tmp,0,sizeof(tmp));
    sprintf(tmp,"%lld",g_timestamp);
    blobmsg_add_string(buf,"timestamp",tmp);
    SPCTRM_SCN_DBG("\r\n");
    
    scan_list = blobmsg_open_array(buf,"scan_list");
    if (scan_list == NULL) {
        SPCTRM_SCN_ERR("scan_list NULL \r\n");
        return FAIL;
    }
    list_for_each_device(p,i,spctrm_scn_2g_device_list) {
        scan_list_elem = blobmsg_open_table(buf,"");  
        SPCTRM_SCN_DBG("series_no %s\r\n",p->series_no); 
        SPCTRM_SCN_DBG("role %s\r\n",p->role); 
        SPCTRM_SCN_DBG("floornoise %d\r\n",p->bw20_channel_info[1].floornoise);
        blobmsg_add_string(buf, "SN", p->series_no);
        blobmsg_add_string(buf, "role", p->role);
        if (p->finished_flag == NOT_FINISH) {
            blobmsg_add_string(buf, "status","0");
        } else {
            blobmsg_add_string(buf, "status","1");  
        }
        
        band_obj = blobmsg_open_table(buf,"2.4G");
        for_each_set_bit(bw_index,&hreq->bw_bitmap,BW_BITMAP_SIZE) {
            add_bw_blobmsg(buf,p,hreq,bw_index);
        }
        blobmsg_close_table(buf,band_obj);
        blobmsg_close_table(buf,scan_list_elem);
    }
    blobmsg_close_array(buf,scan_list);
    
    avg_score_table = blobmsg_open_table(buf,"avg_score_table");
    add_avg_score_list_blobmsg(buf,hreq,spctrm_scn_2g_device_list);
    blobmsg_close_table(buf,avg_score_table);
    SPCTRM_SCN_DBG("add best channel\r\n");
    add_best_channel_blobmsg(buf,hreq);


    return SUCCESS;
}


static void spctrm_scn_2g_tipc_wait_cpe_cb(struct uloop_timeout *t) 
{
    struct spctrm_scn_2g_ubus_set_request *hreq = container_of(t,struct spctrm_scn_2g_ubus_set_request,timeout);
    struct spctrm_scn_2g_device_info *p;
    int i,all_finished_flag;
    __u32 instant;
    instant = 0;

    /*  1 : all device finished | 0 : all device not finished */
    all_finished_flag = 1; 

    SPCTRM_SCN_INFO("band %d\r\n",hreq->band);
    hreq->spctrm_scn_2g_tipc_wait_cpe_retry++;
    if (hreq->spctrm_scn_2g_tipc_wait_cpe_retry == 10) {
        hreq->spctrm_scn_2g_tipc_wait_cpe_retry = 0;
        goto scan_start;
    }
    
    list_for_each_device(p,i,&g_spctrm_scn_2g_device_list) {
        
        SPCTRM_SCN_INFO("--> wait device [%s]\r\n",p->series_no);
        if (p->finished_flag != FINISHED) {
            SPCTRM_SCN_INFO("<-- [%s] not start\r\n",p->series_no);
            if (spctrm_scn_2g_common_mac_2_nodeadd(p->mac,&instant) == FAIL) {
                SPCTRM_SCN_ERR("spctrm_scn_2g_common_mac_2_nodeadd FAIL \r\n");
                free(hreq);
                g_spctrm_scn_2g_status = SPCTRM_SCN_2G_SCAN_ERROR;
                spctrm_scn_2g_dev_ap_status_to_file(g_spctrm_scn_2g_status);
                return;
            }
            spctrm_scn_2g_tipc_send(instant,PROTOCAL_TYPE_SCAN,sizeof(struct spctrm_scn_2g_ubus_set_request),hreq);
            all_finished_flag = 0; /* exit devices not connect */
        } else {
            SPCTRM_SCN_INFO("<-- [%s] start scan\r\n",p->series_no);
        }
        
    }

    if (all_finished_flag == 0) {
        SPCTRM_SCN_INFO("retry\r\n");
        uloop_timeout_set(&hreq->timeout,500);
        return;
    }

scan_start:
    spctrm_scn_2g_dev_reset_stat(&g_spctrm_scn_2g_device_list);
    list_for_each_device(p,i,&g_spctrm_scn_2g_device_list) {
        SPCTRM_SCN_INFO("p->finished_flag %d \r\n",p->finished_flag);
    }

    /* change bw to 20Mhz */
    spctrm_scn_2g_wireless_change_bw(_20MHZ,hreq->band); 
    SPCTRM_SCN_INFO("change to bw %d\r\n",_20MHZ);

    hreq->channel_index = 0;
    hreq->channel_index = find_first_bit(hreq->channel_bitmap[BW_BITMAP_20MHZ_INDEX],CHANNEL_BITMAP_SIZE);
    hreq->timeout.cb = spctrm_scn_2g_wireless_scan_task;
    uloop_timeout_set(&hreq->timeout,1000);
    return;
}

static void spctrm_scn_2g_ubus_set_reply(struct uloop_timeout *t) 
{ 
    char start_msg[9] = "start";
    struct spctrm_scn_2g_channel_info current_channel_info;
    struct spctrm_scn_2g_ubus_set_request *hreq = container_of(t,struct spctrm_scn_2g_ubus_set_request,timeout);
    int i;
    struct spctrm_scn_2g_device_info *p;
    char *payload;
    static struct blob_buf buf;
    __u32 instant;

    instant = 0;

    /* get current channel info */
    memset(&current_channel_info,0,sizeof(current_channel_info));
    if (spctrm_scn_2g_wireless_get_channel_info(&current_channel_info,GET_EXT_IFNAME(hreq->band)) == FAIL) {
        SPCTRM_SCN_ERR("spctrm_scn_2g_wireless_get_channel_info FAIL \r\n");
        return;
    }
    
    if (hreq->band == BAND_5G) {
        spctrm_scn_2g_wireless_channel_info_to_file(&current_channel_info,"saved_channel_info_5g","/etc/spectrum_scan/saved_channel_info.json");
    } else if (hreq->band == BAND_2G) {
        spctrm_scn_2g_wireless_channel_info_to_file(&current_channel_info,"saved_channel_info_2g","/etc/spectrum_scan/saved_channel_info.json");
    }

    spctrm_scn_2g_rlog_get_module_info("spectrumScan");

    list_for_each_device(p,i,&g_spctrm_scn_2g_device_list) {
        if (strcmp(p->role,"ap") != 0) {
            if (spctrm_scn_2g_common_mac_2_nodeadd(p->mac,&instant) == FAIL) {
                SPCTRM_SCN_ERR("spctrm_scn_2g_common_mac_2_nodeadd FAIL \r\n");
                free(hreq);
                return;
            }

            SPCTRM_SCN_INFO("send to mac %x\r\n",p->mac);
            SPCTRM_SCN_INFO("%d\r\n",hreq->scan_time);
            spctrm_scn_2g_tipc_send(instant,PROTOCAL_TYPE_SCAN,sizeof(struct spctrm_scn_2g_ubus_set_request),hreq);
        }	
    }

    p = spctrm_scn_2g_dev_find_ap(&g_spctrm_scn_2g_device_list);
    p->finished_flag = FINISHED;
    hreq->timeout.cb = spctrm_scn_2g_tipc_wait_cpe_cb;
    uloop_timeout_set(&hreq->timeout,1000);
}

static int spctrm_scn_2g_ubus_tipc_send(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
    struct blob_attr *tb[__SPCTRM_SCN_TIPC_SEND_MAX];
    static struct blob_buf b;
    int ret = 0;
    blobmsg_parse(spctrm_scn_2g_ubus_tipc_send_policy, ARRAY_SIZE(spctrm_scn_2g_ubus_tipc_send_policy), tb, blob_data(msg), blob_len(msg));

    spctrm_scn_2g_tipc_send(blobmsg_get_u32(tb[SPCTRM_SCN_INSTANT]),
                        blobmsg_get_u32(tb[SPCTRM_SCN_MSG_TYPE]),
                        strlen(blobmsg_get_string(tb[SPCTRM_SCN_PAYLOAD])) + 1,
                        blobmsg_get_string(tb[SPCTRM_SCN_PAYLOAD]));
    return UBUS_STATUS_OK;
}
static int spctrm_scn_2g_ubus_set(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
    struct spctrm_scn_2g_ubus_set_request *hreq;
    size_t len;
    static struct blob_buf buf;
    struct blob_attr *tb[__SPCTRM_SCN_SCAN_MAX];
    struct blob_attr *channel_list_array[MAX_CHANNEL_NUM];
    struct blob_attr *bw_list_array[MAX_BW_NUM];
    static struct blobmsg_policy channel_list_policy[MAX_CHANNEL_NUM];
    uint8_t bw_bitmap;
    static struct blobmsg_policy bw_list_policy[MAX_BW_NUM];
    int i;
    char tmp[128];
    unsigned long country_channel_bitmap[CHANNEL_BITMAP_ARRAY_DEPTH];
    uint8_t band,channel_num,channel,nr;
    struct spctrm_scn_2g_device_info *p;
    

    memset(&buf,0,sizeof(struct blob_buf));
    blob_buf_init(&buf, 0);

    for (i = 0; i < MAX_BW_NUM; i++) {
        bw_list_policy[i].type = BLOBMSG_TYPE_INT32;
    }

    for (i = 0; i < MAX_CHANNEL_NUM; i++) {
        channel_list_policy[i].type = BLOBMSG_TYPE_INT32;
    }

    blobmsg_parse(spctrm_scn_2g_ubus_set_policy, ARRAY_SIZE(spctrm_scn_2g_ubus_set_policy), tb, blob_data(msg), blob_len(msg));

    if (g_spctrm_scn_2g_status == SPCTRM_SCN_2G_SCAN_BUSY) {
        goto error;
    }

    if (tb[SPCTRM_SCN_BAND]) {
        band = blobmsg_get_u32(tb[SPCTRM_SCN_BAND]);
        SPCTRM_SCN_INFO("band %d\r\n",band);
    } else {
        SPCTRM_SCN_WARN("band NULL\r\n");
        goto error;
    }

    if (band != BAND_5G && band != BAND_2G) {
        SPCTRM_SCN_WARN("band error\r\n");
        goto error;
    }

    memset(country_channel_bitmap,0,sizeof(country_channel_bitmap));
    if (spctrm_scn_2g_wireless_country_channel_get_channellist(country_channel_bitmap,&channel_num,SPCTRM_SCN_2G_BW_20,band) == FAIL) {
        SPCTRM_SCN_ERR("spctrm_scn_2g_wireless_country_channel_get_channellist FAIL \r\n");
        goto error;
    }

    len = sizeof(struct spctrm_scn_2g_ubus_set_request);
	hreq = calloc(1, len);
    if (hreq == NULL) {
        SPCTRM_SCN_ERR("hreq NULL \r\n");
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    memset(&hreq->bw_bitmap,0,sizeof(uint8_t));
    memset(hreq->channel_bitmap,0,sizeof(hreq->channel_bitmap));
    hreq->channel_index = 0;
    hreq->channel_num = 0;
    hreq->scan_time = 0;
    hreq->band = 0;
    memset(&hreq->spctrm_scn_2g_device_info,0,sizeof(struct spctrm_scn_2g_device_info));
    hreq->band = band;
    SPCTRM_SCN_INFO("band %d\r\n",hreq->band);
    bw_bitmap = 0;

    if (spctrm_scn_2g_wireless_country_channel_get_bwlist(&bw_bitmap,hreq->band) == FAIL) {
        SPCTRM_SCN_ERR("spctrm_scn_2g_wireless_country_channel_get_bwlist fail \r\n");
        free(hreq);
        goto error;
    }

    if (tb[SPCTRM_SCN_BW_LIST]) {
        blobmsg_parse_array(bw_list_policy, ARRAY_SIZE(bw_list_policy), bw_list_array, blobmsg_data(tb[SPCTRM_SCN_BW_LIST]), blobmsg_len(tb[SPCTRM_SCN_BW_LIST]));
        for (i = 0;i < blobmsg_check_array(tb[SPCTRM_SCN_BW_LIST], BLOBMSG_TYPE_INT32);i++) {
            set_bit(BW_TO_SET_BIT(blobmsg_get_u32(bw_list_array[i])),&hreq->bw_bitmap);
        }

        if (bw_bitmap & hreq->bw_bitmap != hreq->bw_bitmap) {
            hreq->bw_bitmap = SPCTRM_SCN_2G_BW_20;
        }
    } else {
        hreq->bw_bitmap = SPCTRM_SCN_2G_BW_20;
    }

    if (tb[SPCTRM_SCN_CHANNEL_LIST]) {
        /* custom channel list */
        channel_num = blobmsg_check_array(tb[SPCTRM_SCN_CHANNEL_LIST], BLOBMSG_TYPE_INT32);
        blobmsg_parse_array(channel_list_policy, ARRAY_SIZE(channel_list_policy), channel_list_array, blobmsg_data(tb[SPCTRM_SCN_CHANNEL_LIST]), blobmsg_len(tb[SPCTRM_SCN_CHANNEL_LIST]));
        for (i = 0;i < channel_num;i++) {
            channel = blobmsg_get_u32(channel_list_array[i]);

            if (spctrm_scn_2g_wireless_check_channel(channel) == FAIL) {
                SPCTRM_SCN_ERR("spctrm_scn_2g_wireless_check_channel FAIL \r\n");
                free(hreq);
                goto error;
            }
            SPCTRM_SCN_INFO("band %d",hreq->band);
            if (channel_to_bitset(channel,&nr,hreq->band) == FAIL) {
                SPCTRM_SCN_ERR("channel_to_bitset  FAIL\r\n");
                free(hreq);
                goto error;
            }

            set_bit(nr,hreq->channel_bitmap[BW_BITMAP_20MHZ_INDEX]);            
        }
        spctrm_scn_2g_wireless_show_channel_bitmap(hreq->channel_bitmap[BW_BITMAP_20MHZ_INDEX]);
    
    } else {
        /* default */
        SPCTRM_SCN_INFO("band %d\r\n",hreq->band);
        memcpy(hreq->channel_bitmap[BW_BITMAP_20MHZ_INDEX],country_channel_bitmap,sizeof(country_channel_bitmap));
        spctrm_scn_2g_wireless_show_channel_bitmap(hreq->channel_bitmap[BW_BITMAP_20MHZ_INDEX]);
        SPCTRM_SCN_INFO("band %d\r\n",hreq->band);
    }
    /* real channel num */
    hreq->channel_num = channel_num;
    
    i = 1;
    for_each_set_bit_from(i,&hreq->bw_bitmap,BW_BITMAP_SIZE) {
        if (spctrm_scn_2g_wireless_country_channel_get_channellist(hreq->channel_bitmap[i],&channel_num,SPCTRM_SCN_2G_BW_40,band) == FAIL) {
            SPCTRM_SCN_ERR("spctrm_scn_2g_wireless_country_channel_get_channellist FAIL \r\n");
            goto error;
        }
    }


    SPCTRM_SCN_DBG("band %d\r\n",hreq->band);
    spctrm_scn_2g_wireless_show_channel_bitmap(hreq->channel_bitmap[BW_BITMAP_20MHZ_INDEX]);
    SPCTRM_SCN_DBG("band %d\r\n",hreq->band);
    if (tb[SPCTRM_SCN_SCAN_TIME]) {
        hreq->scan_time = blobmsg_get_u32(tb[SPCTRM_SCN_SCAN_TIME]);
    } else {
        /* default scan time*/
        hreq->scan_time = DEFAULT_SCAN_TIME;
    }

    SPCTRM_SCN_DBG("--------------------bitmap set-----------------\r\n");
    SPCTRM_SCN_DBG("bw20 channel bitmap");
    spctrm_scn_2g_wireless_show_channel_bitmap(hreq->channel_bitmap[BW_BITMAP_20MHZ_INDEX]);
    SPCTRM_SCN_DBG("bw40 channel bitmap");
    spctrm_scn_2g_wireless_show_channel_bitmap(hreq->channel_bitmap[1]);
    SPCTRM_SCN_DBG("bw80 channel bitmap");
    spctrm_scn_2g_wireless_show_channel_bitmap(hreq->channel_bitmap[2]);
    SPCTRM_SCN_DBG("-----------------------------------------------\r\n");
    memset(&g_spctrm_scn_2g_device_list,0,sizeof(struct spctrm_scn_2g_device_list));
    if (spctrm_scn_2g_redbs_get_dev_list_info(&g_spctrm_scn_2g_device_list) == FAIL) {
        SPCTRM_SCN_ERR("spctrm_scn_2g_redbs_get_dev_list_info FAIL \r\n");
        free(hreq);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    SPCTRM_SCN_DBG("--------------------bitmap set-----------------\r\n");
    spctrm_scn_2g_wireless_show_channel_bitmap(hreq->channel_bitmap[BW_BITMAP_20MHZ_INDEX]);
    SPCTRM_SCN_DBG("-----------------------------------------------\r\n");

    list_for_each_device(p,i,&g_spctrm_scn_2g_device_list) {
        SPCTRM_SCN_DBG("%s\r\n",p->series_no);
    }

    SPCTRM_SCN_DBG("band %d\r\n",hreq->band);
    p = spctrm_scn_2g_dev_find_ap(&g_spctrm_scn_2g_device_list);
    if (p == NULL) {
        SPCTRM_SCN_ERR("spctrm_scn_2g_dev_find_ap FAIL \r\n");
        free(hreq);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    SPCTRM_SCN_DBG("band %d\r\n",hreq->band);
    SPCTRM_SCN_DBG("--------------------bitmap set-----------------\r\n");
    spctrm_scn_2g_wireless_show_channel_bitmap(hreq->channel_bitmap[BW_BITMAP_20MHZ_INDEX]);
    SPCTRM_SCN_DBG("-----------------------------------------------\r\n");
    
    
    memcpy(&hreq->spctrm_scn_2g_device_info,p,sizeof(struct spctrm_scn_2g_device_info));
    g_spctrm_scn_2g_status = SPCTRM_SCN_2G_SCAN_BUSY;
    SPCTRM_SCN_DBG("band %d\r\n",hreq->band);
    spctrm_scn_2g_dev_ap_status_to_file(g_spctrm_scn_2g_status);
    SPCTRM_SCN_DBG("band %d\r\n",hreq->band);
    SPCTRM_SCN_DBG("status save success\r\n");
    
    g_timestamp = time(NULL); 
    g_total_channel = hreq->channel_num;

    hreq->timeout.cb = spctrm_scn_2g_ubus_set_reply;
    uloop_timeout_set(&hreq->timeout,1000);
    memset(tmp,0,sizeof(tmp));
    sprintf(tmp,"%d",hreq->channel_num);
    blobmsg_add_string(&buf,"total_channel",tmp);
#ifdef NEW_FIELD
    blobmsg_add_string(&buf,"code","0");
#else
    blobmsg_add_string(&buf,"status_code","0");
#endif
    ubus_send_reply(ctx,req,buf.head);
    return UBUS_STATUS_OK;
error:
#ifdef NEW_FIELD
    blobmsg_add_string(&buf,"code","-1");
#else
    blobmsg_add_string(&buf,"status_code","-1");
#endif
    ubus_send_reply(ctx,req,buf.head);
    return UBUS_STATUS_OK;
}

void spctrm_scn_2g_ubus_send_notify(uint32_t msg_type,char *payload)
{
    struct blob_buf buf; 
    memset(&buf,0,sizeof(struct blob_buf));
    blob_buf_init(&buf, 0);
    blobmsg_add_u32(&buf,"msg_type",msg_type);
    SPCTRM_SCN_INFO("msg_type %d\r\n",msg_type);
    blobmsg_add_string(&buf,"payload",payload);
    SPCTRM_SCN_INFO("payload %s\r\n",payload);
    ubus_notify(g_ctx, &spctrm_scn_2g_object, "notify", buf.head, -1);
    SPCTRM_SCN_INFO("notify success\r\n");
}

static int spctrm_scn_2g_ubus_get(struct ubus_context *ctx, struct ubus_object *obj,
						struct ubus_request_data *req, const char *method,
						struct blob_attr *msg)
{
	struct blob_attr *tb[__SPCTRM_SCN_SCAN_MAX];
    struct spctrm_scn_2g_ubus_get_request *hreq;
    size_t len;
    static struct blob_buf buf;
    char tmp[128];

    len = sizeof(struct spctrm_scn_2g_ubus_get_request);
	hreq = calloc(1, len);
    if (hreq == NULL) {
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    memset(&buf,0,sizeof(struct blob_buf));
    blob_buf_init(&buf, 0);
    blobmsg_add_json_from_file(&buf,SPCTRM_SCN_2G_DEV_LIST_JSON_PATH);
    if (g_spctrm_scn_2g_status == SPCTRM_SCN_2G_SCAN_BUSY) {
        memset(tmp,0,sizeof(tmp));
        sprintf(tmp,"%d",g_spctrm_scn_2g_scan_schedule);
        blobmsg_add_string(&buf,"scan_schedule",tmp);

        memset(tmp,0,sizeof(tmp));
        sprintf(tmp,"%d",g_total_channel);
        blobmsg_add_string(&buf,"total_channel",tmp);
    }
    ubus_send_reply(ctx,req,buf.head);

	return UBUS_STATUS_OK;
}

void spctrm_scn_2g_ubus_task(struct ubus_context *ctx)
{
    const char *ubus_socket = NULL;
    int ret;
    SPCTRM_SCN_INFO("\r\n");
    
    g_ctx = ctx;
    if (!ctx) {
        fprintf(stderr, "Failed to connect to ubus\n");
        return NULL;
    }

    ret = ubus_add_object(ctx, &spctrm_scn_2g_object);
    if (ret) {
        fprintf(stderr, "Failed to add object: %s\n", ubus_strerror(ret));
        return;
    }

    SPCTRM_SCN_INFO("\r\n");
    ubus_add_uloop(ctx);
    SPCTRM_SCN_INFO("spctrm_scn_2g_ubus_task\r\n");
}
