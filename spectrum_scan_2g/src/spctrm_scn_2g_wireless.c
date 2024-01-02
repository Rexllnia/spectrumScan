#include "spctrm_scn_2g_wireless.h"

extern __u32 g_spctrm_scn_2g_ap_instant;
extern uint8_t g_spctrm_scn_2g_scan_schedule;
extern int8_t g_spctrm_scn_2g_status;
extern struct spctrm_scn_2g_device_list g_spctrm_scn_2g_device_list;
char g_2g_ext_ifname[IFNAMSIZ];
char g_5g_ext_ifname[IFNAMSIZ];
extern char g_apcli_ifname[IFNAMSIZ];
static struct avl_tree g_floornoise_avl_tree;
static struct avl_tree g_obss_util_avl_tree;

static int avl_nrcmp(const void *k1, const void *k2, void *ptr);

void spctrm_scn_2g_wireless_channel_scan(struct uloop_timeout *t) 
{
    struct spctrm_scn_2g_ubus_set_request *hreq = container_of(t,struct spctrm_scn_2g_ubus_set_request,timeout);
    static int i,bw_index;
    int counter;
    struct avl_sort_element *avl_elem,*p,*tmp;
    if (i < hreq->scan_time) {
        /* on scanning */
        avl_elem = malloc(sizeof(struct avl_sort_element));
        memset(avl_elem,0,sizeof(struct avl_sort_element));
        if (spctrm_scn_2g_wireless_get_channel_info(&avl_elem->spctrm_scn_2g_channel_info,GET_EXT_IFNAME(hreq->band)) != FAIL) {
            avl_elem->avl_floornoise_node.key = &avl_elem->spctrm_scn_2g_channel_info.floornoise;
            avl_elem->avl_obss_util_node.key = &avl_elem->spctrm_scn_2g_channel_info.obss_util;

            avl_insert(&g_floornoise_avl_tree,&avl_elem->avl_floornoise_node);
            avl_insert(&g_obss_util_avl_tree,&avl_elem->avl_obss_util_node);
        } else {
            SPCTRM_SCN_WARN("spctrm_scn_2g_wireless_get_channel_info FAIL\r\n");
            free(avl_elem);
        }


        hreq->timeout.cb = spctrm_scn_2g_wireless_channel_scan; 
        i++;
    } else {
        /* scan over */
        avl_find_median(&g_floornoise_avl_tree,p,avl_floornoise_node,counter) {
            if (SET_BIT_TO_BW(bw_index) == _20MHZ) {
                hreq->spctrm_scn_2g_device_info.bw20_channel_info[hreq->channel_index].floornoise = p->spctrm_scn_2g_channel_info.floornoise;
            } else if (SET_BIT_TO_BW(bw_index) == _40MHZ) {
                hreq->spctrm_scn_2g_device_info.bw40_channel_info[hreq->channel_index].floornoise = p->spctrm_scn_2g_channel_info.floornoise;
            } else if (SET_BIT_TO_BW(bw_index) == _80MHZ) {
                hreq->spctrm_scn_2g_device_info.bw80_channel_info[hreq->channel_index].floornoise = p->spctrm_scn_2g_channel_info.floornoise;
            }
        }
        avl_find_median(&g_obss_util_avl_tree,p,avl_obss_util_node,counter) {
            if (SET_BIT_TO_BW(bw_index) == _20MHZ) {
                hreq->spctrm_scn_2g_device_info.bw20_channel_info[hreq->channel_index].obss_util = p->spctrm_scn_2g_channel_info.obss_util;
            } else if (SET_BIT_TO_BW(bw_index) == _40MHZ) {
                hreq->spctrm_scn_2g_device_info.bw40_channel_info[hreq->channel_index].obss_util = p->spctrm_scn_2g_channel_info.obss_util;
            } else if (SET_BIT_TO_BW(bw_index) == _80MHZ) {
                hreq->spctrm_scn_2g_device_info.bw80_channel_info[hreq->channel_index].obss_util = p->spctrm_scn_2g_channel_info.obss_util;
            }
        }
        SPCTRM_SCN_DBG("hreq->channel_index %d \r\n",hreq->channel_index);
        SPCTRM_SCN_DBG("channel %d\r\n",hreq->spctrm_scn_2g_device_info.bw20_channel_info[hreq->channel_index].channel);
        SPCTRM_SCN_DBG("floornoise %d\r\n",hreq->spctrm_scn_2g_device_info.bw20_channel_info[hreq->channel_index].floornoise);
        SPCTRM_SCN_DBG("utilization %d\r\n",hreq->spctrm_scn_2g_device_info.bw20_channel_info[hreq->channel_index].obss_util);
        
        /* reinitialize */ 
        avl_remove_all_elements(&g_floornoise_avl_tree,p,avl_floornoise_node,tmp) {
            free(p);
        }
        i = 0;
        bw_index = find_next_bit(&hreq->bw_bitmap,BW_BITMAP_SIZE,bw_index+1);
        SPCTRM_SCN_INFO("find next bw [%d]\r\n",bw_index);

        /* check if the current channel support this bw */
        if ((bw_index != BW_BITMAP_SIZE) && test_bit(hreq->channel_index,hreq->channel_bitmap[bw_index])) { 
            /* switch to next bw */
            spctrm_scn_2g_wireless_change_bw(SET_BIT_TO_BW(bw_index),hreq->band); 
            /* switch to next bw init */
            avl_init(&g_floornoise_avl_tree,avl_nrcmp,false,NULL);
            avl_init(&g_obss_util_avl_tree,avl_nrcmp,false,NULL);
            hreq->timeout.cb = spctrm_scn_2g_wireless_channel_scan;
        } else {
            /* switch to next channel */
            bw_index = 0;
            spctrm_scn_2g_wireless_change_bw(_20MHZ,hreq->band);
            hreq->channel_index = find_next_bit(hreq->channel_bitmap[BW_BITMAP_20MHZ_INDEX],CHANNEL_BITMAP_SIZE,hreq->channel_index+1);
            hreq->timeout.cb = spctrm_scn_2g_wireless_scan_task;
            SPCTRM_SCN_INFO("switch to next channel\r\n");
        }
    }

    uloop_timeout_set(&hreq->timeout,SCAN_INTERVAL);
}

int spctrm_scn_2g_wireless_process_recover_handle()
{
    json_object *root,*status_obj;
    struct spctrm_scn_2g_channel_info saved_channel_info_5g,saved_channel_info_2g;

    status_obj = NULL;
    root = NULL;
    memset(&saved_channel_info_5g,0,sizeof(saved_channel_info_5g));
    memset(&saved_channel_info_2g,0,sizeof(saved_channel_info_2g));

    root = json_object_from_file(SPCTRM_SCN_2G_DEV_LIST_JSON_PATH);
    if (root == NULL) {
        SPCTRM_SCN_ERR("json_object_from_file FAIL\r\n");
        return FAIL;
    }

    status_obj = json_object_object_get(root,"_status_code");

    if (status_obj == NULL) {
        SPCTRM_SCN_ERR("json_object_object_get FAIL\r\n");
        json_object_put(root);
        return FAIL;
    }
    if (json_object_get_int(status_obj) == SPCTRM_SCN_2G_SCAN_BUSY) {
        if (g_band_support & SUPPORT_5G) {
            spctrm_scn_2g_wireless_channel_info_from_file(&saved_channel_info_5g,"saved_channel_info_5g","/etc/spectrum_scan/saved_channel_info.json");
            spctrm_scn_2g_wireless_change_channel(saved_channel_info_5g.channel,BAND_5G);
            spctrm_scn_2g_wireless_change_bw(saved_channel_info_5g.bw,BAND_5G);
        }
        if (g_band_support & SUPPORT_2G) {
            spctrm_scn_2g_wireless_channel_info_from_file(&saved_channel_info_2g,"saved_channel_info_2g","/etc/spectrum_scan/saved_channel_info.json");
            SPCTRM_SCN_INFO("restore channel to [%d] \r\n",saved_channel_info_2g.channel);
            SPCTRM_SCN_INFO("restore bw to [%d] \r\n",saved_channel_info_2g.bw);
            spctrm_scn_2g_wireless_change_channel(saved_channel_info_2g.channel,BAND_2G);
            spctrm_scn_2g_wireless_change_bw(saved_channel_info_2g.bw,BAND_2G);
            spctrm_scn_2g_dev_ap_status_to_file(SPCTRM_SCN_2G_SCAN_ERROR);
        }
    }
    
    json_object_put(root); 
}

int spctrm_scn_2g_wireless_error_handle(struct uloop_timeout *t)
{
    struct spctrm_scn_2g_ubus_set_request *hreq = container_of(t,struct spctrm_scn_2g_ubus_set_request,timeout);
    struct spctrm_scn_2g_channel_info saved_channel_info;

    g_spctrm_scn_2g_status = SPCTRM_SCN_2G_SCAN_ERROR;
    spctrm_scn_2g_dev_ap_status_to_file(g_spctrm_scn_2g_status);
    memset(&saved_channel_info,0,sizeof(saved_channel_info));
    spctrm_scn_2g_wireless_channel_info_from_file(&saved_channel_info,"saved_channel_info","/etc/spectrum_scan/saved_channel_info.json");

    spctrm_scn_2g_wireless_change_channel(saved_channel_info.channel,hreq->band);
    spctrm_scn_2g_wireless_change_bw(saved_channel_info.bw,hreq->band);
    free(hreq);

}

int spctrm_scn_2g_wireless_ap_finish_cb(struct uloop_timeout *t) 
{
    static struct blob_buf buf;
    struct spctrm_scn_2g_ubus_set_request *hreq = container_of(t,struct spctrm_scn_2g_ubus_set_request,timeout);
    static int retry;
    struct spctrm_scn_2g_channel_info saved_channel_info;
    int channel_idx,i;
    struct spctrm_scn_2g_device_info *p;

    SPCTRM_SCN_DBG_FILE("enter spctrm_scn_2g_wireless_ap_finish_cb\r\n");
    SPCTRM_SCN_DBG_FILE("remove disconnect cpe\r\n");
    // spctrm_scn_2g_dev_remove_not_finish_device(&g_spctrm_scn_2g_device_list);
    // spctrm_scn_2g_wireless_get_channel_rate(&g_spctrm_scn_2g_device_list,hreq->channel_bitmap,hreq->band);
    blob_buf_init(&buf, 0);
    SPCTRM_SCN_DBG_FILE("create blobmsg\r\n");
    if (spctrm_scn_2g_ubus_add_blobmsg(&buf,&g_spctrm_scn_2g_device_list,hreq) == FAIL) {
        SPCTRM_SCN_ERR("spctrm_scn_2g_ubus_add_blobmsg FAIL\r\n");
        goto fail;
    }

    if (spctrm_scn_2g_dev_blobmsg_to_file(&buf,SPCTRM_SCN_2G_DEV_LIST_JSON_PATH) == FAIL) {
        SPCTRM_SCN_ERR("spctrm_scn_2g_dev_blobmsg_to_file FAIL\r\n");
        goto fail;
    }
    
    memset(&saved_channel_info,0,sizeof(saved_channel_info));
    if (hreq->band == BAND_5G) {
        spctrm_scn_2g_wireless_channel_info_from_file(&saved_channel_info,"saved_channel_info_5g","/etc/spectrum_scan/saved_channel_info.json");
    } else if (hreq->band == BAND_2G) {
        spctrm_scn_2g_wireless_channel_info_from_file(&saved_channel_info,"saved_channel_info_2g","/etc/spectrum_scan/saved_channel_info.json");
    }
    SPCTRM_SCN_INFO("saved_channel_info.channel %d\r\n",saved_channel_info.channel);
    SPCTRM_SCN_INFO("saved_channel_info.bw %d\r\n",saved_channel_info.bw);
    
    spctrm_scn_2g_wireless_change_channel(saved_channel_info.channel,hreq->band);
    spctrm_scn_2g_wireless_change_bw(saved_channel_info.bw,hreq->band);

    spctrm_scn_2g_rlog_upload_blobmsg_to_macc(&buf);

    if (g_spctrm_scn_2g_status == SPCTRM_SCN_2G_SCAN_TIMEOUT) {
        SPCTRM_SCN_INFO("keep waiting cpe timer on");
        hreq->timeout.cb = spctrm_scn_2g_wireless_keep_waiting_cpe_report; 
        uloop_timeout_set(&hreq->timeout,1000);
    } else {
        g_spctrm_scn_2g_status = SPCTRM_SCN_2G_SCAN_IDLE;
        free(hreq);
    }
    spctrm_scn_2g_dev_ap_status_to_file(g_spctrm_scn_2g_status);
    return SUCCESS;
fail:
    
    spctrm_scn_2g_dev_ap_status_to_file(g_spctrm_scn_2g_status);
    g_spctrm_scn_2g_scan_schedule = 0;
    free(hreq);

    return FAIL;

}

void spctrm_scn_2g_wireless_cpe_finish_cb(struct uloop_timeout *t)
{
    __u32 instant;
    static uint8_t retry;
    struct spctrm_scn_2g_ubus_set_request *hreq = container_of(t,struct spctrm_scn_2g_ubus_set_request,timeout);
    spctrm_scn_2g_tipc_recv_packet_head_t rbuf;

    if (retry > 4000) {
        SPCTRM_SCN_ERR("error\r\n");
        g_spctrm_scn_2g_status = SPCTRM_SCN_2G_SCAN_ERROR;
        goto error;
    }

    if (spctrm_scn_2g_common_mac_2_nodeadd(hreq->spctrm_scn_2g_device_info.mac,&instant) == FAIL) {
        SPCTRM_SCN_ERR("error\r\n");
        g_spctrm_scn_2g_status = SPCTRM_SCN_2G_SCAN_ERROR;
        goto error;
    }
    
    spctrm_scn_2g_common_get_sn(&hreq->spctrm_scn_2g_device_info.series_no);
    if (g_spctrm_scn_2g_mode == AP_MODE) {
        strncpy(&hreq->spctrm_scn_2g_device_info.role,"ap",ROLE_STR_LEN);
    } else {
        strncpy(&hreq->spctrm_scn_2g_device_info.role,"cpe",ROLE_STR_LEN);
    }
    
    SPCTRM_SCN_DBG("hreq->spctrm_scn_2g_device_info.mac instant %d\r\n",instant);
    SPCTRM_SCN_DBG("cpe send floornoise %d\r\n",hreq->spctrm_scn_2g_device_info.bw20_channel_info[1].floornoise);
    if (spctrm_scn_2g_tipc_send_recv(instant,PROTOCAL_TYPE_CPE_REPORT,sizeof(struct spctrm_scn_2g_device_info),(char *)&hreq->spctrm_scn_2g_device_info,&rbuf) == FAIL) {
        SPCTRM_SCN_INFO("cpe send retry %d\r\n",retry);
        retry++;
        uloop_timeout_set(&hreq->timeout,1000);
        return;
    } else {
        SPCTRM_SCN_INFO("cpe send success \r\n");
        g_spctrm_scn_2g_status = SPCTRM_SCN_2G_SCAN_IDLE;
    }

error:
    retry = 0;
    spctrm_scn_2g_dev_ap_status_to_file(g_spctrm_scn_2g_status);
    free(hreq);
    return;

}
void spctrm_scn_2g_wireless_keep_waiting_cpe_report(struct uloop_timeout *t) 
{
    struct spctrm_scn_2g_ubus_set_request *hreq = container_of(t,struct spctrm_scn_2g_ubus_set_request,timeout);
    static int retry;
    struct spctrm_scn_2g_device_info *p;
    int i;
    i = 0;
    static struct blob_buf buf;
    
    SPCTRM_SCN_DBG("keep waiting\r\n");
    if (g_spctrm_scn_2g_status == SCAN_TIMEOUT) {
        SPCTRM_SCN_DBG("g_spctrm_scn_2g_status %d\r\n", g_spctrm_scn_2g_status);
        blob_buf_init(&buf, 0);

        if (spctrm_scn_2g_ubus_add_blobmsg(&buf,&g_spctrm_scn_2g_device_list,hreq) == FAIL) {
            SPCTRM_SCN_ERR("spctrm_scn_2g_ubus_add_blobmsg FAIL\r\n");
        }
        if (spctrm_scn_2g_dev_blobmsg_to_file(&buf,SPCTRM_SCN_2G_DEV_LIST_JSON_PATH) == FAIL) {
            SPCTRM_SCN_ERR("spctrm_scn_2g_dev_blobmsg_to_file FAIL\r\n");
        }


        spctrm_scn_2g_dev_ap_status_to_file(g_spctrm_scn_2g_status);

        list_for_each_device(p,i,&g_spctrm_scn_2g_device_list) {
            if (p->finished_flag == NOT_FINISH) {
                hreq->timeout.cb = spctrm_scn_2g_wireless_keep_waiting_cpe_report; 
                uloop_timeout_set(&hreq->timeout,1000);
                return;
            } 
        }
        SPCTRM_SCN_INFO("receive all devices\r\n");
        g_spctrm_scn_2g_status = SCAN_IDLE;
        spctrm_scn_2g_dev_ap_status_to_file(g_spctrm_scn_2g_status);
        free(hreq);
        return;
    } else {
        SPCTRM_SCN_INFO("waiting finished\r\n");
        SPCTRM_SCN_DBG("g_spctrm_scn_2g_status %d\r\n", g_spctrm_scn_2g_status);
        free(hreq);
        return;
    }

}
void spctrm_scn_2g_wireless_wait_cpe_report_cb(struct uloop_timeout *t) 
{
    struct spctrm_scn_2g_ubus_set_request *hreq = container_of(t,struct spctrm_scn_2g_ubus_set_request,timeout);
    
    struct spctrm_scn_2g_device_info *p;
    int i;
    i = 0;

    hreq->spctrm_scn_2g_tipc_wait_cpe_retry++;
    SPCTRM_SCN_INFO("retry %d\r\n",hreq->spctrm_scn_2g_tipc_wait_cpe_retry);
    if (hreq->spctrm_scn_2g_tipc_wait_cpe_retry == 3) {
        g_spctrm_scn_2g_status = SPCTRM_SCN_2G_SCAN_TIMEOUT;
        spctrm_scn_2g_wireless_ap_finish_cb(t);
        return;
    } 

    list_for_each_device(p,i,&g_spctrm_scn_2g_device_list) {
        SPCTRM_SCN_DBG("p->finished_flag %d\r\np->series_no %s\r\np->role %s\r\n",p->finished_flag,p->series_no,p->role);
        SPCTRM_SCN_DBG("floornoise %d\r\n",p->bw20_channel_info[1].floornoise);
        if (p->finished_flag == NOT_FINISH) {
            hreq->timeout.cb = spctrm_scn_2g_wireless_wait_cpe_report_cb; 
            uloop_timeout_set(&hreq->timeout,1000);
            return;
        }
    }
    
    spctrm_scn_2g_wireless_ap_finish_cb(t);


}
static int avl_nrcmp(const void *k1, const void *k2, void *ptr)
{
    int *data1 = k1;
    int *data2 = k2;

    if (*data1 > *data2) {
        return 1;
    } else if (*data1 < *data2) {
        return -1;
    } else {
        return 0;
    }

}

extern int spctrm_scn_wireless_get_band_5G_apcli_ifname(char *apcli_ifname);

int spctrm_scn_2g_wireless_get_band_5G_apcli_ifname(char *apcli_ifname)
{
    spctrm_scn_wireless_get_band_5G_apcli_ifname(apcli_ifname);
}

int spctrm_scn_2g_wireless_update_device_info_file()
{
    json_object *root;
    root = NULL;
    root = json_object_from_file(SPCTRM_SCN_2G_DEV_LIST_JSON_PATH);
    
    json_object_put(root);
}

int spctrm_scn_2g_wireless_get_ext_ifname(char *ext_ifname,uint8_t band)
{
    json_object *root,*wireless_obj,*ext_ifname_obj,*radiolist_obj;
    json_object *radiolist_elem_obj,*band_support_obj;
    int i;
    char band_str[10];

    memset(band_str,0,sizeof(band_str));
    ext_ifname_obj = NULL;
    wireless_obj = NULL;
    radiolist_obj = NULL;
    radiolist_elem_obj = NULL;
    band_support_obj = NULL;

    if (ext_ifname == NULL) {
        return FAIL;
    }

    if (band == BAND_5G) {
        strcpy(band_str,"5G");
    } else if (band == BAND_2G) {
        strcpy(band_str,"2.4G");
    } else {
        return FAIL;
    }

    root = json_object_from_file("/tmp/rg_device/rg_device.json");
    if (root == NULL) {
        SPCTRM_SCN_DBG("\nFAIL\n");
        json_object_put(root);
        return FAIL;
    }
    wireless_obj = json_object_object_get(root,"wireless");
    if (wireless_obj == NULL) {
        SPCTRM_SCN_DBG("\nFAIL\n");
        json_object_put(root);
        return FAIL;
    }

    radiolist_obj = json_object_object_get(wireless_obj,"radiolist");
    if (radiolist_obj == NULL) {
        SPCTRM_SCN_DBG("\nFAIL\n");
        json_object_put(root);
        return FAIL;
    }

    for (i = 0;i < json_object_array_length(radiolist_obj);i++) {
        radiolist_elem_obj = json_object_array_get_idx(radiolist_obj,i);
        band_support_obj = json_object_object_get(radiolist_elem_obj,"band_support");
        if (strcmp(json_object_get_string(band_support_obj),band_str) == 0) {
            if (band == BAND_5G) {
                g_band_support |= SUPPORT_5G;
            } else if (band == BAND_2G) {
                g_band_support |= SUPPORT_2G;
            }
            ext_ifname_obj = json_object_object_get(radiolist_elem_obj,"ext_ifname");
            if (ext_ifname_obj == NULL) {
                SPCTRM_SCN_DBG("\nFAIL\n");
                json_object_put(root);
                return FAIL;
            }
            break;
        }
    }
    if (ext_ifname_obj == NULL) {
        SPCTRM_SCN_DBG("not support %dG\r\n",band);
        json_object_put(root);
        return FAIL;
    }
    snprintf(ext_ifname,IFNAMSIZ,"%s0",json_object_get_string(ext_ifname_obj));

    json_object_put(root);
    SPCTRM_SCN_DBG("ext_ifname %s\r\n",ext_ifname);
    return SUCCESS;
}

void spctrm_scn_2g_wireless_scan_task(struct uloop_timeout *t) 
{
    struct spctrm_scn_2g_ubus_set_request *hreq = container_of(t,struct spctrm_scn_2g_ubus_set_request,timeout);
    uint8_t channel;
    
    struct spctrm_scn_2g_device_info *p;
    int fd;
    __u32 instant;

    if (hreq->channel_index == CHANNEL_BITMAP_SIZE) {
        goto scan_over;
    }
    
    SPCTRM_SCN_DBG("hreq->scan_time %d\r\n",hreq->scan_time);

    SPCTRM_SCN_INFO("Bit %d is set\n", hreq->channel_index);
    if (bitset_to_channel(hreq->channel_index,&channel,hreq->band) == FAIL) {
        SPCTRM_SCN_ERR("bitset_to_channel error\r\n");
        goto fail;
    }

    SPCTRM_SCN_INFO("channel %d\r\n",channel);
    hreq->spctrm_scn_2g_device_info.bw20_channel_info[hreq->channel_index].channel = channel;
    if (spctrm_scn_2g_wireless_change_channel(channel,hreq->band) == FAIL) {
        SPCTRM_SCN_ERR("spctrm_scn_2g_wireless_change_channel error\r\n");
        goto fail;
    }

    g_spctrm_scn_2g_scan_schedule++;
    /* median calculation init */
    avl_init(&g_floornoise_avl_tree,avl_nrcmp,false,NULL);
    avl_init(&g_obss_util_avl_tree,avl_nrcmp,false,NULL);

    hreq->timeout.cb = spctrm_scn_2g_wireless_channel_scan; 
    uloop_timeout_set(&hreq->timeout,1000);

    return;
    
scan_over:
    /* all channel scan over */
    SPCTRM_SCN_INFO("all channel scan over \r\n");
    g_spctrm_scn_2g_scan_schedule = 0;
    spctrm_scn_2g_wireless_get_channel_score(&hreq->spctrm_scn_2g_device_info,hreq->channel_bitmap,hreq->band);
    if (g_spctrm_scn_2g_mode == AP_MODE) {
        p = spctrm_scn_2g_dev_find_ap(&g_spctrm_scn_2g_device_list);
        if (p == NULL) {
            SPCTRM_SCN_ERR("spctrm_scn_2g_dev_find_ap error\r\n");
            goto fail;
        }

        SPCTRM_SCN_DBG("sn %s\r\n",p->series_no);
        SPCTRM_SCN_DBG("mac %s\r\n",p->mac);
        SPCTRM_SCN_DBG("role %s\r\n",p->role);

        SPCTRM_SCN_DBG("sn %s\r\n",hreq->spctrm_scn_2g_device_info.series_no);
        SPCTRM_SCN_DBG("mac %s\r\n",hreq->spctrm_scn_2g_device_info.mac);
        SPCTRM_SCN_DBG("role %s\r\n",hreq->spctrm_scn_2g_device_info.role);

        memcpy(p,&hreq->spctrm_scn_2g_device_info, sizeof(struct spctrm_scn_2g_device_info));
        SPCTRM_SCN_DBG("%d\r\n",hreq->spctrm_scn_2g_device_info.bw20_channel_info[BW_BITMAP_20MHZ_INDEX].channel);
        SPCTRM_SCN_DBG("%d\r\n",p->bw20_channel_info[30].floornoise);
        SPCTRM_SCN_DBG("%f\r\n",p->bw40_channel_info[30].score);
        SPCTRM_SCN_DBG("hreq->channel_num %d\r\n",hreq->channel_num);
        p->finished_flag = FINISHED;
        
        hreq->timeout.cb = spctrm_scn_2g_wireless_wait_cpe_report_cb; 
        uloop_timeout_set(&hreq->timeout,1000);
        return;
    } else if (g_spctrm_scn_2g_mode == CPE_MODE) {

      
        SPCTRM_SCN_DBG("apcli interface up\r\n");
        spctrm_scn_2g_common_iwpriv_set(g_apcli_ifname,"ApCliEnable=1",strlen("ApCliEnable=1")+1);
        
        SPCTRM_SCN_DBG("floornoise %d\r\n",hreq->spctrm_scn_2g_device_info.bw20_channel_info[1].floornoise);      
        hreq->timeout.cb = spctrm_scn_2g_wireless_cpe_finish_cb;
        uloop_timeout_set(&hreq->timeout,1000);
        return;
    }
    
    return;
fail:
    if (g_spctrm_scn_2g_mode == CPE_MODE) {
        SPCTRM_SCN_DBG("apcli interface up\r\n");
        spctrm_scn_2g_common_iwpriv_set(g_apcli_ifname,"ApCliEnable=1",strlen("ApCliEnable=1")+1);
    }
    
    g_spctrm_scn_2g_scan_schedule = 0;
    g_spctrm_scn_2g_status = SPCTRM_SCN_2G_SCAN_ERROR;
    spctrm_scn_2g_dev_ap_status_to_file(g_spctrm_scn_2g_status);
    free(hreq);
    return;
}

void spctrm_scn_2g_wireless_change_bw(int bw,uint8_t band) 
{
    char tmp[256];
    char ifname[IFNAMSIZ];

    memset(ifname,0,IFNAMSIZ);

    if (band == BAND_5G) {
        memcpy(ifname,g_5g_ext_ifname,IFNAMSIZ);
    } else if (band == BAND_2G) {
        memcpy(ifname,g_2g_ext_ifname,IFNAMSIZ);
    } else {
        return FAIL;
    }
    SPCTRM_SCN_DBG("ifname %s\r\n",ifname);
    SPCTRM_SCN_DBG("bw %d \r\n",bw);
    switch (bw) {
    case _20MHZ:
        spctrm_scn_2g_common_iwpriv_set(ifname,"HtBw=0",strlen("HtBw=0") + 1);
        break;
    case _40MHZ:
        spctrm_scn_2g_common_iwpriv_set(ifname,"HtBw=1",strlen("HtBw=1") + 1);
        spctrm_scn_2g_common_iwpriv_set(ifname,"VhtBw=0",strlen("VhtBw=0") + 1);
        break;
    case _80MHZ:
        spctrm_scn_2g_common_iwpriv_set(ifname,"HtBw=1",strlen("HtBw=1") + 1);
        spctrm_scn_2g_common_iwpriv_set(ifname,"VhtBw=1",strlen("VhtBw=1") + 1);
        break;
    default:
        return FAIL;
    }
    return SUCCESS;
}

int spctrm_scn_2g_wireless_change_channel(uint8_t channel,uint8_t band) 
{
    char temp[128];
    SPCTRM_SCN_DBG("channel %d\r\n",channel);
    memset(temp,0,sizeof(temp));

    if (spctrm_scn_2g_wireless_check_channel(channel) == FAIL) {
        SPCTRM_SCN_WARN("param error %d\r\n",channel);
        return FAIL;
    }
    
    sprintf(temp,"channel=%d",channel);

    if (band == BAND_5G) {
        spctrm_scn_2g_common_iwpriv_set(g_5g_ext_ifname,temp,strlen(temp) + 1);
    } else if (band == BAND_2G) {
        spctrm_scn_2g_common_iwpriv_set(g_2g_ext_ifname,temp,strlen(temp) + 1);
    } else {
        return FAIL;
    }

    
    return SUCCESS;
}

int spctrm_scn_2g_wireless_get_channel_info(struct spctrm_scn_2g_channel_info *info,char *ifname) 
{
    char msg[1024];
    int skfd;
    int ret;
    struct ifreq ifr;
    rj_ex_ioctl_t ioc;
    rj_radioinfo_t *radio;

    if (ifname == NULL || info == NULL) {
        return FAIL;
    }

    memset(msg,0,1024);
    memset(&ioc, 0, sizeof(rj_ex_ioctl_t));
    ioc.buf = msg;
    ioc.len = 1024;
    ioc.cmd = RJ_WAS_GET_RADIOINFO_EN;;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return FAIL;
    }

    ifr.ifr_data = (__caddr_t)&ioc;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    ret = ioctl(skfd, RJ_WAS_IOCTL_EXTEND, &ifr);
    if (ret != 0) {
        close(skfd);
        return FAIL;
    }
    close(skfd);

    radio = msg;
    SPCTRM_SCN_DBG("bssid:%02x:%02x:%02x:%02x:%02x:%02x\n", PRINT_MAC(radio->bssid));
    SPCTRM_SCN_DBG("channel:%d\n", radio->channel);
    SPCTRM_SCN_DBG("floornoise:%d\n", radio->floornoise);
    SPCTRM_SCN_DBG("utilization:%d\n", radio->utilization);
    SPCTRM_SCN_DBG("txpower:%d\n", radio->txpower);
    SPCTRM_SCN_DBG("bw:%d\n", radio->BW);
    SPCTRM_SCN_DBG("obss_util:%d\n", radio->util_info.obss_util);
    SPCTRM_SCN_DBG("tx_util:%d\n", radio->util_info.tx_util);
    SPCTRM_SCN_DBG("rx_util:%d\n", radio->util_info.rx_util);
    SPCTRM_SCN_DBG("tp_base:%d.%d\n", radio->txpower_base / 2, (radio->txpower_base % 2) * 10 / 2);
    SPCTRM_SCN_DBG("mgmt_frame_pwr:%d.%d\n", radio->mgmt_frame_pwr / 2, (radio->mgmt_frame_pwr % 2) * 10 / 2);
    SPCTRM_SCN_DBG("cac_time:%d\n", radio->dfs_cac_time);
    info->channel = radio->channel;
    if (info->channel == 0) {
        SPCTRM_SCN_WARN("info->channel = 0\r\n");
        return FAIL;
    }
    info->floornoise = radio->floornoise;
    if (info->floornoise == 0) {
        SPCTRM_SCN_WARN("radio->floornoise = 0\r\n");
        return FAIL;
    }

    info->bw = radio->BW;

    info->obss_util = radio->utilization;
    if (info->obss_util > 95 || info->obss_util < 0) {
        SPCTRM_SCN_WARN("info->obss_util %d\r\n",info->obss_util);
        return FAIL;
    }

    info->rx_util = radio->util_info.rx_util;
    info->tx_util = radio->util_info.tx_util;

    info->utilization = radio->utilization;
    if (info->utilization > 95 || info->utilization < 0) {
        SPCTRM_SCN_WARN("info->utilization %d\r\n",info->obss_util);
        return FAIL;
    }  

    return SUCCESS;
}

inline int spctrm_scn_2g_wireless_band_check(uint8_t band) 
{
    if (band != BAND_5G && band != BAND_2G) {
        SPCTRM_SCN_ERR("band error %d\r\n",band);
        return FAIL;
    }
    return SUCCESS;
}

inline int spctrm_scn_2g_wireless_check_channel(uint8_t channel)
{
    if (channel >= 1 && channel <= 13) {
        return SUCCESS;
    }
    if (channel < 36 || channel > 181) {
        return FAIL;
    }

    if (channel >= 36 && channel <= 144) {
        if (channel % 4 != 0) {
            return FAIL;
        }
    }

    if (channel >= 149 && channel <= 181) {
        if ((channel - 1) % 4 != 0) {
            return FAIL;
        }
    }

    return SUCCESS;
}

int spctrm_scn_2g_wireless_get_group_channel_bitmap(unsigned long int* channel_bitmap,
        unsigned long * group_channel_bitmap,int band,int bw_hz) 
{ 
    unsigned long mask[CHANNEL_BITMAP_ARRAY_DEPTH];
    int i;

    if (bw_hz == _20MHZ) {
        memcpy(group_channel_bitmap,channel_bitmap,CHANNEL_BITMAP_ARRAY_DEPTH * sizeof(int));
        return SUCCESS;
    }

    if (band == BAND_5G) {
        memset(group_channel_bitmap,0,sizeof(group_channel_bitmap));
        memset(mask,0,sizeof(mask));

        for (i = 0;i < CHANNEL_BITMAP_SIZE;i+=bw_hz/_20MHZ) {
            set_bit(i,mask);
        }  

        if (bitmap_and(group_channel_bitmap,channel_bitmap,mask,CHANNEL_BITMAP_SIZE) != SUCCESS) {
            return FAIL;
        }
    } else if (band == BAND_2G) {
        memcpy(group_channel_bitmap,channel_bitmap,CHANNEL_BITMAP_ARRAY_DEPTH * sizeof(int));
        return SUCCESS;
    }

    return FAIL;
    
}

int spctrm_scn_2g_wireless_get_channel_score(struct spctrm_scn_2g_device_info *spctrm_scn_2g_device_info,
        unsigned long int (*channel_bitmap)[CHANNEL_BITMAP_ARRAY_DEPTH],uint8_t band) 
{
#define N(floornoise) ((floornoise <= -87)?0.0:\
                        ((floornoise <= -85)?1.0:\
                        ((floornoise <= -82)?2.0:\
                        ((floornoise <= -80)?2.8:\
                        ((floornoise <= -76)?4.0:\
                        ((floornoise <= -71)?4.8:\
                        ((floornoise <= -69)?5.2:\
                        ((floornoise <= -66)?6.4:\
                        ((floornoise <= -62)?7.6:\
                        ((floornoise <= -60)?8.2:\
                        ((floornoise <= -56)?8.8:\
                        ((floornoise <= -52)?9.4:10))))))))))))

    unsigned long bw40_channel_bitmap[CHANNEL_BITMAP_ARRAY_DEPTH],bw80_channel_bitmap[CHANNEL_BITMAP_ARRAY_DEPTH]; 
    int i,channel_num = 0;

    if (spctrm_scn_2g_device_info == NULL) {
        return FAIL;
    }

    i = 0;
    SPCTRM_SCN_DBG("----------------------bw20---------------------\r\n");
    spctrm_scn_2g_wireless_show_channel_bitmap(channel_bitmap[BW_BITMAP_20MHZ_INDEX]);
    SPCTRM_SCN_DBG("----------------------bw40---------------------\r\n");
    spctrm_scn_2g_wireless_show_channel_bitmap(channel_bitmap[BW_BITMAP_40MHZ_INDEX]);
    SPCTRM_SCN_DBG("----------------------bw80---------------------\r\n");
    spctrm_scn_2g_wireless_show_channel_bitmap(channel_bitmap[BW_BITMAP_80MHZ_INDEX]);
    /* bw20 */
    for_each_set_bit(i,channel_bitmap[BW_BITMAP_20MHZ_INDEX],CHANNEL_BITMAP_SIZE) {
        spctrm_scn_2g_device_info->bw20_channel_info[i].score = (1.0 - N((double)spctrm_scn_2g_device_info->bw20_channel_info[i].floornoise) / 20.0) * (1.0 - (double)spctrm_scn_2g_device_info->bw20_channel_info[i].obss_util / 95.0) * 100.0;
    }

    /* bw40 bw80*/
    if (band == BAND_5G) {
        spctrm_scn_2g_wireless_get_group_channel_bitmap(channel_bitmap[1],bw40_channel_bitmap,BAND_5G,_40MHZ);
        for_each_set_bit(i,bw40_channel_bitmap,CHANNEL_BITMAP_SIZE) {
            spctrm_scn_2g_device_info->bw40_channel_info[i].score = ((double)1 - N(MAX(spctrm_scn_2g_device_info->bw40_channel_info[i].floornoise, spctrm_scn_2g_device_info->bw40_channel_info[i+1].floornoise)) / 20) *
                                                    (double)((double)1 - (double)(spctrm_scn_2g_device_info->bw40_channel_info[i].obss_util +
                                                    spctrm_scn_2g_device_info->bw40_channel_info[i + 1].obss_util) / (95 * _40MHZ / _20MHZ)) * 100;
            spctrm_scn_2g_device_info->bw40_channel_info[i].rate = spctrm_scn_2g_device_info->bw20_channel_info[i].score * BAND_5G_BW_40_MAX_RATE / 100;
        }
        spctrm_scn_2g_wireless_get_group_channel_bitmap(channel_bitmap[2],bw80_channel_bitmap,BAND_5G,_80MHZ);
        for_each_set_bit(i,bw80_channel_bitmap,CHANNEL_BITMAP_SIZE) {
            spctrm_scn_2g_device_info->bw80_channel_info[i].score = ((double)1 - N(MAX(MAX(MAX(spctrm_scn_2g_device_info->bw80_channel_info[i].floornoise, 
                                                                                        spctrm_scn_2g_device_info->bw80_channel_info[i + 1].floornoise),
                                                                                        spctrm_scn_2g_device_info->bw80_channel_info[i + 2].floornoise),
                                                                                        spctrm_scn_2g_device_info->bw80_channel_info[i + 3].floornoise)) / 20) *
                                                                    (double)((double)1 - (double)(spctrm_scn_2g_device_info->bw80_channel_info[i].obss_util +
                                                                                                spctrm_scn_2g_device_info->bw80_channel_info[i + 1].obss_util + 
                                                                                                spctrm_scn_2g_device_info->bw80_channel_info[i + 2].obss_util +
                                                                                                spctrm_scn_2g_device_info->bw80_channel_info[i + 3].obss_util) / (95 * _80MHZ / _20MHZ)) * 100;
            spctrm_scn_2g_device_info->bw80_channel_info[i].rate = spctrm_scn_2g_device_info->bw20_channel_info[i].score * BAND_5G_BW_80_MAX_RATE / 100;                       
        }
#ifdef OLD_ALGORITHM
        i = 0;
        for_each_set_bit(i,bw40_channel_bitmap,CHANNEL_BITMAP_SIZE) {
            SPCTRM_SCN_DBG("channel_index %d\r\n",i);
            spctrm_scn_2g_device_info->bw40_channel_info[i].floornoise = MAX(spctrm_scn_2g_device_info->bw20_channel_info[i].floornoise, spctrm_scn_2g_device_info->bw20_channel_info[i+1].floornoise);
            spctrm_scn_2g_device_info->bw40_channel_info[i].score = ((double)1 - N(spctrm_scn_2g_device_info->bw40_channel_info[i].floornoise) / 20) *
                                                    (double)((double)1 - (double)(spctrm_scn_2g_device_info->bw20_channel_info[i].obss_util +
                                                    spctrm_scn_2g_device_info->bw20_channel_info[i + 1].obss_util) / (95 * 40 / 20)) * 100;

            SPCTRM_SCN_DBG("channel %d floornoise %d\r\n",spctrm_scn_2g_device_info->bw20_channel_info[i].channel,spctrm_scn_2g_device_info->bw20_channel_info[i].floornoise);
            SPCTRM_SCN_DBG("channel %d floornoise %d\r\n",spctrm_scn_2g_device_info->bw20_channel_info[i + 1].channel,spctrm_scn_2g_device_info->bw20_channel_info[i + 1].floornoise);
            SPCTRM_SCN_DBG("obss_util %d\r\n",spctrm_scn_2g_device_info->bw20_channel_info[i].obss_util);
            SPCTRM_SCN_DBG("obss_util %d\r\n",spctrm_scn_2g_device_info->bw20_channel_info[i + 1].obss_util);
            SPCTRM_SCN_DBG("score %f\r\n",spctrm_scn_2g_device_info->bw40_channel_info[i].score);      
        } 
#endif
    } else if (band == BAND_2G) {
        for_each_set_bit(i,channel_bitmap[BW_BITMAP_20MHZ_INDEX],CHANNEL_BITMAP_SIZE) {
            spctrm_scn_2g_device_info->bw40_channel_info[i].score = (1.0 - N(spctrm_scn_2g_device_info->bw40_channel_info[i].floornoise)/20) * (1.0 - (double)spctrm_scn_2g_device_info->bw40_channel_info[i].obss_util / 95) * 100;
        }
#ifdef OLD_ALGORITHM
        spctrm_scn_2g_wireless_get_group_channel_bitmap(channel_bitmap[1],bw40_channel_bitmap,BAND_5G,_40MHZ);
        for_each_set_bit(i,bw40_channel_bitmap,CHANNEL_BITMAP_SIZE) {
           spctrm_scn_2g_device_info->bw40_channel_info[i].score = ((double)1 - N(MAX(spctrm_scn_2g_device_info->bw40_channel_info[i].floornoise, spctrm_scn_2g_device_info->bw40_channel_info[i + 4].floornoise)) / 20) *
                                                    (double)((double)1 - (double)(spctrm_scn_2g_device_info->bw40_channel_info[i].obss_util +
                                                    spctrm_scn_2g_device_info->bw40_channel_info[i + 4].obss_util) / (95 * 40 / 20)) * 100;
        }  
#endif      
    }

#undef N
    return SUCCESS;
}
int spctrm_scn_2g_wireless_get_channel_rate(struct spctrm_scn_2g_device_list *device_list,
        unsigned long int (*channel_bitmap)[CHANNEL_BITMAP_ARRAY_DEPTH],uint8_t band) 
{
    unsigned long bw40_channel_bitmap[CHANNEL_BITMAP_ARRAY_DEPTH],bw80_channel_bitmap[CHANNEL_BITMAP_ARRAY_DEPTH]; 
    int i,channel_num = 0,j;
    struct spctrm_scn_2g_device_info *p;

    if (device_list == NULL) {
        return FAIL;
    }

#define STREAM_NUM ((device_list->list_len == 0)? 1 : (device_list->list_len - 1))
    
    list_for_each_device(p,j,device_list) {
        /* bw20 */
        i = 0;
        for_each_set_bit(i,channel_bitmap[BW_BITMAP_20MHZ_INDEX],CHANNEL_BITMAP_SIZE) {
            p->bw20_channel_info[i].rate = p->bw20_channel_info[i].score * BAND_5G_BW_20_MAX_RATE / STREAM_NUM / 100 ;
        }
        /* bw40 bw80*/
        if (band == BAND_5G) {
            spctrm_scn_2g_wireless_get_group_channel_bitmap(channel_bitmap[BW_BITMAP_40MHZ_INDEX],bw40_channel_bitmap,BAND_5G,_40MHZ);
            for_each_set_bit(i,bw40_channel_bitmap,CHANNEL_BITMAP_SIZE) {
                p->bw40_channel_info[i].rate = p->bw20_channel_info[i].score * BAND_5G_BW_40_MAX_RATE / STREAM_NUM / 100;
            }
            spctrm_scn_2g_wireless_get_group_channel_bitmap(channel_bitmap[BW_BITMAP_80MHZ_INDEX],bw80_channel_bitmap,BAND_5G,_80MHZ);
            for_each_set_bit(i,bw80_channel_bitmap,CHANNEL_BITMAP_SIZE) {
                p->bw80_channel_info[i].rate = p->bw20_channel_info[i].score * BAND_5G_BW_80_MAX_RATE / STREAM_NUM / 100;                       
            }

        }
    }
#undef STREAM_NUM
}
inline int channel_to_bitset(int channel,uint8_t *bitset,uint8_t band)
{
    if (bitset == NULL) {
        SPCTRM_SCN_DBG("FAIL\r\n");
        return FAIL;
    }

    if (spctrm_scn_2g_wireless_band_check(band) == FAIL) {
        SPCTRM_SCN_DBG("band %d\r\n",band);
        SPCTRM_SCN_DBG("FAIL\r\n");
        return FAIL;
    }

    if (band == BAND_5G) {
        if (channel >= 36 && channel <= 144) {
            *bitset = channel/4 - 9;
        } else if (channel >= 149 && channel <= 181) {
            *bitset = (channel-1)/4 - 9;
        } else {
            return FAIL;
        }
    } else if (band == BAND_2G) {
        *bitset = channel - 1; 
    }

    return SUCCESS;
}

inline int bitset_to_channel(int bit_set,uint8_t *channel,uint8_t band)
{
    if (channel == NULL) {
        return FAIL;
    }

    if (spctrm_scn_2g_wireless_band_check(band) == FAIL) {
        return FAIL;
    }

    if (band == BAND_5G) {
        if (bit_set >= 0 && bit_set <= 27) {
            *channel = (bit_set + 9 ) * 4;
        } else if (bit_set >= 28 && bit_set <= 45) {
            *channel = (bit_set + 9) * 4 + 1;
        } else {
            return FAIL;
        }
    } else if (band == BAND_2G ) {
        *channel = bit_set + 1;
    }

    return SUCCESS;
    
}
int spctrm_scn_2g_wireless_channel_info_from_file(struct spctrm_scn_2g_channel_info *info,char *table_name,char *path) 
{
    json_object *root,*channel_info_obj,*channel_obj,*bw_obj;
    char *rbuf;
    
    if (info == NULL || path == NULL || table_name == NULL ) {
        return FAIL;
    }
    
    channel_info_obj = NULL;
    channel_obj = NULL;
    bw_obj = NULL;

    root = json_object_from_file(path);
    if (root == NULL) {
        return FAIL;
    }

    channel_info_obj = json_object_object_get(root,table_name);
    if (channel_info_obj == NULL) {
        json_object_put(root);  
        return FAIL;      
    }

    channel_obj = json_object_object_get(channel_info_obj,"channel");
    if (channel_obj == NULL) {
        json_object_put(root);
        return FAIL;
    }
    rbuf = json_object_get_string(channel_obj);
    SPCTRM_SCN_DBG("rbuf channel %s\r\n",rbuf);
    if (rbuf != NULL) {
        info->channel = atoi(rbuf);
        SPCTRM_SCN_DBG("info->channel %d\r\n",info->channel);
    }


    bw_obj = json_object_object_get(channel_info_obj,"bw");
    if (bw_obj == NULL) {
        json_object_put(root);
        return FAIL;
    }
    rbuf = json_object_get_string(bw_obj);
    SPCTRM_SCN_DBG("rbuf bw %s\r\n",rbuf);
    if (rbuf != NULL) {
        info->bw = atoi(rbuf);
        SPCTRM_SCN_DBG("info->bw %d\r\n",info->bw);
    }

    json_object_put(root);
}

int spctrm_scn_2g_wireless_channel_info_to_file(struct spctrm_scn_2g_channel_info *info,char *table_name,char *path) 
{
    json_object *root,*channel_info_obj,*channel_obj,*bw_obj;
    char tmp[1024];
    int fd;
    char *rbuf;

    if (info == NULL || path == NULL || table_name == NULL ) {
        return FAIL;
    }  

    memset(tmp,0,sizeof(tmp));

    if (access(path,F_OK) == FAIL) {
        SPCTRM_SCN_DBG("file not exit\r\n");
        if (fd = creat(path, 0777) == FAIL) {
            SPCTRM_SCN_DBG("FAIL\r\n");
            return FAIL;
        } 
        close(fd);
        

        root = json_object_new_object();
        if (root == NULL) {
            return FAIL;
        }

        channel_info_obj = json_object_new_object();

        sprintf(tmp,"%d",info->bw);
        bw_obj = json_object_new_string(tmp);
        json_object_object_add(channel_info_obj,"bw",bw_obj);

        memset(tmp,0,sizeof(tmp));
        sprintf(tmp,"%d",info->channel);
        channel_obj = json_object_new_string(tmp);
        json_object_object_add(channel_info_obj,"channel",channel_obj);
        
        json_object_object_add(root,table_name,channel_info_obj);
        json_object_to_file(path,root);
        json_object_put(root);
    } else {
        SPCTRM_SCN_DBG("file exit\r\n");
        root = json_object_from_file(path);
        if (root == NULL) {
            root = json_object_new_object();
            if (root == NULL) {
                SPCTRM_SCN_ERR("root create error\r\n");
                return FAIL;
            }
        }

        channel_info_obj = json_object_new_object();
        if (channel_info_obj == NULL) {
            SPCTRM_SCN_ERR("channel_info_obj create error\r\n");
            json_object_put(root);
            return FAIL;
        }

        sprintf(tmp,"%d",info->bw);
        bw_obj = json_object_new_string(tmp);
        json_object_object_add(channel_info_obj,"bw",bw_obj);

        memset(tmp,0,sizeof(tmp));
        sprintf(tmp,"%d",info->channel);
        channel_obj = json_object_new_string(tmp);
        json_object_object_add(channel_info_obj,"channel",channel_obj);
        
        json_object_object_add(root,table_name,channel_info_obj);
        json_object_to_file(path,root);

        json_object_put(channel_info_obj);
        json_object_put(root);
    }

    return SUCCESS;
}

int spctrm_scn_2g_wireless_get_wds_state(uint8_t *mode) 
{
    char *rbuf;
    json_object *rbuf_root;
    json_object *role_obj;

    if (spctrm_scn_2g_common_cmd("dev_sta get -m wds_status", &rbuf) == FAIL) {
        SPCTRM_SCN_DBG("cmd fail\r\n");
        return FAIL;
    }
    rbuf_root = json_tokener_parse(rbuf);
    if (rbuf_root == NULL) {
        free(rbuf);
        return FAIL;
    }

    role_obj = json_object_object_get(rbuf_root,"role");
    if (role_obj == NULL) {
        free(rbuf);
        json_object_put(rbuf_root);
        return FAIL;
    }

    if (strcmp(json_object_get_string(role_obj),"cpe") == 0) {
        *mode = CPE_MODE;
    } else if (strcmp(json_object_get_string(role_obj),"ap") == 0) {
        *mode = AP_MODE;
    }

    free(rbuf);
    json_object_put(rbuf_root);
    SPCTRM_SCN_DBG("g_spctrm_scn_2g_mode %d\r\n",*mode);
}

int spctrm_scn_2g_wireless_country_channel_get_bwlist(uint8_t *bw_bitmap,uint8_t band)
{
    int array_len,i,ret;
    char *rbuf;
    uf_cmd_msg_t *msg_obj;
    json_object *param_obj;
    char *param;
    json_object *root;
    json_object *bandwidth_obj,*elem;
    char *bw_str;
    struct spctrm_scn_2g_device_info*p;
    int j;

    if (bw_bitmap == NULL) {
        return FAIL;
    }

    param_obj = json_object_new_object();
    if (param_obj == NULL) {
        SPCTRM_SCN_DBG("FAIL\r\n");
        return FAIL;
    }

    json_object_object_add(param_obj, "qry_type", json_object_new_string("bandwidth_list"));

    if (band == BAND_5G) {
        json_object_object_add(param_obj, "range", json_object_new_string("5G"));
    } else if (band == BAND_2G) {
        json_object_object_add(param_obj, "range", json_object_new_string("2.4G"));
    }
    
    param = json_object_to_json_string(param_obj);
    if (param == NULL) {
        SPCTRM_SCN_DBG("FAIL\r\n");
        json_object_put(param_obj);
        return FAIL;
    }
    SPCTRM_SCN_DBG("%s\n",param);

    msg_obj = (uf_cmd_msg_t*)malloc(sizeof(uf_cmd_msg_t));
    if (msg_obj == NULL) {
        json_object_put(param_obj);
        return FAIL;
    }
    memset(msg_obj, 0, sizeof(uf_cmd_msg_t));

    msg_obj->param = param;
    msg_obj->ctype = UF_DEV_STA_CALL;    /* 调用类型 ac/dev/.. */
    msg_obj->cmd = "get";
    msg_obj->module = "country_channel";               /* 必填参数，其它可选参数根据需要使用 */
    msg_obj->caller = "group_change";       /* 自定义字符串，标记调用者 */
    ret = uf_client_call(msg_obj, &rbuf, NULL);
    if (ret == FAIL) {
        json_object_put(param_obj);
        free(msg_obj);
        return FAIL;      
    }
    SPCTRM_SCN_DBG("%s\n",rbuf);
    
    root = json_tokener_parse(rbuf);
    if (root == NULL) {
        json_object_put(param_obj);
        if (rbuf != NULL) {
            free (rbuf);
        }
        free(msg_obj);
        return FAIL;
    }

    if (band == BAND_5G) {
        bandwidth_obj = json_object_object_get(root,"bandwidth_5G");
    } else if (band == BAND_2G) {
        bandwidth_obj = json_object_object_get(root,"bandwidth_2G");
    }
    
    if (bandwidth_obj == NULL) {
        if (rbuf != NULL) {
            json_object_put(param_obj);
            free (rbuf);
        }
        json_object_put(root);
        free(msg_obj);
        return FAIL;
    }

    array_len = 0;
    array_len = json_object_array_length(bandwidth_obj);

    *bw_bitmap = 0;
    for (i = 0;i < array_len;i++) {
        elem = json_object_array_get_idx(bandwidth_obj, i);
        if (strcmp(json_object_get_string(elem),"20") == 0) {
            *bw_bitmap |= SPCTRM_SCN_2G_BW_20;
        } else if (strcmp(json_object_get_string(elem),"40") == 0) {
            *bw_bitmap |= SPCTRM_SCN_2G_BW_40;
        } else if (strcmp(json_object_get_string(elem),"80") == 0) {
            *bw_bitmap |= SPCTRM_SCN_2G_BW_80;
        }
    }

    SPCTRM_SCN_DBG("bw_bitmap %d\r\n",*bw_bitmap);

    if (rbuf != NULL) {
        free (rbuf);
    }
    json_object_put(param_obj);
    json_object_put(root);

    free(msg_obj);

    return SUCCESS;
}

int spctrm_scn_2g_wireless_country_channel_get_channellist(unsigned long int *channel_bitmap,uint8_t *channel_num,uint8_t bw,uint8_t band)
{
    uf_cmd_msg_t *msg_obj;
    int ret,len;
    uint8_t *temp;
    char *rbuf;
    char *param;
    json_object *param_obj;
    int i;
    uint8_t nr;
    struct json_object *ret_obj;
    struct json_object *elem;
    json_object *frequency_obj,*channel_obj;

    if (channel_bitmap == NULL || channel_num == NULL) {
        return FAIL;
    }

    if (spctrm_scn_2g_wireless_band_check(band) == FAIL) {
        return FAIL;
    }

    len = 0;
    param_obj = json_object_new_object();
    if (param_obj == NULL) {
        SPCTRM_SCN_ERR("param_obj create error\r\n");
        return FAIL;
    }

    switch (bw) {
    case SPCTRM_SCN_2G_BW_20:
        json_object_object_add(param_obj, "band", json_object_new_string("BW_20"));
        break;
    case SPCTRM_SCN_2G_BW_40:
        json_object_object_add(param_obj, "band", json_object_new_string("BW_40"));
        break;
    case SPCTRM_SCN_2G_BW_80:
        json_object_object_add(param_obj, "band", json_object_new_string("BW_80"));
        break;
    case SPCTRM_SCN_2G_BW_160:
        json_object_object_add(param_obj, "band", json_object_new_string("BW_160"));
        break;
    default:
        json_object_put(param_obj);
        return FAIL;
    }
 
    rbuf = NULL;
    
    json_object_object_add(param_obj, "qry_type", json_object_new_string("channellist"));

    if (band == BAND_5G) {
        json_object_object_add(param_obj, "range", json_object_new_string("5G"));
    } else if (band == BAND_2G) {
        json_object_object_add(param_obj, "range", json_object_new_string("2.4G"));
    }
    
    param = json_object_to_json_string(param_obj);
    if (param == NULL) {
        json_object_put(param_obj);
        SPCTRM_SCN_ERR("param NULL\r\n");
        return FAIL;
    }
    SPCTRM_SCN_DBG("%s\n",param);

    msg_obj = (uf_cmd_msg_t*)malloc(sizeof(uf_cmd_msg_t));
    if (msg_obj == NULL) {
        json_object_put(param_obj);
        SPCTRM_SCN_ERR("msg_obj NULL\r\n");
        return FAIL;
    }
    memset(msg_obj, 0, sizeof(uf_cmd_msg_t));

    msg_obj->param = param;
    msg_obj->ctype = UF_DEV_STA_CALL;    /* 调用类型 ac/dev/.. */
    msg_obj->cmd = "get";
    msg_obj->module = "country_channel";               /* 必填参数，其它可选参数根据需要使用 */
    msg_obj->caller = "group_change";       /* 自定义字符串，标记调用者 */
    SPCTRM_SCN_DBG("============\r\n");
    ret = uf_client_call(msg_obj, &rbuf, NULL);
    if (ret == FAIL) {
        json_object_put(param_obj);
        free(msg_obj);
        SPCTRM_SCN_ERR("uf_client_call error\r\n");
        return FAIL;      
    }
    SPCTRM_SCN_DBG("============\r\n");
    SPCTRM_SCN_DBG("%s\n",rbuf);

    ret_obj = json_tokener_parse(rbuf);
    if (ret_obj == NULL) {
        json_object_put(param_obj);
        free(rbuf);
        free(msg_obj);
        SPCTRM_SCN_ERR("json_tokener_parse error\r\n");
        return FAIL;
    }

    *channel_num = json_object_array_length(ret_obj);
    if (*channel_num <= 0) {
        json_object_put(param_obj);
        json_object_put(ret_obj);
        free(rbuf);
        free(msg_obj);
        SPCTRM_SCN_ERR("json_object_array_length error\r\n");
        return FAIL;        
    }
    SPCTRM_SCN_DBG("channel_num %d\r\n",*channel_num);
    for (i = 0; i < *channel_num; i++) {
        elem = json_object_array_get_idx(ret_obj, i);
        channel_obj = json_object_object_get(elem, "channel");
        if (channel_obj == NULL) {
            SPCTRM_SCN_ERR("get channel_obj  FAIL\r\n");
            json_object_put(param_obj);
            json_object_put(ret_obj);
            free(rbuf);
            free(msg_obj);
            return FAIL;
        }

        len = json_object_get_string_len(channel_obj) + 1;
        temp = malloc(len);
        if (temp == NULL) {
            SPCTRM_SCN_ERR("temp malloc FAIL\r\n");
            json_object_put(param_obj);
            json_object_put(ret_obj);
            free(rbuf);
            free(msg_obj);
            return FAIL;                
        }
        memset(temp,0,len);

        strncpy(temp,json_object_get_string(channel_obj),len);
        SPCTRM_SCN_DBG("%s\r\n",temp);

        if (channel_to_bitset(atoi(temp),&nr,band) == FAIL) {
            SPCTRM_SCN_ERR("channel_to_bitset error\r\n");
            json_object_put(param_obj);
            json_object_put(ret_obj);
            free(temp);
            free(rbuf);
            free(msg_obj);
            return FAIL; 
        }

        free(temp);
        temp = NULL;
        SPCTRM_SCN_DBG("nr %d\r\n",nr);
        set_bit(nr,channel_bitmap);/*36 ~ 144    149 153 157 161 165 169 173 177 181*/
        /* xxx bitmap and */
    }

    for_each_set_bit(i,channel_bitmap,CHANNEL_BITMAP_SIZE) {
        SPCTRM_SCN_DBG("Bit %d is set\n", i);
    }

    json_object_put(param_obj);
    json_object_put(ret_obj);
    /* 资源需要调用者释放 */
    if (rbuf) {
      free(rbuf);
    }

    free(msg_obj);

    return SUCCESS;
}

int spctrm_scn_2g_wireless_show_channel_bitmap(unsigned long *channel_bitmap)
{
    int i;
    i = 0;
    for_each_set_bit(i,channel_bitmap,CHANNEL_BITMAP_SIZE) {
        SPCTRM_SCN_DBG("Bit %d is set\n", i);
    }
}
