#include "spctrm_scn_wireless.h"

static int timeout_func();
static double calculate_N(struct channel_info *info);
static inline channel_to_bitmap (int channel);
static inline bitmap_to_channel (int bit_set);
static void channel_scan(struct channel_info *input,int scan_time);
extern char g_wds_bss[16];
extern char g_apcli_ifname[16];
extern unsigned char g_mode;
extern struct device_list g_finished_device_list;
extern struct device_list g_device_list;
extern struct channel_info g_channel_info_5g[MAX_BAND_5G_CHANNEL_NUM];
extern struct channel_info realtime_channel_info_5g[MAX_BAND_5G_CHANNEL_NUM];
int g_scan_schedule;
extern struct user_input g_input;
volatile int g_status,g_scan_time;
extern volatile uint64_t g_scan_timestamp;
extern uint64_t g_bitmap_2G,g_bitmap_5G;
extern pthread_mutex_t g_mutex,g_finished_device_list_mutex;
extern pthread_mutex_t g_scan_schedule_mutex;
extern sem_t g_semaphore;
time_t g_current_time;
extern int g_bw40_channel_num;
extern int g_bw80_channel_num;
extern __u32 g_ap_instant;
extern int g_stream_num;
extern char g_rlog_server_addr[MAX_RLOG_SERVER_ADDR_LEN];
extern pthread_mutex_t g_rlog_server_addr_mutex;
double g_multi_user_loss[MAX_DEVICE_NUM + 1];

static double spctrm_scn_wireless_get_exp_ratio(struct device_info *device_info);

void spctrm_scn_wireless_multi_user_loss_init()
{
    int i,j,k;
    double temp;

    temp = 1.0;
    for (k = 0,i = 0;i < 5 ;i++) {
        SPCTRM_SCN_DBG_FILE(" ------------%d----\r\n",(2 << i));
        for (j = k;j < (2 << i); j++) {
            g_multi_user_loss[j] = temp;
        }

        k = (2 << i);
        temp *= 0.75;
    }
    g_multi_user_loss[MAX_DEVICE_NUM] = 0.24;

    for (i = 0 ; i <= MAX_DEVICE_NUM ;i++) {
        SPCTRM_SCN_DBG_FILE("%f\r\n",g_multi_user_loss[i]);
    }
}

void spectrm_scn_debug_device_list(struct device_list* list)
{
    struct device_info *p;
    int j;

    list_for_each_device(p,j,list) {
        SPCTRM_SCN_DBG_FILE("SN %s \r\n",p->series_no);
    }
}

int spctrm_scn_wireless_get_band_5G_apcli_ifname(char *apcli_ifname)
{
    json_object *root,*wireless_obj,*apcli_ifname_obj,*radiolist_obj;
    json_object *radiolist_elem_obj,*band_support_obj;
    int i;

    if (apcli_ifname == NULL) {
        return FAIL;
    }
    root = json_object_from_file("/tmp/rg_device/rg_device.json");
    if (root == NULL) {
        SPCTRM_SCN_DBG_FILE("\nFAIL\n");
        json_object_put(root);
        return FAIL;
    }
    wireless_obj = json_object_object_get(root,"wireless");
    if (wireless_obj == NULL) {
        SPCTRM_SCN_DBG_FILE("\nFAIL\n");
        json_object_put(root);
        return FAIL;
    }

    radiolist_obj = json_object_object_get(wireless_obj,"radiolist");
    if (radiolist_obj == NULL) {
        SPCTRM_SCN_DBG_FILE("\nFAIL\n");
        json_object_put(root);
        return FAIL;
    }

    for (i = 0;i < json_object_array_length(radiolist_obj);i++) {
        radiolist_elem_obj = json_object_array_get_idx(radiolist_obj,i);
        band_support_obj = json_object_object_get(radiolist_elem_obj,"band_support");
        if (strcmp(json_object_get_string(band_support_obj),"5G") == 0) {
            apcli_ifname_obj = json_object_object_get(radiolist_elem_obj,"apcli_ifname");
            if (apcli_ifname_obj == NULL) {
                SPCTRM_SCN_DBG_FILE("\nFAIL\n");
                json_object_put(root);
                return FAIL;
            }
            break;
        }
    }

    SPCTRM_SCN_DBG_FILE("%s\r\n",json_object_get_string(apcli_ifname_obj));
    snprintf(apcli_ifname,IFNAMSIZ,"%s0",json_object_get_string(apcli_ifname_obj));

    json_object_put(root);
}

int spctrm_scn_wireless_get_wds_bss(char *wds_bss)
{
    json_object *root,*wireless_obj,*wds_bss_obj,*radiolist_obj;
    json_object *radiolist_elem_obj,*band_support_obj;
    int i;

    if (wds_bss == NULL) {
        return FAIL;
    }

    root = json_object_from_file("/tmp/rg_device/rg_device.json");
    if (root == NULL) {
        SPCTRM_SCN_DBG_FILE("\nFAIL\n");
        json_object_put(root);
        return FAIL;
    }
    wireless_obj = json_object_object_get(root,"wireless");
    if (wireless_obj == NULL) {
        SPCTRM_SCN_DBG_FILE("\nFAIL\n");
        json_object_put(root);
        return FAIL;
    }

    radiolist_obj = json_object_object_get(wireless_obj,"radiolist");
    if (radiolist_obj == NULL) {
        SPCTRM_SCN_DBG_FILE("\nFAIL\n");
        json_object_put(root);
        return FAIL;
    }

    for (i = 0;i < json_object_array_length(radiolist_obj);i++) {
        radiolist_elem_obj = json_object_array_get_idx(radiolist_obj,i);
        band_support_obj = json_object_object_get(radiolist_elem_obj,"band_support");
        if (strcmp(json_object_get_string(band_support_obj),"5G") == 0) {
            wds_bss_obj = json_object_object_get(radiolist_elem_obj,"wds_bss");
            if (wds_bss_obj == NULL) {
                SPCTRM_SCN_DBG_FILE("\nFAIL\n");
                json_object_put(root);
                return FAIL;
            }
            break;
        }
    }

    strcpy(wds_bss,json_object_get_string(wds_bss_obj));

    json_object_put(root);
    return SUCCESS;

}

void spctrm_scn_wireless_set_status() {
    json_object *root;
    char temp[128];

    root = json_object_from_file("/etc/spectrum_scan_cache");
    if (root == NULL) {
        return;
    }

    if (g_status == SCAN_BUSY) {
        json_object_object_add(root,"status",json_object_new_string("busy"));
    } else if(g_status == SCAN_IDLE) {
        json_object_object_add(root,"status",json_object_new_string("idle"));
    } else if(g_status == SCAN_ERR) {
        json_object_object_add(root,"status",json_object_new_string("error"));
    }

    sprintf(temp,"%d",g_status);
    json_object_object_add(root,"status_code",json_object_new_string(temp));

    json_object_to_file("/etc/spectrum_scan_cache",root);
    json_object_put(root);
}

int spctrm_scn_wireless_set_current_channel_info(struct channel_info *current_channel_info)
{
    json_object *root;
    char temp[128];
    int fd;

    if (access("/etc/spectrum_scan/current_channel_info",F_OK) == FAIL) {
        SPCTRM_SCN_DBG_FILE("\nnot exit");
        fd = creat("/etc/spectrum_scan/current_channel_info",0777);
        if (fd < 0) {
            return FAIL;
        }
        close(fd);
    }

    root = json_object_new_object();
    if (root == NULL) {
        return FAIL;
    }

    sprintf(temp,"%d",current_channel_info->channel);
    json_object_object_add(root,"current_channel",json_object_new_string(temp));
    sprintf(temp,"%d",current_channel_info->bw);
    json_object_object_add(root,"current_bw",json_object_new_string(temp));
    json_object_to_file("/etc/spectrum_scan/current_channel_info",root);
    json_object_put(root);

    return SUCCESS;
}

int spctrm_scn_wireless_get_current_channel_info (struct channel_info *current_channel_info)
{
    json_object *root;
    json_object *current_channel_obj,*current_bw_obj;
    const char *current_channel_str,*current_bw_str;

    root = json_object_from_file("/etc/spectrum_scan/current_channel_info");
    if (root == NULL) {
        return FAIL;
    }
    SPCTRM_SCN_DBG_FILE("\n%s",json_object_to_json_string(root));
    current_channel_obj = json_object_object_get(root,"current_channel");
    if (current_channel_obj == NULL) {
        json_object_put(root);
        return FAIL;
    }

    current_channel_str = json_object_get_string(current_channel_obj);
    if (current_channel_str == NULL) {
        json_object_put(root);
        return FAIL;
    }
    current_channel_info->channel = atoi(current_channel_str);

    current_bw_obj = json_object_object_get(root,"current_bw");
    if (current_bw_obj == NULL) {
        json_object_put(root);
        return FAIL;
    }

    current_bw_str = json_object_get_string(current_bw_obj);
    if (current_bw_str == NULL) {
        json_object_put(root);
        return FAIL;
    }

    current_channel_info->bw = atoi(current_bw_str);

    return SUCCESS;
}
int spctrm_scn_wireless_restore_device_info(char *path,struct device_list *device_list)
{
    json_object *root,*scan_list_obj;
    struct json_object* scan_list_elem,*status_obj,*sn_obj,*role_obj,*band_5g_obj;
    json_object *bw20_obj;
    json_object *score_list_obj,*score_list_elem_obj,*channel_obj,*score_obj;
    int i;
    int j,k;
    struct device_info *p;

    root = json_object_from_file(path);
    if (root == NULL) {

        return FAIL;
    }
    SPCTRM_SCN_DBG_FILE("%s\n",json_object_to_json_string(root));
    scan_list_obj = json_object_object_get(root,"scan_list");
    device_list->list_len = json_object_array_length(scan_list_obj);
    SPCTRM_SCN_DBG_FILE("%d",device_list->list_len);
    list_for_each_device(p,i,device_list) {
        scan_list_elem = json_object_array_get_idx(scan_list_obj,i);
        status_obj = json_object_object_get(scan_list_elem,"status");
        if (status_obj != NULL) {
            p->status = atoi(json_object_get_string(status_obj));
            SPCTRM_SCN_DBG_FILE("p->status %d\n",p->status);
        }

        role_obj = json_object_object_get(scan_list_elem,"role");
        if (role_obj != NULL) {
            strcpy(p->role,json_object_get_string(role_obj));
            SPCTRM_SCN_DBG_FILE("p->role %s\n",p->role);
        }

        sn_obj = json_object_object_get(scan_list_elem,"SN");
        if (sn_obj != NULL) {
            strcpy(p->series_no,json_object_get_string(sn_obj));
            SPCTRM_SCN_DBG_FILE("p->series_no %s \n",p->series_no);
        }

        band_5g_obj = json_object_object_get(scan_list_elem,"5G");
        bw20_obj = json_object_object_get(band_5g_obj,"bw_20");
        score_list_obj = json_object_object_get(bw20_obj,"score_list");

        for (k = 0;k < json_object_array_length(score_list_obj);k++) {
            score_list_elem_obj = json_object_array_get_idx(score_list_obj,k);
            channel_obj = json_object_object_get(score_list_elem_obj,"channel");

            if (channel_obj != NULL) {
                p->channel_info[k].channel = atoi(json_object_get_string(channel_obj));
                SPCTRM_SCN_DBG_FILE("channel %d\n",p->channel_info[k].channel);
            }

            score_obj = json_object_object_get(score_list_elem_obj,"score");
            if (score_obj != NULL) {
                sscanf(json_object_get_string(score_obj),"%lf",&(p->channel_info[k].score));
                SPCTRM_SCN_DBG_FILE("score %f \n ",p->channel_info[k].score);
            }
        }
    }
    p = spctrm_scn_dev_find_ap2(&g_finished_device_list);
    memcpy(g_channel_info_5g,p->channel_info,sizeof(g_channel_info_5g));

    SPCTRM_SCN_DBG_FILE("%d\n",p->channel_info[0].channel);
    SPCTRM_SCN_DBG_FILE("%d\n",p->channel_info[1].channel);
    SPCTRM_SCN_DBG_FILE("%d\n",p->channel_info[2].channel);
    SPCTRM_SCN_DBG_FILE("%d\n",p->channel_info[3].channel);

    SPCTRM_SCN_DBG_FILE("%d\n",g_channel_info_5g[0].channel);
    SPCTRM_SCN_DBG_FILE("%d\n",g_channel_info_5g[1].channel);
    SPCTRM_SCN_DBG_FILE("%d\n",g_channel_info_5g[2].channel);
    SPCTRM_SCN_DBG_FILE("%d\n",g_channel_info_5g[3].channel);

    json_object_put(root);
}
int spctrm_scn_wireless_check_status(char *path)
{
    json_object *root;
    json_object *status_obj,*current_channel_obj,*current_bw_obj;
    char *rbuf;
    const char *status_str;
    int status;
    struct channel_info current_channel_info;

    SPCTRM_SCN_DBG_FILE("\nfile exit");
    root = json_object_from_file(path);
    if (root == NULL) {
        return FAIL;
    }

    status_obj = json_object_object_get(root,"status_code");
    if (status_obj == NULL) {
        json_object_put(root);
        return FAIL;
    }
    status_str = json_object_get_string(status_obj);
    if (status_str == NULL) {
        json_object_put(root);
        return FAIL;
    }
    SPCTRM_SCN_DBG_FILE("\n%s",status_str);
    status = atoi(status_str);
    if (status == SCAN_IDLE) {
        SPCTRM_SCN_DBG_FILE("\nSCAN_IDLE");
    } else if (status == SCAN_BUSY) {
        SPCTRM_SCN_DBG_FILE("\nSCAN_BUSY");
        g_status = SCAN_ERR;
        spctrm_scn_wireless_get_current_channel_info(&current_channel_info);
        spctrm_scn_wireless_change_channel(current_channel_info.channel);
        spctrm_scn_wireless_change_bw(current_channel_info.bw);
        spctrm_scn_wireless_set_status();
    } else if (status == SCAN_ERR) {
        SPCTRM_SCN_DBG_FILE("\nSCAN_ERR");
        g_status = status;
    }
    json_object_put(root);
    return SUCCESS;
}

void spctrm_scn_wireless_change_bw(int bw)
{
    char cmd[256];

    switch (bw) {
    case BW_20:
        sprintf(cmd,"iwpriv %s set HtBw=0",g_wds_bss);
        break;
    case BW_40:
        sprintf(cmd,"iwpriv %s set HtBw=1 && iwpriv %s set VhtBw=0",g_wds_bss,g_wds_bss);
        break;
    case BW_80:
        sprintf(cmd,"iwpriv %s set HtBw=1 && iwpriv %s set VhtBw=1",g_wds_bss,g_wds_bss);
        SPCTRM_SCN_DBG_FILE("%s",cmd);
        break;
    default:
        return;
    }
    system(cmd);
}
static void print_bits(uint64_t num) {
    int i;

    for (i = 0; i < sizeof(uint64_t) * 8; i++) {
        if ((num & (((uint64_t)1)<< i)) != 0) {
            SPCTRM_SCN_DBG_FILE("\nBit %d is set\n", i);
        }
    }
}

#ifdef AP_PLATFORM

#elif defined BRIDGE_PLATFORM
int spctrm_scn_wireless_get_country_channel_bwlist(uint8_t *bw_bitmap)
{
    int array_len,i;
    char *rbuf;
    json_object *root;
    json_object *bandwidth_5G_obj,*elem;
    char *bw_str;
    struct device_info*p;
    int j;
    list_for_each_device(p,j,&g_finished_device_list) {
        SPCTRM_SCN_DBG_FILE("SN %s \r\n",p->series_no);
    }

    if (bw_bitmap == NULL) {
        return FAIL;
    }
    SPCTRM_SCN_DBG_FILE("\n");
    if (spctrm_scn_common_cmd("dev_sta get -m country_channel '{\"qry_type\": \"bandwidth_list\"}'",&rbuf) == FAIL) {
        if (rbuf != NULL) {
            free (rbuf);
        }
        return FAIL;
    }

    SPCTRM_SCN_DBG_FILE("\n%s",rbuf);
    root = json_tokener_parse(rbuf);
    if (root == NULL) {
        if (rbuf != NULL) {
            free (rbuf);
        }
        return FAIL;
    }
    SPCTRM_SCN_DBG_FILE("\n");
    bandwidth_5G_obj = json_object_object_get(root,"bandwidth_5G");
    if (bandwidth_5G_obj == NULL) {
        if (rbuf != NULL) {
            free (rbuf);
        }
        json_object_put(root);
        return FAIL;
    }

    array_len = 0;
    array_len = json_object_array_length(bandwidth_5G_obj);
    SPCTRM_SCN_DBG_FILE("\n");
    *bw_bitmap = 0;
    for (i = 0;i < array_len;i++) {
        elem = json_object_array_get_idx(bandwidth_5G_obj, i);
        SPCTRM_SCN_DBG_FILE("\n");
        if (strcmp(json_object_get_string(elem),"20") == 0) {
            *bw_bitmap |= 1;
        } else if (strcmp(json_object_get_string(elem),"40") == 0) {
            *bw_bitmap |= 1 << 1;
        } else if (strcmp(json_object_get_string(elem),"80") == 0) {
            *bw_bitmap |= 1 << 2;
        }
    }

    SPCTRM_SCN_DBG_FILE("\nbw_bitmap %d",*bw_bitmap);

    if (rbuf != NULL) {
        free (rbuf);
    }
    json_object_put(root);

    list_for_each_device(p,j,&g_finished_device_list) {
        SPCTRM_SCN_DBG_FILE("SN %s \r\n",p->series_no);
    }

    return SUCCESS;
}
int spctrm_scn_wireless_country_channel(int bw,uint64_t *bitmap_2G,uint64_t *bitmap_5G,int band)
{

#ifdef UNIFY_FRAMEWORK_ENABLE
    uf_cmd_msg_t *msg_obj;
#elif defined POPEN_CMD_ENABLE
    char cmd[MAX_POPEN_BUFFER_SIZE];
#endif
    int ret;
    int channel_num;
    char *rbuf;
    const char *param_input;
    json_object *input_param_root,*output_param_root;
    json_object *qry_type_obj,*band_obj;
    int i,p;
    struct json_object *elem;
    json_object *frequency_obj,*channel_obj;
    char channel[8],frequency[8]; /* 信道字符串 */

    if (band != PLATFORM_5G && band != PLATFORM_2G) {
        SPCTRM_SCN_DBG_FILE("\n");
        return FAIL;
    }

    input_param_root = json_object_new_object();
    if (input_param_root == NULL) {
        SPCTRM_SCN_DBG_FILE("\n");
        return FAIL;
    }

    if (bw == BW_20) {
        json_object_object_add(input_param_root, "band", json_object_new_string("BW_20"));
    } else if (bw == BW_40) {
        json_object_object_add(input_param_root, "band", json_object_new_string("BW_40"));
    } else if (bw == BW_80) {
        json_object_object_add(input_param_root, "band", json_object_new_string("BW_80"));
    } else if (bw == BW_160) {
        json_object_object_add(input_param_root, "band", json_object_new_string("BW_160"));
    } else {
        SPCTRM_SCN_DBG_FILE("\n");
        json_object_put(input_param_root);
        return FAIL;
    }

    if (bitmap_2G == NULL || bitmap_5G == NULL) {
        SPCTRM_SCN_DBG_FILE("\n");
        json_object_put(input_param_root);
        return FAIL;
    }

    memset(cmd,0,sizeof(cmd));
    *bitmap_2G = 0;
    *bitmap_5G = 0;

    rbuf = NULL;

    json_object_object_add(input_param_root, "qry_type", json_object_new_string("channellist"));
    json_object_object_add(input_param_root, "range", json_object_new_string("5G"));

    param_input = json_object_to_json_string(input_param_root);
    if (param_input == NULL) {
        SPCTRM_SCN_DBG_FILE("\n");
        json_object_put(input_param_root);
        return FAIL;
    }
    SPCTRM_SCN_DBG_FILE("\n%s\n",param_input);

#ifdef UNIFY_FRAMEWORK_ENABLE
    msg_obj = (uf_cmd_msg_t*)malloc(sizeof(uf_cmd_msg_t));
    if (msg_obj == NULL) {
        json_object_put(input_param_root);
        return FAIL;
    }
    memset(msg_obj, 0, sizeof(uf_cmd_msg_t));

    msg_obj->param = param_input;
    msg_obj->ctype = UF_DEV_STA_CALL;    /* 调用类型 ac/dev/.. */
    msg_obj->cmd = "get";
    msg_obj->module = "country_channel";               /* 必填参数，其它可选参数根据需要使用 */
    msg_obj->caller = "group_change";       /* 自定义字符串，标记调用者 */
    ret = uf_client_call(msg_obj, &rbuf, NULL);
    if (ret == FAIL) {
        json_object_put(input_param_root);
        return FAIL;
    }
    SPCTRM_SCN_DBG_FILE("\n%s\n",rbuf);

#elif defined POPEN_CMD_ENABLE
    SPCTRM_SCN_DBG_FILE("\n%s\n",param_input);
    sprintf(cmd,"dev_sta get -m country_channel '%s'",param_input);
    SPCTRM_SCN_DBG_FILE("\n%s\r\n",cmd);
    spctrm_scn_common_cmd(cmd,&rbuf);
#endif

    output_param_root=json_tokener_parse(rbuf);
    if (output_param_root == NULL) {
        ret = FAIL;
        SPCTRM_SCN_DBG_FILE("\n");
        goto output_param_root_error;
    }

    if (band == PLATFORM_5G || band == PLATFORM_BOTH) {
        channel_num = json_object_array_length(output_param_root);
        SPCTRM_SCN_DBG_FILE("\nchannel_num %d",channel_num);
        for (i = 0; i < channel_num; i++) {
            elem = json_object_array_get_idx(output_param_root, i);
            frequency_obj = json_object_object_get(elem, "frequency");
            if (frequency_obj == NULL) {
                ret = FAIL;
                SPCTRM_SCN_DBG_FILE("\n");
                goto clear;
            }
            channel_obj = json_object_object_get(elem, "channel");
            if (channel_obj == NULL) {
                ret = FAIL;
                SPCTRM_SCN_DBG_FILE("\n");
                goto clear;
            }
            strcpy(channel,json_object_get_string(channel_obj));
            SPCTRM_SCN_DBG_FILE("\n%s\r\n",channel);
            *bitmap_5G |= ((uint64_t)1) << channel_to_bitmap(atoi(channel));  /*36 ~ 144    149 153 157 161 165 169 173 177 181*/
        }
    }
    if (band == PLATFORM_2G || band == PLATFORM_BOTH) {
        channel_num = json_object_array_length(output_param_root);
        for (i = 0; i < channel_num; i++) {
            struct json_object *elem = json_object_array_get_idx(output_param_root, i);
            frequency_obj = json_object_object_get(elem, "frequency");
            if (frequency_obj == NULL) {
                ret = FAIL;
                SPCTRM_SCN_DBG_FILE("\n");
                goto clear;
            }
            channel_obj = json_object_object_get(elem, "channel");
            if (channel_obj == NULL) {
                ret = FAIL;
                SPCTRM_SCN_DBG_FILE("\n");
                goto clear;
            }
            strcpy(channel,json_object_get_string(channel_obj));
            SPCTRM_SCN_DBG_FILE("\n%s\r\n",channel);
            *bitmap_2G |= ((uint64_t)1)<< atoi(channel);
        }
    }
    SPCTRM_SCN_DBG_FILE("\nbitmap_5G %llu\n",*bitmap_5G);
    SPCTRM_SCN_DBG_FILE("\nbitmap_2G %u\n",*bitmap_2G);
    print_bits(*bitmap_5G);
    ret = channel_num;

clear:
    json_object_put(output_param_root);
output_param_root_error:
    json_object_put(input_param_root);
    /* 资源需要调用者释放 */
    if (rbuf) {
      free(rbuf);
    }

#ifdef UNIFY_FRAMEWORK_ENABLE
    free(msg_obj);
#endif
    return ret;
}
#endif

static inline int channel_to_bitmap (int channel)
{
    if (channel >= 36 && channel <= 144) {
        return channel/4 - 9;
    }
    if (channel >= 149 && channel <= 181) {
        return (channel-1)/4 - 9;
    }

    return FAIL;
}

static inline int bitmap_to_channel (int bit_set)
{
    if (bit_set >= 0 && bit_set <= 27) {
        return (bit_set + 9 ) * 4;
    }
    if (bit_set >= 28 && bit_set <= 45) {
        return (bit_set + 9) * 4 + 1;
    }

    return FAIL;
}

void *spctrm_scn_wireless_ap_scan_thread()
{
    int i,j;
    char rlog_str[64],temp[1024];
    struct channel_info current_channel_info;
    struct device_info *p;
    double exp_ratio,multi_user_loss;
    struct port_status_list port_list;
    struct port_status_list_elem *elem;
    char ipaddr[IP_ADDR_LEN];

    memset(&current_channel_info,0,sizeof(current_channel_info));
    memset(rlog_str,0,sizeof(rlog_str));
    memset(temp,0,sizeof(temp));

    SPCTRM_SCN_DBG_FILE("\nAP THREAND START");
    while (1) {
        sem_wait(&g_semaphore);
        if (g_status == SCAN_BUSY) {
            spctrm_scn_rlog_get_module_server_addr();
            p = spctrm_scn_dev_find_ap2(&g_finished_device_list);

            spctrm_scn_wireless_set_status();
            SPCTRM_SCN_DBG_FILE("\nAP SCAN START");
            spctrm_scn_wireless_channel_info(&current_channel_info,g_wds_bss);
            spctrm_scn_wireless_change_bw(BW_20);
            spctrm_scn_wireless_set_current_channel_info(&current_channel_info);
            sleep(5);
            memset(realtime_channel_info_5g,0,sizeof(realtime_channel_info_5g));
            for (g_scan_schedule = 0,j = 0,i = 0; i < sizeof(uint64_t) * BITS_PER_BYTE; i++) {
                if ((g_input.channel_bitmap& (((uint64_t)1)<< i)) != 0) {
                    if (g_scan_schedule < g_input.channel_num - 1) {
                        pthread_mutex_lock(&g_scan_schedule_mutex);
                        g_scan_schedule++;
                        pthread_mutex_unlock(&g_scan_schedule_mutex);
                    }

                    realtime_channel_info_5g[j].channel = bitmap_to_channel(i);

                    SPCTRM_SCN_DBG_FILE("\nchange to channel : %d",realtime_channel_info_5g[j].channel);
                    if (spctrm_scn_wireless_change_channel(realtime_channel_info_5g[j].channel) == FAIL) {
                        goto error;
                    }

                    channel_scan(&realtime_channel_info_5g[j],g_input.scan_time);

                    if (spctrm_scn_rlog_get_module_enable() == RLOG_ENABLE) {
                        sprintf(rlog_str,"{\\\"channel\\\":\\\"%d\\\" }",realtime_channel_info_5g[j].channel);
                        pthread_mutex_lock(&g_rlog_server_addr_mutex);
                        sprintf(temp,"ubus call rlog upload_stream '{\"module_name\":\"spectrumScan\",\"server\":\"%s\",\"data\":\"%s\"}'",g_rlog_server_addr,rlog_str);
                        pthread_mutex_unlock(&g_rlog_server_addr_mutex);
                        SPCTRM_SCN_DBG_FILE("\n%s",temp);
                        system(temp);
                        memset(rlog_str,0,sizeof(rlog_str));
                        memset(temp,0,sizeof(temp));
                    }

                    SPCTRM_SCN_DBG_FILE("\ng_input.channel_bitmap : %llu",g_input.channel_bitmap);
                    if (spctrm_scn_wireless_check_channel_score(realtime_channel_info_5g[j].score) != FAIL) {
                        realtime_channel_info_5g[j].score = spctrm_scn_wireless_channel_score(&realtime_channel_info_5g[j]);
                        realtime_channel_info_5g[j].rate = realtime_channel_info_5g[j].score / 100 * 200 * 0.75;
                    }

                    spctrm_scn_wireless_rate_filter(p,&realtime_channel_info_5g[j].rate);
                    SPCTRM_SCN_DBG_FILE("\nscore %f\r\n",realtime_channel_info_5g[j].score);
                    SPCTRM_SCN_DBG_FILE("\n------------------\r\n");
                    j++;
                }
            }

            if (spctrm_scn_wireless_change_channel(current_channel_info.channel) == FAIL) {
                goto error;
            }

            spctrm_scn_dev_reset_stat(&g_device_list);
            /* find AP */
            i = spctrm_scn_dev_find_ap(&g_device_list);
            g_device_list.device[i].finished_flag = FINISHED;

            if (timeout_func() == FAIL) {

                memcpy(g_channel_info_5g,realtime_channel_info_5g,sizeof(realtime_channel_info_5g));
                pthread_mutex_lock(&g_finished_device_list_mutex);
                memcpy(&g_finished_device_list,&g_device_list,sizeof(struct device_list));
                SPCTRM_SCN_DBG_FILE("\ng_finished_device_list.list_len %d",g_finished_device_list.list_len);
                pthread_mutex_unlock(&g_finished_device_list_mutex);

                pthread_mutex_lock(&g_mutex);
                /* 获得ap uplink速度 */
#ifdef PORT_STATUS_FILTER_ENABLE
                spctrm_scn_wireless_port_status_init(&port_list);
                spctrm_scn_common_uci_anonymous_get("sysinfo", "sysinfo", "sysinfo", "wan_ip", ipaddr,IP_ADDR_LEN);
                SPCTRM_SCN_DBG_FILE("ipaddr %s\r\n",ipaddr);

                elem = spctrm_scn_wireless_find_uplink_port(&port_list,ipaddr);
                p->port_speed = elem->speed;
                p->port_status = elem->status;
                SPCTRM_SCN_DBG_FILE("elem->speed %d,elem->status %d",elem->speed,elem->status);
                spctrm_scn_wireless_delete_port_status_list(&port_list);
#endif
                SPCTRM_SCN_DBG_FILE("\ng_finished_device_list.list_len %d",g_finished_device_list.list_len);
                list_for_each_device(p,i,&g_finished_device_list) {
                    if ((strcmp(p->role,"ap") != 0) && (p->finished_flag == FINISHED)) {
                        for (j = 0;j < g_input.channel_num;j++) {
                            exp_ratio = spctrm_scn_wireless_get_exp_ratio(p);
                            SPCTRM_SCN_DBG_FILE("exp_ratio %f\r\n",exp_ratio);
                            p->channel_info[j].rate = p->channel_info[j].score / 100 * 200 * exp_ratio / g_stream_num * g_multi_user_loss[g_stream_num];
                            spctrm_scn_wireless_rate_filter(p,&p->channel_info[j].rate);
                            SPCTRM_SCN_DBG_FILE("rate %f\r\n",p->channel_info[j].rate);
                        }
                    }
                }

                g_status = SCAN_TIMEOUT;
                g_input.scan_time = MIN_SCAN_TIME; /* restore scan time */
                pthread_mutex_unlock(&g_mutex);

                pthread_mutex_lock(&g_scan_schedule_mutex);
                g_scan_schedule++;
                pthread_mutex_unlock(&g_scan_schedule_mutex);
            } else {

                spectrm_scn_debug_device_list(&g_finished_device_list);
                memcpy(g_channel_info_5g,realtime_channel_info_5g,sizeof(realtime_channel_info_5g));

                pthread_mutex_lock(&g_finished_device_list_mutex);
                memcpy(&g_finished_device_list,&g_device_list,sizeof(struct device_list));

                spectrm_scn_debug_device_list(&g_finished_device_list);

                SPCTRM_SCN_DBG_FILE("\ng_finished_device_list.list_len %d",g_finished_device_list.list_len);
                pthread_mutex_unlock(&g_finished_device_list_mutex);

                pthread_mutex_lock(&g_mutex);
                SPCTRM_SCN_DBG_FILE("\ng_finished_device_list.list_len %d",g_finished_device_list.list_len);
                /* 获得ap uplink速度 */
#ifdef PORT_STATUS_FILTER_ENABLE
                spctrm_scn_wireless_port_status_init(&port_list);
                spctrm_scn_common_uci_anonymous_get("sysinfo", "sysinfo", "sysinfo", "wan_ip", ipaddr,IP_ADDR_LEN);
                SPCTRM_SCN_DBG_FILE("ipaddr %s\r\n",ipaddr);
                elem = spctrm_scn_wireless_find_uplink_port(&port_list,ipaddr);
                p->port_speed = elem->speed;
                p->port_status = elem->status;
                SPCTRM_SCN_DBG_FILE("elem->speed %d,elem->status %d",elem->speed,elem->status);
                spctrm_scn_wireless_delete_port_status_list(&port_list);
#endif
                list_for_each_device(p,i,&g_finished_device_list) {
                    if ((strcmp(p->role,"ap") != 0) && (p->finished_flag == FINISHED)) {
                        for (j = 0;j < g_input.channel_num;j++) {
                            exp_ratio = spctrm_scn_wireless_get_exp_ratio(p);
                            p->channel_info[j].rate = p->channel_info[j].score / 100 * 200 * exp_ratio / g_stream_num * g_multi_user_loss[g_stream_num];
                            SPCTRM_SCN_DBG_FILE("p->channel_info[j].rate %f\n",p->channel_info[j].rate);
                            SPCTRM_SCN_DBG_FILE("p->channel_info[j].score %f\n",p->channel_info[j].score);
                            SPCTRM_SCN_DBG_FILE("exp_ratio %f\n",exp_ratio);
                            SPCTRM_SCN_DBG_FILE("g_stream_num %d\n",g_stream_num);
                            SPCTRM_SCN_DBG_FILE("g_multi_user_loss[g_stream_num] %f\n",g_multi_user_loss[g_stream_num]);
                            spctrm_scn_wireless_rate_filter(p,&p->channel_info[j].rate);
                            SPCTRM_SCN_DBG_FILE("exp_ratio %f g_stream_num %d g_multi_user_loss %f rate %f\r\n",exp_ratio,g_stream_num,g_multi_user_loss[g_stream_num],p->channel_info[j].rate);
                        }
                    }
                }
                g_status = SCAN_IDLE;
                
                g_input.scan_time = MIN_SCAN_TIME; /* restore scan time */
                pthread_mutex_unlock(&g_mutex);

                pthread_mutex_lock(&g_scan_schedule_mutex);
                g_scan_schedule++;
                pthread_mutex_unlock(&g_scan_schedule_mutex);
            }
            SPCTRM_SCN_DBG_FILE("current_channel_info.bw %d",current_channel_info.bw);
            spctrm_scn_wireless_change_bw(current_channel_info.bw);
            system("dev_sta get -m spectrumScan");
            sleep(2);
            spctrm_scn_wireless_set_status();
error:
            pthread_mutex_lock(&g_mutex);
            g_status = SCAN_ERR;
            g_input.scan_time = MIN_SCAN_TIME; /* restore scan time */
            pthread_mutex_unlock(&g_mutex);
        }
    }
}

int spctrm_scn_wireless_show_apcli_enable(char *ifname) 
{
    char msg[1024];
    int skfd;
    int ret;
    struct ifreq ifr;
    rj_ex_ioctl_t ioc;
    rj_radioinfo_t *radio;

    if (ifname == NULL) {
        return FAIL;
    }

    memset(msg,0,1024);
    memset(&ioc, 0, sizeof(rj_ex_ioctl_t));
    ioc.buf = msg;
    ioc.len = 1024;
    ioc.cmd = RJ_WAS_GET_APCLIENABLE_EN;;

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
  
    printf("%s\r\n",msg);
    return SUCCESS;

}

int spctrm_scn_wireless_get_apcli_enable(char *ifname,uint8_t *status)
{
    char msg[1024];
    int skfd;
    int ret;
    struct ifreq ifr;
    rj_ex_ioctl_t ioc;
    rj_radioinfo_t *radio;

    if (ifname == NULL) {
        return FAIL;
    }

    memset(msg,0,1024);
    memset(&ioc, 0, sizeof(rj_ex_ioctl_t));
    ioc.buf = msg;
    ioc.len = 1024;
    ioc.cmd = RJ_WAS_GET_APCLIENABLE_EN;;

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
    if (strncmp(msg,"0",1024) == 0 || strncmp(msg,"1",1024) == 0) {
        *status = atoi(msg);
        return SUCCESS;
    }
    return FAIL;
}

void *spctrm_scn_wireless_cpe_scan_thread()
{
    char *json_str;
    int i,j,len;
    double score;
    struct channel_info current_channel_info;

    memset(&current_channel_info,0,sizeof(struct channel_info));
    SPCTRM_SCN_DBG_FILE("\nCPE THREAND START");
    while (1) {
        sem_wait(&g_semaphore);

        if (g_status == SCAN_BUSY) {
            /* timestamp */
            SPCTRM_SCN_DBG_FILE("\nCPE SCAN START");
            
            spctrm_scn_wireless_channel_info(&current_channel_info,g_wds_bss);
            sleep(5);
            memset(realtime_channel_info_5g,0,sizeof(realtime_channel_info_5g));
            spctrm_scn_common_iwpriv_set(g_apcli_ifname,"ApCliEnable=0",strlen("ApCliEnable=0")+1);
            sleep(1);
            for (j = 0,i = 0; i < sizeof(uint64_t) * BITS_PER_BYTE; i++) {
                if ((g_input.channel_bitmap & (((uint64_t)1)<< i)) != 0) {

                    realtime_channel_info_5g[j].channel = bitmap_to_channel(i);
                    SPCTRM_SCN_DBG_FILE("\nchange channel to %d ",realtime_channel_info_5g[j].channel);

                    if (spctrm_scn_wireless_change_channel(realtime_channel_info_5g[j].channel) == FAIL) {
                        goto error;
                    }

                    channel_scan(&realtime_channel_info_5g[j],g_input.scan_time);

                    SPCTRM_SCN_DBG_FILE("\n%llu\r\n",g_input.channel_bitmap);
                    if (spctrm_scn_wireless_check_channel_score(realtime_channel_info_5g[j].score) != FAIL) {
                        realtime_channel_info_5g[j].score = spctrm_scn_wireless_channel_score(&realtime_channel_info_5g[j]);
                    }
                    SPCTRM_SCN_DBG_FILE("\n------------------\r\n");
                    j++;
                }

                if (g_status == SCAN_TIMEOUT) {
                    goto error;
                }
            }
        
            if (spctrm_scn_wireless_change_channel(current_channel_info.channel) == FAIL) {
                goto error;
            }
            pthread_mutex_lock(&g_mutex);
            memcpy(g_channel_info_5g,realtime_channel_info_5g,sizeof(realtime_channel_info_5g));
            memset(realtime_channel_info_5g,0,sizeof(realtime_channel_info_5g));
            g_status = SCAN_IDLE;
            g_input.scan_time = MIN_SCAN_TIME; /* restore scan time */

            pthread_mutex_unlock(&g_mutex);
            spctrm_scn_common_iwpriv_set(g_apcli_ifname,"ApCliEnable=1",strlen("ApCliEnable=1")+1);
        }
error:
    spctrm_scn_common_iwpriv_set(g_apcli_ifname,"ApCliEnable=1",strlen("ApCliEnable=1")+1);
    if (g_status == SCAN_TIMEOUT) {
            spctrm_scn_wireless_change_channel(current_channel_info.channel);
            pthread_mutex_lock(&g_mutex);
            g_status = SCAN_IDLE;
            g_input.scan_time = MIN_SCAN_TIME; /* restore scan time */
            memset(realtime_channel_info_5g,0,sizeof(realtime_channel_info_5g));
            pthread_mutex_unlock(&g_mutex);
        }
    }
}

static int quick_select(int* arr, int len, int k)
{
    int pivot, i, j, tmp;

    pivot = arr[len / 2];
    for (i = 0, j = len - 1;; i++, j--) {
        while (arr[i] < pivot) {
            i++;
        }

        while (arr[j] > pivot) {
            j--;
        }

        if (i >= j) {
            break;
        }

        tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }

    if (i == k - 1) {
        return pivot;
    }
    if (i < k - 1) {
        return quick_select(arr + i, len - i, k - i);
    }

    return quick_select(arr, i, k);
}


static int median(int* arr, int len)
{
    int median;

    if (len % 2 == 0) {
        median = (quick_select(arr, len, len / 2) + quick_select(arr, len, len / 2 + 1)) / 2;
    } else {
        median = quick_select(arr, len, len / 2 + 1);
    }

    return median;
}

int spctrm_scn_wireless_channel_info(struct channel_info *info,char *ifname)
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

    radio = (rj_radioinfo_t*)msg;
    SPCTRM_SCN_DBG_FILE("bssid:%02x:%02x:%02x:%02x:%02x:%02x\n", PRINT_MAC(radio->bssid));
    SPCTRM_SCN_DBG_FILE("channel:%d\n", radio->channel);
    SPCTRM_SCN_DBG_FILE("floornoise:%d\n", radio->floornoise);
    SPCTRM_SCN_DBG_FILE("utilization:%d\n", radio->utilization);
    SPCTRM_SCN_DBG_FILE("txpower:%d\n", radio->txpower);
    SPCTRM_SCN_DBG_FILE("bw:%d\n", radio->BW);
    SPCTRM_SCN_DBG_FILE("obss_util:%d\n", radio->util_info.obss_util);
    SPCTRM_SCN_DBG_FILE("tx_util:%d\n", radio->util_info.tx_util);
    SPCTRM_SCN_DBG_FILE("rx_util:%d\n", radio->util_info.rx_util);
    SPCTRM_SCN_DBG_FILE("tp_base:%d.%d\n", radio->txpower_base / 2, (radio->txpower_base % 2) * 10 / 2);
    SPCTRM_SCN_DBG_FILE("mgmt_frame_pwr:%d.%d\n", radio->mgmt_frame_pwr / 2, (radio->mgmt_frame_pwr % 2) * 10 / 2);
    // SPCTRM_SCN_DBG_FILE("cac_time:%d\n", radio->dfs_cac_time);
    info->channel = radio->channel;
    if (info->channel == 0) {
        return FAIL;
    }
    
    if (radio->floornoise == 0) {
        info->floornoise = -92; 
    } else {
        info->floornoise = radio->floornoise;
    }
    info->bw = radio->BW;
    info->obss_util = radio->util_info.obss_util;
    info->rx_util = radio->util_info.rx_util;
    info->tx_util = radio->util_info.tx_util;
    info->utilization = radio->utilization;
  

    return SUCCESS;
}
#define EXPECTATION(array,n,expectation) do {\
    int i,sum;\
    for (sum = 0,i = 0;i < n;i++) {\
        sum += array[i];\
    }\
    expectation = sum / n;\
\
} while(0);\

#define ABS(a) (((a) > 0)?(a):-(a))

#define VARIANCE(array,n,expectation) do {\
    int i,sum;\
    sum = 0;\
    for (i = 0;i < (n);i++) {\
       sum += ABS(array[i] - (expectation)) << 2\
    }\
\
} while(0);\

// void channel_info_test(struct channel_info *channel_info,int channel) {
//     char path[128];
//     json_object *root,*floornoise_array,*channel_array,*utilization_array,*floornoise_variance_array,*utilization_variance_array;    snprintf(path,sizeof(path),"/tmp/spectrum_scan/channel%d",channel);
//     root = json_object_from_file(path);

//     json_object_object_get(root,floornoise_array,"floornoise");
//     json_object
//     channel_info->floornoise = 

// }
void channel_scan(struct channel_info *input,int scan_time)
{
    int fd;
    char path[128];
    json_object *root,*floornoise_array,*channel_array,*utilization_array,*floornoise_variance_array,*utilization_variance_array;
    int i,err_count;
    struct channel_info info[MAX_SCAN_TIME];
    int utilization_temp[MAX_SCAN_TIME];
    int obss_util_temp[MAX_SCAN_TIME];
    int floornoise_temp[MAX_SCAN_TIME];
    int channel_temp[MAX_SCAN_TIME];
    time_t timestamp[MAX_SCAN_TIME];
    struct tm *local_time;

    memset(info,0,sizeof(info));
    memset(floornoise_temp,0,sizeof(floornoise_temp));
    memset(obss_util_temp,0,sizeof(obss_util_temp));
    memset(channel_temp,0,sizeof(channel_temp));
    memset(utilization_temp,0,sizeof(utilization_temp));
    memset(timestamp,0,sizeof(timestamp));
    memset(path,0,sizeof(path));

    snprintf(path,sizeof(path),"/tmp/spectrum_scan/channel%d",input->channel);
    if (access(path,F_OK) == FAIL) {
        fd = creat(path,0777);
        if (fd < 0) {
            return;
        }
        close(fd);
    }

    root = json_object_new_object();

    if (input == NULL) {
        SPCTRM_SCN_DBG_FILE("\nparam error");
        return;
    }
    if (scan_time > MAX_SCAN_TIME) {
        scan_time = MAX_SCAN_TIME;
    }

    if (scan_time < MIN_SCAN_TIME) {
        scan_time = MIN_SCAN_TIME;
    }

    err_count = 0;
    for (i = 0 ;i < scan_time ;i++) {
        sleep(1);
        spctrm_scn_wireless_channel_info(&info[i],g_wds_bss);
        timestamp[i] = time(NULL);
        SPCTRM_SCN_DBG_FILE("\ncurrent channel %d",info[i].channel);
    }

    input->bw=info[0].bw;

    channel_array = json_object_new_array();
    floornoise_array = json_object_new_array();
    utilization_array = json_object_new_array();
    floornoise_variance_array = json_object_new_array();
    utilization_variance_array = json_object_new_array();

    json_object_object_add(root,"floornoise",floornoise_array);
    json_object_object_add(root,"utilization",utilization_array);
    json_object_object_add(root,"channel",channel_array);
    for (i = 0 ;i < scan_time ;i++) {
        json_object_array_add(floornoise_array,json_object_new_int(info[i].floornoise));
        json_object_array_add(utilization_array,json_object_new_int(info[i].utilization));
        json_object_array_add(channel_array,json_object_new_int(info[i].channel));
        channel_temp[i] = info[i].channel;
        if (info[i].channel == input->channel) {
            floornoise_temp[i] = info[i].floornoise;
            utilization_temp[i] = info[i].utilization;
            obss_util_temp[i] = info[i].obss_util;
            
        } else {
            err_count++;
        }
    }

    if (err_count <= 5) {
        input->floornoise = median(floornoise_temp,scan_time - err_count);
        input->utilization = median(utilization_temp,scan_time - err_count);
        input->obss_util = median(obss_util_temp,scan_time - err_count);
        
    } else {
        input->utilization = 100;
        input->floornoise = 0;
        input->obss_util = 100;
        input->score = -1;
    }

    json_object_object_add(root,"median floornoise",json_object_new_int(input->floornoise));
    json_object_object_add(root,"median obss_util",json_object_new_int(input->obss_util));

    json_object_to_file(path,root);
    json_object_put(channel_array);
    json_object_put(floornoise_array);
    json_object_put(utilization_array);
    json_object_put(floornoise_variance_array);
    json_object_put(utilization_variance_array);
    json_object_put(root);

    SPCTRM_SCN_DBG_FILE("\ng_status %d",g_status);

    return;
}

void spctrm_scn_wireless_wds_state()
{
    char *rbuf;
    json_object *rbuf_root;
    json_object *role_obj;

    if (spctrm_scn_common_cmd("dev_sta get -m wds_status", &rbuf) == FAIL) {
        SPCTRM_SCN_DBG_FILE("\ncmd fail");
        return;
    }
    rbuf_root = json_tokener_parse(rbuf);
    if (rbuf_root == NULL) {
        free(rbuf);
        return;
    }
    role_obj = json_object_object_get(rbuf_root,"role");
    if (role_obj == NULL) {
        goto clear;
    }
    if (strcmp(json_object_get_string(role_obj),"cpe") == 0) {
        g_mode = CPE_MODE;
    } else if (strcmp(json_object_get_string(role_obj),"ap") == 0) {
        g_mode = AP_MODE;
    }
clear:
    free(rbuf);
    json_object_put(rbuf_root);
    SPCTRM_SCN_DBG_FILE("\ng_mode %d",g_mode);
}

static double calculate_N(struct channel_info *info)
{
    double N;

    if (info == NULL) {
        return FAIL;
    }

    if (info->floornoise <= -87) {
        N = 0;
    } else if ( -87 < info->floornoise && info->floornoise <= -85) {
        N = 1;
    } else if (-85 < info->floornoise && info->floornoise <= -82) {
        N = 2;
    } else if (-82 < info->floornoise && info->floornoise <= -80) {
        N = 2.8;
    } else if (-80 < info->floornoise && info->floornoise <= -76) {
        N = 4;
    } else if (-76 < info->floornoise && info->floornoise <= -71) {
        N = 4.8;
    } else if (-71 < info->floornoise && info->floornoise <= -69) {
        N = 5.2;
    } else if (-69 < info->floornoise && info->floornoise <= -66) {
        N = 6.4;
    } else if (-66 < info->floornoise && info->floornoise <= -62) {
        N = 7.6;
    } else if (-62 < info->floornoise && info->floornoise <= -60) {
        N = 8.2;
    } else if (-60 < info->floornoise && info->floornoise <= -56) {
        N = 8.8;
    } else if (-56 < info->floornoise && info->floornoise <= -52) {
        N = 9.4;
    } else if (-52 < info->floornoise ) {
        N = 10;
    }

    return N;
}

double spctrm_scn_wireless_channel_score(struct channel_info *info)
{
    double N;

    if (info == NULL) {
        SPCTRM_SCN_DBG_FILE("\ninfo NULL");
        return FAIL;
    }

    N = calculate_N(info);
    if (N == FAIL) {
        return FAIL;
    }

    return ((double)1 - N/20)*(double)((double)1 - (double)info->obss_util / 95) * 100;/* bw20公式 */
}
int spctrm_scn_wireless_check_channel_score(double score)
{
    if (score < 0) {
        return FAIL;
    } else {
        return SUCCESS;
    }
}
void spctrm_scn_wireless_bw40_channel_score (struct device_info *device)
{
    int j,k,i;
    int bw;
    uint64_t bitmap_2G,bitmap_5G;
    double exp_ratio,multi_user_loss;
    struct device_info *p,*low_performance_dev;

    if (device == NULL) {
        SPCTRM_SCN_DBG_FILE("\nparam NULL");
        return;
    }

    if (device->finished_flag != FINISHED) {
        return;
    }

    SPCTRM_SCN_DBG_FILE("\ng_input.channel_num %d ",g_bw40_channel_num);
    for (k = 0, j = 0; j < g_bw40_channel_num / 2;j++,k += 2) {
        for (i = 0;i < g_bw40_channel_num / 2;i++) {
            if (spctrm_scn_wireless_channel_group_check(device->channel_info,&k,BW_40) == FAIL) {
                SPCTRM_SCN_DBG_FILE("channel_group_check FAIL %d\r\n",j);
                SPCTRM_SCN_DBG_FILE("channel_group_check channel %d\r\n",device->channel_info[k].channel);
            } else {
                break;
            }
        }

        SPCTRM_SCN_DBG_FILE("bw 40 channel %d\r\n",device->channel_info[k].channel);
        device->bw40_channel[j] = device->channel_info[k];
        SPCTRM_SCN_DBG_FILE("\nbw40_channel %d",device->bw40_channel[j].channel);
        /* bw40底噪 */
        device->bw40_channel[j].floornoise = MAX(device->channel_info[k].floornoise, device->channel_info[k + 1].floornoise);
        /* bw40得分公式 */
        if ((spctrm_scn_wireless_check_channel_score(device->channel_info[k].score) == FAIL) ||
            (spctrm_scn_wireless_check_channel_score(device->channel_info[k + 1].score) == FAIL)) {
                device->bw40_channel[j].score = -1;
                device->bw40_channel[j].rate = -1;
                continue;
        }
        device->bw40_channel[j].score = ((double)1 - calculate_N(&(device->bw40_channel[j])) / 20) *
                                        (double)((double)1 - (double)(device->channel_info[k].obss_util +
                                                                      device->channel_info[k + 1].obss_util) / (95 * BW_40 / 20)) * 100;
        if (strcmp(device->role,"ap") == 0) {
            device->bw40_channel[j].rate = device->bw40_channel[j].score / 100 * 400;
        } else {
            exp_ratio = spctrm_scn_wireless_get_exp_ratio(device);
            SPCTRM_SCN_DBG_FILE("exp_ratio %f\r\n",exp_ratio);

            device->bw40_channel[j].rate = device->bw40_channel[j].score / 100 * 400 * exp_ratio / g_stream_num * g_multi_user_loss[g_stream_num]; /* bw40公式 */
        }
        spctrm_scn_wireless_rate_filter(device,&(device->bw40_channel[j].rate));

    }
}

int spctrm_scn_wireless_channel_group_check(struct channel_info *channel_info,int *index,int band)
{
    int i,k,index_temp;

    if (channel_info == NULL) {
        return FAIL;
    }

    if (band == BW_40) {
        k = 2;
    } else if (band == BW_80) {
        k = 4;
    } else {
        return FAIL;
    }
    index_temp = *index;
    for (i = 0;i < k;i++) {
        SPCTRM_SCN_DBG_FILE("channel_info[index + i].channel %d\r\n",channel_info[index_temp + i].channel);
        SPCTRM_SCN_DBG_FILE("channel_info[index].channel + 4 * i %d\r\n",channel_info[index_temp].channel + 4 * i);
        if ((channel_info[index_temp].channel + 4 * i) != channel_info[index_temp + i].channel) {
            *index = index_temp + i;
            return FAIL;
        }
    }

    return SUCCESS;
}

void spctrm_scn_wireless_bw80_channel_score (struct device_info *device)
{
    int j,k,i;
    int bw;
    uint64_t bitmap_2G,bitmap_5G;
    double exp_ratio;
    struct device_info *p;
    double multi_user_loss;

    if (device == NULL) {
        SPCTRM_SCN_DBG_FILE("\nparam error");
        return ;
    }

    if (device->finished_flag != FINISHED) {
        return;
    }

    list_for_each_device(p,j,&g_finished_device_list) {
        SPCTRM_SCN_DBG_FILE("SN %s \r\n",p->series_no);
    }

    SPCTRM_SCN_DBG_FILE("g_bw80_channel_num %d",g_bw80_channel_num);
    for (k = 0,j = 0; j < g_bw80_channel_num / 4; j++,k += 4) {
        for (i = 0 ;i < g_bw80_channel_num / 4; i++) {
            if (spctrm_scn_wireless_channel_group_check(device->channel_info,&k,BW_80) == FAIL) {
                SPCTRM_SCN_DBG_FILE("channel_group_check FAIL %d\r\n",j);
                SPCTRM_SCN_DBG_FILE("channel_group_check channel %d\r\n",device->channel_info[k].channel);
            } else {
                break;
            }
        }
        if ((spctrm_scn_wireless_check_channel_score(device->channel_info[k].score) == FAIL) ||
            (spctrm_scn_wireless_check_channel_score(device->channel_info[k + 1].score) == FAIL) ||
            (spctrm_scn_wireless_check_channel_score(device->channel_info[k + 2].score) == FAIL) ||
            (spctrm_scn_wireless_check_channel_score(device->channel_info[k + 3].score) == FAIL)) {
                device->bw80_channel[j].score = -1;
                device->bw80_channel[j].rate = -1;
                continue;
        }
        device->bw80_channel[j] = device->channel_info[k];
        /* bw80底噪 */
        device->bw80_channel[j].floornoise = MAX(MAX(MAX(device->channel_info[k].floornoise,
                                                        device->channel_info[k + 1].floornoise),
                                                         device->channel_info[k + 2].floornoise),
                                                         device->channel_info[k + 3].floornoise);
        /* bw80得分公式 */
        device->bw80_channel[j].score = ((double)1 - calculate_N(&(device->bw80_channel[j])) / 20) *
                                        (double)((double)1 - (double)(device->channel_info[k].obss_util +
                                        device->channel_info[k + 1].obss_util +
                                        device->channel_info[k + 2].obss_util +
                                        device->channel_info[k + 3].obss_util) / (95 * BW_80 / 20)) * 100;

        
        SPCTRM_SCN_DBG_FILE("exp_ratio %f\r\n",exp_ratio);
        if (strcmp(device->role,"ap") == 0) {
            device->bw80_channel[j].rate = device->bw80_channel[j].score /100 * 800 * 0.75;
        } else {
            exp_ratio = spctrm_scn_wireless_get_exp_ratio(device);
            device->bw80_channel[j].rate = device->bw80_channel[j].score /100 * 800 *  exp_ratio / g_stream_num * g_multi_user_loss[g_stream_num];
        }
        spctrm_scn_wireless_rate_filter(device,&(device->bw80_channel[j].rate));

    }
}

void spctrm_scn_wireless_port_status_init(struct port_status_list *list)
{
    json_object *root,*list_obj,*list_elem_obj,*speed_obj,*status_obj,*ipaddr_obj,*count_obj;
    char *rbuf;
    int i;

    spctrm_scn_common_cmd("dev_sta get -m \"port_status\"",&rbuf);
    root = json_tokener_parse(rbuf);
    if (root == NULL) {
        if (rbuf != NULL) {
            free(rbuf);
        }
        return;
    }

    list_obj = json_object_object_get(root,"List");
    if (list_obj == NULL) {
        if (rbuf != NULL) {
            free(rbuf);
        }
        json_object_put(root);
        return;
    }

    list->port_status_list_len = json_object_array_length(list_obj);
    list->list = malloc(list->port_status_list_len * sizeof(struct port_status_list_elem));
    if (list->list == NULL) {
        if (rbuf != NULL) {
            free(rbuf);
        }
        json_object_put(root);
        return;
    }

    for (i = 0;i < list->port_status_list_len;i++) {
        list_elem_obj = json_object_array_get_idx(list_obj,i);
        speed_obj = json_object_object_get(list_elem_obj,"speed");
        if (speed_obj == NULL) {
            if (rbuf != NULL) {
                free(rbuf);
            }
            json_object_put(root);
            return;
        }

        list->list[i].speed = atoi(json_object_get_string(speed_obj));

        status_obj = json_object_object_get(list_elem_obj,"status");
        if (status_obj == NULL) {
            if (rbuf != NULL) {
                free(rbuf);
            }
            json_object_put(root);
            return;
        }

        if (strcmp(json_object_get_string(status_obj),"off") == 0) {
            list->list[i].status = PORT_STATUS_OFF;
        } else if (strcmp(json_object_get_string(status_obj),"on") == 0) {
            list->list[i].status = PORT_STATUS_ON;
        }

        ipaddr_obj = json_object_object_get(list_elem_obj,"ipaddr");
        if (ipaddr_obj == NULL) {
            if (rbuf != NULL) {
                free(rbuf);
            }
            json_object_put(root);
            return;
        }
        memcpy(list->list[i].ipaddr,json_object_get_string(ipaddr_obj),IP_ADDR_LEN);
    }

    json_object_put(root);
    if (rbuf != NULL) {
        free(rbuf);
    }
}

struct port_status_list_elem *spctrm_scn_wireless_find_uplink_port(struct port_status_list *list,char *ip)
{
    int i;
    struct port_status_list_elem *p;

    if (list == NULL || ip == NULL) {
        return NULL;
    }


    p = list->list;
    for (i = 0;i < list->port_status_list_len;i++,p++) {
        SPCTRM_SCN_DBG_FILE("list->list[i].ipaddr %s \r\n",p->ipaddr);
        if (strcmp(ip,p->ipaddr) == 0) {
            return p;
        }
    }

    return NULL;

}
void spctrm_scn_wireless_delete_port_status_list(struct port_status_list *list)
{
    free(list->list);
}

void spctrm_scn_wireless_rate_filter(struct device_info *device,double *rate)
{
    struct device_info *ap;

    if (device == NULL || rate == NULL) {
        return;
    }
    ap = spctrm_scn_dev_find_ap2(&g_finished_device_list);
    if (ap == NULL) {
        return;
    }

#ifdef PORT_STATUS_FILTER_ENABLE
    if (*rate > 90) {

        if (ap->port_speed <= 100 && ap->port_speed > 0) {
            SPCTRM_SCN_DBG_FILE("ap speed 100M");
            *rate = 90;
        } else if (ap->port_speed > 100) {
            SPCTRM_SCN_DBG_FILE("ap speed 1000M");
            if (device->port_status == PORT_STATUS_ON ) {
                SPCTRM_SCN_DBG_FILE("PORT_STATUS_ON");
            } else {
                SPCTRM_SCN_DBG_FILE("PORT_STATUS_OFF");
            }

            if((device->port_status == PORT_STATUS_ON && device->port_speed <= 100 ) ||
                (device->port_status == PORT_STATUS_OFF && device->wan_speed_cap <= 100)) {
                *rate = 90;
            }
        }
    }
#else
    if (*rate > 90) {
        if(device->wan_speed_cap <= 100) {
            *rate = 90;
        }
    }
#endif

    if (*rate > 900) {
        *rate = 900;
    }
}
static int timeout_func()
{
    int i,j;

    for (j = 0; j < 30;j++) {
        SPCTRM_SCN_DBG_FILE("\nwait %d",j);
        sleep(1);
        if (spctrm_scn_tipc_send_auto_get_msg(&g_device_list,3) == SUCCESS) {
            return SUCCESS;
        }
    }
    return FAIL;
}

static double spctrm_scn_wireless_get_exp_ratio(struct device_info *device_info)
{
    double exp_ratio;

    exp_ratio = 0;

    SPCTRM_SCN_DBG_FILE("device_info->rssi %d",device_info->rssi);
    if (device_info->rssi >= -58) {
        exp_ratio = 230.0 / 400.0;
    } else if (device_info->rssi >= -66 && device_info->rssi < -58) {
        exp_ratio = 200.0/ 400.0;
    } else if (device_info->rssi >= -70 && device_info->rssi < -66) {
        exp_ratio = 150.0 / 400.0;
    } else if (device_info->rssi >= -78 && device_info->rssi < -70) {
        exp_ratio = 80.0 / 400.0;
    } else if (device_info->rssi >= -85 && device_info->rssi < -78) {
        exp_ratio = 80.0 / 400.0 / 2;
    } else if (device_info->rssi >= -90 && device_info->rssi < -85) {
        exp_ratio = 80.0 / 400.0 / 4;
    } else if (device_info->rssi >= -95 && device_info->rssi < -90) {
        exp_ratio = 80.0 / 400.0 / 8;
    }
    return exp_ratio;

}

inline int spctrm_scn_wireless_channel_check(int channel)
{
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

#ifdef POPEN_CMD_ENABLE
int spctrm_scn_wireless_change_channel(int channel)
{
    char cmd[1024];
    
    memset(cmd,0,sizeof(cmd));
    if (spctrm_scn_wireless_channel_check(channel) == FAIL) {
        SPCTRM_SCN_DBG_FILE("\nparam error");
        return FAIL;
    }

    sprintf(cmd,"iwpriv %s set  channel=%d",g_wds_bss,channel);

    spctrm_scn_common_cmd(cmd,NULL);

    return SUCCESS;
}
#elif defined UNIFY_FRAMEWORK_ENABLE
int spctrm_scn_wireless_change_channel(int channel)
{
    uf_cmd_msg_t *msg_obj;
    int ret;
    char* rbuf;
    char param[100];

    if (spctrm_scn_wireless_channel_check(channel) == FAIL) {
        SPCTRM_SCN_DBG_FILE("\nparam error");
        return FAIL;
    }

    sprintf(param,"{\"radioList\": [ { \"radioIndex\": \"1\", \"type\":\"5G\", \"channel\":\"%d\" }]}",channel);
    SPCTRM_SCN_DBG_FILE("\n%s\r\n",param);
    msg_obj = (uf_cmd_msg_t*)malloc(sizeof(uf_cmd_msg_t));
    if (msg_obj == NULL) {
        return -1;
    }
    memset(msg_obj, 0, sizeof(uf_cmd_msg_t));
    msg_obj->ctype = UF_DEV_CONFIG_CALL;/* 调用类型 ac/dev/.. */
    msg_obj->param = param;
    msg_obj->cmd = "update";
    msg_obj->module = "radio";             /* 必填参数，其它可选参数根据需要使用 */
    msg_obj->caller = "group_change";   /* 自定义字符串，标记调用者 */
    ret = uf_client_call(msg_obj, &rbuf, NULL);
    if (ret == FAIL) {
        json_object_put(input_param_root);
        return FAIL;
    }
    if (rbuf) {
      free(rbuf);
    }
    free(msg_obj);
}
#endif
