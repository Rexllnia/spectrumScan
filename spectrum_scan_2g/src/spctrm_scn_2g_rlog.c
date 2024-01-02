#include "spctrm_scn_2g_rlog.h"

#define MAX_URL_LEN 1024
static int g_macc_func_stat;
static char g_spctrm_scn_rlog_url[MAX_URL_LEN];
static int g_module_enable_result;
static struct ubus_context *g_spctrm_scn_2g_rlog_ctx;
extern int8_t g_spctrm_scn_2g_status;

/*
 * rlog  module enable result policy
 */
enum
{
    RESULT,
    __RESULT_MAX
};

static const struct blobmsg_policy result_policy[] = {
    [RESULT] = {.name = "result", .type = BLOBMSG_TYPE_STRING},
};

/*
 * rlog get module info policy
 */
enum
{
    MODULE_LIST,
    SPCTRM_SCN_RLOG_MODULE_TOTAL,
    __MODULE_INFO_MAX
};

enum
{
    SPCTRM_SCN_RLOG_MODULE_NAME,
    SPCTRM_SCN_RLOG_MODULE_SERVER,
    SPCTRM_SCN_RLOG_MODULE_UPLOAD_PERIOD,
    SPCTRM_SCN_RLOG_MODULE_CREATE_PERIOD,
    SPCTRM_SCN_RLOG_MODULE_SINGLE,
    SPCTRM_SCN_RLOG_MODULE_MODULE_DIR,
    SPCTRM_SCN_RLOG_MODULE_FILE,
    __MODULE_LIST_MAX
};

static const struct blobmsg_policy module_info_policy[] = {
    [MODULE_LIST] = {.name = "module_list", .type = BLOBMSG_TYPE_ARRAY},
    [SPCTRM_SCN_RLOG_MODULE_TOTAL] = {.name = "total", .type = BLOBMSG_TYPE_INT64},
};

static const struct blobmsg_policy module_list_elem_policy[] = {
    [SPCTRM_SCN_RLOG_MODULE_NAME] = {.name = "module_name", .type = BLOBMSG_TYPE_STRING},
    [SPCTRM_SCN_RLOG_MODULE_SERVER] = {.name = "server", .type = BLOBMSG_TYPE_STRING},
    [SPCTRM_SCN_RLOG_MODULE_UPLOAD_PERIOD] = {.name = "upload_period", .type = BLOBMSG_TYPE_INT64},
    [SPCTRM_SCN_RLOG_MODULE_CREATE_PERIOD] = {.name = "create_period", .type = BLOBMSG_TYPE_INT64},
    [SPCTRM_SCN_RLOG_MODULE_SINGLE] = {.name = "single", .type = BLOBMSG_TYPE_INT64},
    [SPCTRM_SCN_RLOG_MODULE_MODULE_DIR] = {.name = "module_dir", .type = BLOBMSG_TYPE_STRING},
    [SPCTRM_SCN_RLOG_MODULE_FILE] = {.name = "file", .type = BLOBMSG_TYPE_STRING},
};

static void rlog_module_enable_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct blob_attr *tb[__RESULT_MAX];
    
    
    g_module_enable_result = SPCTRM_SCN_RLOG_MODULE_ERROR;
    blobmsg_parse(result_policy, ARRAY_SIZE(result_policy), tb, blob_data(msg), blob_len(msg));
    SPCTRM_SCN_INFO("RESULT %s\r\n",blobmsg_get_string(tb[RESULT]));
    if (strcmp(blobmsg_get_string(tb[RESULT]),"0") == 0) {
        g_module_enable_result = SPCTRM_SCN_RLOG_MODULE_DISABLE;
    } else if (strcmp(blobmsg_get_string(tb[RESULT]),"1") == 0) {
        g_module_enable_result = SPCTRM_SCN_RLOG_MODULE_ENABLE;
    } else {
        g_module_enable_result = SPCTRM_SCN_RLOG_MODULE_ERROR;
    }
      
}

static void rlog_module_info_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct blobmsg_policy *module_list_policy;
    struct blob_attr *tb[__MODULE_INFO_MAX];
    struct blob_attr *module_list[1024];
    struct blob_attr *module_list_elem_tb[__MODULE_LIST_MAX];
    char sn[SN_LEN];
    __u64 total,i,len;
    total = 0;
    len = 0;

    blobmsg_parse(module_info_policy, ARRAY_SIZE(module_info_policy), tb, blob_data(msg), blob_len(msg));


    if (tb[SPCTRM_SCN_RLOG_MODULE_TOTAL] == NULL || tb[MODULE_LIST] == NULL) {
        SPCTRM_SCN_WARN("=====SPCTRM_SCN_RLOG_MODULE_TOTAL====%s=====\r\n",tb[SPCTRM_SCN_RLOG_MODULE_TOTAL]);
        return;
    }
  
    total = blobmsg_get_u64(tb[SPCTRM_SCN_RLOG_MODULE_TOTAL]);


    SPCTRM_SCN_INFO("total %lld\r\n",total);

    module_list_policy = (struct blobmsg_policy*)malloc(total * sizeof(struct blobmsg_policy));
    if (module_list_policy == NULL) {
        return;
    }
  
    for (i = 0; i < total; i++) {
        module_list_policy[i].type = BLOBMSG_TYPE_TABLE;
    }
  
    blobmsg_parse_array(module_list_policy, total, module_list, blobmsg_data(tb[MODULE_LIST]), blobmsg_len(tb[MODULE_LIST]));

    for (i = 0 ;i < total;i++) {
        blobmsg_parse(module_list_elem_policy,ARRAY_SIZE(module_list_elem_policy),module_list_elem_tb,blobmsg_data(module_list[i]),blobmsg_len(module_list[i]));

        if (strcmp(blobmsg_get_string(module_list_elem_tb[SPCTRM_SCN_RLOG_MODULE_NAME]),"spectrumScan") == 0) {
            
            len = strlen(blobmsg_get_string(module_list_elem_tb[SPCTRM_SCN_RLOG_MODULE_SERVER]));
            memset(g_spctrm_scn_rlog_url,0,sizeof(g_spctrm_scn_rlog_url));
            memset(sn,0,sizeof(sn));
            spctrm_scn_2g_common_get_sn(sn);
            if (len < MAX_URL_LEN - SN_LEN - strlen("?sn=")) {
                snprintf(g_spctrm_scn_rlog_url,MAX_URL_LEN,"%s?sn=%s",blobmsg_get_string(module_list_elem_tb[SPCTRM_SCN_RLOG_MODULE_SERVER]),sn);
                SPCTRM_SCN_INFO("spectrumScan MACC server url %s\r\n",g_spctrm_scn_rlog_url);
            } else {
                SPCTRM_SCN_WARN("spectrumScan MACC server url too long");
            }
        }
    }

    free(module_list_policy);
    
      
}

int spctrm_scn_2g_rlog_connect_ubus_ctx(struct ubus_context *ctx)
{
    if (ctx == NULL) {
        return FAIL;
    }
    g_spctrm_scn_2g_rlog_ctx = ctx;
    return SUCCESS;
}

int spctrm_scn_2g_rlog_upload_stream(char *module,char *data)
{
    unsigned int id;
    int ret;
    static struct blob_buf b;
    
    if (module == NULL || g_spctrm_scn_2g_rlog_ctx == NULL || data == NULL) {
        return FAIL;
    }
 
    blob_buf_init(&b, 0);
 
    blobmsg_add_string(&b,"module_name",module);
    blobmsg_add_string(&b,"data",data);
    blobmsg_add_string(&b,"server",g_spctrm_scn_rlog_url);
    SPCTRM_SCN_DBG("spectrumScan MACC server url %s\r\n",g_spctrm_scn_rlog_url);
    blobmsg_add_string(&b,"header","Content-Type:application/json;charset=UTF-8");
    
    ret = ubus_lookup_id(g_spctrm_scn_2g_rlog_ctx, "rlog", &id);
    if (ret != UBUS_STATUS_OK) {
        SPCTRM_SCN_DBG("lookup rlog failed\n");
        return FAIL;
    } else {
        SPCTRM_SCN_DBG("lookup rlog successs\n");
    }

    ubus_invoke(g_spctrm_scn_2g_rlog_ctx, id, "upload_stream", b.head, NULL, NULL,1000);
    return SUCCESS;    
}

int spctrm_scn_2g_rlog_onetime_upload(const char *module) 
{
    unsigned int id;
    int ret;
    static struct blob_buf b;
    
    if (module == NULL || g_spctrm_scn_2g_rlog_ctx == NULL) {
        return FAIL;
    }
 
    blob_buf_init(&b, 0);
 
    blobmsg_add_string(&b,"module_name",module);
 
    ret = ubus_lookup_id(g_spctrm_scn_2g_rlog_ctx, "rlog", &id);
    if (ret != UBUS_STATUS_OK) {
        SPCTRM_SCN_WARN("lookup rlog failed\n");
        return FAIL;
    } else {
        SPCTRM_SCN_INFO("lookup rlog successs\n");
    }
    ubus_invoke(g_spctrm_scn_2g_rlog_ctx, id, "onetime_upload", b.head, NULL, NULL,1000);
    return SUCCESS;
}

int spctrm_scn_2g_rlog_check_module_enable(const char *module) 
{
    unsigned int id;
    int ret;
    static struct blob_buf b;
    
    if (module == NULL || g_spctrm_scn_2g_rlog_ctx == NULL) {
        return FAIL;
    }
 
    blob_buf_init(&b, 0);
 
    blobmsg_add_string(&b,"module",module);
 
    ret = ubus_lookup_id(g_spctrm_scn_2g_rlog_ctx, "rlog", &id);
    if (ret != UBUS_STATUS_OK) {
        SPCTRM_SCN_WARN("lookup rlog failed\n");
        return FAIL;
    } else {
        SPCTRM_SCN_INFO("lookup rlog successs\n");
    }
    ubus_invoke(g_spctrm_scn_2g_rlog_ctx, id, "module_enable", b.head, rlog_module_enable_cb, NULL,3000);
    return SUCCESS;
}


int spctrm_scn_2g_rlog_get_module_info(const char *module) 
{
    unsigned int id;
    int ret;
    static struct blob_buf b;
    
    if (module == NULL || g_spctrm_scn_2g_rlog_ctx == NULL) {
        return FAIL;
    }
 
    blob_buf_init(&b, 0);
    
    SPCTRM_SCN_INFO("%s",module);
    blobmsg_add_string(&b,"module",module);
 
    ret = ubus_lookup_id(g_spctrm_scn_2g_rlog_ctx, "rlog", &id);
    if (ret != UBUS_STATUS_OK) {
        SPCTRM_SCN_WARN("lookup rlog failed\n");
        return FAIL;
    } else {
        SPCTRM_SCN_INFO("lookup rlog success\n");
    }
    ubus_invoke(g_spctrm_scn_2g_rlog_ctx, id, "module_info", b.head, rlog_module_info_cb, NULL,3000);
    return SUCCESS;
}

int spctrm_scn_2g_rlog_get_module_enable_result()
{
    return g_module_enable_result;
}

void spctrm_scn_2g_rlog_get_upload_to_macc_fn_stat()
{

    spctrm_scn_2g_rlog_check_module_enable("spectrumScan");
    if (spctrm_scn_2g_rlog_get_module_enable_result() == SPCTRM_SCN_RLOG_MODULE_ENABLE) {
        g_macc_func_stat = SPCTRM_SCN_UPLOAD_TO_MACC_ENABLE;
    } else {
        printf("spectrumScan upload to macc disable\r\n"); 
    }
}
void spctrm_scn_2g_rlog_upload_blobmsg_to_macc(struct blob_buf *buf)
{
    if (g_macc_func_stat == SPCTRM_SCN_UPLOAD_TO_MACC_ENABLE) {
        spctrm_scn_2g_rlog_upload_stream("spectrumScan",blobmsg_format_json(buf->head,true));
    }
}

void spctrm_scn_2g_rlog_upload_timer_cb(struct uloop_timeout *t) 
{
    struct stat file_stat;
    char *buf;

    uloop_timeout_set(t,5000);

    if ((g_spctrm_scn_2g_status == SPCTRM_SCN_2G_SCAN_BUSY) || (g_macc_func_stat == SPCTRM_SCN_UPLOAD_TO_MACC_DISABLE)) {
        return;
    }
    
    if (stat(SPCTRM_SCN_2G_DEV_LIST_JSON_PATH, &file_stat) == SUCCESS) {
        buf = malloc(file_stat.st_size);
        SPCTRM_SCN_DBG("file_stat.st_size %ld\r\n",file_stat.st_size);
        if (buf == NULL) {
            SPCTRM_SCN_ERR("malloc fail");
            return;
        }

        if (spctrm_scn_2g_common_read_file(SPCTRM_SCN_2G_DEV_LIST_JSON_PATH,buf,file_stat.st_size) != FAIL) {
            spctrm_scn_2g_rlog_upload_stream("spectrumScan",buf);
            SPCTRM_SCN_DBG("send buf %s\r\n",buf);
        }
        free(buf);
    }
    
}