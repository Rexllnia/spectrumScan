#include "spctrm_scn_2g_config.h"
#include <libubox/blobmsg_json.h>
#include "libubus.h"

#define SPCTRM_SCN_RLOG_MODULE_ERROR       -1
#define SPCTRM_SCN_RLOG_MODULE_DISABLE     1
#define SPCTRM_SCN_RLOG_MODULE_ENABLE      0

#define SPCTRM_SCN_UPLOAD_TO_MACC_ENABLE     1
#define SPCTRM_SCN_UPLOAD_TO_MACC_DISABLE    0

int spctrm_scn_2g_rlog_connect_ubus_ctx(struct ubus_context *ctx);
int spctrm_scn_2g_rlog_check_module_enable(const char *module);
int spctrm_scn_2g_rlog_upload_stream(char *module,char *data);
void spctrm_scn_2g_rlog_upload_blobmsg_to_macc(struct blob_buf *buf);
int spctrm_scn_2g_rlog_get_module_info(const char *module);
void spctrm_scn_2g_rlog_upload_timer_cb(struct uloop_timeout *t); 
void spctrm_scn_2g_rlog_get_upload_to_macc_fn_stat();
