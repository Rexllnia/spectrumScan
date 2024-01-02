#include "spctrm_scn_2g_uloop.h"
#include <sys/resource.h>

extern __u32 g_spctrm_scn_2g_ap_instant;
extern int8_t g_spctrm_scn_2g_status;
extern char g_2g_ext_ifname[IFNAMSIZ];
extern char g_5g_ext_ifname[IFNAMSIZ];
extern char g_apcli_ifname[IFNAMSIZ];

extern uint8_t g_band_support;
extern struct spctrm_scn_2g_device_list g_spctrm_scn_2g_device_list;

static int server_main(struct ubus_context *ctx)
{
    int ret;
    char mac[20];
    struct uloop_timeout *spctrm_scn_2g_rlog_upload_timer;

    
    if (g_spctrm_scn_2g_mode == AP_MODE) {

    } else if (g_spctrm_scn_2g_mode == CPE_MODE) {
        spctrm_scn_2g_wireless_get_band_5G_apcli_ifname(g_apcli_ifname);
    }
    if (g_spctrm_scn_2g_mode == AP_MODE) {
        spctrm_scn_2g_wireless_process_recover_handle();
        spctrm_scn_2g_common_read_file("/proc/rg_sys/sys_mac",mac,sizeof(mac) - 1);
        if (spctrm_scn_2g_common_mac_2_nodeadd(mac,&g_spctrm_scn_2g_ap_instant) == FAIL) {
            return FAIL;
        }
        spctrm_scn_2g_ubus_task(ctx);
        

        /* spctrm_scn_2g_rlog init */
        if (spctrm_scn_2g_rlog_connect_ubus_ctx(ctx) == FAIL) {
            return FAIL;
        }
        spctrm_scn_2g_rlog_get_upload_to_macc_fn_stat();
        spctrm_scn_2g_rlog_get_module_info("spectrumScan");
        spctrm_scn_2g_rlog_upload_timer = malloc(sizeof(struct uloop_timeout));
        memset(spctrm_scn_2g_rlog_upload_timer,0,sizeof(struct uloop_timeout));
        spctrm_scn_2g_rlog_upload_timer->cb = spctrm_scn_2g_rlog_upload_timer_cb;
        uloop_timeout_set(spctrm_scn_2g_rlog_upload_timer,5000);
        
    }

    spctrm_scn_2g_tipc_task();
    return SUCCESS;
}

int spctrm_scn_2g_uloop(struct ubus_context *ctx)
{
    int ret;
    FILE *fp;
    struct rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &limit);
    spectrm_scn_debug_init();

    if (spctrm_scn_2g_wireless_get_wds_state(&g_spctrm_scn_2g_mode) == FAIL) {
        return FAIL;
    }

    spctrm_scn_2g_wireless_get_ext_ifname(g_5g_ext_ifname,BAND_5G);
    spctrm_scn_2g_wireless_get_ext_ifname(g_2g_ext_ifname,BAND_2G);
    
    system("mkdir /tmp/spectrum_scan_2g");

    fp = fopen("/tmp/spectrum_scan_2g/curl_pid","w+");
    if (fp == NULL) {
        return FAIL;
    } 
    
    fprintf(fp,"%d",getpid());
    fclose(fp);

    server_main(ctx);

	return 0;
}

void spctrm_scn_2g_close()
{
    SPCTRM_SCN_DBG("spctrm_scn_2g done");
    tipc_close();
    uloop_done();
}




