/* spctrm_scn_debug.h */
#ifndef _SPCTRM_SCN_DEBUG_H_
#define _SPCTRM_SCN_DEBUG_H_
#include <libdebug/libdebug.h>
#include "spctrm_scn_config.h"

/*
    ubus call spectrum_scan.debug set '{"level":"INFO","module":"all","status":"open","tty":"/dev/tty"}'
    ubus call spectrum_scan.debug set '{"level":"DEBUG","module":"all","status":"open","tty":"/dev/tty"}'

*/
#define SPCTRM_SCN_DEBUG        "spectrum_scan"
#define SPCTRM_SCN_FILE         "/tmp/spectrum_scan/debug.log"
#define SPCTRM_SCN_DEBUG_SIZE   20

int g_dbg_id;

#define SPCTRM_SCN_DBG_FILE(fmt, arg...) do {  \
    dbg_logfile(g_dbg_id,  "[%s:%d] "fmt, __FUNCTION__, __LINE__, ##arg);  \
} while (0)

#define SPCTRM_SCN_DBG(fmt, arg...) do { \
    dbg_printf(g_dbg_id, DBG_LV_DEBUG, "[%s:%d] "fmt, __FUNCTION__, __LINE__, ##arg);\
} while (0)

#define SPCTRM_SCN_WARN(fmt, arg...) do { \
    dbg_printf(g_dbg_id, DBG_LV_WARNING, "WARNING in %s [%d]: "fmt, __FILE__, __LINE__, ##arg);\
} while (0)

#define SPCTRM_SCN_IS_ZERO_WARN(param,fmt, arg...) do { \
    if (param == 0) {\
        dbg_printf(g_dbg_id, DBG_LV_WARNING, "WARNING in %s [%d]: "fmt, __FILE__, __LINE__, ##arg);\
    }\
} while (0)

#define SPCTRM_SCN_ERR(fmt, arg...) do { \
    dbg_printf(g_dbg_id, DBG_LV_ERROR, "ERROR in %s [%d]: "fmt, __FILE__, __LINE__, ##arg);\
} while (0)

#define SPCTRM_SCN_INFO(fmt, arg...) do { \
    dbg_printf(g_dbg_id, DBG_LV_INFO, "[INFO] %s [%d]: "fmt, __FILE__, __LINE__, ##arg);\
} while (0)

int spectrm_scn_debug_init(void);

#endif