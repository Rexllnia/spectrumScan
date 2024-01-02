
#ifdef SPECTRUM_SCAN_REDBS_ENABLE
#ifndef _SPCTRM_SCN_2G_REDBS_H_
#define _SPCTRM_SCN_2G_REDBS_H_
#include <hiredis/redbs.h>
#include <hiredis/hiredis.h>
#include <hiredis/redbs_common.h>
#include <hiredis/est/wds/wdsinfo.pb-c.h>
#include "spctrm_scn_2g_config.h"


int spctrm_scn_2g_redbs_get_dev_list_info(struct spctrm_scn_2g_device_list *spctrm_scn_2g_device_list);
#endif
#endif
