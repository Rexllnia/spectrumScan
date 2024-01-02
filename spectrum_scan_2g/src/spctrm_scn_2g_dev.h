#ifndef _SPCTRM_SCN_2G_DEV_H_
#define _SPCTRM_SCN_2G_DEV_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <json-c/json.h>
#include "lib_unifyframe.h"
#include "spctrm_scn_2g_config.h"

#define ROLE_STR_LEN 4
#define FINISHED 	1
#define NOT_FINISH	0

/* 
p: type spctrm_scn_2g_device_info loop
i: counter
dev_list : type spctrm_scn_2g_device_list
*/
#define list_for_each_device(p,i,dev_list) \
    for ((p) = (dev_list)->device,i = 0;i < (dev_list)->list_len;p++,i++)

int spctrm_scn_2g_dev_ap_status_to_file(int8_t status);
int spctrm_scn_2g_dev_wds_list(struct spctrm_scn_2g_device_list *spctrm_scn_2g_device_list);
int spctrm_scn_2g_dev_chk_stat(struct spctrm_scn_2g_device_list *spctrm_scn_2g_device_list);
int spctrm_scn_2g_dev_find_by_sn(struct spctrm_scn_2g_device_list *spctrm_scn_2g_device_list,char *series_no);
void spctrm_scn_2g_dev_reset_stat(struct spctrm_scn_2g_device_list *list);
int spctrm_scn_2g_dev_list_cmp(struct spctrm_scn_2g_device_list *src_list,struct spctrm_scn_2g_device_list *dest_list);
struct spctrm_scn_2g_device_info *spctrm_scn_2g_dev_find_ap(struct spctrm_scn_2g_device_list *spctrm_scn_2g_device_list);
int spctrm_scn_2g_dev_blobmsg_to_file(struct blob_buf *buf,char *path);
int spctrm_scn_2g_dev_remove_not_finish_device(struct spctrm_scn_2g_device_list * spctrm_scn_2g_device_list);
#endif
