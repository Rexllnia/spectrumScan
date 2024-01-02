#include "spctrm_scn_2g_redbs.h"
#ifdef SPECTRUM_SCAN_REDBS_ENABLE
extern struct spctrm_scn_2g_device_list g_spctrm_scn_2g_device_list;
static redbs_t* wds_list_all_dbs = NULL;

static int wds_list_all_scan_cb(const redbs_t* dbs, redbs_pubsub_msg_t* msg, void* arg) {
	WWdsinfo__InfoTable* info_table;
	WWdsinfo__InfoTableKey* info_key;
    char sn[SN_LEN];
	struct spctrm_scn_2g_device_list *spctrm_scn_2g_device_list;
	struct spctrm_scn_2g_device_info *p;
	int j = 0;

	spctrm_scn_2g_device_list = arg;
    spctrm_scn_2g_common_get_sn(sn);

	if (msg->error != 0) {
		SPCTRM_SCN_DBG("error occur %d\n", msg->error);
		return FAIL;
	}

	if (msg->cmd == REDBS_CMD_SCAN) {
		if (msg->flag == 0) {   							
			SPCTRM_SCN_DBG("[wds_list_all] start\n");
			spctrm_scn_2g_device_list->list_len = 0;
		} else if (msg->flag == REDBS_SCAN_OVER) {  		
			SPCTRM_SCN_DBG("[wds_list_all] end\n");
			
		}
	} else if (msg->cmd == REDBS_CMD_HSET || msg->cmd == REDBS_CMD_SET) {
		info_table = (WWdsinfo__InfoTable*) (msg->value);
		
		SPCTRM_SCN_DBG("%s\r\n",info_table->keys->sn);
		
        if (strcmp(info_table->keys->sn,sn) == 0) {
			SPCTRM_SCN_DBG("find self sn [%s]\r\n",info_table->keys->sn);
			memcpy(&spctrm_scn_2g_device_list->device[spctrm_scn_2g_device_list->list_len].series_no,info_table->keys->sn,SN_LEN);
			SPCTRM_SCN_DBG("%s \r\n",g_spctrm_scn_2g_device_list.device[spctrm_scn_2g_device_list->list_len].series_no); 
			memcpy(&spctrm_scn_2g_device_list->device[spctrm_scn_2g_device_list->list_len].mac,info_table->sys_mac,20);
			SPCTRM_SCN_DBG("%s \r\n",g_spctrm_scn_2g_device_list.device[spctrm_scn_2g_device_list->list_len].mac);
			memcpy(&spctrm_scn_2g_device_list->device[spctrm_scn_2g_device_list->list_len].role,info_table->role,ROLE_STR_LEN); 
			SPCTRM_SCN_DBG("%s \r\n",g_spctrm_scn_2g_device_list.device[spctrm_scn_2g_device_list->list_len].role,info_table->role);
			spctrm_scn_2g_device_list->list_len++;
			
        }

        if (strcmp(info_table->peer_sn,sn) == 0) {
			SPCTRM_SCN_INFO("find peer sn [%s]\r\n",info_table->keys->sn); 
			memcpy(&spctrm_scn_2g_device_list->device[spctrm_scn_2g_device_list->list_len].series_no,info_table->keys->sn,SN_LEN); 
			memcpy(&spctrm_scn_2g_device_list->device[spctrm_scn_2g_device_list->list_len].mac,info_table->sys_mac,20);
			memcpy(&spctrm_scn_2g_device_list->device[spctrm_scn_2g_device_list->list_len].role,info_table->role,ROLE_STR_LEN); 
			spctrm_scn_2g_device_list->list_len++;
        }		
	}


	return SUCCESS;
}
static void wds_all_redis_disconnect() {
	if (wds_list_all_dbs) {
		redbs_finish(wds_list_all_dbs);
		wds_list_all_dbs = NULL;
	}
}
static int get_wds_list_all(struct spctrm_scn_2g_device_list *spctrm_scn_2g_device_list) {
	WWdsinfo__InfoTable info_table = W_WDSINFO__INFO_TABLE__INIT;
	WWdsinfo__InfoTableKey info_key = W_WDSINFO__INFO_TABLE_KEY__INIT;
	int ret;

	info_table.keys = &info_key;
	ret = redbs_scan(wds_list_all_dbs, REDBS_HOST_DB, (const redbs_obj*) &info_table, 0, wds_list_all_scan_cb, (struct spctrm_scn_2g_device_list *)spctrm_scn_2g_device_list);
	return ret;
}

int spctrm_scn_2g_redbs_get_dev_list_info(struct spctrm_scn_2g_device_list *spctrm_scn_2g_device_list)
{
    void* arg = NULL;
	redbs_obj info_table = W_WDSINFO__INFO_TABLE__INIT;
	WWdsinfo__InfoTableKey info_key = W_WDSINFO__INFO_TABLE_KEY__INIT;
	int ret;
	SPCTRM_SCN_DBG("redbs start\r\n");
	if (spctrm_scn_2g_device_list == NULL) {
		SPCTRM_SCN_ERR("spctrm_scn_2g_device_list NULL\r\n");
		return FAIL;
	}

    wds_list_all_dbs = redbs_init("WDS_LIST_ALL_REDBS", NULL);
	if (wds_list_all_dbs == NULL) {
		return FAIL;
	}
	SPCTRM_SCN_DBG("redbs init success\r\n");

	if (redbs_connect(wds_list_all_dbs, REDBS_HOST_DB, NULL, arg) != 0) {
		SPCTRM_SCN_ERR("wds_list_all connect REDBS_NCDB_DB failed!\n");
		wds_all_redis_disconnect();
		return FAIL;
	}
	SPCTRM_SCN_DBG("redbs connect success\r\n");

	get_wds_list_all(spctrm_scn_2g_device_list);
	wds_all_redis_disconnect();

	return SUCCESS;
}
#endif