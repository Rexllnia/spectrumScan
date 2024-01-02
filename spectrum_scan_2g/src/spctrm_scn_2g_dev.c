#include "spctrm_scn_2g_dev.h"

extern int8_t g_spctrm_scn_2g_status;

int spctrm_scn_2g_dev_remove_not_finish_device(struct spctrm_scn_2g_device_list * spctrm_scn_2g_device_list)
{
    struct spctrm_scn_2g_device_info *p;
    struct spctrm_scn_2g_device_list tmp_device_list ;
    int i = 0;
    memset(&tmp_device_list,0,sizeof(struct spctrm_scn_2g_device_list));
    list_for_each_device(p,i,spctrm_scn_2g_device_list) {
        if (p->finished_flag == FINISHED) {
            memcpy(&tmp_device_list.device[tmp_device_list.list_len],p,sizeof(struct spctrm_scn_2g_device_info));
            tmp_device_list.list_len++;
        }
    }
    memcpy(spctrm_scn_2g_device_list,&tmp_device_list,sizeof(struct spctrm_scn_2g_device_list));
}
int spctrm_scn_2g_dev_ap_status_to_file(int8_t status) 
{
    json_object *root;
    json_object *status_obj;

#ifndef NEW_FIELD
    char tmp[128]; 
    json_object *status_code_str_obj;
    json_object *status_str_obj;
#endif

    int fd;
    char *rbuf;
    
    if (access(SPCTRM_SCN_2G_DEV_LIST_JSON_PATH,F_OK) == FAIL) {
        SPCTRM_SCN_INFO("file not exit\r\n");
        if (fd = creat(SPCTRM_SCN_2G_DEV_LIST_JSON_PATH , 0777) == FAIL) {
            SPCTRM_SCN_ERR("spctrm_scn_2g_device_list.json create error\r\n");
            return FAIL;
        } 
        close(fd);
        

        root = json_object_new_object();
        if (root == NULL) {
            return FAIL;
        }
        
        SPCTRM_SCN_INFO("status to file %d",status);
        status_obj = json_object_new_int(status);
        if (status_obj == NULL) {
            json_object_put(root);
            return FAIL;
        }

        json_object_object_add(root,"_status_code",status_obj);

#ifndef NEW_FIELD
        memset(tmp,0,sizeof(tmp));
        sprintf(tmp,"%d",status);
        status_code_str_obj = json_object_new_string(tmp);
        json_object_object_add(root,"status_code",status_code_str_obj);

        memset(tmp,0,sizeof(tmp));
        switch (status) {
        case SPCTRM_SCN_2G_SCAN_ERROR:
            sprintf(tmp,"error");
            break;
        case SPCTRM_SCN_2G_SCAN_IDLE:
            sprintf(tmp,"idle");
            break;
        case SPCTRM_SCN_2G_SCAN_TIMEOUT:
            sprintf(tmp,"timeout");
            break;
        case SPCTRM_SCN_2G_SCAN_BUSY:
            sprintf(tmp,"busy");
            break;
        default:
            sprintf(tmp,"error");
            break;
        }
        status_str_obj = json_object_new_string(tmp);
        json_object_object_add(root,"status",status_str_obj);
#endif

        json_object_to_file(SPCTRM_SCN_2G_DEV_LIST_JSON_PATH,root);
        json_object_put(root);
    } else {
        SPCTRM_SCN_INFO("file exit\r\n");
        root = json_object_from_file(SPCTRM_SCN_2G_DEV_LIST_JSON_PATH);
        if (root == NULL) {
            SPCTRM_SCN_WARN("file NULL\r\n");
            root = json_object_new_object();
            if (root == NULL) {
                SPCTRM_SCN_ERR("json object create error\r\n");
                return FAIL;
            }
        }
        SPCTRM_SCN_INFO("status to file %d\r\n",status);
        status_obj = json_object_new_int(status);
        if (status_obj == NULL) {
            SPCTRM_SCN_ERR("status_obj create error\r\n");
            json_object_put(root);
            return FAIL;
        }

        json_object_object_add(root,"_status_code",status_obj);

#ifndef NEW_FIELD
        sprintf(tmp,"%d",status);
        status_code_str_obj = json_object_new_string(tmp);
        json_object_object_add(root,"status_code",status_code_str_obj);

        memset(tmp,0,sizeof(tmp));
        switch (status) {
        case SPCTRM_SCN_2G_SCAN_ERROR:
            sprintf(tmp,"error");
            break;
        case SPCTRM_SCN_2G_SCAN_IDLE:
            sprintf(tmp,"idle");
            break;
        case SPCTRM_SCN_2G_SCAN_TIMEOUT:
            sprintf(tmp,"timeout");
            break;
        case SPCTRM_SCN_2G_SCAN_BUSY:
            sprintf(tmp,"busy");
            break;
        default:
            sprintf(tmp,"error");
            break;
        }
        status_str_obj = json_object_new_string(tmp);
        json_object_object_add(root,"status",status_str_obj); 
#endif

        json_object_to_file(SPCTRM_SCN_2G_DEV_LIST_JSON_PATH,root);
        json_object_put(status_obj);
        json_object_put(root);
    }

    return SUCCESS;
}

int spctrm_scn_2g_dev_blobmsg_to_file(struct blob_buf *buf,char *path) 
{
    FILE *fp;
    char *json_str;
    
    if (buf == NULL || path == NULL) {
        return FAIL;
    }

    fp = fopen(path,"w+");
    if (fp == NULL) {
        return FAIL;
    }

    json_str = blobmsg_format_json(buf->head,true);
    if (json_str == NULL) {
        SPCTRM_SCN_ERR("blobmsg format json error\r\n");
        fclose(fp);
        return FAIL;
    }
    fwrite(json_str,sizeof(char),strlen(json_str)+1,fp);

    free(json_str);
    fclose(fp);
    return SUCCESS;
}

int spctrm_scn_2g_dev_wds_list(struct spctrm_scn_2g_device_list *spctrm_scn_2g_device_list)
{
    char *rbuf;
    char sn[SN_LEN];
    int i,j,find_flag,ret;
    uf_cmd_msg_t *msg_obj;
    json_object *rbuf_root;
    json_object *list_all_obj;
    json_object *list_pair_obj;
    json_object *sn_obj,*role_obj,*mac_obj;
    json_object *list_all_elem ;
    json_object *list_pair_elem;

    if (spctrm_scn_2g_device_list == NULL) {
        SPCTRM_SCN_INFO("spctrm_scn_2g_device_list NULL\r\n");
        return FAIL;
    }
    
    msg_obj = (uf_cmd_msg_t*)malloc(sizeof(uf_cmd_msg_t));
    if (msg_obj == NULL) {
        return FAIL;
    }
    memset(msg_obj, 0, sizeof(uf_cmd_msg_t));

    msg_obj->ctype = UF_DEV_STA_CALL;    /* 调用类型 ac/dev/.. */
    msg_obj->cmd = "get";
    msg_obj->module = "wds_list_all";               /* 必填参数，其它可选参数根据需要使用 */
    msg_obj->caller = "group_change";       /* 自定义字符串，标记调用者 */
    ret = uf_client_call(msg_obj, &rbuf, NULL);
    if (ret == FAIL) {
        free(msg_obj);
        return FAIL;      
    }

    rbuf_root = json_tokener_parse(rbuf);
    if (rbuf_root == NULL) {
        perror("rbuf_root");
        free(msg_obj);
        return FAIL;
    }
    list_all_obj = json_object_object_get(rbuf_root,"list_all");
    if (list_all_obj == NULL) {
        perror("list_all_obj");
        free(rbuf);
        json_object_put(rbuf_root);
        free(msg_obj);
        return FAIL;
    }

    SPCTRM_SCN_INFO("\r\n");
    spctrm_scn_2g_common_get_sn(sn);
    SPCTRM_SCN_INFO("sn %s\r\n",sn);

    find_flag = 0;
    for (i = 0;i < json_object_array_length(list_all_obj);i++) {
        list_all_elem = json_object_array_get_idx(list_all_obj,i);
        if (list_all_elem == NULL) {
            perror("list_all_obj");
            free(rbuf);
            json_object_put(rbuf_root);
            free(msg_obj);
            return FAIL;
        }

        list_pair_obj = json_object_object_get(list_all_elem,"list_pair");
        if (list_pair_obj == NULL) {
            perror("list_all_elem");
            free(rbuf);
            json_object_put(rbuf_root);
            free(msg_obj);
            return FAIL;
        }

        for (j = 0;j < json_object_array_length(list_pair_obj);j++) {
            list_pair_elem = json_object_array_get_idx(list_pair_obj,j);
            if (list_pair_elem == NULL) {
                perror("list_pair_elem");
                free(rbuf);
                json_object_put(rbuf_root);
                free(msg_obj);
                return FAIL;
            }
            sn_obj = json_object_object_get(list_pair_elem,"sn");
            if (sn_obj == NULL) {
                perror("sn_obj");
                free(rbuf);
                json_object_put(rbuf_root);
                free(msg_obj);
                return FAIL;
            }
            if (strcmp(json_object_get_string(sn_obj),sn) == 0) {
                SPCTRM_SCN_INFO("%d\r\n",i);
                find_flag = 1;
                break;
            }
        }
        if (find_flag == 1) {
            break;
        }
    }
    SPCTRM_SCN_INFO("%d\r\n",i);

    list_all_elem = json_object_array_get_idx(list_all_obj,i);
    if (list_all_elem == NULL) {
        free(rbuf);
        json_object_put(rbuf_root);	
        perror("list_all_elem");
        free(msg_obj);
        return FAIL;
    }
    list_pair_obj = json_object_object_get(list_all_elem,"list_pair");
    if (list_pair_obj == NULL) {
        free(rbuf);
        json_object_put(rbuf_root);
        SPCTRM_SCN_INFO("list_pair_obj\r\n");
        free(msg_obj);
        return FAIL;
    }
    spctrm_scn_2g_device_list->list_len = json_object_array_length(list_pair_obj);

    if (spctrm_scn_2g_device_list->list_len > SPCTRM_SCN_2G_MAX_DEVICE_NUM) {
        free(rbuf);
        json_object_put(rbuf_root);
        SPCTRM_SCN_INFO("over SPCTRM_SCN_2G_MAX_DEVICE_NUM\r\n");
        free(msg_obj);
        return FAIL;
    }

    for (i = 0;i < spctrm_scn_2g_device_list->list_len;i++) {
        list_pair_elem = json_object_array_get_idx(list_pair_obj,i);
        sn_obj = json_object_object_get(list_pair_elem,"sn");
        if (sn_obj == NULL) {
            free(rbuf);
            json_object_put(rbuf_root);
        if (role_obj == NULL) {
            free(rbuf);
            SPCTRM_SCN_INFO("sn_obj\r\n");
            free(msg_obj);
            return FAIL;
        }
        role_obj = json_object_object_get(list_pair_elem,"role");
            json_object_put(rbuf_root);
            SPCTRM_SCN_INFO("role_obj\r\n");
            free(msg_obj);
            return FAIL;
        }
        mac_obj = json_object_object_get(list_pair_elem,"mac");
        if (mac_obj == NULL) {
            free(rbuf);
            json_object_put(rbuf_root);
            SPCTRM_SCN_INFO("mac_obj\r\n");
            free(msg_obj);
            return FAIL;
        }
        strcpy(spctrm_scn_2g_device_list->device[i].series_no,json_object_get_string(sn_obj));
        strcpy(spctrm_scn_2g_device_list->device[i].role,json_object_get_string(role_obj));
        strcpy(spctrm_scn_2g_device_list->device[i].mac,json_object_get_string(mac_obj));
    }
    
    if (rbuf != NULL) {
        free (rbuf);
    }
    json_object_put(rbuf_root);
    free(msg_obj);
    
    return SUCCESS;
}

struct spctrm_scn_2g_device_info *spctrm_scn_2g_dev_find_ap(struct spctrm_scn_2g_device_list *spctrm_scn_2g_device_list)
{
    struct spctrm_scn_2g_device_info *p;
    int i;

    if (spctrm_scn_2g_device_list == NULL) {
        SPCTRM_SCN_ERR("spctrm_scn_2g_device_list NULL\r\n");
        return NULL;
    }

    list_for_each_device(p,i,spctrm_scn_2g_device_list) {
        SPCTRM_SCN_INFO("\r\n");
        if (strcmp(spctrm_scn_2g_device_list->device[i].role,"ap") == 0) {
            SPCTRM_SCN_INFO("\r\n");
            return p;
        }
    }
}

void spctrm_scn_2g_dev_reset_stat(struct spctrm_scn_2g_device_list *list) {
    struct spctrm_scn_2g_device_info *p;
    int i;

    if (list == NULL) {
        return;
    }
    list_for_each_device(p, i, list) {
        p->finished_flag = NOT_FINISH;
    }
}


int spctrm_scn_2g_dev_find_by_sn(struct spctrm_scn_2g_device_list *spctrm_scn_2g_device_list,char *series_no)
{
    int i;

    if (spctrm_scn_2g_device_list == NULL || series_no == NULL) {
        return FAIL;
    }

    for (i = 0;i < spctrm_scn_2g_device_list->list_len;i++) {
        if (strcmp(spctrm_scn_2g_device_list->device[i].series_no,series_no) == 0) {
            return i;
        }
    }
    return FAIL;
}

int spctrm_scn_2g_dev_chk_stat(struct spctrm_scn_2g_device_list *spctrm_scn_2g_device_list) {
    
    struct spctrm_scn_2g_device_info *p;
    int i;

    if (spctrm_scn_2g_device_list == NULL) {
        return FAIL;
    }
    
    list_for_each_device(p, i, spctrm_scn_2g_device_list) {
        SPCTRM_SCN_INFO("mac:%x p->finished_flag %d\r\n",p->mac,p->finished_flag);
        if (p->finished_flag == NOT_FINISH) {
            return FAIL;
        }
    }

    return SUCCESS;
}
