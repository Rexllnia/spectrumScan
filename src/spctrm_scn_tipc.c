
#include "spctrm_scn_tipc.h"

static void server_type_scan_reply_cb(tipc_recv_packet_head_t *head,char *pkt);
extern time_t g_current_time ;
extern volatile int g_status;
extern unsigned char g_mode;
extern struct user_input g_input;
extern struct device_list g_finished_device_list,g_device_list;
extern struct channel_info g_channel_info_5g[MAX_BAND_5G_CHANNEL_NUM];
extern struct channel_info realtime_channel_info_5g[MAX_BAND_5G_CHANNEL_NUM];
extern pthread_mutex_t g_mutex,g_finished_device_list_mutex;
extern sem_t g_semaphore;
__u32 g_ap_instant;
static sem_t receive_finish_semaphore;
extern pthread_mutex_t g_dev_cmd_mutex;

int spctrm_scn_tipc_send_start_msg(struct device_list *list,int wait_sec)
{
    struct device_info *p;
    __u32 instant = 0;
    int i;

    if (list == NULL) {
        return FAIL;
    }

    memset(list,0,sizeof(struct device_list));
    if (spctrm_scn_dev_wds_list(list) == FAIL) {
        return FAIL;
    }
    list_for_each_device(p,i,list) {
        if (strcmp(p->role,"ap") != 0) {
            instant = spctrm_scn_common_mac_2_nodeadd(p->mac);
            SPCTRM_SCN_DBG_FILE("\nsend to mac %x",p->mac);
            spctrm_scn_tipc_send(instant,SERVER_TYPE_SCAN,sizeof(g_input),(char *)&g_input);

        }
    }
    return SUCCESS;
}

int spctrm_scn_tipc_send_get_msg(struct device_list *dst_list,int wait_sec)
{
    struct device_info *p;
    __u32 instant;
    int i;
    char msg[19] = "client get message";

    if (dst_list == NULL) {
        return FAIL;
    }

    list_for_each_device(p,i,dst_list) {
        if (strcmp(p->role,"ap") != 0 && p->finished_flag != FINISHED ) {
            instant = spctrm_scn_common_mac_2_nodeadd(p->mac);
            SPCTRM_SCN_DBG_FILE("\nline : %d fun : %s instant : %x \r\n",__LINE__,__func__,instant);
            spctrm_scn_tipc_send(instant,SERVER_TYPE_GET,sizeof(msg),msg);
        }
    }

    for (i = 0;i < 3;i++) {
        sleep(1);
        if (spctrm_scn_dev_chk_stat(&g_device_list) == SUCCESS) {
            return SUCCESS;
        }
    }
    return FAIL;
}

int spctrm_scn_tipc_send_auto_get_msg(struct device_list *dst_list,int wait_sec)
{
    struct device_info *p;
    __u32 instant;
    int i;
    char msg[19] = "client get message";

    if (dst_list == NULL) {
        return FAIL;
    }

    list_for_each_device(p,i,dst_list) {
        if (strcmp(p->role,"ap") != 0 && p->finished_flag != FINISHED ) {
            instant = spctrm_scn_common_mac_2_nodeadd(p->mac);
            SPCTRM_SCN_DBG_FILE("\nline : %d fun : %s instant : %x \r\n",__LINE__,__func__,instant);
            spctrm_scn_tipc_send(instant,SERVER_TYPE_AUTO_GET,sizeof(msg),msg);
        }
    }

    for (i = 0;i < wait_sec;i++) {
        sleep(1);
        if (spctrm_scn_dev_chk_stat(&g_device_list) == SUCCESS) {
            return SUCCESS;
        }
    }

    return FAIL;
}

int spctrm_scn_tipc_send(__u32 dst_instance,__u32 type,size_t payload_size,char *payload)
{
    int sd;
    struct sockaddr_tipc server_addr;
    struct timeval timeout={4,0};
    __u32 src_instant = 0;
    char mac[20];
    char *pkt;
    tipc_recv_packet_head_t *head;
    size_t pkt_size;
    int j;
    struct port_status_list port_list;
    char ipaddr[IP_ADDR_LEN];
    struct port_status_list_elem *elem;

    if (payload == NULL) {
        return FAIL;
    }

    pkt_size = sizeof(tipc_recv_packet_head_t) + payload_size;
    pkt = (char*)malloc(pkt_size * sizeof(char));
    if (pkt == NULL) {
        SPCTRM_SCN_DBG_FILE("\nFAIL");
        return FAIL;
    }
    memset(mac,0,sizeof(mac));
    spctrm_scn_common_read_file("/proc/rg_sys/sys_mac",mac,sizeof(mac) - 1);
    src_instant = spctrm_scn_common_mac_2_nodeadd(mac);

    memcpy(pkt+sizeof(tipc_recv_packet_head_t),payload,payload_size);
    head = (tipc_recv_packet_head_t *)pkt;

    head->instant = src_instant;
    head->type = type;
    head->payload_size = payload_size;
    head->timestamp = g_current_time;
    spctrm_scn_wireless_port_status_init(&port_list);
    spctrm_scn_common_uci_anonymous_get("sysinfo", "sysinfo", "sysinfo", "wan_ip", ipaddr,IP_ADDR_LEN);
    SPCTRM_SCN_DBG_FILE("ipaddr %s\r\n",ipaddr);
#ifdef PORT_STATUS_FILTER_ENABLE
    elem = spctrm_scn_wireless_find_uplink_port(&port_list,ipaddr);
    SPCTRM_SCN_DBG_FILE("port_list.list[index] %s\r\n",elem->ipaddr);

    head->port_speed = elem->speed;
    head->port_status = elem->status;
    
    spctrm_scn_wireless_delete_port_status_list(&port_list);
#endif
    sd = socket(AF_TIPC, SOCK_RDM, 0);
    if (sd < 0) {
        SPCTRM_SCN_DBG_FILE("\nFAIL");
        free(pkt);
        return FAIL;
    }
    server_addr.family = AF_TIPC;
    server_addr.addrtype = TIPC_ADDR_NAME;
    server_addr.addr.name.name.type = SERVER_TYPE;
    server_addr.addr.name.name.instance = ntohl(dst_instance);
    server_addr.addr.name.domain = 0;

    setsockopt(sd,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(struct timeval));

    if (0 > sendto(sd, pkt, pkt_size, 0,
                    (struct sockaddr*)&server_addr, sizeof(server_addr))) {
        perror("Client: failed to send");
        free(pkt);
        close(sd);
        return FAIL;
    }
    free(pkt);
    close(sd);
    return SUCCESS;
}

void *spctrm_scn_tipc_thread()
{

    struct sockaddr_tipc server_addr;
    struct sockaddr_tipc client_addr;
    socklen_t alen = sizeof(client_addr);
    int sd;
    char *pkt;
    tipc_recv_packet_head_t head;
    size_t pkt_size;
    struct timeval timeout={4,0};
    unsigned char mac[20];
    __u32 instant;

    SPCTRM_SCN_DBG_FILE("\n****** TIPC server program started ******\n\n");

    sem_init(&receive_finish_semaphore,0,0);

    memset(mac,0,sizeof(mac));
    spctrm_scn_common_read_file("/proc/rg_sys/sys_mac",mac,sizeof(mac) - 1);

    instant = spctrm_scn_common_mac_2_nodeadd(mac);

    server_addr.family = AF_TIPC;
    server_addr.addrtype = TIPC_ADDR_NAMESEQ;
    server_addr.addr.nameseq.type = SERVER_TYPE;
    server_addr.addr.nameseq.lower = ntohl(instant);
    server_addr.addr.nameseq.upper = ntohl(instant);
    server_addr.scope = TIPC_ZONE_SCOPE;

    sd = socket(AF_TIPC, SOCK_RDM, 0);
    if (sd < 0) {
        return NULL;
    }

    if (0 != bind(sd, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
        SPCTRM_SCN_DBG_FILE("\nServer: failed to bind port name\n");
        close(sd);
        return NULL;
    }

    while (1) {
        pkt = NULL;
        memset(&head, 0, sizeof(head));
        if (0 >= recvfrom(sd, &head, sizeof(head), MSG_PEEK,
                        (struct sockaddr *)&client_addr, &alen)) {
            perror("Server: unexpected message");
            goto clear;
        }
        SPCTRM_SCN_DBG_FILE("\ntype %d",head.type);
        pkt_size = head.payload_size + sizeof(head);
        SPCTRM_SCN_DBG_FILE("\npkt_size %d",pkt_size);
        pkt = (char *)malloc(sizeof(char) * pkt_size);
        if (pkt == NULL) {
            SPCTRM_SCN_DBG_FILE("\nmalloc FAIL");
            goto clear;
        }
        SPCTRM_SCN_DBG_FILE("\nmalloc");
        if (0 >= recvfrom(sd, pkt,pkt_size, 0,
                        (struct sockaddr *)&client_addr, &alen)) {
            perror("Server: unexpected message");
            free(pkt);
            goto clear;
        }
        SPCTRM_SCN_DBG_FILE("\n");
        if (head.type == SERVER_TYPE_GET) {
            SPCTRM_SCN_DBG_FILE("\nSERVER_TYPE_GET_REPLY,%d",realtime_channel_info_5g[0].floornoise);
            SPCTRM_SCN_DBG_FILE("\ng_channel_info_5g %d\r\n",g_channel_info_5g[0].floornoise);
            SPCTRM_SCN_DBG_FILE("\ng_status %d",g_status);
            if (g_status == SCAN_BUSY) {
                SPCTRM_SCN_DBG_FILE("\nrealtime_channel_info_5g[0].channel %d\r\n",realtime_channel_info_5g[0].channel);
                SPCTRM_SCN_DBG_FILE("\nrealtime_channel_info_5g[0].floornoise %d\r\n",realtime_channel_info_5g[0].floornoise);
                spctrm_scn_tipc_send(head.instant,SERVER_TYPE_GET_REPLY,sizeof(realtime_channel_info_5g),(char *)realtime_channel_info_5g);
            } else {
                SPCTRM_SCN_DBG_FILE("\ng_channel_info_5g %d\r\n",g_channel_info_5g[0].floornoise);
                spctrm_scn_tipc_send(head.instant,SERVER_TYPE_GET_REPLY,sizeof(g_channel_info_5g),(char *)g_channel_info_5g);
            }
        } else if (head.type == SERVER_TYPE_GET_REPLY) {
            SPCTRM_SCN_DBG_FILE("\nSERVER_TYPE_GET_REPLY %x",head.instant);
            
            if (sizeof(time_t) > 4) {
                SPCTRM_SCN_DBG_FILE("\nSERVER_TYPE_GET_REPLY TIME %lld\r\n",head.timestamp);
                SPCTRM_SCN_DBG_FILE("\ncurrent TIME %lld\r\n",g_current_time);
            } else {
                SPCTRM_SCN_DBG_FILE("\nSERVER_TYPE_GET_REPLY TIME %ld\r\n",head.timestamp);
                SPCTRM_SCN_DBG_FILE("\ncurrent TIME %ld\r\n",g_current_time);
            }
            
            if (head.timestamp == g_current_time) {
                server_type_scan_reply_cb(&head,pkt);
            }
        } else if (head.type == SERVER_TYPE_AUTO_GET) {
            SPCTRM_SCN_DBG_FILE("\nAUTO GET %x",head.instant);
            if (g_status == SCAN_IDLE) {
                spctrm_scn_tipc_send(head.instant,SERVER_TYPE_GET_REPLY,sizeof(g_channel_info_5g),(char *)g_channel_info_5g);
            }
        } else if (head.type == SERVER_TYPE_SCAN) {
            g_ap_instant = head.instant;
            g_current_time = head.timestamp;
            SPCTRM_SCN_DBG_FILE("\nSERVER_TYPE_SCAN");
            while (1) {
                SPCTRM_SCN_DBG_FILE("\ng_status %d",g_status);
                if (g_status == SCAN_IDLE || g_status == SCAN_NOT_START) {
                    pthread_mutex_lock(&g_mutex);
                    memset(realtime_channel_info_5g,0,sizeof(realtime_channel_info_5g));
                    memcpy(&g_input,(pkt+sizeof(tipc_recv_packet_head_t)),sizeof(g_input));
                    SPCTRM_SCN_DBG_FILE("\n%llu",g_input.channel_bitmap);
                    g_status = SCAN_BUSY;
                    pthread_mutex_unlock(&g_mutex);
                    sem_post(&g_semaphore);
                    break;
                } else if (g_status == SCAN_BUSY) {
                    pthread_mutex_lock(&g_mutex);
                    g_status = SCAN_TIMEOUT;
                    pthread_mutex_unlock(&g_mutex);
                }
            }
            sem_post(&receive_finish_semaphore);
        }
    SPCTRM_SCN_DBG_FILE("\nfree");
    free(pkt);
    continue;
clear:
    (void)recvfrom(sd, &head, sizeof(head),0,(struct sockaddr *)&client_addr, &alen);

    }
    close(sd);
    return NULL;
}

static void server_type_scan_reply_cb(tipc_recv_packet_head_t *head,char *pkt)
{
    struct device_info *p;
    int i;
    __u32 instant = 0;

    if (head == NULL || pkt == NULL) {
        return;
    }

    SPCTRM_SCN_DBG_FILE("\nlist len %d",g_finished_device_list.list_len);
    pthread_mutex_lock(&g_finished_device_list_mutex);
    list_for_each_device(p,i,&g_device_list) {
        if (p->finished_flag != FINISHED) {
            instant = spctrm_scn_common_mac_2_nodeadd(p->mac);
            SPCTRM_SCN_DBG_FILE("\ninstant : %x ",instant);
            if (instant == head->instant) {
                memcpy(p->channel_info,pkt+sizeof(tipc_recv_packet_head_t),head->payload_size);
                p->finished_flag = FINISHED;
                p->port_speed = head->port_speed;
                p->port_status = head->port_status;
                SPCTRM_SCN_DBG_FILE("\np->finished_flag %d",p->finished_flag);
                SPCTRM_SCN_DBG_FILE("\np->channel_info[0].channel %d",p->channel_info[0].channel);
                SPCTRM_SCN_DBG_FILE("\np->channel_info[0].floornoise %d",p->channel_info[0].floornoise);
            }
        }
    }
    /* update g_finish_device_list */
    memcpy(&g_finished_device_list,&g_device_list,sizeof(struct device_list));
    pthread_mutex_unlock(&g_finished_device_list_mutex);

    /* upload to MACC */
    pthread_mutex_lock(&g_dev_cmd_mutex);
    system("dev_sta get -m spectrumScan");
    pthread_mutex_unlock(&g_dev_cmd_mutex);

}