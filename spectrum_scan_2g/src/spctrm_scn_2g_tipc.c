
#include "spctrm_scn_2g_tipc.h"

__u32 g_spctrm_scn_2g_ap_instant;
extern int8_t g_spctrm_scn_2g_status;
struct uloop_fd c_fd; 
struct sockaddr_tipc server_addr;
struct sockaddr_tipc client_addr;
extern struct spctrm_scn_2g_device_list g_spctrm_scn_2g_device_list;
extern char g_5g_ext_ifname[IFNAMSIZ];
extern char g_2g_ext_ifname[IFNAMSIZ];
extern char g_apcli_ifname[IFNAMSIZ];
extern void spctrm_scn_2g_ubus_task();
int spctrm_scn_2g_tipc_send(__u32 dst_instance,__u32 type,size_t payload_size,char *payload)
{
    int sd;
    struct sockaddr_tipc server_addr;
    struct timeval timeout={4,0};
    __u32 src_instant = 0;
    char mac[20];
    char *pkt;
    spctrm_scn_2g_tipc_recv_packet_head_t *head;
    size_t pkt_size;
    int j;
    
    if (payload == NULL) {
        return FAIL;
    } 
    
    pkt_size = sizeof(spctrm_scn_2g_tipc_recv_packet_head_t) + payload_size;
    SPCTRM_SCN_INFO("pkt_size %d",pkt_size);
    pkt = (char*)malloc(pkt_size * sizeof(char));
    if (pkt == NULL) {
        SPCTRM_SCN_ERR("error\r\n");
        return FAIL;
    }
    memset(mac,0,sizeof(mac));
    spctrm_scn_2g_common_read_file("/proc/rg_sys/sys_mac",mac,sizeof(mac) - 1);
    if (spctrm_scn_2g_common_mac_2_nodeadd(mac,&src_instant)) {
        free(pkt);
        return FAIL;
    }
    SPCTRM_SCN_INFO("src_instant %x \r\n",src_instant);
    SPCTRM_SCN_INFO("payload_size %d \r\n",payload_size);
    memcpy(pkt+sizeof(spctrm_scn_2g_tipc_recv_packet_head_t),payload,payload_size);
    head = (spctrm_scn_2g_tipc_recv_packet_head_t *)pkt;
    

    head->instant = src_instant;
    head->type = type;
    head->payload_size = payload_size;

    sd = socket(AF_TIPC, SOCK_RDM, 0);
    if (sd < 0) {
        SPCTRM_SCN_ERR("error\r\n");
        free(pkt);
        return FAIL;
    }

    server_addr.family = AF_TIPC;
    server_addr.addrtype = TIPC_ADDR_NAME;
    server_addr.addr.name.name.type = SPCTRM_SCN_2G_SERVER_TYPE;
    server_addr.addr.name.name.instance = ntohl(dst_instance);
    server_addr.addr.name.domain = 0;
    
    setsockopt(sd,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(struct timeval));
    SPCTRM_SCN_INFO("tipc send \r\n");
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

int spctrm_scn_2g_tipc_send_recv(__u32 dst_instance,__u32 type,
                            size_t payload_size,char *payload,char*rbuf)
{
    int sd;
    struct sockaddr_tipc server_addr;
    struct timeval timeout={1,0};
    __u32 src_instant = 0;
    char mac[20];
    char *pkt;
    spctrm_scn_2g_tipc_recv_packet_head_t *head;
    size_t pkt_size;
    struct spctrm_scn_2g_device_info *p;
    int j;
    p = payload;

    SPCTRM_SCN_DBG("cpe send floornoise %d\r\n",p->bw20_channel_info[1].floornoise);
    
    if (payload == NULL || rbuf == NULL) {
        SPCTRM_SCN_DBG("FAIL\r\n");
        return FAIL;
    } 
    
    pkt_size = sizeof(spctrm_scn_2g_tipc_recv_packet_head_t) + payload_size;
    SPCTRM_SCN_DBG("pkt_size %d\r\n",pkt_size);
    pkt = (char*)malloc(pkt_size * sizeof(char));
    if (pkt == NULL) {
        SPCTRM_SCN_DBG("FAIL\r\n");
        return FAIL;
    }
    memset(mac,0,sizeof(mac));
    spctrm_scn_2g_common_read_file("/proc/rg_sys/sys_mac",mac,sizeof(mac) - 1);
    if (spctrm_scn_2g_common_mac_2_nodeadd(mac,&src_instant)) {
        return FAIL;
    }
    SPCTRM_SCN_DBG("src_instant %x\r\n",src_instant);
    SPCTRM_SCN_DBG("payload_size %d\r\n",payload_size);
    memcpy(pkt+sizeof(spctrm_scn_2g_tipc_recv_packet_head_t),payload,payload_size);
    head = (spctrm_scn_2g_tipc_recv_packet_head_t *)pkt;
    

    head->instant = src_instant;
    head->type = type;
    head->payload_size = payload_size;

    sd = socket(AF_TIPC, SOCK_RDM, 0);
    if (sd < 0) {
        SPCTRM_SCN_DBG("FAIL\r\n");
        free(pkt);
        return FAIL;
    }

    server_addr.family = AF_TIPC;
    server_addr.addrtype = TIPC_ADDR_NAME;
    server_addr.addr.name.name.type = SPCTRM_SCN_2G_SERVER_TYPE;
    server_addr.addr.name.name.instance = ntohl(dst_instance);
    server_addr.addr.name.domain = 0;

    setsockopt(sd,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(struct timeval));
    if (0 > sendto(sd, pkt, pkt_size, 0,
                    (struct sockaddr*)&server_addr, sizeof(server_addr))) {
        perror("Client: failed to send");
        free(pkt);
        close(sd);
        return FAIL;
    }
    if (recv(sd,pkt,sizeof(spctrm_scn_2g_tipc_recv_packet_head_t),0) < 0) {
        SPCTRM_SCN_WARN("Client: failed to recv\r\n");
        perror("Client: failed to recv");
        free(pkt);
        close(sd);       
        return FAIL;
    }

    free(pkt);
    close(sd);

    return SUCCESS;
}

int spctrm_scn_2g_tipc_protocal_scan_ack_cb(spctrm_scn_2g_tipc_recv_packet_head_t *head,char *pkt) 
{
    struct spctrm_scn_2g_device_info *p;
    int i;
    __u32 instant;
    spctrm_scn_2g_tipc_scan_ack_pkt_t *ack_buf_p;

    ack_buf_p = pkt + sizeof(spctrm_scn_2g_tipc_recv_packet_head_t);
    instant = 0;
    list_for_each_device(p,i,&g_spctrm_scn_2g_device_list) {
        
        if (spctrm_scn_2g_common_mac_2_nodeadd(p->mac,&instant) == FAIL) {
            SPCTRM_SCN_ERR("error\r\n");
            return FAIL;
        }
        if (instant == head->instant) {
            SPCTRM_SCN_DBG("cpe [%s] band support %d\r\n",p->series_no,ack_buf_p->band_support);
            SPCTRM_SCN_DBG("receive ack\r\n");
            p->band_support = ack_buf_p->band_support;
            p->finished_flag = FINISHED;
            return;
        }
    }
}

int spctrm_scn_2g_tipc_protocal_scan_cb(spctrm_scn_2g_tipc_recv_packet_head_t *head,char *pkt) 
{
    void *table,*dev_model_obj;
    struct spctrm_scn_2g_ubus_set_request *hreq;
    int i;
    struct spctrm_scn_2g_tipc_scan_ack_pkt ack_buf;
    
    hreq = malloc(sizeof(struct spctrm_scn_2g_ubus_set_request));
    if (hreq == NULL) {
        return FAIL;
    }
    /* convert spctrm_scn tipc packet to spctrm_scn_2g_ubus_set_request hreq */
    memcpy(hreq,pkt + sizeof(spctrm_scn_2g_tipc_recv_packet_head_t),sizeof(struct spctrm_scn_2g_ubus_set_request));
    SPCTRM_SCN_DBG("bw20 channel bitmap\r\n");
    spctrm_scn_2g_wireless_show_channel_bitmap(hreq->channel_bitmap[0]);
    SPCTRM_SCN_DBG("bw40 channel bitmap\r\n");
    spctrm_scn_2g_wireless_show_channel_bitmap(hreq->channel_bitmap[1]);
    SPCTRM_SCN_DBG("bw80 channel bitmap\r\n");
    spctrm_scn_2g_wireless_show_channel_bitmap(hreq->channel_bitmap[2]);
    SPCTRM_SCN_DBG("%d",hreq->scan_time);
    g_spctrm_scn_2g_ap_instant = head->instant;

    /* cpe send ack message */
    ack_buf.band_support = g_band_support;
    spctrm_scn_2g_tipc_send(head->instant,PROTOCAL_TYPE_SCAN_ACK,sizeof(ack_buf),&ack_buf);
    hreq->timeout.cb = spctrm_scn_2g_wireless_scan_task;

    spctrm_scn_2g_wireless_change_bw(_20MHZ,hreq->band); 
    SPCTRM_SCN_INFO("change to bw %d\r\n",_20MHZ);

    SPCTRM_SCN_INFO("apcli interface down\r\n");
    spctrm_scn_2g_common_iwpriv_set(g_apcli_ifname,"ApCliEnable=0",strlen("ApCliEnable=0")+1);

    uloop_timeout_set(&hreq->timeout,1000);
    return SUCCESS;

}

void spctrm_scn_2g_tipc_recv_cb(struct uloop_fd *sock, unsigned int events) {
	spctrm_scn_2g_tipc_recv_packet_head_t head;
	size_t pkt_size;
    __u32 instant;
    spctrm_scn_2g_tipc_recv_packet_head_t sender_head;
    struct spctrm_scn_2g_device_info *p;
    int i;
	socklen_t alen = sizeof(client_addr);
	struct timeval timeout={4,0};
	char *pkt;
    instant = 0;

    pkt = NULL;
    memset(&head, 0, sizeof(head));
    SPCTRM_SCN_INFO("TIPC\r\n");
    if (0 >= recvfrom(sock->fd, &head, sizeof(head), MSG_PEEK,
                    (struct sockaddr *)&client_addr, &alen)) {
        perror("Server: unexpected message");
        goto clear;
    }
    SPCTRM_SCN_INFO("type %d\r\n",head.type);
    pkt_size = head.payload_size + sizeof(head);
    SPCTRM_SCN_INFO("pkt_size %d\r\n",pkt_size);
    pkt = (char *)malloc(sizeof(char) * pkt_size);
    if (pkt == NULL) {
        SPCTRM_SCN_DBG("malloc FAIL");
        goto clear;
    }
    SPCTRM_SCN_INFO("malloc\r\n");
    if (0 >= recvfrom(sock->fd, pkt,pkt_size, 0,
                    (struct sockaddr *)&client_addr, &alen)) {
        perror("Server: unexpected message");
        free(pkt);
        goto clear;
    }

    switch (head.type) {
    case PROTOCAL_TYPE_SCAN:
        SPCTRM_SCN_INFO("TYPE_SCAN\r\n");
        SPCTRM_SCN_INFO("status %d\r\n",g_spctrm_scn_2g_status);
        if (g_spctrm_scn_2g_status != SPCTRM_SCN_2G_SCAN_BUSY) {
            g_spctrm_scn_2g_status = SPCTRM_SCN_2G_SCAN_BUSY;
            spctrm_scn_2g_tipc_protocal_scan_cb(&head,pkt);
        }
        break;
    case PROTOCAL_TYPE_CPE_REPORT:
        list_for_each_device(p,i,&g_spctrm_scn_2g_device_list) {
            SPCTRM_SCN_DBG("pre p->series_no %s\r\n",p->series_no);
            SPCTRM_SCN_DBG("pre p->role %s\r\n",p->role);
            SPCTRM_SCN_DBG("pre p->finished_flag %d\r\n",p->finished_flag);
            spctrm_scn_2g_common_mac_2_nodeadd(p->mac,&instant);
            if (instant == head.instant) {
                memcpy(p,pkt+sizeof(head),sizeof(struct spctrm_scn_2g_device_info));
                p->finished_flag = FINISHED;
            }
            SPCTRM_SCN_DBG("now p->series_no %s\r\n",p->series_no);
            SPCTRM_SCN_DBG("now p->finished_flag %d\r\n",p->finished_flag);
        }

        SPCTRM_SCN_INFO("ap receive cpe PROTOCAL_TYPE_CPE_REPORT\r\n");
        sender_head.instant = g_spctrm_scn_2g_ap_instant;
        sender_head.type = PROTOCAL_TYPE_CPE_REPORT_ACK;
        sender_head.payload_size = 0;
        if (0 > sendto(sock->fd,&sender_head,sizeof(sender_head), 0,
                    (struct sockaddr*)&client_addr, sizeof(client_addr))) {
            perror("Client: failed to send");
            free(pkt);
            close(sock->fd);
            return FAIL;
        }  
        break;
    case PROTOCAL_TYPE_SCAN_ACK:
        SPCTRM_SCN_INFO("TYPE_SCAN_ACK\r\n");   
        spctrm_scn_2g_tipc_protocal_scan_ack_cb(&head,pkt);
        break;
    default:
        SPCTRM_SCN_INFO("other tipc msg\r\n"); 
        if (g_spctrm_scn_2g_mode == AP_MODE) {
            spctrm_scn_2g_ubus_send_notify(head.type,pkt+sizeof(spctrm_scn_2g_tipc_recv_packet_head_t));
        }
        break;
    }

    
    SPCTRM_SCN_INFO("free\r\n");
    free(pkt);
    return;

clear: 
    (void)recvfrom(sock->fd, &head, sizeof(head),0,(struct sockaddr *)&client_addr, &alen);    
}

void spctrm_scn_2g_tipc_task()
{
	unsigned char mac[20];
	__u32 instant;
    instant = 0; 

    memset(mac,0,sizeof(mac));
    spctrm_scn_2g_common_read_file("/proc/rg_sys/sys_mac",mac,sizeof(mac) - 1);

    if (spctrm_scn_2g_common_mac_2_nodeadd(mac,&instant) == FAIL) {
        return FAIL;
    }
    SPCTRM_SCN_DBG("instant %x\r\n",instant);
	server_addr.family = AF_TIPC;
	server_addr.addrtype = TIPC_ADDR_NAMESEQ;
	server_addr.addr.nameseq.type = SPCTRM_SCN_2G_SERVER_TYPE;
	server_addr.addr.nameseq.lower = ntohl(instant);
	server_addr.addr.nameseq.upper = ntohl(instant);
	server_addr.scope = TIPC_ZONE_SCOPE;

	c_fd.fd = socket(AF_TIPC, SOCK_RDM, 0);
    if (c_fd.fd < 0) {
        SPCTRM_SCN_ERR("socket create fail\r\n");
        exit(1);
    }
	if (0 != bind(c_fd.fd, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
		printf("Server: failed to bind port name\n");
		exit(1);
	}
	c_fd.cb = spctrm_scn_2g_tipc_recv_cb;
	uloop_fd_add(&c_fd,ULOOP_READ);	
}

void tipc_close() 
{
    close(c_fd.fd);
}