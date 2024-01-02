#include "spctrm_scn_2g_common.h"

int spctrm_scn_2g_common_iwpriv_set(char *ifname,char *data,size_t data_size)
{
    int socket_id;
    struct iwreq wreq;
    int ret;
    char data_buf[255];

    if (ifname == NULL || data == NULL) {
        return FAIL;
    }
    memset(data_buf,0,sizeof(data));
    memset(&wreq,0,sizeof(struct iwreq));

    socket_id = socket(AF_INET,SOCK_DGRAM,0);
    if (socket_id < 0) {
        return FAIL;
    }
    strcpy(data_buf,data);
    strcpy(wreq.ifr_ifrn.ifrn_name,ifname);
    debug("wreq.ifr_ifrn.ifrn_name %s\r\n",wreq.ifr_ifrn.ifrn_name);

    wreq.u.data.pointer = data_buf;
    wreq.u.data.length = data_size;
    wreq.u.data.flags = 0;
    ret = ioctl(socket_id,RTPRIV_IOCTL_SET,&wreq);
    if (ret != 0) {
        close(socket_id);
        return FAIL;
    }
    close(socket_id);
    return SUCCESS;
}

#define HEAD_LEN (4 + 3 + 1) /* "0000│ " */
#define HEX_LEN (16 * 3 + 1)
#define SPACE_LEN (3 + 1) /* "│ " */

unsigned char *phrase_line(unsigned int num, unsigned char *src, unsigned int len)
{
    int i = 0;
    static unsigned char dst[128];

    if (src == NULL) {
        return NULL;
    }

    memset(dst, 0x0, sizeof(dst));

    if(0 == len) {
        return dst;
    }
    sprintf(dst, "%04X│ ", num);

    for(i = 0; i < len; i++) {
        sprintf(dst + HEAD_LEN + i * 3 + (i >= 8 ? 1 : 0), "%02X ", src[i]);
        dst[HEAD_LEN + HEX_LEN + SPACE_LEN + i + (i >= 8 ? 1 : 0)] = (src[i] >= 0x20 && src[i] <= 0x7E) ? src[i] : '.';
    }

    dst[HEAD_LEN + 8 * 3] = ' ';
    memcpy(dst + HEAD_LEN + HEX_LEN, "│ ", SPACE_LEN);
    for(i = HEAD_LEN + len * 3 + (len > 8 ? 1 : 0); i < HEAD_LEN + HEX_LEN; i++) {
        dst[i] = ' ';
    }
    dst[HEAD_LEN + HEX_LEN + SPACE_LEN + 8] = ' ';
    return dst;
}

void spctrm_scn_2g_common_dump_packet(unsigned char *src, unsigned int len)
{
    int i = 0, tmpLen = 0;

    if (src == NULL) {
        return;
    }

    while(i < len) {
        tmpLen = 16;
        if(i + 16 > len) {
            tmpLen = len - i;
        }
        printf("%s\n", phrase_line(i, src + i, tmpLen));
        i += tmpLen;
    }

    return;
}


int spctrm_scn_2g_common_mac_2_nodeadd(unsigned char *mac_src,__u32 *instant)
{
    unsigned int mac[ETH_ALEN];
    unsigned int tmp;
    char buf[30];

    if (mac_src == NULL) {
        return FAIL;
    }

    memset(mac,0,sizeof(mac));
    if (sscanf(mac_src, "%2x:%2x:%2x:%2x:%2x:%2x",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]) != 6) {
        perror("please input right like :rg_tipc_mac_to_nodeadd aa:bb:cc:dd:ee:ffi \n");
        return FAIL;
    }

    tmp = (mac[0] ^ mac[1] ^ mac[2]) & 0xff;
    tmp = (tmp & 0x0f) ^ (tmp >> 4);

    memset(buf,0,sizeof(buf));
    sprintf(buf,"%x%02x%02x%02x",tmp,mac[3],mac[4],mac[5]);

    tmp = 0;
    sscanf(buf,"%x",&tmp);
    *instant = tmp;

    return SUCCESS;
}

char spctrm_scn_2g_common_read_file(char *name,char *buf,int len) {
    int fd;

    if (name == NULL || buf == NULL ) {
        return FAIL;
    }

    memset(buf,0,len);
    fd = open(name, O_RDONLY);
    if (fd > 0) {
        read(fd,buf,len);
        close(fd);
        if (buf[strlen(buf) - 1] == '\n') {
            buf[strlen(buf) - 1] = 0;
        }
        return SUCCESS;
    }
    return FAIL;
}

int spctrm_scn_2g_common_cmd(char *cmd,char **rbuf)
{
    FILE *fp;

    if (cmd == NULL) {
        return FAIL;
    }

    fp = popen(cmd, "r");
    if (fp == NULL) {
        return FAIL;
    }

    if (rbuf == NULL) {
        pclose(fp);
        return SUCCESS;
    }
    *rbuf =(char *) malloc(POPEN_BUFFER_MAX_SIZE);
    if (rbuf == NULL) {
        pclose(fp);
        return FAIL;
    }


    fread(*rbuf,sizeof(char),POPEN_BUFFER_MAX_SIZE,fp);
    pclose(fp);
    return SUCCESS;
}
void spctrm_scn_2g_common_get_sn(char *sn)
{
    int ret;
    char res[SN_LEN];

    if (sn == NULL) {
        return ;
    }

    memset(res, 0, SN_LEN);
    ret = spctrm_scn_2g_common_uci_anonymous_get("sysinfo", "sysinfo", "sysinfo", "serial_num", res, sizeof(res));
    if (ret != 0) {
        return;
    }


    strncpy(sn, res, SN_LEN);
    return;
}
int spctrm_scn_2g_common_uci_anonymous_get(char *file, char *type, char *name, char *option, char *buf, int len)
{
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *sec = NULL;
    struct uci_element *ele = NULL;
    const char *str = NULL;
    char ret = FAIL;

    if (file == NULL) {
        return FAIL;
    }
    if (type == NULL) {
        return FAIL;
    }
    if (name == NULL) {
        return FAIL;
    }
    if (option == NULL) {
        return FAIL;
    }
    if (buf == NULL) {
        return FAIL;
    }
    if (len <= 0) {
        return FAIL;
    }

    ctx = uci_alloc_context();
    if (ctx == NULL) {
        return FAIL;
    }

    if (UCI_OK != uci_load(ctx, file, &pkg)) {
        ret = FAIL;
        goto cleanup;
    }


    uci_foreach_element(&pkg->sections, ele) {
        sec = uci_to_section(ele);
        if (strcmp(sec->type, name) != 0) {
            continue;
        }
        str = uci_lookup_option_string(ctx, sec, option);
        if (str != NULL) {
            strncpy(buf, str, len);
            ret = SUCCESS;
            break;
        }
    }

    uci_unload(ctx, pkg);

cleanup:
    uci_free_context(ctx);
    ctx = NULL;

    return ret;
}
