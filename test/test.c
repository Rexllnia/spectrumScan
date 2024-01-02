#include <json-c/json.h>  
#include <string.h>
#include <libubox/blobmsg_json.h>
#include "uf_plugin_intf.h"  
#include "libubus.h"
#include <libubox/blobmsg_json.h>
#include <unistd.h>
#include <fcntl.h>
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/tipc.h>
#include<sys/resource.h>
#define SERVER_TYPE  18888
#define SERVER_INST  17
#define BUF_SIZE 40

#define SUCCESS 0
#define FAIL    -1

// // #include "wds_sdk.h"

// char g_spctrm_scn_ubus_rbuf[4096];
// enum {
//          HELLO_ID,
//          HELLO_MSG,
//         __HELLO_MAX
// };
 
//  static const struct blobmsg_policy hello_policy[] = {
//         [HELLO_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
//         [HELLO_MSG] = { .name = "msg", .type = BLOBMSG_TYPE_STRING },
// };
// struct hello_request {
//          struct ubus_request_data req;
//         struct uloop_timeout timeout;
//         int fd;
//         int idx;
// } ;
// // static struct {
// //     const char *module;
// //     uf_call_type_t ctype;
// //     const char *cmd;
// //     const char *param;
// // } *test_get_proc, test_proc[] = {
// //     {"wds_password",UF_DEV_STA_CALL,"get", NULL},
// //     {"wds_password",UF_DEV_STA_CALL,"get", NULL},
// //     {"wds_password",UF_DEV_STA_CALL,"get", NULL},
// //     {"wds_password",UF_DEV_STA_CALL,"get", NULL},
// //     {"wds_password",UF_DEV_STA_CALL,"get", NULL},
// //     {NULL,}
// // };

// // int test_unifyframework()
// // {
// //     char *rbuf;
// //     char sn[SN_LEN];
// //     int i,j,find_flag,ret;
// //     uf_cmd_msg_t *msg_obj;
    
// //     for (i = 0;i < 20;i++) {
// //         msg_obj = (uf_cmd_msg_t*)malloc(sizeof(uf_cmd_msg_t));
// //         if (msg_obj == NULL) {
// //             return FAIL;
// //         }
// //         memset(msg_obj, 0, sizeof(uf_cmd_msg_t));

// //         msg_obj->ctype = UF_DEV_STA_CALL;    /* 调用类型 ac/dev/.. */
// //         msg_obj->cmd = "get";
// //         msg_obj->module = "wds_list_all";               /* 必填参数，其它可选参数根据需要使用 */
// //         msg_obj->caller = "group_change";       /* 自定义字符串，标记调用者 */
// //         ret = uf_client_call(msg_obj, &rbuf, NULL);
// //         if (ret == FAIL) {
// //             free(msg_obj);
// //             return FAIL;      
// //         }

// //         if (rbuf != NULL) {
// //             free (rbuf);
// //         }
// //         json_object_put(rbuf_root);
// //         free(msg_obj);
// //     }

// //     return SUCCESS;
// // }

// static int spctrm_scn_ubus_invoke_handle_cb(struct ubus_request *req,int type, struct blob_attr *msg)
// {
//    strcpy(g_spctrm_scn_ubus_rbuf,blobmsg_format_json(msg,true));
// }
// static struct ubus_subscriber test_event;
// static int test_notify(struct ubus_context *ctx, struct ubus_object *obj,
//             struct ubus_request_data *req, const char *method,
//             struct blob_attr *msg)
// {
//     printf("1232323\r\n");
//     return UBUS_STATUS_OK;
// }

// static int test_hello(struct ubus_context *ctx, struct ubus_object *obj,
//                       struct ubus_request_data *req, const char *method,
//                       struct blob_attr *msg)
// {
  
//          return 0;
// }

// static const struct ubus_method test_methods[] = {
//          UBUS_METHOD("hello", test_hello, hello_policy),
// };
// static struct ubus_object_type test_object_type =
//          UBUS_OBJECT_TYPE("test", test_methods);

// static struct ubus_object test_object = {
//         .name = "test",
//         .type = &test_object_type,
//          .methods = test_methods,
//          .n_methods = ARRAY_SIZE(test_methods),
// };
// int main()
// {
    
//     int ret;
//     const char *para_obj;
//     uint32_t id = 0;
//     struct ubus_context *ctx;
//     static struct blob_buf b;

//     printf("qqqqqqqqqqqqq\n");
//     blob_buf_init(&b, 0);
    
//     ctx = ubus_connect(NULL);
//         printf("qqqqqqqqqqqqq\n");

//     ubus_add_uloop(ctx);

//     ret = ubus_add_object(ctx, &test_object);
//     ret = ubus_register_subscriber(ctx, &test_event);
//     if (ret != UBUS_STATUS_OK) {
//         printf("\nerror");
//         return;
//     }
//     test_event.cb = test_notify;

//     if (ubus_lookup_id(ctx, "rlog", &id)) {
//         fprintf(stderr, "Failed to look up rlog object\n");
 
//     } else {
//         ret = ubus_subscribe(ctx, &test_event,id);
//         if (ret != UBUS_STATUS_OK) {
//             printf("error");
//             return;
//         }
//     }

//     uloop_run();
//     ubus_free(ctx);
//     uloop_done();
//     // ubus_invoke(ctx, id, "get", NULL, spctrm_scn_ubus_invoke_handle_cb, 0, 3000);
//     // printf("%s",g_spctrm_scn_ubus_rbuf);
//     // ubus_free(ctx);
     
// }
/*
 * Copyright (C) 2011-2014 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
static struct ubus_context *ctx;
static struct ubus_subscriber test_event;

static int test_notify(struct ubus_context *ctx, struct ubus_object *obj,
            struct ubus_request_data *req, const char *method,
            struct blob_attr *msg)
{
    
    printf("ubus receive notify %s\r\n",blobmsg_format_json(msg,true));
    
    return UBUS_STATUS_OK;
}

struct ubus_event_handler mode_switch_event;
static void server_main(void)
{
    int ret;
    uint32_t id;

    ret = ubus_register_subscriber(ctx, &test_event);
    if (ret != UBUS_STATUS_OK) {
        printf("\nerror");
        return;
    }
    test_event.cb = test_notify;

    if (ubus_lookup_id(ctx, "spctrm_scn_2g", &id)) {
        fprintf(stderr, "Failed to look up rlog object\n");
        printf("\n not support rlog");
    } else {
        ret = ubus_subscribe(ctx, &test_event,id);
        if (ret != UBUS_STATUS_OK) {
            printf("\nerror");
            return;
        }
    }

    uloop_run();
}


void spctrm_scn_ubus_thread()
{
    const char *ubus_socket = NULL;

    uloop_init();
    // signal(SIGPIPE, SIG_IGN);
    printf("\nubus start");
    ctx = ubus_connect(ubus_socket);
    if (!ctx) {
        fprintf(stderr, "Failed to connect to ubus\n");
        return;
    }

    ubus_add_uloop(ctx);
    server_main();

    ubus_free(ctx);
    uloop_done();
    printf("\nubus done");

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
int spctrm_scn_call_lua_module_set(lua_State *lua_state,char *param,char **lua_rbuf)
{
    if (lua_state == NULL || param == NULL) {
        return FAIL;
    }

    lua_getglobal(lua_state,"module_set");
    lua_pushstring(lua_state,param);
    lua_pcall(lua_state,1,1,0);
    *lua_rbuf = malloc(strlen(lua_tostring(lua_state,-1)) + 1);
    memcpy(*lua_rbuf,lua_tostring(lua_state,-1),strlen(lua_tostring(lua_state,-1)) + 1);

    return SUCCESS;

}
int spctrm_scn_call_lua_module_get(lua_State *lua_state,char **lua_rbuf)
{
    if (lua_state == NULL) {
        return FAIL;
    }
    lua_newtable(lua_state);
    lua_pushstring(lua_state,"\"band\":5");

    lua_getglobal(lua_state,"module_get");

    lua_call(lua_state,1,1);
    *lua_rbuf = malloc(strlen(lua_tostring(lua_state,-1)) + 1);
    memcpy(*lua_rbuf,lua_tostring(lua_state,-1),strlen(lua_tostring(lua_state,-1)) + 1);

    return SUCCESS;

}
int lua_test()
{
    lua_State *lua_state;
    char *lua_rbuf;
    int t = 0;

    lua_state = luaL_newstate();
    luaL_openlibs(lua_state);
    luaL_dofile(lua_state,"/root/123.lua");
  

    lua_getglobal(lua_state,"module_set");

    lua_pushstring(lua_state,"{\"band\":5}");

    lua_call(lua_state,1,1);
    printf("%s",lua_tostring(lua_state,-1));

    lua_close(lua_state);    
}



int tipc_test()
{
	struct sockaddr_tipc server_addr;
	struct sockaddr_tipc client_addr;
	socklen_t alen = sizeof(client_addr);
	int sd;
	char inbuf[BUF_SIZE];
	char outbuf[BUF_SIZE] = "Uh ?";
    struct timeval timeout={4,0};
#ifdef CONFIG_TIPC_CORE_DUBUG
    struct rlimit limit;
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &limit);
#endif
	printf("****** TIPC server hello world program started ******\n\n");

	server_addr.family = AF_TIPC;
	server_addr.addrtype = TIPC_ADDR_NAMESEQ;
	server_addr.addr.nameseq.type = SERVER_TYPE;
	server_addr.addr.nameseq.lower = SERVER_INST;
	server_addr.addr.nameseq.upper = SERVER_INST;
	server_addr.scope = TIPC_ZONE_SCOPE;

	sd = socket(AF_TIPC, SOCK_RDM, 0);

	if (0 != bind(sd, (struct sockaddr *)&server_addr, sizeof(server_addr))) {
		printf("Server: failed to bind port name\n");
		exit(1);
	}

	if (0 >= recvfrom(sd, inbuf, sizeof(inbuf), 0,
	                  (struct sockaddr *)&client_addr, &alen)) {
		perror("Server: unexpected message");
	}
	printf("Server: Message received: %s !\n", inbuf);
    setsockopt(sd,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(struct timeval));
	if (0 > sendto(sd, outbuf, strlen(outbuf)+1, 0,
	                (struct sockaddr *)&client_addr, sizeof(client_addr))) {
		perror("Server: failed to send");
	}
	printf("\n****** TIPC server hello program finished ******\n");

	exit(0);
}

int main ()
{

    

    
}