#if defined(SPECTRUM_SCAN_2G) || defined(SPECTRUM_SCAN_5G)
#include <json-c/json.h>  
#include <string.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include "uf_plugin_intf.h"  
#include "libubus.h"
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#define SUCCESS 0
#define FAIL    -1

#define BAND_5G     5
#define BAND_2G     2

/* 
    dev_sta get -m spectrumScan | jq . 
    dev_sta get -m spectrumScan '{"band":2}'
    dev_sta set -m spectrumScan '{"band":5}'
    dev_sta set -m spectrumScan '{"band":2}'
*/
char g_spctrm_scn_ubus_rbuf[4096];
int spctrm_scn_call_lua_module_set(lua_State *spctrm_scn_lua_state,char *spctrm_scn_lua_param,char **spctrm_scn_lua_rbuf)
{
    int len;

    len = 0;
    if (spctrm_scn_lua_state == NULL || spctrm_scn_lua_param == NULL) {
        return FAIL;
    }

    lua_getglobal(spctrm_scn_lua_state,"module_set");
    lua_pushstring(spctrm_scn_lua_state,spctrm_scn_lua_param);
    lua_pcall(spctrm_scn_lua_state,1,1,0);
    len = strlen(lua_tostring(spctrm_scn_lua_state,-1)) + 1;
    *spctrm_scn_lua_rbuf = malloc(len);
    memcpy(*spctrm_scn_lua_rbuf,lua_tostring(spctrm_scn_lua_state,-1),len);

    return SUCCESS;
}

int spctrm_scn_call_lua_module_get(lua_State *spctrm_scn_lua_state,char **spctrm_scn_lua_rbuf)
{
    int len;

    len = 0;
    if (spctrm_scn_lua_state == NULL) {
        return FAIL;
    }

    lua_getglobal(spctrm_scn_lua_state,"module_get");
    lua_pcall(spctrm_scn_lua_state,0,1,0);
    len = strlen(lua_tostring(spctrm_scn_lua_state,-1)) + 1;
    *spctrm_scn_lua_rbuf = malloc(len);
    memcpy(*spctrm_scn_lua_rbuf,lua_tostring(spctrm_scn_lua_state,-1),len);

    return SUCCESS;
}

static int spctrm_scn_ubus_invoke_handle_cb(struct ubus_request *req,int type, struct blob_attr *msg)
{
   strcpy(g_spctrm_scn_ubus_rbuf,blobmsg_format_json(msg,true));
}
static int spctrm_scn_fnc(uf_plugin_attr_t *attr, char **rbuf)
{
    int ret;
    const char *para_obj;
    int id;
    struct ubus_context *ctx;
    static struct blob_buf b;
    char json_string[1024];
    lua_State *spctrm_scn_lua_state;
    char *spctrm_scn_lua_rbuf;
    json_object *root,*band_obj;


    blob_buf_init(&b, 0);

    para_obj = NULL;
    para_obj = json_object_get_string(attr->para_obj);



    switch (attr->cmd) {
    case UF_CMD_ADD:
        /* dev_sta add */
        break;
    case UF_CMD_GET:

        uf_ubus_lock();

#if defined(SPECTRUM_SCAN_2G) && defined(SPECTRUM_SCAN_5G)
        if (para_obj == NULL) {
            goto spectrum_scan_default_handle;
        }
        root = json_tokener_parse(para_obj);
        if (root== NULL) {
            goto spectrum_scan_default_handle;
        }
        band_obj = json_object_object_get(root,"band");
        if (band_obj == NULL) {
            goto spectrum_scan_default_handle;
        }

        if (json_object_get_int(band_obj) == 2) {
#endif

#ifdef SPECTRUM_SCAN_2G 
            ctx = ubus_connect(NULL);
            if (ctx == NULL) {
#if defined(SPECTRUM_SCAN_2G) && defined(SPECTRUM_SCAN_5G)
                json_object_put(root);
#endif
                uf_ubus_unlock(); 
                return FAIL;
            }

            if (ubus_lookup_id(ctx,"spctrm_scn_2g",&id)) {
#if defined(SPECTRUM_SCAN_2G) && defined(SPECTRUM_SCAN_5G)
                json_object_put(root);
#endif
                ubus_free(ctx);
                uf_ubus_unlock(); 
                return FAIL;
            }

            if (ubus_invoke(ctx, id, "get", NULL, spctrm_scn_ubus_invoke_handle_cb, 0, 3000)) {
#if defined(SPECTRUM_SCAN_2G) && defined(SPECTRUM_SCAN_5G)
                json_object_put(root);
#endif
                ubus_free(ctx);
                uf_ubus_unlock();
                return FAIL;
            }

            ubus_free(ctx);
            *rbuf = strdup(g_spctrm_scn_ubus_rbuf);
#endif

#if defined(SPECTRUM_SCAN_2G) && defined(SPECTRUM_SCAN_5G)
        } else {
#endif

#ifdef SPECTRUM_SCAN_5G 
spectrum_scan_default_handle:
            spctrm_scn_lua_state = luaL_newstate();
            if (spctrm_scn_lua_state == NULL) {
#if defined(SPECTRUM_SCAN_2G) && defined(SPECTRUM_SCAN_5G)
                json_object_put(root);
#endif
                uf_ubus_unlock();
                return FAIL;                
            }
            luaL_openlibs(spctrm_scn_lua_state);
            luaL_dofile(spctrm_scn_lua_state,"/etc/spectrum_scan/spectrumScan.lua");
            if (spctrm_scn_call_lua_module_get(spctrm_scn_lua_state,&spctrm_scn_lua_rbuf) == FAIL) {
#if defined(SPECTRUM_SCAN_2G) && defined(SPECTRUM_SCAN_5G)
                json_object_put(root);
#endif                
                lua_close(spctrm_scn_lua_state);
                uf_ubus_unlock();
                return FAIL;  
            }
            *rbuf = strdup(spctrm_scn_lua_rbuf);
            lua_close(spctrm_scn_lua_state);
            free(spctrm_scn_lua_rbuf);
#endif

#if defined(SPECTRUM_SCAN_2G) && defined(SPECTRUM_SCAN_5G)
        }
#endif
        uf_ubus_unlock();
#if defined(SPECTRUM_SCAN_2G) && defined(SPECTRUM_SCAN_5G)
                json_object_put(root);
#endif        
        /* dev_sta get */
        break;
    case UF_CMD_DEL:
        /* dev_sta del */
        break;
    case UF_CMD_SET:

        if (para_obj == NULL) {
            return FAIL;
        }
        uf_ubus_lock();

        root = json_tokener_parse(para_obj);
        if (root== NULL) {
            uf_ubus_unlock();
            return FAIL;
        }
        band_obj = json_object_object_get(root,"band");
        if (json_object_get_int(band_obj) == BAND_5G) {
            spctrm_scn_lua_state = luaL_newstate();
            if (spctrm_scn_lua_state == NULL) {
                json_object_put(root);
                uf_ubus_unlock();
                return FAIL;                
            }
            luaL_openlibs(spctrm_scn_lua_state);
            luaL_dofile(spctrm_scn_lua_state,"/etc/spectrum_scan/spectrumScan.lua");
            if (spctrm_scn_call_lua_module_set(spctrm_scn_lua_state,para_obj,&spctrm_scn_lua_rbuf) == FAIL) {
                json_object_put(root);
                lua_close(spctrm_scn_lua_state);
                uf_ubus_unlock();
                return FAIL;  
            }
            *rbuf = strdup(spctrm_scn_lua_rbuf);
            lua_close(spctrm_scn_lua_state);
            free(spctrm_scn_lua_rbuf);
        } else {
            ctx = ubus_connect(NULL);
            if (ctx == NULL) {
                json_object_put(root);
                uf_ubus_unlock();
                return FAIL;            
            }
            if (ubus_lookup_id(ctx,"spctrm_scn_2g",&id)) {
                ubus_free(ctx);
                json_object_put(root);
                uf_ubus_unlock(); 
                return FAIL;
            }
            
            blobmsg_add_json_from_string(&b,para_obj);

            if (ubus_invoke(ctx, id, "set", b.head, spctrm_scn_ubus_invoke_handle_cb, 0, 3000)) {
                ubus_free(ctx);
                json_object_put(root);
                uf_ubus_unlock();    
                return FAIL;            
            }
            ubus_free(ctx);
            *rbuf = strdup(g_spctrm_scn_ubus_rbuf);
        }

        uf_ubus_unlock();

        json_object_put(root);
        /* dev_sta set */
        break;
    case UF_CMD_UPDATE:
        break;
    case UF_CMD_GET_DEFAULT:
        break;
    default:
        break;
    }
    return 0;
}  
void module_init_spectrum_scan(uf_plugin_intf_t *intf)  
{  
    if (intf == NULL) {
        return;
    }
    strcpy(intf->name, "spectrumScan");
    intf->fuc = (uf_handle_fuc)spctrm_scn_fnc;
    return ;  
} 
#endif
