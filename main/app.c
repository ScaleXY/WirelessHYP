#include "service.h"
#include "web.h"
#include "web_logic.h"
#include "sdkconfig.h"
#include "transport.h"
#include "ccid_host.h"
#include "signer_proto.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "psa/crypto.h"
#include <stdio.h>
#include <string.h>
static nvs_handle_t nv;static bool storage_ok,usb_ok;
static signer_service service;static ep_card card;
static bool present(void *ctx) {(void)ctx;return usb_ok&&ccid_host_present();}
static uint32_t generation(void *ctx) {(void)ctx;return ccid_host_generation();}
static void reset(void *ctx) {(void)ctx;ep_zero(&card,sizeof(card));ep_card_init(&card,ccid_host_exchange,NULL);}
static int prepare(void *ctx) {
    (void)ctx;uint8_t atr[64];size_t n=sizeof(atr);
    if(ccid_host_power_on(atr,&n)) return EP_IO;
    return ep_card_prepare(&card);
}
static int verify(void *ctx,const char *pin) {(void)ctx;return ep_card_verify(&card,pin);}
static int public_key(void *ctx,uint8_t out[65]) {(void)ctx;int r=ep_card_public(&card);if(!r) memcpy(out,card.point,65);return r;}
static int sign_digest(void *ctx,const uint8_t in[32],uint8_t out[64]) {(void)ctx;return ep_card_sign(&card,in,out);}
static uint16_t sw(void *ctx) {(void)ctx;return card.sw;}
static uint64_t time_us(void *ctx) {(void)ctx;return (uint64_t)esp_timer_get_time();}
static int marker_save(void *ctx,const pin_marker *marker) {
    (void)ctx;if(!storage_ok) return -1;
    esp_err_t err=marker?nvs_set_blob(nv,"pin_rejected",marker,sizeof(*marker)):nvs_erase_key(nv,"pin_rejected");
    if(err!=ESP_OK&&err!=ESP_ERR_NVS_NOT_FOUND) return -1;
    return nvs_commit(nv)==ESP_OK?0:-1;
}
static void ready(void *ctx,const uint8_t point[65],bool changed) {
    (void)ctx;char line[512];
    if(changed) ESP_LOGW("signer","Token public point differs from first point seen since boot");
    proto_public(line,sizeof(line),NULL,true,point);transport_write_line(line);
}
static const char *detail(int err,char out[128]) {
    if(service.rejected) {snprintf(out,128,"PIN authentication latched (code %ld); set_pin required",(long)service.marker.code);return out;}
    if(err==EP_ABSENT) return "no HYP2003 token present";
    if(err==EP_KEY_NOT_FOUND) return "key id 01 not found on the token";
    if(err==EP_UNSUPPORTED) return "token error: unsupported FIPS/plain SM mode or CCID exchange level";
    if(err==EP_STORAGE) return service.pin_set?"NVS storage failure":"PIN not provisioned; use set_pin";
    snprintf(out,128,"token error: driver %d SW %04x (%s)",err,card.sw,ccid_host_detail());return out;
}
static void handle(char *line) {
    proto_request request;const char *error=proto_parse(line,&request);
    char out[512],message[128];uint8_t sig[64];int r=0;
    if(service.rejected&&(request.op==OP_SIGN||request.op==OP_PUBKEY))
        proto_error(out,sizeof(out),&request,true,detail(EP_PIN_REJECTED,message));
    else if(error) proto_error(out,sizeof(out),&request,false,error);
    else if(request.op==OP_SET_ADMIN_PASSWORD) {
        if(hyp_admin_set(request.password)) proto_ok(out,sizeof(out),&request);
        else proto_error(out,sizeof(out),&request,false,"admin password storage failed");
    } else if(request.op==OP_SET_PIN) {
        if(!storage_ok||nvs_set_blob(nv,"pin",request.pin,strlen(request.pin)+1)!=ESP_OK||nvs_set_u8(nv,"pin_seeded",1)!=ESP_OK||nvs_commit(nv)!=ESP_OK) r=EP_STORAGE;
        else r=signer_set_pin(&service,request.pin);
        if(!r) proto_ok(out,sizeof(out),&request);
        else proto_error(out,sizeof(out),&request,service.rejected,detail(r,message));
    } else if(request.op==OP_STATUS) {
        bool attached=present(NULL);
        if(service.ready&&service.generation!=generation(NULL)) signer_invalidate(&service);
        proto_status(out,sizeof(out),&request,attached?(service.ready?"ready":"present"):"absent",service.pin_set,service.rejected);
    } else {
        int64_t start=esp_timer_get_time();
        r=signer_run(&service,request.op==OP_SIGN?request.digest:NULL,sig);
        if(r) proto_error(out,sizeof(out),&request,service.rejected,detail(r,message));
        else if(request.op==OP_SIGN) proto_signature(out,sizeof(out),&request,sig,(esp_timer_get_time()-start)/1000.0);
        else proto_public(out,sizeof(out),&request,false,service.point);
    }
    transport_write_line(out);
    /* set_pin acknowledgement must precede the ensuing open/ready/fatal. */
    bool open_after=!error&&request.op==OP_SET_PIN&&!r;
    ep_zero(&request,sizeof(request));ep_zero(line,PROTO_LINE_MAX);ep_zero(sig,sizeof(sig));
    if(open_after) {
        r=signer_open(&service);
        if(r&&service.rejected) {proto_error(out,sizeof(out),NULL,true,detail(r,message));transport_write_line(out);}
    }
}
void app_main(void) {
    transport_logs_init();if(transport_init()) {ESP_LOGE("signer","UART0 init failed");return;}
    char pin[65]={0};pin_marker marker={0};
    /* Never erase/reinitialize NVS on an error: doing so could erase the latch. */
    storage_ok=nvs_flash_init()==ESP_OK&&nvs_open("hyp_signer",NVS_READWRITE,&nv)==ESP_OK;
    if(storage_ok) {
        uint8_t seeded=0;esp_err_t seed_err=nvs_get_u8(nv,"pin_seeded",&seeded);
        if(seed_err!=ESP_OK&&seed_err!=ESP_ERR_NVS_NOT_FOUND) storage_ok=false;
        size_t n=sizeof(pin);esp_err_t e=nvs_get_blob(nv,"pin",pin,&n);
        if(storage_ok&&e==ESP_ERR_NVS_NOT_FOUND&&hyp_should_seed(false,seeded,CONFIG_HYP_DEFAULT_PIN)) {
            size_t len=strlen(CONFIG_HYP_DEFAULT_PIN);
            if(len>=sizeof(pin)||nvs_set_blob(nv,"pin",CONFIG_HYP_DEFAULT_PIN,len+1)!=ESP_OK||nvs_set_u8(nv,"pin_seeded",1)!=ESP_OK||nvs_commit(nv)!=ESP_OK) storage_ok=false;
            else {memcpy(pin,CONFIG_HYP_DEFAULT_PIN,len+1);n=len+1;e=ESP_OK;}
        }
        if(e==ESP_OK&&(n<2||n>sizeof(pin)||pin[n-1]!=0||strlen(pin)!=n-1)) storage_ok=false;
        if(e!=ESP_OK&&e!=ESP_ERR_NVS_NOT_FOUND) storage_ok=false;
        n=sizeof(marker);e=nvs_get_blob(nv,"pin_rejected",&marker,&n);
        if(e!=ESP_OK&&e!=ESP_ERR_NVS_NOT_FOUND) storage_ok=false;
        if(e==ESP_OK&&(n!=sizeof(marker)||marker.version!=1)) storage_ok=false;
    }
    if(!storage_ok) marker=(pin_marker){.version=1,.code=EP_STORAGE};
    signer_ops ops={.present=present,.generation=generation,.reset=reset,.prepare=prepare,.verify=verify,
        .public_key=public_key,.sign=sign_digest,.sw=sw,.time_us=time_us,.save_marker=marker_save,.became_ready=ready};
    signer_init(&service,&ops,pin,&marker);ep_zero(pin,sizeof(pin));
    usb_ok=psa_crypto_init()==PSA_SUCCESS&&ccid_host_init()==0;
    if(!usb_ok) ESP_LOGE("signer","USB/crypto init failed");
    if(storage_ok) hyp_web_init();
    bool announced=false;int64_t next_open=0;
    for(;;) {
        if(usb_ok) ccid_host_poll();
        if(service.ready&&generation(NULL)!=service.generation) signer_invalidate(&service);
        char line[PROTO_LINE_MAX];int have=transport_read_line(line,sizeof(line));
        if(have==1) handle(line);
        else if(have<0) {proto_error(line,sizeof(line),NULL,false,"request too long or binary input");transport_write_line(line);}
        if(service.rejected&&!announced) {
            char msg[128];proto_error(line,sizeof(line),NULL,true,detail(EP_PIN_REJECTED,msg));transport_write_line(line);announced=true;
        }
        if(!service.rejected) announced=false;
        if(!service.ready&&!service.rejected&&service.pin_set&&esp_timer_get_time()>=next_open) {
            signer_open(&service);next_open=esp_timer_get_time()+1000000;
        }
        hyp_web_publish(present(NULL),service.ready,service.pin_set,service.rejected,service.point);
        vTaskDelay(pdMS_TO_TICKS(5));
    }
}
