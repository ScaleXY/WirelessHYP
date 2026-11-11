#include "ccid_host.h"
#include "usb/usb_host.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"
#include "sdkconfig.h"
#include <stdio.h>
#include <string.h>
/* All client operations run on the main task. Only the USB daemon has its
 * own task. Callbacks never submit transfers, free handles or block. */
static struct {
    usb_host_client_handle_t client;usb_device_handle_t dev;
    usb_transfer_t *transfer;bool done,busy,gone,claimed;
    uint8_t seq,iface,alt,in,out,intr;uint16_t in_mps;
    uint32_t features,max_message,generation;unsigned level;
    uint8_t stream[CCID_CAP];size_t buffered;ccid_t1 t1;
    char detail[96];
} h;
static int failure(const char *msg) {snprintf(h.detail,sizeof(h.detail),"%s",msg);return -1;}
const char *ccid_host_detail(void) {return h.detail;}
static void event(const usb_host_client_event_msg_t *m,void *arg) {
    (void)arg;
    if(m->event==USB_HOST_CLIENT_EVENT_DEV_GONE&&m->dev_gone.dev_hdl==h.dev) {h.gone=true;h.generation++;}
}
static void completed(usb_transfer_t *t) {(void)t;h.done=true;h.busy=false;}
static void daemon_task(void *arg) {
    (void)arg;
    for(;;) {uint32_t flags;usb_host_lib_handle_events(portMAX_DELAY,&flags);
        if(flags&USB_HOST_LIB_EVENT_FLAGS_NO_CLIENTS) usb_host_device_free_all();}
}
int ccid_host_init(void) {
    usb_host_config_t conf={.intr_flags=ESP_INTR_FLAG_LEVEL1};
    if(usb_host_install(&conf)!=ESP_OK) return failure("USB host install failed");
    if(xTaskCreate(daemon_task,"usb_daemon",4096,NULL,20,NULL)!=pdPASS) return failure("USB daemon task failed");
    usb_host_client_config_t cfg={.max_num_event_msg=8,.async={.client_event_callback=event}};
    if(usb_host_client_register(&cfg,&h.client)!=ESP_OK) return failure("USB client registration failed");
    if(usb_host_transfer_alloc(CCID_CAP,0,&h.transfer)!=ESP_OK) return failure("USB transfer allocation failed");
    return 0;
}
void ccid_host_close(void) {
    if(h.busy) return;
    if(h.dev) {
        if(h.claimed) usb_host_interface_release(h.client,h.dev,h.iface);
        usb_host_device_close(h.client,h.dev);
    }
    h.dev=NULL;h.claimed=false;h.gone=false;h.buffered=0;h.in=h.out=h.intr=0;
}
void ccid_host_poll(void) {
    if(!h.client) return;
    usb_host_client_handle_events(h.client,0);
    if(h.gone&&!h.busy) ccid_host_close();
}
uint32_t ccid_host_generation(void) {return h.generation;}
/* Called only when no operation owns a transfer. Opening a descriptor is safe
 * even while the PIN latch is set: it cannot authenticate to the card. */
int ccid_host_open(void) {
    ccid_host_poll();if(h.dev&&!h.gone) return 0;
    if(h.busy) return failure("USB transfer cancellation pending");
    uint8_t addresses[16];int count=0;
    if(usb_host_device_addr_list_fill(16,addresses,&count)!=ESP_OK) return failure("USB device list failed");
    for(int i=0;i<count;i++) {
        usb_device_handle_t dev;
        if(usb_host_device_open(h.client,addresses[i],&dev)!=ESP_OK) continue;
        const usb_device_desc_t *dd=NULL;
        usb_host_get_device_descriptor(dev,&dd);
        if(!dd||dd->idVendor!=0x2ccf||dd->idProduct!=0x080a) {usb_host_device_close(h.client,dev);continue;}
        const usb_config_desc_t *cd=NULL;
        if(usb_host_get_active_config_descriptor(dev,&cd)!=ESP_OK) {usb_host_device_close(h.client,dev);continue;}
        const uint8_t *p=(const uint8_t *)cd;size_t n=cd->wTotalLength;
        bool selected=false,descriptor=false;h.in=h.out=0;h.intr=0;h.features=0;h.max_message=0;
        while(n>=2&&p[0]>=2&&p[0]<=n) {
            size_t len=p[0];
            if(p[1]==4&&len>=9) {
                if(selected&&h.in&&h.out&&descriptor) break;
                selected=p[3]==0&&(p[5]==0x0b||p[5]==0xff);
                if(selected) {h.iface=p[2];h.alt=p[3];h.in=h.out=h.intr=0;descriptor=false;}
            } else if(selected&&p[1]==0x21&&len>=54) {
                if(p[4]!=0) {usb_host_device_close(h.client,dev);return failure("only CCID slot zero supported");}
                h.features=ccid_le32(p+40);h.max_message=ccid_le32(p+44);descriptor=true;
            } else if(selected&&p[1]==5&&len>=7) {
                unsigned type=p[3]&3;uint16_t mps=(uint16_t)(p[4]|(p[5]<<8));
                if(type==2) {if(p[2]&0x80) {h.in=p[2];h.in_mps=mps;}else h.out=p[2];}
                if(type==3&&(p[2]&0x80)) h.intr=p[2];
            }
            p+=len;n-=len;
        }
        if(!descriptor||!h.in||!h.out||!h.in_mps||h.in_mps>64||h.max_message<10) {
            usb_host_device_close(h.client,dev);return failure("invalid CCID interface/class descriptor");
        }
        h.level=(h.features>>16)&7;
        if(h.level!=1&&h.level!=2&&h.level!=4) {usb_host_device_close(h.client,dev);return failure("CCID character exchange is unsupported");}
        if(usb_host_interface_claim(h.client,dev,h.iface,h.alt)!=ESP_OK) {usb_host_device_close(h.client,dev);return failure("claim CCID interface failed");}
        h.dev=dev;h.claimed=true;h.gone=false;h.seq=0;h.buffered=0;h.generation++;
        snprintf(h.detail,sizeof(h.detail),"CCID level %u",h.level);return 0;
    }
    return failure("no HYP2003 token present");
}
bool ccid_host_present(void) {return ccid_host_open()==0;}
static int bulk(uint8_t ep,uint8_t *data,size_t n,size_t *actual,int64_t deadline) {
    if(!h.dev||h.gone||h.busy) return failure("USB disconnected or transfer pending");
    usb_transfer_t *t=h.transfer;t->device_handle=h.dev;t->bEndpointAddress=ep;
    t->callback=completed;t->context=NULL;t->flags=0;t->num_bytes=(int)n;
    if(!(ep&0x80)) memcpy(t->data_buffer,data,n);
    h.done=false;h.busy=true;
    if(usb_host_transfer_submit(t)!=ESP_OK) {h.busy=false;return failure("USB submit failed");}
    while(!h.done&&!h.gone&&esp_timer_get_time()<deadline) usb_host_client_handle_events(h.client,pdMS_TO_TICKS(10));
    if(!h.done) {
        usb_host_endpoint_halt(h.dev,ep);usb_host_endpoint_flush(h.dev,ep);
        int64_t drain=esp_timer_get_time()+2000000;
        while(!h.done&&esp_timer_get_time()<drain) usb_host_client_handle_events(h.client,pdMS_TO_TICKS(10));
        if(!h.gone&&h.done) usb_host_endpoint_clear(h.dev,ep);
        return failure(h.gone?"USB disconnected":"USB transfer timeout");
    }
    if(t->status!=USB_TRANSFER_STATUS_COMPLETED||h.gone) return failure("USB transfer failed/disconnected");
    *actual=(size_t)t->actual_num_bytes;
    if(ep&0x80) memcpy(data,t->data_buffer,*actual);
    else if(*actual!=n) return failure("short CCID write");
    return 0;
}
static int message(uint8_t type,uint8_t seq,ccid_message *m,int64_t deadline,uint8_t *frame) {
    for(;;) {
        if(h.buffered>=10) {
            uint32_t len=ccid_le32(h.stream+1);
            if(len>CCID_CAP-10) return failure("oversize CCID response");
            size_t total=len+10;
            if(h.buffered>=total) {
                memcpy(frame,h.stream,total);memmove(h.stream,h.stream+total,h.buffered-total);h.buffered-=total;
                /* Discard late replies from an earlier timed-out command. */
                if(frame[6]!=seq) {if(esp_timer_get_time()>=deadline) return failure("stale CCID reply deadline");continue;}
                int r=ccid_decode(frame,total,type,seq,m);
                if(r==1) {if(esp_timer_get_time()>=deadline) return failure("CCID time extension deadline");continue;}
                if(r) {snprintf(h.detail,sizeof(h.detail),"CCID status %02x error %02x",frame[7],frame[8]);return -1;}
                return 0;
            }
        }
        if(h.buffered+h.in_mps>sizeof(h.stream)) return failure("CCID receive overflow");
        size_t got=0;int r=bulk(h.in,h.stream+h.buffered,h.in_mps,&got,deadline);if(r) return r;
        if(!got) {if(esp_timer_get_time()>=deadline) return failure("CCID empty response timeout");continue;}
        h.buffered+=got;
    }
}
static int transact(uint8_t cmd,uint8_t response,const uint8_t args[3],const uint8_t *tx,size_t txn,uint8_t *rx,size_t *rxn,uint8_t *chain) {
    uint8_t frame[CCID_CAP];uint8_t seq=h.seq++;
    int bytes=ccid_encode(cmd,seq,args,tx,txn,frame,sizeof(frame));
    if(bytes<0||(uint32_t)bytes>h.max_message) return failure("CCID message exceeds reader limit");
    int64_t deadline=esp_timer_get_time()+(int64_t)CONFIG_HYP_USB_TIMEOUT_MS*1000;size_t actual=0;
    int r=bulk(h.out,frame,(size_t)bytes,&actual,deadline);if(r) return r;
    ccid_message m;r=message(response,seq,&m,deadline,frame);if(r) return r;
    if(m.n>*rxn) return failure("CCID response exceeds caller buffer");
    if(m.n) memcpy(rx,m.data,m.n);
    *rxn=m.n;if(chain) *chain=m.chain;return 0;
}
int ccid_host_slot_status(uint8_t *status) {
    uint8_t frame[CCID_CAP],args[3]={0};size_t actual;uint8_t seq=h.seq++;
    int bytes=ccid_encode(0x65,seq,args,NULL,0,frame,sizeof(frame));
    int64_t deadline=esp_timer_get_time()+(int64_t)CONFIG_HYP_USB_TIMEOUT_MS*1000;
    int r=bulk(h.out,frame,(size_t)bytes,&actual,deadline);if(r) return r;
    ccid_message m;r=message(0x81,seq,&m,deadline,frame);if(!r) *status=m.status&3;return r;
}
int ccid_host_power_off(void) {size_t n=0;uint8_t args[3]={0};return transact(0x63,0x81,args,NULL,0,NULL,&n,NULL);}
int ccid_host_power_on(uint8_t *atr,size_t *n) {
    /* A power cycle invalidates login and resets the T=1 sequence numbers. */
    h.buffered=0;
    int r=ccid_host_power_off();if(r) return r;
    uint8_t args[3]={0};r=transact(0x62,0x80,args,NULL,0,atr,n,NULL);if(r) return r;
    if(h.level==1) {
        if(ccid_t1_atr(&h.t1,atr,*n)) return failure("TPDU requires a direct-convention T=1 ATR");
        /* This path depends on reader automatic ATR/PPS parameter setup.
         * Never send APDU bytes as TPDUs or guess negotiated Fi/Di. */
        if(!(h.features&2)||!(h.features&0x40)) return failure("TPDU reader lacks automatic parameter negotiation");
    }
    return 0;
}
static int tpdu(void *ctx,const uint8_t *tx,size_t txn,uint8_t *rx,size_t *rxn) {
    (void)ctx;uint8_t args[3]={0};return transact(0x6f,0x80,args,tx,txn,rx,rxn,NULL);
}
static int apdu_link(void *ctx,uint16_t level,const uint8_t *tx,size_t txn,uint8_t *rx,size_t *rxn,uint8_t *chain) {
    (void)ctx;uint8_t args[3]={0,(uint8_t)level,(uint8_t)(level>>8)};
    return transact(0x6f,0x80,args,tx,txn,rx,rxn,chain);
}
int ccid_host_exchange(void *ctx,const uint8_t *tx,size_t txn,uint8_t *rx,size_t *rxn) {
    (void)ctx;
    if(h.level==1) return ccid_t1_exchange(&h.t1,tpdu,NULL,tx,txn,rx,rxn);
    return ccid_apdu_exchange(apdu_link,NULL,h.level==4,h.max_message-10,tx,txn,rx,rxn);
}
