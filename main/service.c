#include "service.h"
#include <string.h>
void signer_init(signer_service *s,const signer_ops *ops,const char *pin,const pin_marker *marker) {
    memset(s,0,sizeof(*s));s->ops=*ops;
    if(pin&&*pin) {strncpy(s->pin,pin,sizeof(s->pin)-1);s->pin_set=true;}
    if(marker&&marker->version) {s->marker=*marker;s->rejected=true;}
}
void signer_invalidate(signer_service *s) {s->ready=false;}
int signer_set_pin(signer_service *s,const char *pin) {
    s->ready=false;s->ops.reset(s->ops.ctx);
    if(s->ops.save_marker(s->ops.ctx,NULL)) {s->rejected=true;return EP_STORAGE;}
    ep_zero(s->pin,sizeof(s->pin));strncpy(s->pin,pin,sizeof(s->pin)-1);
    s->pin_set=true;s->rejected=false;memset(&s->marker,0,sizeof(s->marker));return 0;
}
int signer_open(signer_service *s) {
    signer_ops *o=&s->ops;void *ctx=o->ctx;
    if(s->rejected) return EP_PIN_REJECTED;
    if(!o->present(ctx)) {s->ready=false;return EP_ABSENT;}
    uint32_t gen=o->generation(ctx);
    if(s->ready&&gen==s->generation) return 0;
    s->ready=false;s->generation=gen;if(!s->pin_set) return EP_STORAGE;
    o->reset(ctx);int r=o->prepare(ctx);if(r) return r;
    /* Write-ahead guard: a brownout, USB failure or unverifiable response must
     * never allow a second attempt with a possibly rejected PIN. */
    s->marker=(pin_marker){.version=1,.code=EP_IO,.time_us=o->time_us(ctx)};
    s->rejected=true;
    if(o->save_marker(ctx,&s->marker)) return EP_STORAGE;
    r=o->verify(ctx,s->pin);
    if(!r&&gen!=o->generation(ctx)) r=EP_ABSENT;
    if(r) {
        uint16_t sw=o->sw(ctx);
        s->marker.code=sw?sw:r;
        /* Even if this update fails, the already committed guard remains. */
        o->save_marker(ctx,&s->marker);
        s->last_error=r;return EP_PIN_REJECTED;
    }
    if(o->save_marker(ctx,NULL)) return EP_STORAGE;
    s->rejected=false;memset(&s->marker,0,sizeof(s->marker));
    r=o->public_key(ctx,s->point);if(r) return r;
    if(gen!=o->generation(ctx)) return EP_ABSENT;
    s->generation=gen;s->ready=true;
    bool changed=s->first_seen&&memcmp(s->first_point,s->point,65);
    if(!s->first_seen) {memcpy(s->first_point,s->point,65);s->first_seen=true;}
    if(o->became_ready) o->became_ready(ctx,s->point,changed);
    return 0;
}
int signer_run(signer_service *s,const uint8_t *digest,uint8_t sig[64]) {
    if(s->rejected) return EP_PIN_REJECTED;
    int r=signer_open(s);
    uint32_t gen=s->generation;
    if(!r&&digest) r=s->ops.sign(s->ops.ctx,digest,sig);
    if(!r) return 0;
    if(s->rejected||r==EP_PIN_REJECTED) return EP_PIN_REJECTED;
    if(r==EP_ABSENT||gen!=s->ops.generation(s->ops.ctx)) {s->ready=false;return r;}
    signer_invalidate(s);r=signer_open(s);
    if(!r&&digest) r=s->ops.sign(s->ops.ctx,digest,sig);
    if(r) s->ready=false;
    return s->rejected?EP_PIN_REJECTED:r;
}
