/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Adapted from OpenSC card-epass2003.c at 3856d69, copyright
 * (C) 2008 Weitao Sun, (C) 2011 Xiaoshuo Wu. See LICENSE.
 * Ports get_data, mutual_auth, external_key_auth, hash_data,
 * epass2003_select_fid_/hook_path, set_security_env and decipher (EC only).
 * Deliberately omits get_external_key_retries after successful authentication. */
#include "epass2003.h"
#include <string.h>
static int transmit(ep_card *c,const ep_apdu *a,uint8_t *out,size_t *n) {
    uint8_t tx[512],rx[1024];size_t txn=sizeof(tx),rxn=sizeof(rx);int r;
    c->sw=0;
    if(c->sm.active) r=ep_sm_wrap(&c->sm,a,tx,&txn);
    else {
        if(a->lc>255||a->le>256) return EP_FORMAT;
        tx[0]=a->cla;tx[1]=a->ins;tx[2]=a->p1;tx[3]=a->p2;txn=4;
        if(a->lc) {tx[txn++]=(uint8_t)a->lc;memcpy(tx+txn,a->data,a->lc);txn+=a->lc;}
        if(a->response) tx[txn++]=(uint8_t)a->le;
        r=0;
    }
    if(!r) r=c->exchange(c->ctx,tx,txn,rx,&rxn);
    if(!r) {
        if(rxn<2) r=EP_FORMAT;
        else {
            c->sw=((uint16_t)rx[rxn-2]<<8)|rx[rxn-1];
            if(c->sm.active) r=ep_sm_unwrap(&c->sm,rx,rxn,out,n,&c->sw);
            else if(rxn-2>*n) r=EP_FORMAT;
            else {*n=rxn-2;if(*n) memcpy(out,rx,*n);}
        }
    }
    ep_zero(tx,sizeof(tx));ep_zero(rx,sizeof(rx));return r;
}
static int command(ep_card *c,uint8_t cla,uint8_t ins,uint8_t p1,uint8_t p2,
                   const uint8_t *data,size_t len,bool response,unsigned le,uint8_t *out,size_t *n) {
    ep_apdu a={cla,ins,p1,p2,data,len,response,le};
    int r=transmit(c,&a,out,n);
    if(!r&&!response&&ins==0xa4&&(c->sw>>8)==0x61) return 0;
    return r?r:(c->sw==0x9000?0:EP_IO);
}
static int select_fid(ep_card *c,uint16_t fid,bool fci,uint8_t *out,size_t *n) {
    uint8_t b[2]={(uint8_t)(fid>>8),(uint8_t)fid};
    if(b[0]==0x29||(b[0]>=0x30&&b[0]<=0x34)) b[1]=(uint8_t)(b[1]*0x20); /* OpenSC epass2003_hook_path */
    return command(c,0,0xa4,0,0,b,2,fci,0,out,n);
}
static int select_path(ep_card *c,const ep_path *path,uint8_t *fci,size_t *fci_n) {
    uint8_t absolute[20];size_t n=0;
    if(path->n>=2&&path->bytes[0]==0x3f&&path->bytes[1]==0) {
        memcpy(absolute,path->bytes,path->n);n=path->n;
    } else {
        memcpy(absolute,"\x3f\x00\x50\x15",4);n=4;
        if(path->n>=2&&path->bytes[0]==0x50&&path->bytes[1]==0x15) n=2;
        memcpy(absolute+n,path->bytes,path->n);n+=path->n;
    }
    for(size_t i=0;i<n;i+=2) {
        size_t len=i+2==n?*fci_n:0;
        int r=select_fid(c,((uint16_t)absolute[i]<<8)|absolute[i+1],i+2==n,fci,&len);
        if(r) return r;
        if(i+2==n) *fci_n=len;
    }
    return 0;
}
static int read_file(ep_card *c,const ep_path *path,uint8_t *out,size_t *outn) {
    uint8_t fci[256];size_t fn=sizeof(fci);int r=select_path(c,path,fci,&fn);
    if(r) return r;
    const uint8_t *p=fci;size_t n=fn;ep_tlv outer,t;
    if(ep_tlv_next(&p,&n,&outer)||outer.tag!=0x6f) return EP_FORMAT;
    if(ep_tlv_find(outer.v,outer.n,0x80,&t)&&ep_tlv_find(outer.v,outer.n,0x81,&t)) return EP_FORMAT;
    if(!t.n||t.n>2) return EP_FORMAT;
    size_t size=t.v[0];if(t.n==2) size=(size<<8)|t.v[1];
    if(path->index>size) return EP_FORMAT;
    size-=path->index;
    if(path->has_count) {if(path->count>size) return EP_FORMAT;size=path->count;}
    if(size>*outn||path->index+size>0x8000) return EP_FORMAT;
    size_t got=0;
    while(got<size) {
        size_t want=size-got;if(want>96) want=96;size_t actual=want;
        unsigned offset=(unsigned)(path->index+got);
        /* Call transmit directly: only a cleanly unwrapped 6282 (EOF) may end
         * the read early; SM/transport failures must never be masked by it. */
        ep_apdu a={0,0xb0,(uint8_t)(offset>>8),(uint8_t)offset,NULL,0,true,(unsigned)want};
        r=transmit(c,&a,out+got,&actual);
        if(r) return r;
        if(c->sw!=0x9000&&c->sw!=0x6282) return EP_IO;
        if(actual>want||!actual) return EP_FORMAT;
        got+=actual;
        if(actual<want||c->sw==0x6282) break;
    }
    *outn=got;return 0;
}
void ep_card_init(ep_card *c,ep_exchange exchange,void *ctx) {
    memset(c,0,sizeof(*c));c->exchange=exchange;c->ctx=ctx;
}
int ep_card_prepare(ep_card *c) {
    uint8_t buf[EP_MAX],host[8],external[16];size_t n=sizeof(buf);int r;
    /* MF + AppDF per OpenSC epass2003.profile; not an inferred AID. */
    size_t z=0;
    if((r=select_fid(c,0x3f00,false,buf,&z))) goto done;
    z=0;if((r=select_fid(c,0x5015,false,buf,&z))) goto done;
    n=sizeof(buf);if((r=command(c,0,0xca,1,0x86,NULL,0,true,0,buf,&n))) goto done;
    if(n<35) {r=EP_FORMAT;goto done;}
    c->sm.aes=buf[2]==1;
    c->sm.fips=!memcmp(buf,"\x80\x01\x01",3)&&!memcmp(buf+32,"\x87\x01\x01",3);
    /* Reference explicitly skips FIPS response MAC checks. Fail before PIN
     * instead of guessing an authentication algorithm or accepting unchecked MACs. */
    if(c->sm.fips) {r=EP_UNSUPPORTED;goto done;}
    if(buf[14]==0x84&&buf[16]==0) {r=EP_UNSUPPORTED;goto done;}
    if((r=ep_random(host,8))) goto done;
    n=sizeof(buf);if((r=command(c,0x80,0x50,0,0,host,8,true,28,buf,&n))) goto done;
    if((r=ep_sm_derive(&c->sm,host,buf,n,external))) goto done;
    n=sizeof(buf);if((r=command(c,0x84,0x82,3,0,external,16,false,0,buf,&n))) goto done;
    c->sm.active=true;
    ep_path odf={.bytes={0x50,0x31},.n=2},pr,pub,auth;
    n=sizeof(buf);if((r=read_file(c,&odf,buf,&n))) goto done;
    if((r=ep_p15_odf(buf,n,0xa0,&pr))||(r=ep_p15_odf(buf,n,0xa1,&pub))||
       (r=ep_p15_odf(buf,n,0xa8,&auth))) goto done;
    n=sizeof(buf);if((r=read_file(c,&pr,buf,&n))) goto done;
    if((r=ep_p15_key(buf,n,&c->private_key))) goto done;
    if(!c->private_key.has_ref) {r=EP_FORMAT;goto done;}
    n=sizeof(buf);if((r=read_file(c,&auth,buf,&n))) goto done;
    if((r=ep_p15_pin(buf,n,c->private_key.auth,c->private_key.authn,&c->pin_ref))) goto done;
    n=sizeof(buf);if((r=read_file(c,&pub,buf,&n))) goto done;
    ep_key public_key;
    if((r=ep_p15_key(buf,n,&public_key))) goto done;
    c->public_path=public_key.path;
    r=0;
done:
    ep_zero(buf,sizeof(buf));ep_zero(host,sizeof(host));ep_zero(external,sizeof(external));return r;
}
bool ep_pin_sw(uint16_t sw) {
    return (sw&0xfff0)==0x63c0||sw==0x6300||sw==0x6983||sw==0x6984||sw==0x6700||sw==0x6a80;
}
int ep_card_verify(ep_card *c,const char *pin) {
    uint8_t challenge[32],key[24]={0},answer[8],zero[16]={0},response[64];
    size_t len=strlen(pin),n=sizeof(challenge);int r;
    c->sw=0;
    if(len<4||len>16) return EP_PIN_REJECTED;
    /* OpenSC epass2003_get_challenge asks for 16, uses its first 8 bytes. */
    r=command(c,0,0x84,0,0,NULL,0,true,16,challenge,&n);
    if(r) goto done;
    if(n<8) {r=EP_FORMAT;goto done;}
    if((r=ep_sha1((const uint8_t *)pin,len,key))) goto done;
    key[20]=(uint8_t)(len>>24);key[21]=(uint8_t)(len>>16);key[22]=(uint8_t)(len>>8);key[23]=(uint8_t)len;
    if((r=ep_cipher(false,true,false,key,24,zero,challenge,8,answer))) goto done;
    n=sizeof(response);
    r=command(c,0,0x82,1,0x80|c->pin_ref,answer,8,false,0,response,&n);
    if(ep_pin_sw(c->sw)) r=EP_PIN_REJECTED;
    /* No GET_INFO, retries query, refresh or retransmission here. */
done:
    ep_zero(challenge,sizeof(challenge));ep_zero(key,sizeof(key));ep_zero(answer,sizeof(answer));ep_zero(response,sizeof(response));return r;
}
int ep_card_public(ep_card *c) {
    uint8_t buf[EP_MAX];size_t n=sizeof(buf);
    int r=read_file(c,&c->public_path,buf,&n);
    if(!r) r=ep_point(buf,n,c->point);
    ep_zero(buf,sizeof(buf));return r;
}
int ep_card_sign(ep_card *c,const uint8_t digest[32],uint8_t signature[64]) {
    unsigned fid=0x2900+0x20*c->private_key.ref;
    if(fid>0xffff) return EP_FORMAT;
    uint8_t env[]={0x80,1,0x92,0x81,2,(uint8_t)(fid>>8),(uint8_t)fid};
    uint8_t out[128];size_t n=sizeof(out);
    int r=command(c,0,0x22,0x41,0xb6,env,sizeof(env),false,0,out,&n);
    if(r) return r;
    n=sizeof(out);r=command(c,0,0x2a,0x9e,0x9a,digest,32,true,0,out,&n);
    if(!r) {if(n!=64) r=EP_FORMAT;else {memcpy(signature,out,64);r=ep_low_s(signature);}}
    ep_zero(out,sizeof(out));return r;
}
