/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Adapted from OpenSC card-epass2003.c at 3856d69:
 * gen_init_key, verify_init_key, construct_{data,le,mac}_tlv, encode_apdu,
 * epass2003_check_response_mac_and_sw, decrypt_response.
 * Copyright (C) 2008 Weitao Sun; 2011 Xiaoshuo Wu. */
#include "epass2003.h"
#include <string.h>
static const uint8_t initial[16]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
static int same(const uint8_t *a,const uint8_t *b,size_t n) {
    unsigned x=0; for(size_t i=0;i<n;i++) x|=a[i]^b[i]; return x==0;
}
static void increment(ep_sm *s) {
    for(int i=s->aes?15:7;i>=0;i--) if(++s->icv[i]) break;
}
/* ISO 9797-1 algorithm 3 (retail MAC) or AES CBC-MAC. Input is padded. */
static int mac_padded(ep_sm *s,const uint8_t *p,size_t n,uint8_t out[8]) {
    uint8_t work[EP_MAX],tmp[8],zero[16]={0};
    if(n>sizeof(work)) return EP_FORMAT;
    int r=ep_cipher(s->aes,false,false,s->mac,s->aes?16:8,s->icv,p,n,work);
    if(!r&&!s->aes) {
        r=ep_cipher(false,false,true,s->mac+8,8,zero,work+n-8,8,tmp);
        if(!r) r=ep_cipher(false,false,false,s->mac,8,zero,tmp,8,work+n-8);
    }
    if(!r) memcpy(out,work+n-(s->aes?16:8),8);
    ep_zero(work,sizeof(work)); ep_zero(tmp,sizeof(tmp)); return r;
}
int ep_sm_derive(ep_sm *s,const uint8_t host[8],const uint8_t *init,size_t n,uint8_t external[16]) {
    uint8_t data[48]={0},crypt[48]={0},mac[32]={0},zero[16]={0}; int r=EP_FORMAT;
    size_t b=s->aes?16:8;
    if(n!=(s->fips?29u:28u)|| (s->fips&&!s->aes)) goto done;
    const uint8_t *card=init+12+(s->fips?1:0);
    if(s->fips) {
        data[11]=4;data[14]=0x80;data[15]=1;
        memcpy(data+16,host,8);memcpy(data+24,card,8);
        if((r=ep_cmac(initial,data,32,s->enc))) goto done;
        data[11]=6;
        if((r=ep_cmac(initial,data,32,s->mac))) goto done;
        data[11]=0;data[14]=0x40;
        if((r=ep_cmac(s->enc,data,32,crypt))) goto done;
    } else {
        memcpy(data,card+4,4);memcpy(data+4,host,4);
        memcpy(data+8,card,4);memcpy(data+12,host+4,4);
        if((r=ep_cipher(s->aes,true,false,initial,16,NULL,data,16,s->enc))) goto done;
        memcpy(s->mac,s->enc,16);
        memset(data,0,sizeof(data));memcpy(data,host,8);memcpy(data+8,card,8);data[16]=0x80;
        if((r=ep_cipher(s->aes,true,false,s->enc,16,zero,data,16+b,crypt))) goto done;
    }
    if(!same(crypt+(s->fips?0:16),init+(s->fips?21:20),8)) { r=EP_CRYPTO;goto done; }
    memset(data,0,sizeof(data));
    if(s->fips) {
        data[11]=1;data[14]=0x40;data[15]=1;memcpy(data+16,host,8);memcpy(data+24,card,8);
        if((r=ep_cmac(s->enc,data,32,crypt))) goto done;
    } else {
        memcpy(data,card,8);memcpy(data+8,host,8);data[16]=0x80;
        if((r=ep_cipher(s->aes,true,false,s->enc,16,zero,data,16+b,crypt))) goto done;
    }
    memcpy(external,crypt+(s->fips?0:16),8);
    memset(data,0,sizeof(data));memcpy(data,"\x84\x82\x03\x00\x10",5);memcpy(data+5,external,8);
    if(s->fips) r=ep_cmac(s->mac,data,13,mac);
    else { data[13]=0x80;r=ep_cipher(s->aes,true,false,s->mac,16,zero,data,16,mac); }
    if(r) goto done;
    memcpy(external+8,mac+(s->aes?0:8),8);
    memset(s->icv,0,16);memcpy(s->icv,external+8,8);
    r=0;
done:
    ep_zero(data,sizeof(data));ep_zero(crypt,sizeof(crypt));ep_zero(mac,sizeof(mac));
    if(r) {ep_zero(s->enc,16);ep_zero(s->mac,16);ep_zero(external,16);} return r;
}
int ep_sm_wrap(ep_sm *s,const ep_apdu *a,uint8_t *out,size_t *outn) {
    uint8_t data[EP_MAX]={0},tlv[EP_MAX]={0},pad[EP_MAX]={0},mac[16]={0},zero[16]={0};
    size_t b=s->aes?16:8,t=0;int r=EP_FORMAT;
    if(a->lc>232||a->le>256||!s->active) goto done;
    data[0]=a->cla|0x0c;data[1]=a->ins;data[2]=a->p1;data[3]=a->p2;data[4]=0x80;
    if(a->lc) {
        size_t n=((a->lc+1+b-1)/b)*b;
        memcpy(pad,a->data,a->lc);pad[a->lc]=0x80;
        tlv[t++]=0x87;
        if(n>126) {tlv[t++]=0x82;tlv[t++]=(uint8_t)((n+1)>>8);tlv[t++]=(uint8_t)(n+1);}
        else tlv[t++]=(uint8_t)(n+1);
        tlv[t++]=1;
        if((r=ep_cipher(s->aes,true,false,s->enc,16,zero,pad,n,tlv+t))) goto done;
        t+=n;
    }
    if(a->response) {
        tlv[t++]=0x97;tlv[t++]=a->le>127?2:1;
        if(a->le>127) tlv[t++]=(uint8_t)(a->le>>8);
        tlv[t++]=(uint8_t)a->le;
    }
    memcpy(data+b,tlv,t); increment(s);
    if(s->fips) {
        for(size_t i=0;i<b;i++) data[i]^=s->icv[i];
        r=ep_cmac(s->mac,data,b+t,mac);
    } else {
        size_t n=b;
        if(t) {data[b+t]=0x80;n=b+((t+1+b-1)/b)*b;}
        r=mac_padded(s,data,n,mac);
    }
    if(r) goto done;
    tlv[t++]=0x8e;tlv[t++]=8;memcpy(tlv+t,mac,8);t+=8;
    bool ext=t>255 || (a->response&&a->le>127);
    size_t need=4+(ext?3:1)+t+(ext?2:1);
    if(*outn<need) {r=EP_FORMAT;goto done;}
    out[0]=a->cla|0x0c;out[1]=a->ins;out[2]=a->p1;out[3]=a->p2;
    size_t pos=4;
    if(ext) {out[pos++]=0;out[pos++]=(uint8_t)(t>>8);}
    out[pos++]=(uint8_t)t;memcpy(out+pos,tlv,t);pos+=t;
    /* OpenSC sets case 4 even when the original command had no response. */
    if(ext) out[pos++]=(uint8_t)(a->le>>8);
    out[pos++]=(uint8_t)a->le;*outn=pos;r=0;
done:
    ep_zero(data,sizeof(data));ep_zero(tlv,sizeof(tlv));ep_zero(pad,sizeof(pad));ep_zero(mac,sizeof(mac));return r;
}
int ep_sm_unwrap(ep_sm *s,const uint8_t *in,size_t n,uint8_t *out,size_t *outn,uint16_t *sw) {
    if(n<2) return EP_FORMAT;
    *sw=((uint16_t)in[n-2]<<8)|in[n-1]; n-=2;
    const uint8_t *p=in;size_t left=n;ep_tlv data={0},status,mac;
    if(left&&p[0]==0x87) {
        /* OpenSC's documented workaround: literal one-byte length 0x81, marker 01. */
        if(left>3&&p[1]>=0x80&&p[1]!=0x82&&p[2]==1) {
            size_t len=p[1];if(len+2>left) return EP_FORMAT;
            data=(ep_tlv){.tag=0x87,.v=p+2,.n=len,.total=len+2};p+=len+2;left-=len+2;
        } else if(ep_tlv_next(&p,&left,&data)) return EP_FORMAT;
    }
    if(ep_tlv_next(&p,&left,&status)||status.tag!=0x99||status.n!=2||
       (((uint16_t)status.v[0]<<8)|status.v[1])!=*sw) return EP_CRYPTO;
    const uint8_t *mac_start=p;
    if(ep_tlv_next(&p,&left,&mac)||mac.tag!=0x8e||mac.n!=8||left) return EP_FORMAT;
    uint8_t buf[EP_MAX]={0},expected[8],zero[16]={0};int r=EP_CRYPTO;
    if(!s->fips) {
        size_t len=(size_t)(mac_start-in),b=s->aes?16:8;
        if(len+b>sizeof(buf)) return EP_FORMAT;
        memcpy(buf,in,len);buf[len++]=0x80;len=((len+b-1)/b)*b;
        if(mac_padded(s,buf,len,expected)||!same(expected,mac.v,8)) goto done;
    }
    /* FIPS response MAC is unspecified in OpenSC 3856d69 and is not verified
     * there either. card.c refuses FIPS mode before any PIN is sent. */
    if(s->fips) {r=EP_UNSUPPORTED;goto done;}
    if(!data.n) {*outn=0;r=0;goto done;}
    size_t b=s->aes?16:8;
    if(data.n<2||data.v[0]!=1||(data.n-1)%b||data.n-1>sizeof(buf)) {r=EP_FORMAT;goto done;}
    if((r=ep_cipher(s->aes,true,true,s->enc,16,zero,data.v+1,data.n-1,buf))) goto done;
    size_t len=data.n-1;
    while(len&&buf[len-1]==0) len--;
    if(!len||buf[len-1]!=0x80||len-1>*outn) {r=EP_FORMAT;goto done;}
    *outn=len-1;memcpy(out,buf,*outn);r=0;
done:
    ep_zero(buf,sizeof(buf));ep_zero(expected,sizeof(expected));return r;
}
