#include "ccid_host.h"
#include <string.h>
static uint16_t crc16(const uint8_t *p,size_t n) {
    uint16_t c=0xffff;
    while(n--) {c^=*p++;for(unsigned i=0;i<8;i++) c=(c&1)?(uint16_t)((c>>1)^0x8408):(uint16_t)(c>>1);}
    return c;
}
static size_t block(ccid_t1 *s,uint8_t pcb,const uint8_t *p,size_t n,uint8_t *out) {
    out[0]=0;out[1]=pcb;out[2]=(uint8_t)n;if(n) memcpy(out+3,p,n);
    if(s->crc) {uint16_t c=crc16(out,n+3);out[n+3]=(uint8_t)(c>>8);out[n+4]=(uint8_t)c;return n+5;}
    uint8_t lrc=0;for(size_t i=0;i<n+3;i++) lrc^=out[i];out[n+3]=lrc;return n+4;
}
static bool valid(ccid_t1 *s,const uint8_t *p,size_t n) {
    if(n<4||p[0]||n!=(size_t)p[2]+(s->crc?5:4)) return false;
    if(s->crc) {uint16_t c=crc16(p,n-2);return p[n-2]==(uint8_t)(c>>8)&&p[n-1]==(uint8_t)c;}
    uint8_t x=0;for(size_t i=0;i<n;i++) x^=p[i];return x==0;
}
int ccid_t1_atr(ccid_t1 *s,const uint8_t *atr,size_t n) {
    if(n<2||atr[0]!=0x3b) return -1;
    *s=(ccid_t1){.ifsc=32};unsigned y=atr[1]>>4,group=1,protocol=0;size_t pos=2;bool t1=false;
    while(y) {
        unsigned current=y,next=0;
        for(unsigned bit=0;bit<4;bit++) if(current&(1u<<bit)) {
            if(pos>=n) return -1;
            uint8_t v=atr[pos++];
            if(group>=3&&protocol==1) {
                if(bit==0) {if(!v||v==255) return -1;s->ifsc=v;}
                if(bit==2) s->crc=(v&1)!=0;
            }
            if(bit==3) {protocol=v&15;t1|=protocol==1;next=v>>4;}
        }
        y=next;
        if(!y) break;
        group++;
        if(group>8) return -1;
        /* Groups without TD end the interface bytes. */
        if(pos>=n) return -1;
    }
    if(!t1||pos+(atr[1]&15)+1!=n) return -1;
    uint8_t check=0;for(size_t i=1;i<n;i++) check^=atr[i];
    return check? -1:0;
}
int ccid_t1_exchange(ccid_t1 *s,t1_link link,void *ctx,const uint8_t *in,size_t n,uint8_t *out,size_t *outn) {
    uint8_t tx[260],rx[260],last[260];size_t pos=0,got=0,lastn=0,sent=0;
    unsigned errors=0,steps=0;bool sending=true;
    size_t take=n<s->ifsc?n:s->ifsc;
    sent=take;lastn=block(s,(uint8_t)((s->send_seq<<6)|(take<n?0x20:0)),in,take,last);
    memcpy(tx,last,lastn);size_t txn=lastn;
    while(++steps<256) {
        size_t rn=sizeof(rx);int r=link(ctx,tx,txn,rx,&rn);if(r) return r;
        if(!valid(s,rx,rn)) {
            if(++errors>2) return -1;
            txn=block(s,(uint8_t)(0x81|(s->recv_seq<<4)),NULL,0,tx);continue;
        }
        uint8_t pcb=rx[1];size_t len=rx[2];
        if((pcb&0xc0)==0xc0) {
            if(pcb==0xc3&&len==1&&rx[3]>=1&&rx[3]<=59) {txn=block(s,0xe3,rx+3,1,tx);continue;}
            if(pcb==0xc1&&len==1&&rx[3]>0&&rx[3]<255) {s->ifsc=rx[3];txn=block(s,0xe1,rx+3,1,tx);continue;}
            return -1;
        }
        if((pcb&0xc0)==0x80) {
            if(!sending||len) return -1;
            unsigned nr=(pcb>>4)&1;
            if((pcb&15)||nr==s->send_seq) {
                if(++errors>2) return -1;
                memcpy(tx,last,lastn);txn=lastn;continue;
            }
            pos+=sent;s->send_seq^=1;errors=0;
            if(pos>=n) return -1;
            take=n-pos;if(take>s->ifsc) take=s->ifsc;sent=take;
            lastn=block(s,(uint8_t)((s->send_seq<<6)|(pos+take<n?0x20:0)),in+pos,take,last);
            memcpy(tx,last,lastn);txn=lastn;continue;
        }
        if(pcb&0x80) return -1;
        if(sending) {if(pos+sent!=n) return -1;s->send_seq^=1;sending=false;}
        if(((pcb>>6)&1)!=s->recv_seq) {
            if(++errors>2) return -1;
            txn=block(s,(uint8_t)(0x80|(s->recv_seq<<4)),NULL,0,tx);continue;
        }
        if(got+len>*outn) return -1;
        memcpy(out+got,rx+3,len);got+=len;s->recv_seq^=1;errors=0;
        if(!(pcb&0x20)) {*outn=got;return 0;}
        txn=block(s,(uint8_t)(0x80|(s->recv_seq<<4)),NULL,0,tx);
    }
    return -1;
}
