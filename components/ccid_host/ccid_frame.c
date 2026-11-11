#include "ccid_host.h"
#include <string.h>
uint32_t ccid_le32(const uint8_t *p) {return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
int ccid_encode(uint8_t type,uint8_t seq,const uint8_t specific[3],const uint8_t *p,size_t n,uint8_t *out,size_t cap) {
    if(n>CCID_CAP-10||cap<n+10) return -1;
    memset(out,0,10);out[0]=type;
    for(unsigned i=0;i<4;i++) out[i+1]=(uint8_t)(n>>(i*8));
    out[6]=seq;if(specific) memcpy(out+7,specific,3);
    if(n) memcpy(out+10,p,n);
    return (int)(n+10);
}
int ccid_decode(const uint8_t *p,size_t n,uint8_t type,uint8_t seq,ccid_message *m) {
    if(n<10||ccid_le32(p+1)!=n-10||p[0]!=type||p[5]!=0||p[6]!=seq) return -1;
    *m=(ccid_message){p[0],p[5],p[6],p[7],p[8],p[9],p+10,n-10};
    if((p[7]&0xc0)==0x80) return 1; /* time extension, bError is multiplier */
    if((p[7]&0xc0)||((p[7]&3)==2)) return -1;
    return 0;
}

int ccid_apdu_exchange(ccid_apdu_link link,void *ctx,bool extended,size_t max_payload,const uint8_t *tx,size_t txn,uint8_t *rx,size_t *rxn) {
    if(!max_payload||(!extended&&txn>max_payload)) return -1;
    size_t sent=0,got=0;unsigned steps=0;uint8_t chain=0;
    do {
        size_t piece=txn-sent;if(piece>max_payload) piece=max_payload;
        bool last=sent+piece==txn;
        uint16_t level=sent?(last?2:3):(last?0:1);
        size_t n=last?*rxn:0;
        int r=link(ctx,level,tx+sent,piece,rx,&n,&chain);if(r) return r;
        if(!last&&(n||chain!=0x10)) return -1;
        sent+=piece;if(last) got=n;
        if(++steps>128) return -1;
    } while(sent<txn);
    if(!extended&&chain) return -1;
    while(chain==1||chain==3||chain==0x10) {
        size_t n=*rxn-got;
        int r=link(ctx,0x10,NULL,0,rx+got,&n,&chain);if(r) return r;
        got+=n;if(++steps>128) return -1;
    }
    if(chain!=0&&chain!=2) return -1;
    *rxn=got;return 0;
}
