/* SPDX-License-Identifier: LGPL-2.1-or-later
 * PKCS#15 subset following OpenSC asn1.c, pkcs15-prkey.c,
 * pkcs15-pubkey.c and pkcs15-pin.c at 3856d69. */
#include "epass2003.h"
#include <string.h>
int ep_tlv_next(const uint8_t **p,size_t *n,ep_tlv *t) {
    if(*n<2||((**p&31)==31)) return EP_FORMAT;
    const uint8_t *s=*p;size_t h=2,len=s[1];
    if(len&0x80) {
        unsigned k=(unsigned)(len&0x7f);
        if(k==0||k>2||*n<2+k) return EP_FORMAT;
        len=0;h+=k;for(unsigned i=0;i<k;i++) len=(len<<8)|s[2+i];
    }
    if(len>*n-h) return EP_FORMAT;
    *t=(ep_tlv){.tag=s[0],.v=s+h,.n=len,.total=h+len};
    *p+=t->total;*n-=t->total;return 0;
}
int ep_tlv_find(const uint8_t *p,size_t n,uint8_t tag,ep_tlv *t) {
    while(n) {if(ep_tlv_next(&p,&n,t)) return EP_FORMAT;if(t->tag==tag) return 0;}
    return EP_KEY_NOT_FOUND;
}
static int number(const ep_tlv *t,unsigned *v) {
    if(!t->n||t->n>3||(t->v[0]&0x80)) return EP_FORMAT;
    *v=0;for(size_t i=0;i<t->n;i++) *v=(*v<<8)|t->v[i];return 0;
}
static int path_decode(const ep_tlv *seq,ep_path *path) {
    const uint8_t *p=seq->v;size_t n=seq->n;ep_tlv t;
    memset(path,0,sizeof(*path));
    if(seq->tag!=0x30||ep_tlv_next(&p,&n,&t)||t.tag!=4||!t.n||t.n>16||(t.n&1)) return EP_FORMAT;
    path->n=t.n;memcpy(path->bytes,t.v,t.n);
    if(n) {
        if(ep_tlv_next(&p,&n,&t)||t.tag!=2||number(&t,&path->index)) return EP_FORMAT;
        if(n) {
            if(ep_tlv_next(&p,&n,&t)||t.tag!=0x80||number(&t,&path->count)) return EP_FORMAT;
            path->has_count=true;
        }
    }
    return n?EP_FORMAT:0;
}
int ep_p15_odf(const uint8_t *p,size_t n,uint8_t tag,ep_path *path) {
    ep_tlv entry,t;
    while(n&&*p!=0&&*p!=0xff) {
        if(ep_tlv_next(&p,&n,&entry)) return EP_FORMAT;
        if(entry.tag==tag) {
            const uint8_t *q=entry.v;size_t m=entry.n;
            if(ep_tlv_next(&q,&m,&t)||m) return EP_FORMAT;
            return path_decode(&t,path);
        }
    }
    return EP_KEY_NOT_FOUND;
}
/* CommonObjectAttributes, CommonKey/AuthAttributes, optional subclass,
 * [1] EXPLICIT type attributes. No recursive searches into arbitrary blobs. */
static int object_parts(const ep_tlv *obj,ep_tlv *common,ep_tlv *klass,ep_tlv *type) {
    const uint8_t *p=obj->v;size_t n=obj->n;
    if(ep_tlv_next(&p,&n,common)||common->tag!=0x30||ep_tlv_next(&p,&n,klass)||klass->tag!=0x30) return EP_FORMAT;
    if(ep_tlv_next(&p,&n,type)) return EP_FORMAT;
    if(type->tag==0xa0&&ep_tlv_next(&p,&n,type)) return EP_FORMAT;
    if(type->tag!=0xa1||n) return EP_FORMAT;
    p=type->v;n=type->n;ep_tlv inner;
    if(ep_tlv_next(&p,&n,&inner)||inner.tag!=0x30||n) return EP_FORMAT;
    *type=inner;return 0;
}
int ep_p15_key(const uint8_t *p,size_t n,ep_key *key) {
    ep_tlv obj,common,klass,type,id,t;
    while(n&&*p!=0&&*p!=0xff) {
        if(ep_tlv_next(&p,&n,&obj)) return EP_FORMAT;
        if(obj.tag!=0xa0) continue; /* EC choice; skip RSA/GOST objects */
        if(object_parts(&obj,&common,&klass,&type)) return EP_FORMAT;
        const uint8_t *q=klass.v;size_t m=klass.n;
        if(ep_tlv_next(&q,&m,&id)||id.tag!=4) return EP_FORMAT;
        if(id.n!=1||id.v[0]!=1) continue;
        memset(key,0,sizeof(*key));
        if(!ep_tlv_find(common.v,common.n,4,&t)) {
            if(!t.n||t.n>sizeof(key->auth)) return EP_FORMAT;
            memcpy(key->auth,t.v,t.n);key->authn=t.n;
        }
        if(!ep_tlv_find(klass.v,klass.n,2,&t)) {
            if(number(&t,&key->ref)||key->ref>255) return EP_FORMAT;
            key->has_ref=true;
        }
        q=type.v;m=type.n;
        if(ep_tlv_next(&q,&m,&t)) return EP_FORMAT;
        int r=path_decode(&t,&key->path);
        if(r) return r;
        /* Optional private fieldSize extension: P-256 only. Public keyInfo
         * is not fieldSize, so enforce the public point's exact length later. */
        return 0;
    }
    return EP_KEY_NOT_FOUND;
}
int ep_p15_pin(const uint8_t *p,size_t n,const uint8_t *auth,size_t authn,uint8_t *ref) {
    ep_tlv obj,common,klass,type,id,t;
    if(!authn) return EP_FORMAT;
    while(n&&*p!=0&&*p!=0xff) {
        if(ep_tlv_next(&p,&n,&obj)) return EP_FORMAT;
        if(obj.tag!=0x30) continue;
        if(object_parts(&obj,&common,&klass,&type)) return EP_FORMAT;
        if(ep_tlv_find(klass.v,klass.n,4,&id)) return EP_FORMAT;
        if(id.n!=authn||memcmp(id.v,auth,authn)) continue;
        unsigned v;
        if(ep_tlv_find(type.v,type.n,0x80,&t)||number(&t,&v)||v>0x7f) return EP_FORMAT;
        *ref=(uint8_t)v;return 0;
    }
    return EP_KEY_NOT_FOUND;
}
int ep_point(const uint8_t *p,size_t n,uint8_t point[65]) {
    ep_tlv t;
    if(ep_tlv_next(&p,&n,&t)||t.tag!=4||t.n!=65||t.v[0]!=4) return EP_FORMAT;
    /* EF allocation can exceed the DER object. Only zero/FF padding allowed. */
    for(size_t i=0;i<n;i++) if(p[i]!=0&&p[i]!=0xff) return EP_FORMAT;
    memcpy(point,t.v,65);return 0;
}
