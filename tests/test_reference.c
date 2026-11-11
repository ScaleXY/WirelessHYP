/* Test-only adapter for the actual OpenSC 3856d69 SM functions, LGPL-2.1+. */
#include "epass2003.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#define SM_PLAIN 0
#define KEY_TYPE_AES 1
#define KEY_TYPE_DES 2
#define SC_SUCCESS 0
#define SC_ERROR_INVALID_ARGUMENTS -1
#define SC_ERROR_INVALID_DATA -1
#define SC_ERROR_BUFFER_TOO_SMALL -1
#define SC_ERROR_INTERNAL -1
#define SC_ERROR_CARD_CMD_FAILED -1
#define SC_APDU_CASE_3_SHORT 3
#define SC_APDU_CASE_4_SHORT 4
#define SC_APDU_CASE_4_EXT 0x14
#define LOG_TEST_RET(ctx,r,msg) do {if((r)<0) return (r);} while(0)
#define LOG_FUNC_CALLED(ctx) ((void)0)
#define LOG_FUNC_RETURN(ctx,r) return (r)
#define sc_log(...) ((void)0)
typedef unsigned char u8;
struct sc_card {void *drv_data;void *ctx;};
struct sc_apdu {
    unsigned cla,ins,p1,p2;size_t lc,le,datalen,resplen;int cse;
    const unsigned char *data;unsigned char *resp;unsigned sw1,sw2;
};
typedef struct {unsigned char sm,smtype,sk_enc[16],sk_mac[16],icv_mac[16],bFipsCertification;} epass2003_exdata;
static int ref_cipher(const EVP_CIPHER *alg,const uint8_t *key,const uint8_t *iv,const uint8_t *in,size_t n,uint8_t *out,int dec) {
    EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new();int len,tail;
    assert(c);assert(EVP_CipherInit_ex(c,alg,NULL,key,iv,!dec));assert(EVP_CIPHER_CTX_set_padding(c,0));
    assert(EVP_CipherUpdate(c,out,&len,in,(int)n));assert(EVP_CipherFinal_ex(c,out+len,&tail));
    EVP_CIPHER_CTX_free(c);return 0;
}
static int aes128_encrypt_ecb(struct sc_card *c,const uint8_t *k,int ks,const uint8_t *in,size_t n,uint8_t *out) {(void)c;(void)ks;return ref_cipher(EVP_aes_128_ecb(),k,NULL,in,n,out,0);}
static int des3_encrypt_ecb(struct sc_card *c,const uint8_t *k,int ks,const uint8_t *in,size_t n,uint8_t *out) {(void)c;uint8_t key[24];memcpy(key,k,(size_t)ks);if(ks==16)memcpy(key+16,k,8);return ref_cipher(EVP_des_ede3_ecb(),key,NULL,in,n,out,0);}
static int aes128_encrypt_cbc(struct sc_card *c,const uint8_t *k,int ks,uint8_t *iv,const uint8_t *in,size_t n,uint8_t *out) {(void)c;(void)ks;return ref_cipher(EVP_aes_128_cbc(),k,iv,in,n,out,0);}
static int aes128_decrypt_cbc(struct sc_card *c,const uint8_t *k,int ks,uint8_t *iv,const uint8_t *in,size_t n,uint8_t *out) {(void)c;(void)ks;return ref_cipher(EVP_aes_128_cbc(),k,iv,in,n,out,1);}
static int des3_encrypt_cbc(struct sc_card *c,const uint8_t *k,int ks,uint8_t *iv,const uint8_t *in,size_t n,uint8_t *out) {
    (void)c;uint8_t key[24];memcpy(key,k,(size_t)ks);if(ks==16) memcpy(key+16,k,8);
    return ref_cipher(EVP_des_ede3_cbc(),key,iv,in,n,out,0);
}
static int des3_decrypt_cbc(struct sc_card *c,const uint8_t *k,int ks,uint8_t *iv,const uint8_t *in,size_t n,uint8_t *out) {
    (void)c;uint8_t key[24];memcpy(key,k,(size_t)ks);if(ks==16) memcpy(key+16,k,8);
    return ref_cipher(EVP_des_ede3_cbc(),key,iv,in,n,out,1);
}
/* EDE3 K,K,K equals single DES; avoids depending on OpenSSL legacy provider. */
static int des_encrypt_cbc(struct sc_card *c,const uint8_t *k,int ks,uint8_t *iv,const uint8_t *in,size_t n,uint8_t *out) {(void)c;(void)ks;uint8_t key[24];for(int i=0;i<3;i++) memcpy(key+8*i,k,8);return ref_cipher(EVP_des_ede3_cbc(),key,iv,in,n,out,0);}
static int des_decrypt_cbc(struct sc_card *c,const uint8_t *k,int ks,uint8_t *iv,const uint8_t *in,size_t n,uint8_t *out) {(void)c;(void)ks;uint8_t key[24];for(int i=0;i<3;i++) memcpy(key+8*i,k,8);return ref_cipher(EVP_des_ede3_cbc(),key,iv,in,n,out,1);}
/* FIPS commands are not in the supported firmware path. */
static int aes128_encrypt_cmac(struct sc_card *c,const uint8_t *k,int ks,const uint8_t *in,size_t n,uint8_t *out) {(void)c;(void)k;(void)ks;(void)in;(void)n;(void)out;abort();}
static int aes128_encrypt_cmac_ft(struct sc_card *c,const uint8_t *k,int ks,const uint8_t *in,size_t n,uint8_t *out,uint8_t *iv) {(void)iv;return aes128_encrypt_cmac(c,k,ks,in,n,out);}
#define EVP_MAX_IV_LENGTH 16
static const uint8_t *sc_asn1_find_tag(void *ctx,const uint8_t *p,size_t n,unsigned tag,size_t *len) {
    (void)ctx;ep_tlv t;if(ep_tlv_find(p,n,(uint8_t)tag,&t)) return NULL;*len=t.n;return t.v;
}
static int sc_asn1_read_tag(const uint8_t **p,size_t n,unsigned *cla,unsigned *tag,size_t *len) {
    ep_tlv t;const uint8_t *q=*p;
    if(n>3&&q[0]==0x87&&q[1]>=0x80&&q[1]!=0x82&&q[2]==1) {t=(ep_tlv){.tag=q[0],.v=q+2,.n=q[1]};}
    else if(ep_tlv_next(&q,&n,&t)) return -1;
    *cla=t.tag&0xe0;*tag=t.tag&31;*len=t.n;*p=t.v;return 0;
}
static int sc_check_sw(struct sc_card *c,unsigned a,unsigned b) {(void)c;return a==0x90&&b==0?0:-1;}
static uint8_t g_random[8],init_response[28],last_external[16];
static int fixed_random(uint8_t *p,size_t n) {for(size_t i=0;i<n;i++)p[i]=(uint8_t)i;return 1;}
#define RAND_bytes fixed_random
static void sc_format_apdu(struct sc_card *c,struct sc_apdu *a,int cse,unsigned ins,unsigned p1,unsigned p2) {(void)c;memset(a,0,sizeof(*a));a->cse=cse;a->ins=ins;a->p1=p1;a->p2=p2;}
static int epass2003_transmit_apdu(struct sc_card *c,struct sc_apdu *a) {
    (void)c;
    if(a->ins==0x50) {assert(a->lc==8&&!memcmp(a->data,g_random,8));memcpy(a->resp,init_response,28);a->resplen=28;}
    else {assert(a->ins==0x82&&a->p1==3&&a->lc==16);memcpy(last_external,a->data,16);}
    a->sw1=0x90;a->sw2=0;return 0;
}
#include "opensc_sm.inc"
static void hex(const uint8_t *p,size_t n) {for(size_t i=0;i<n;i++) printf("%02x",p[i]);puts("");}
int main(void) {
    for(unsigned aes=0;aes<2;aes++) {
        ep_sm ours={.aes=aes,.active=true};epass2003_exdata ref={.sm=1,.smtype=aes?1:2};
        for(unsigned j=0;j<16;j++) {ours.enc[j]=ref.sk_enc[j]=(uint8_t)(j+1);ours.mac[j]=ref.sk_mac[j]=(uint8_t)(0x10+j);ours.icv[j]=ref.icv_mac[j]=(uint8_t)j;}
        if(!aes) {memset(ours.icv+8,0,8);memset(ref.icv_mac+8,0,8);}
        struct sc_card card={.drv_data=&ref};
        uint8_t payload[232];for(unsigned j=0;j<sizeof(payload);j++) payload[j]=(uint8_t)j;
        for(unsigned test=0;test<5;test++) {
            unsigned lens[]={0,2,8,32,232};unsigned les[]={96,0,0,0,0};
            ep_apdu a={.cla=0,.ins=test==3?0x2a:0xa4,.p1=0,.p2=0,.data=payload,.lc=lens[test],.response=test!=1&&test!=2,.le=les[test]};
            uint8_t out[4096],expected[4096]={0},smdata[4096]={0};size_t n=sizeof(out),en=sizeof(expected);
            struct sc_apdu plain={.cla=0x0c,.ins=a.ins,.p1=a.p1,.p2=a.p2,.lc=a.lc,.data=payload,.le=a.le,.resplen=a.response?256:0};
            struct sc_apdu sm={.data=smdata};
            assert(!encode_apdu(&card,&plain,&sm,expected,&en));
            assert(!ep_sm_wrap(&ours,&a,out,&n));
            /* encode_apdu omits the outer Le when no DO97 is requested;
             * sc_apdu_get_octets still emits Le=00 for the case-4 APDU. */
            if(!a.response || sm.cse==SC_APDU_CASE_4_EXT) expected[en++]=0;
            if(n!=en||memcmp(out,expected,n)) {fprintf(stderr,"wrap mismatch aes=%u test=%u n=%zu expected=%zu\n",aes,test,n,en);hex(out,n);hex(expected,en);return 1;}
            printf("OpenSC %s wrap[%u]: ",aes?"AES":"3DES",test);hex(out,n);
            assert(!memcmp(ours.icv,ref.icv_mac,16));
        }
        /* Build INITIALIZE UPDATE fixture with independent OpenSSL. Execute
         * actual gen_init_key/verify_init_key, then compare ported derivation. */
        uint8_t initial[16],derivation[16],session[16],challenge[32]={0},cryptogram[32],iv0[16]={0};
        memset(init_response,0,sizeof(init_response));
        for(unsigned j=0;j<16;j++) initial[j]=(uint8_t)(j+1);
        for(unsigned j=0;j<8;j++) {g_random[j]=(uint8_t)j;init_response[12+j]=(uint8_t)(j+8);}
        memcpy(derivation,init_response+16,4);memcpy(derivation+4,g_random,4);
        memcpy(derivation+8,init_response+12,4);memcpy(derivation+12,g_random+4,4);
        if(aes) aes128_encrypt_ecb(&card,initial,16,derivation,16,session);
        else des3_encrypt_ecb(&card,initial,16,derivation,16,session);
        memcpy(challenge,g_random,8);memcpy(challenge+8,init_response+12,8);challenge[16]=0x80;
        if(aes) aes128_encrypt_cbc(&card,session,16,iv0,challenge,32,cryptogram);
        else des3_encrypt_cbc(&card,session,16,iv0,challenge,24,cryptogram);
        memcpy(init_response+20,cryptogram+16,8);
        epass2003_exdata derived={.sm=1,.smtype=aes?1:2};struct sc_card dcard={.drv_data=&derived};uint8_t result[256];
        assert(!gen_init_key(&dcard,initial,initial,result,derived.smtype));
        assert(!verify_init_key(&dcard,result+12,derived.smtype));
        ep_sm dours={.aes=aes};uint8_t ext[16];
        assert(!ep_sm_derive(&dours,g_random,init_response,28,ext));
        assert(!memcmp(dours.enc,derived.sk_enc,16)&&!memcmp(dours.mac,derived.sk_mac,16));
        assert(!memcmp(dours.icv,derived.icv_mac,16)&&!memcmp(ext,last_external,16));
        printf("OpenSC %s INITIALIZE UPDATE: ",aes?"AES":"3DES");hex(init_response,28);
        printf("OpenSC %s EXTERNAL AUTH: ",aes?"AES":"3DES");hex(ext,16);
        /* Build a response with independent OpenSSL CBC and retail MAC, then
         * run both the original unwrap and the firmware unwrap on it. */
        uint8_t wire[256],pad[80]={0},cipher[80],mac[128],tmp[8],iv[16]={0};
        for(unsigned j=0;j<64;j++) pad[j]=(uint8_t)(j+0x20);
        pad[64]=0x80;size_t b=aes?16:8,cn=64+b;
        if(aes) aes128_encrypt_cbc(&card,ref.sk_enc,16,iv,pad,cn,cipher);
        else des3_encrypt_cbc(&card,ref.sk_enc,16,iv,pad,cn,cipher);
        size_t w=0;wire[w++]=0x87;wire[w++]=(uint8_t)(cn+1);wire[w++]=1;memcpy(wire+w,cipher,cn);w+=cn;
        memcpy(wire+w,"\x99\x02\x90\x00",4);w+=4;
        memset(pad,0,sizeof(pad));uint8_t macin[128]={0};memcpy(macin,wire,w);macin[w]=0x80;size_t mn=((w+1+b-1)/b)*b;
        if(aes) aes128_encrypt_cbc(&card,ref.sk_mac,16,ref.icv_mac,macin,mn,mac);
        else {
            des_encrypt_cbc(&card,ref.sk_mac,8,ref.icv_mac,macin,mn,mac);
            des_decrypt_cbc(&card,ref.sk_mac+8,8,iv,mac+mn-8,8,tmp);
            des_encrypt_cbc(&card,ref.sk_mac,8,iv,tmp,8,mac+mn-8);
        }
        wire[w++]=0x8e;wire[w++]=8;memcpy(wire+w,mac+mn-b,8);w+=8;
        uint8_t original[128]={0},decoded[128];
        struct sc_apdu sm={.resp=wire,.resplen=w,.sw1=0x90,.sw2=0};
        struct sc_apdu plain={.resp=original,.resplen=sizeof(original)};
        assert(!epass2003_sm_unwrap_apdu(&card,&sm,&plain));
        wire[w++]=0x90;wire[w++]=0;
        size_t dn=sizeof(decoded);uint16_t sw;
        assert(!ep_sm_unwrap(&ours,wire,w,decoded,&dn,&sw));assert(dn==plain.resplen&&dn==64&&!memcmp(decoded,original,dn));
        printf("OpenSC %s response: ",aes?"AES":"3DES");hex(wire,w);
        wire[w-3]^=1;dn=sizeof(decoded);assert(ep_sm_unwrap(&ours,wire,w,decoded,&dn,&sw));
    }
    puts("PASS: original OpenSC SM wrap/unwrap comparison (10 commands, 2 responses)");
    return 0;
}
