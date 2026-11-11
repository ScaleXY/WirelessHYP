#include "epass2003.h"
#include "ccid_host.h"
#include "signer_proto.h"
#include "service.h"
#include "web_logic.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static size_t unhex(const char *s,uint8_t *out) {
    size_t n=strlen(s)/2;for(size_t i=0;i<n;i++) {unsigned v;assert(sscanf(s+2*i,"%2x",&v)==1);out[i]=(uint8_t)v;}return n;
}
static void test_crypto(void) {
    uint8_t key[32],in[64],out[64],plain[64],expect[64],iv[16]={0};
    unhex("133457799bbcdff1",key);unhex("0123456789abcdef",in);unhex("85e813540f0ab405",expect);
    ep_des_block(key,false,in,out);assert(!memcmp(out,expect,8));ep_des_block(key,true,out,plain);assert(!memcmp(plain,in,8));
    unhex("2b7e151628aed2a6abf7158809cf4f3c",key);
    unhex("6bc1bee22e409f96e93d7e117393172a",in);
    unhex("3ad77bb40d7a3660a89ecaf32466ef97",expect);
    assert(!ep_aes_block(key,in,out)&&!memcmp(out,expect,16));
    /* RFC 4493 CMAC examples 1 and 2. */
    unhex("bb1d6929e95937287fa37d129b756746",expect);
    assert(!ep_cmac(key,in,0,out)&&!memcmp(out,expect,16));
    unhex("070a16b46b4d4144f79bdd9dd04a287c",expect);
    assert(!ep_cmac(key,in,16,out)&&!memcmp(out,expect,16));
    assert(!ep_cipher(true,true,false,key,16,iv,in,16,out));assert(!ep_cipher(true,true,true,key,16,iv,out,16,plain));assert(!memcmp(plain,in,16));
    unhex("a9993e364706816aba3e25717850c26c9cd0d89d",expect);
    assert(!ep_sha1((const uint8_t *)"abc",3,out)&&!memcmp(out,expect,20));
    /* Test non-FIPS session derivation against independent fixed vectors. */
    puts("PASS: DES, AES, CMAC and SHA-1 known-answer tests");
}
static void test_low_s(void) {
    const char *half="7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8";
    uint8_t sig[64]={0},expected[32];sig[31]=1;unhex(half,sig+32);memcpy(expected,sig+32,32);
    assert(!ep_low_s(sig)&&!memcmp(sig+32,expected,32));
    sig[63]++;assert(!ep_low_s(sig)&&!memcmp(sig+32,expected,32));
    unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",sig+32);
    assert(!ep_low_s(sig));for(unsigned i=32;i<63;i++) assert(sig[i]==0);assert(sig[63]==1);
    memset(sig+32,0,32);assert(ep_low_s(sig));
    unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",sig+32);assert(ep_low_s(sig));
    puts("PASS: low-s boundaries (n/2, n/2+1, n-1), invalid scalars");
}
static void test_proto(void) {
    proto_request r;char line[512],hex[67];uint8_t bytes[32]={0};proto_hex(bytes,32,hex);
    assert(!proto_digest(hex,bytes));assert(proto_digest("0X0000",bytes));
    hex[65]='G';assert(proto_digest(hex,bytes));hex[65]='A';assert(!proto_digest(hex,bytes));
    snprintf(line,sizeof(line),"{\"id\":9223372036854775807,\"digest\":\"%s\"}",hex);
    assert(!proto_parse(line,&r)&&r.id==INT64_MAX&&r.op==OP_SIGN);
    assert(!proto_parse("{\"id\":-9223372036854775808,\"op\":\"pubkey\"}",&r)&&r.id==INT64_MIN);
    const char *bad[]={"{\"id\":1.0}","{\"id\":01}","{\"id\":9223372036854775808}","{\"id\":1,\"id\":2}","{\"op\":\"status\",}","{} true","[]","{\"x\":1}","{\"op\":\"set_pin\",\"pin\":\"a\\u0000b\"}","{\"digest\":null}"};
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);i++) assert(proto_parse(bad[i],&r));
    assert(!proto_parse("{\"id\":7,\"op\":\"set_pin\",\"pin\":\"12\\u003334\"}",&r)&&!strcmp(r.pin,"12334"));
    assert(!proto_parse("{\"id\":4,\"op\":\"status\"}",&r));
    proto_status(line,sizeof(line),&r,"present",true,false,"x\"y");
    assert(!strcmp(line,"{\"id\":4,\"token\":\"present\",\"pin_set\":true,\"pin_rejected\":false,\"usb\":\"x\\\"y\"}"));
    proto_error(line,sizeof(line),&r,true,"bad \"PIN\"\n");
    assert(!strcmp(line,"{\"id\":4,\"fatal\":\"pin_rejected\",\"error\":\"bad \\\"PIN\\\"\\u000a\"}"));
    uint8_t sig[64]={0},point[65]={4};sig[31]=1;sig[63]=2;
    proto_signature(line,sizeof(line),&r,sig,11.2);assert(strstr(line,"\"ms\":11.200")&&strstr(line,"\"r\":\"0x"));
    proto_public(line,sizeof(line),NULL,true,point);assert(!strncmp(line,"{\"ready\":true,",14));
    proto_ok(line,sizeof(line),&r);assert(!strcmp(line,"{\"id\":4,\"ok\":true}"));
    puts("PASS: digest validation, strict JSON parsing and response formatting");
}
static void test_ccid(void) {
    uint8_t frame[64],args[]={0,0,0},apdu[]={0,0xa4,0,0};
    int n=ccid_encode(0x6f,0xff,args,apdu,4,frame,sizeof(frame));assert(n==14);
    assert(!memcmp(frame,"\x6f\x04\x00\x00\x00\x00\xff\x00\x00\x00\x00\xa4\x00\x00",14));
    frame[0]=0x80;ccid_message m;assert(!ccid_decode(frame,14,0x80,0xff,&m)&&m.n==4);
    frame[7]=0x80;frame[8]=2;assert(ccid_decode(frame,14,0x80,0xff,&m)==1);
    frame[7]=0x40;assert(ccid_decode(frame,14,0x80,0xff,&m)<0);
    frame[7]=0;assert(ccid_decode(frame,13,0x80,0xff,&m)<0);assert(ccid_decode(frame,14,0x80,0,&m)<0);
    frame[5]=1;assert(ccid_decode(frame,14,0x80,0xff,&m)<0);
    assert(ccid_encode(0x6f,0,args,apdu,4,frame,13)<0);
    puts("PASS: CCID framing, sequence/slot checks, time extension and errors");
}
static void test_pkcs15(void) {
    uint8_t odf[]={0xa0,8,0x30,6,4,4,0x3f,0,0x44,3,0xa1,6,0x30,4,4,2,0x44,4,0,0};ep_path path;
    assert(!ep_p15_odf(odf,sizeof(odf),0xa0,&path)&&path.n==4&&path.bytes[3]==3);
    assert(!ep_p15_odf(odf,sizeof(odf),0xa1,&path)&&path.n==2&&path.bytes[1]==4);
    assert(ep_p15_odf(odf,5,0xa0,&path));
    /* EC PKCS15 object with common attrs authId=01, class attrs id=01,
     * keyReference=1, and type [1] -> SEQUENCE -> Path(2901). */
    uint8_t actual[128];size_t actualn=unhex("a01e3003040101300a04010103020040020101a10b3009300704022901020100",actual);
    ep_key k;assert(!ep_p15_key(actual,actualn,&k)&&k.has_ref&&k.ref==1&&k.authn==1&&k.path.bytes[1]==1);
    actual[11]=2;assert(ep_p15_key(actual,actualn,&k)==EP_KEY_NOT_FOUND);actual[11]=1;
    uint8_t auth[128];size_t authlen=unhex("301e30003003040101a1153013030200000a0101020104020110020110800102",auth);
    uint8_t ref=0,id=1;assert(!ep_p15_pin(auth,authlen,&id,1,&ref)&&ref==2);
    uint8_t point[67]={4,65,4},out[65];assert(!ep_point(point,sizeof(point),out)&&out[0]==4);
    point[1]=64;assert(ep_point(point,sizeof(point),out));
    uint8_t indefinite[]={0x30,0x80};const uint8_t *p=indefinite;size_t n=2;ep_tlv t;assert(ep_tlv_next(&p,&n,&t));
    puts("PASS: bounded DER, ODF, EC key ID/path/reference, AODF and public point");
}
typedef struct {unsigned verify,prepare,sign,reset,ready;bool reject,storage_fail,clear_fail;pin_marker stored;uint32_t gen;int sign_fail;} mock;
static bool m_present(void *p) {(void)p;return true;}
static uint32_t m_gen(void *p) {return ((mock *)p)->gen;}
static void m_reset(void *p) {((mock *)p)->reset++;}
static int m_prepare(void *p) {((mock *)p)->prepare++;return 0;}
static int m_verify(void *p,const char *pin) {mock *m=p;assert(!strcmp(pin,"1234"));assert(m->stored.version==1);m->verify++;return m->reject?EP_PIN_REJECTED:0;}
static int m_public(void *p,uint8_t out[65]) {(void)p;memset(out,0,65);out[0]=4;return 0;}
static int m_sign(void *p,const uint8_t in[32],uint8_t out[64]) {(void)in;memset(out,0,64);mock *m=p;m->sign++;if(m->sign_fail>0) {m->sign_fail--;return EP_IO;}return 0;}
static uint16_t m_sw(void *p) {return ((mock *)p)->reject?0x63c2:0x9000;}
static uint64_t m_time(void *p) {(void)p;return 123456;}
static int m_save(void *p,const pin_marker *marker) {mock *m=p;if(m->storage_fail||(!marker&&m->clear_fail)) return -1;if(marker)m->stored=*marker;else memset(&m->stored,0,sizeof(m->stored));return 0;}
static void m_ready(void *p,const uint8_t out[65],bool changed) {(void)out;(void)changed;((mock *)p)->ready++;}
static signer_ops m_ops(mock *m) {return (signer_ops){m,m_present,m_gen,m_reset,m_prepare,m_verify,m_public,m_sign,m_sw,m_time,m_save,m_ready};}
static void test_marker(void) {
    mock m={.reject=true};signer_ops o=m_ops(&m);signer_service s;
    signer_init(&s,&o,"1234",NULL);assert(signer_open(&s)==EP_PIN_REJECTED&&m.verify==1&&s.rejected&&m.stored.code==0x63c2);
    assert(signer_open(&s)==EP_PIN_REJECTED&&m.verify==1);m.gen++;
    assert(signer_open(&s)==EP_PIN_REJECTED&&m.verify==1);
    signer_init(&s,&o,"1234",&m.stored);assert(signer_open(&s)==EP_PIN_REJECTED&&m.verify==1);
    uint8_t digest[32]={0},sig[64];assert(signer_run(&s,digest,sig)==EP_PIN_REJECTED&&m.verify==1);
    m.reject=false;assert(!signer_set_pin(&s,"1234"));assert(!signer_open(&s)&&m.verify==2&&s.ready&&!m.stored.version);
    m.sign_fail=1;assert(!signer_run(&s,digest,sig)&&m.sign==2&&m.verify==3);
    m.sign_fail=2;assert(signer_run(&s,digest,sig)==EP_IO&&m.sign==4); /* exactly one retry */
    m=(mock){.storage_fail=true};o=m_ops(&m);signer_init(&s,&o,"1234",NULL);assert(signer_open(&s)==EP_STORAGE&&!m.verify);
    m=(mock){.clear_fail=true};o=m_ops(&m);signer_init(&s,&o,"1234",NULL);assert(signer_open(&s)==EP_STORAGE&&m.verify==1&&s.rejected&&m.stored.version);
    assert(signer_open(&s)==EP_PIN_REJECTED&&m.verify==1);
    /* Simulate reboot from the pre-VERIFY write-ahead guard. */
    m=(mock){.stored={.version=1,.code=EP_IO}};o=m_ops(&m);signer_init(&s,&o,"1234",&m.stored);assert(signer_open(&s)==EP_PIN_REJECTED&&!m.verify);
    /* Boot seeding never calls signer_set_pin or clears a stored guard. */
    const char *persisted=NULL;bool seeded=false;
    assert(hyp_should_seed(false,seeded,"1234"));persisted="1234";seeded=true;
    signer_init(&s,&o,persisted,&m.stored);
    assert(s.rejected&&s.pin_set&&signer_open(&s)==EP_PIN_REJECTED&&!m.verify&&m.stored.version==1);
    assert(!hyp_should_seed(true,seeded,"9999")&&!strcmp(persisted,"1234"));
    puts("PASS: PIN boot seed preserves existing PIN and rejected marker");
    puts("PASS: rejected VERIFY exactly once across opens, replug and reboot; durable pre-VERIFY guard, NVS failures, one retry");
}
static unsigned apdu_calls;
static int mock_card(void *ctx,const uint8_t *tx,size_t n,uint8_t *rx,size_t *rn) {
    (void)ctx;apdu_calls++;
    if(apdu_calls==1) {assert(n==5&&!memcmp(tx,"\x00\x84\x00\x00\x10",5));assert(*rn>=18);for(unsigned i=0;i<16;i++) rx[i]=(uint8_t)i;rx[16]=0x90;rx[17]=0;*rn=18;return 0;}
    assert(apdu_calls==2&&n==13&&!memcmp(tx,"\x00\x82\x01\x82\x08",5));
    uint8_t expected[8];unhex("914f754a76496aea",expected);
    assert(!memcmp(tx+5,expected,8)); /* Independent OpenSSL 3DES fixture. */
    rx[0]=0x90;rx[1]=0;*rn=2;return 0;
}
static void test_pin_apdu(void) {
    ep_card c;ep_card_init(&c,mock_card,NULL);c.pin_ref=2;apdu_calls=0;
    assert(!ep_card_verify(&c,"1234")&&apdu_calls==2); /* no post-VERIFY retries query */
    assert(ep_card_verify(&c,"1")==EP_PIN_REJECTED&&apdu_calls==2);
    assert(ep_pin_sw(0x63c0)&&ep_pin_sw(0x63cf)&&ep_pin_sw(0x6983)&&ep_pin_sw(0x6984)&&ep_pin_sw(0x6700));
    puts("PASS: PIN challenge/auth APDUs; no retries query after success; local PIN length refusal");
}
static size_t t1_reply(uint8_t pcb,const uint8_t *p,size_t n,uint8_t *out) {
    out[0]=0;out[1]=pcb;out[2]=(uint8_t)n;memcpy(out+3,p,n);uint8_t lrc=0;
    for(size_t i=0;i<n+3;i++) lrc^=out[i];
    out[n+3]=lrc;
    return n+4;
}
static unsigned t1_calls;
static int t1_mock(void *ctx,const uint8_t *tx,size_t n,uint8_t *rx,size_t *rn) {
    (void)ctx;assert(n>=4);uint8_t lrc=0;for(size_t i=0;i<n;i++)lrc^=tx[i];assert(!lrc);
    uint8_t data[]={0x90,0};t1_calls++;
    if(t1_calls==1) {assert(tx[1]==0x20&&tx[2]==2);*rn=t1_reply(0x90,data,0,rx);}
    else if(t1_calls==2) {assert(tx[1]==0x40&&tx[2]==2);uint8_t wait=1;*rn=t1_reply(0xc3,&wait,1,rx);}
    else if(t1_calls==3) {assert(tx[1]==0xe3);*rn=t1_reply(0x20,data,1,rx);}
    else {assert(t1_calls==4&&tx[1]==0x90);*rn=t1_reply(0x40,data+1,1,rx);}
    return 0;
}
static void test_t1(void) {
    uint8_t atr[64];size_t n=unhex("3b9f958131fe9f006646530501001171df000003900080",atr);ccid_t1 s;
    assert(!ccid_t1_atr(&s,atr,n)&&s.ifsc==254&&!s.crc);
    assert(ccid_t1_atr(&s,atr,3));
    s=(ccid_t1){.ifsc=2};uint8_t apdu[]={0,0xa4,0,0},out[4];size_t outn=sizeof(out);t1_calls=0;
    assert(!ccid_t1_exchange(&s,t1_mock,NULL,apdu,sizeof(apdu),out,&outn));
    assert(outn==2&&out[0]==0x90&&out[1]==0&&t1_calls==4);
    puts("PASS: T=1 ATR, I/R chaining, sequence tracking and WTX");
}
static int mock_sign_card(void *ctx,const uint8_t *tx,size_t n,uint8_t *rx,size_t *rn) {
    (void)ctx;apdu_calls++;
    if(apdu_calls==1) {
        uint8_t expected[]={0,0x22,0x41,0xb6,7,0x80,1,0x92,0x81,2,0x29,0x20};
        assert(n==sizeof(expected)&&!memcmp(tx,expected,n));rx[0]=0x90;rx[1]=0;*rn=2;
    } else {
        assert(apdu_calls==2&&n==38&&!memcmp(tx,"\x00\x2a\x9e\x9a\x20",5)&&tx[37]==0);
        for(unsigned i=0;i<32;i++) assert(tx[5+i]==i);
        assert(*rn>=66);memset(rx,0,66);rx[31]=1;
        unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",rx+32);
        rx[64]=0x90;*rn=66;
    }
    return 0;
}
static void test_sign_apdu(void) {
    ep_card c;ep_card_init(&c,mock_sign_card,NULL);c.private_key.ref=1;
    uint8_t digest[32],sig[64];for(unsigned i=0;i<32;i++)digest[i]=(uint8_t)i;apdu_calls=0;
    assert(!ep_card_sign(&c,digest,sig)&&apdu_calls==2&&sig[63]==1);
    puts("PASS: exact MSE/PSO EC APDUs, unchanged 32-byte digest, raw signature and low-s");
}

static unsigned chain_calls;
static int chain_mock(void *ctx,uint16_t level,const uint8_t *tx,size_t n,uint8_t *rx,size_t *rn,uint8_t *chain) {
    (void)ctx;chain_calls++;
    if(chain_calls==1) {assert(level==1&&n==2&&tx[0]==0);*rn=0;*chain=0x10;}
    else if(chain_calls==2) {assert(level==3&&n==2&&tx[0]==2);*rn=0;*chain=0x10;}
    else if(chain_calls==3) {assert(level==2&&n==1&&tx[0]==4&&*rn>=1);rx[0]=0x90;*rn=1;*chain=1;}
    else {assert(chain_calls==4&&level==0x10&&!n&&tx==NULL&&*rn>=1);rx[0]=0;*rn=1;*chain=2;}
    return 0;
}
static void test_ccid_chain(void) {
    uint8_t tx[]={0,1,2,3,4},rx[4];size_t n=sizeof(rx);chain_calls=0;
    assert(!ccid_apdu_exchange(chain_mock,NULL,true,2,tx,sizeof(tx),rx,&n)&&n==2&&rx[0]==0x90&&!rx[1]&&chain_calls==4);
    chain_calls=0;assert(ccid_apdu_exchange(chain_mock,NULL,false,2,tx,sizeof(tx),rx,&n)&&!chain_calls);
    puts("PASS: CCID extended command/response chaining and short-reader bounds");
}
static int t1_crc_mock(void *ctx,const uint8_t *tx,size_t n,uint8_t *rx,size_t *rn) {
    (void)ctx;
    const uint8_t expected[]={0,0,4,0,0xa4,0,0,0x32,0x29};
    assert(n==sizeof(expected)&&!memcmp(tx,expected,n));
    const uint8_t response[]={0,0,2,0x90,0,0x9c,0x6d};
    assert(*rn>=sizeof(response));memcpy(rx,response,sizeof(response));*rn=sizeof(response);return 0;
}
static void test_t1_crc(void) {
    ccid_t1 s={.ifsc=32,.crc=true};uint8_t tx[]={0,0xa4,0,0},out[8];size_t n=sizeof(out);
    assert(!ccid_t1_exchange(&s,t1_crc_mock,NULL,tx,sizeof(tx),out,&n)&&n==2&&out[0]==0x90);
    puts("PASS: T=1 CRC vector (libccid ISO 3309 convention)");
}

#include "fixtures/sm_vectors.h"
static void test_sm_vectors(void) {
    for(unsigned aes=0;aes<2;aes++) {
        ep_sm sm={.aes=aes,.active=true};
        for(unsigned j=0;j<16;j++) {sm.enc[j]=(uint8_t)(j+1);sm.mac[j]=(uint8_t)(0x10+j);sm.icv[j]=(uint8_t)j;}
        if(!aes) memset(sm.icv+8,0,8);
        uint8_t payload[232],out[1024],expected[1024];for(unsigned j=0;j<232;j++)payload[j]=(uint8_t)j;
        for(unsigned i=0;i<5;i++) {
            unsigned lens[]={0,2,8,32,232},les[]={96,0,0,0,0};
            ep_apdu a={.ins=i==3?0x2a:0xa4,.data=payload,.lc=lens[i],.response=i!=1&&i!=2,.le=les[i]};
            size_t n=sizeof(out),en=unhex(sm_wrap_vectors[aes][i],expected);
            assert(!ep_sm_wrap(&sm,&a,out,&n)&&n==en&&!memcmp(out,expected,n));
        }
        size_t n=unhex(sm_response_vectors[aes],expected),outn=sizeof(out);uint16_t sw;
        assert(!ep_sm_unwrap(&sm,expected,n,out,&outn,&sw)&&sw==0x9000&&outn==64);
        for(unsigned i=0;i<64;i++)assert(out[i]==i+0x20);
        expected[n-3]^=1;outn=sizeof(out);assert(ep_sm_unwrap(&sm,expected,n,out,&outn,&sw));expected[n-3]^=1;
        expected[n-1]=1;outn=sizeof(out);assert(ep_sm_unwrap(&sm,expected,n,out,&outn,&sw));
        uint8_t host[8]={0,1,2,3,4,5,6,7},ext[16];ep_sm derived={.aes=aes};
        n=unhex(sm_init_vectors[aes],expected);assert(!ep_sm_derive(&derived,host,expected,n,ext));
        unhex(sm_external_vectors[aes],out);assert(!memcmp(ext,out,16));
        expected[27]^=1;assert(ep_sm_derive(&derived,host,expected,n,ext)==EP_CRYPTO);
    }
    puts("PASS: frozen OpenSC AES/3DES derivation, 10 wraps, 2 unwraps, tampered MAC/SW/cryptogram rejection");
}
static int read_mode;
static int read_mock(void *ctx,const uint8_t *tx,size_t n,uint8_t *rx,size_t *rn) {
    (void)ctx;(void)n;apdu_calls++;
    if(tx[1]==0xa4) {
        if(n>7) {static const uint8_t fci[]={0x6f,4,0x80,2,0,0x50,0x90,0};memcpy(rx,fci,sizeof(fci));*rn=sizeof(fci);}
        else {rx[0]=0x90;rx[1]=0;*rn=2;}
        return 0;
    }
    assert(tx[1]==0xb0&&tx[4]==0x50);
    if(read_mode==1) {rx[0]=0x6a;rx[1]=0x82;*rn=2;return 0;}
    if(read_mode==2) {rx[0]=0x62;*rn=1;return 0;}
    rx[0]=4;rx[1]=0x41;rx[2]=4;for(unsigned i=0;i<64;i++) rx[3+i]=(uint8_t)(i+1);
    rx[67]=0x62;rx[68]=0x82;*rn=69;return 0; /* short file: EOF with data */
}
static void test_read_file(void) {
    ep_card c;
    for(read_mode=0;read_mode<3;read_mode++) {
        ep_card_init(&c,read_mock,NULL);apdu_calls=0;
        memcpy(c.public_path.bytes,"\x3f\x00\x50\x15\x30\x01",6);c.public_path.n=6;
        int r=ep_card_public(&c);
        if(read_mode==0) assert(!r&&c.point[0]==4&&c.point[1]==1&&c.point[64]==64);
        else if(read_mode==1) assert(r==EP_IO);
        else assert(r==EP_FORMAT); /* malformed response ending in 62: never treated as EOF data */
    }
    puts("PASS: READ BINARY 6282 EOF accepted only on a well-formed response; errors not masked");
}
int main(void) {
    test_crypto();test_low_s();test_proto();test_ccid();test_pkcs15();test_marker();test_pin_apdu();test_read_file();test_sign_apdu();test_t1();test_t1_crc();test_ccid_chain();test_sm_vectors();
    puts("PASS: all native tests");return 0;
}
