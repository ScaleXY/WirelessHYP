#include "signer_proto.h"
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int unhex(int c) {if(c>='0'&&c<='9') return c-'0';if(c>='a'&&c<='f') return c-'a'+10;if(c>='A'&&c<='F') return c-'A'+10;return -1;}
int proto_digest(const char *s,uint8_t out[32]) {
    if(strlen(s)!=66||s[0]!='0'||s[1]!='x') return -1;
    for(unsigned i=0;i<32;i++) {int a=unhex(s[2+2*i]),b=unhex(s[3+2*i]);if(a<0||b<0) return -1;out[i]=(uint8_t)((a<<4)|b);}
    return 0;
}
static void whitespace(const char **p) {while(**p==' '||**p=='\t'||**p=='\r'||**p=='\n') (*p)++;}
static int string(const char **p,char *out,size_t cap) {
    if(*(*p)++!='"') return -1;
    size_t n=0;
    while(**p&&**p!='"') {
        unsigned char c=(unsigned char)*(*p)++;
        if(c<0x20||c>=0x80) return -1;
        if(c=='\\') {
            c=(unsigned char)*(*p)++;if(!c) return -1;
            switch(c) {
            case '"':case '\\':case '/':break;
            case 'b':c='\b';break;case 'f':c='\f';break;case 'n':c='\n';break;case 'r':c='\r';break;case 't':c='\t';break;
            case 'u': {
                unsigned v=0;for(unsigned i=0;i<4;i++) {if(!**p) return -1;int h=unhex(*(*p)++);if(h<0) return -1;v=(v<<4)|(unsigned)h;}
                if(!v||v>=0x80) return -1;
                c=(unsigned char)v;break;
            }
            default:return -1;
            }
        }
        if(n+1>=cap) return -1;
        out[n++]=(char)c;
    }
    if(**p!='"') return -1;
    (*p)++;out[n]=0;return 0;
}
const char *proto_parse(const char *line,proto_request *r) {
    memset(r,0,sizeof(*r));r->op=OP_SIGN;
    const char *p=line;unsigned fields=0;char op[24]="",digest[80]="";
    const char *error=NULL;
    if(strlen(line)>=PROTO_LINE_MAX) return "request too long";
    whitespace(&p);if(*p++!='{') return "bad JSON";whitespace(&p);
    if(*p!='}') for(;;) {
        char key[24];if(string(&p,key,sizeof(key))) return "bad JSON";
        whitespace(&p);if(*p++!=':') return "bad JSON";whitespace(&p);
        unsigned bit=!strcmp(key,"id")?1:!strcmp(key,"op")?2:!strcmp(key,"digest")?4:!strcmp(key,"pin")?8:!strcmp(key,"password")?16:0;
        if(!bit) return "unknown field";
        if(fields&bit) {r->has_id=false;return "duplicate field";}fields|=bit;
        if(bit==1) {
            const char *start=p;
            if(*p=='-') p++;
            if(!isdigit((unsigned char)*p)) return "bad id";
            if(*p=='0') p++;else while(isdigit((unsigned char)*p)) p++;
            if(*p!=','&&*p!='}'&&*p!=' '&&*p!='\r'&&*p!='\n'&&*p!='\t') return "bad id";
            errno=0;char *end;long long id=strtoll(start,&end,10);
            if(errno||end!=p) return "bad id";
            r->id=(int64_t)id;r->has_id=true;
        } else {
            char *dest=bit==2?op:bit==4?digest:bit==16?r->password:r->pin;
            size_t cap=bit==2?sizeof(op):bit==4?sizeof(digest):bit==16?sizeof(r->password):sizeof(r->pin);
            if(string(&p,dest,cap)) return bit==4?"bad digest":"bad JSON string";
        }
        whitespace(&p);if(*p!=',') break;p++;whitespace(&p);
    }
    if(*p++!='}') return "bad JSON";
    whitespace(&p);
    if(*p) return "bad JSON";
    if((fields&2)&&strcmp(op,"sign")) {
        if(!strcmp(op,"pubkey")) r->op=OP_PUBKEY;
        else if(!strcmp(op,"status")) r->op=OP_STATUS;
        else if(!strcmp(op,"set_admin_password")) r->op=OP_SET_ADMIN_PASSWORD;
        else if(!strcmp(op,"set_pin")) r->op=OP_SET_PIN;
        else error="unknown op";
    }
    if(!error&&r->op==OP_SIGN&&(!(fields&4)||proto_digest(digest,r->digest))) error="bad digest";
    if(r->op==OP_SET_PIN) {
        if(!(fields&8)||!r->pin[0]) error="PIN required";
        for(size_t i=0;r->pin[i];i++) if((unsigned char)r->pin[i]<0x20||(unsigned char)r->pin[i]>0x7e) error="invalid PIN encoding";
    }
    if(r->op==OP_SET_ADMIN_PASSWORD&&(!(fields&16)||strlen(r->password)<8||strlen(r->password)>64)) error="password must be 8-64 characters";
    volatile char *v=digest;for(size_t i=0;i<sizeof(digest);i++) v[i]=0;
    return error;
}
void proto_hex(const uint8_t *p,size_t n,char *out) {
    static const char hex[]="0123456789abcdef";out[0]='0';out[1]='x';
    for(size_t i=0;i<n;i++) {out[2+2*i]=hex[p[i]>>4];out[3+2*i]=hex[p[i]&15];}out[2+2*n]=0;
}
static void prefix(char out[48],const proto_request *r) {
    if(r&&r->has_id) snprintf(out,48,"\"id\":%" PRId64 ",",r->id);else out[0]=0;
}
static void escape(const char *s,char out[256]) {
    size_t j=0;
    for(size_t i=0;s[i]&&j+7<256;i++) {
        unsigned char c=(unsigned char)s[i];
        if(c=='"'||c=='\\') {out[j++]='\\';out[j++]=(char)c;}
        else if(c<0x20||c>=0x80) {int k=snprintf(out+j,256-j,"\\u%04x",c);j+=(size_t)k;}
        else out[j++]=(char)c;
    }
    out[j]=0;
}
int proto_error(char *out,size_t n,const proto_request *r,bool fatal,const char *error) {
    char id[48],e[256];prefix(id,r);escape(error,e);
    return snprintf(out,n,"{%s%s\"error\":\"%s\"}",id,fatal?"\"fatal\":\"pin_rejected\",":"",e);
}
int proto_public(char *out,size_t n,const proto_request *r,bool ready,const uint8_t point[65]) {
    char id[48],x[67],y[67];prefix(id,r);proto_hex(point+1,32,x);proto_hex(point+33,32,y);
    return snprintf(out,n,"{%s%s\"qx\":\"%s\",\"qy\":\"%s\"}",id,ready?"\"ready\":true,":"",x,y);
}
int proto_signature(char *out,size_t n,const proto_request *r,const uint8_t sig[64],double ms) {
    char id[48],a[67],b[67];prefix(id,r);proto_hex(sig,32,a);proto_hex(sig+32,32,b);
    return snprintf(out,n,"{%s\"r\":\"%s\",\"s\":\"%s\",\"ms\":%.3f}",id,a,b,ms);
}
int proto_status(char *out,size_t n,const proto_request *r,const char *token,bool pin_set,bool rejected,const char *usb) {
    char id[48],esc[200];size_t k=0;prefix(id,r);
    for(const char *s=usb?usb:"";*s&&k+7<sizeof(esc);s++) {
        unsigned char c=(unsigned char)*s;
        if(c=='"'||c=='\\') {esc[k++]='\\';esc[k++]=(char)c;}
        else if(c<0x20) k+=(size_t)snprintf(esc+k,sizeof(esc)-k,"\\u%04x",c);
        else esc[k++]=(char)c;
    }
    esc[k]=0;
    return snprintf(out,n,"{%s\"token\":\"%s\",\"pin_set\":%s,\"pin_rejected\":%s,\"usb\":\"%s\"}",id,token,pin_set?"true":"false",rejected?"true":"false",esc);
}
int proto_ok(char *out,size_t n,const proto_request *r) {
    char id[48];prefix(id,r);return snprintf(out,n,"{%s\"ok\":true}",id);
}
