/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "epass2003.h"
#include <string.h>
#ifdef ESP_PLATFORM
#include "psa/crypto.h"
#include "esp_random.h"
#include "bootloader_random.h"
#else
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif
void ep_zero(void *p,size_t n) { volatile uint8_t *v=p; while(n--) *v++=0; }
int ep_random(uint8_t *out,size_t n) {
#ifdef ESP_PLATFORM
    bootloader_random_enable();
    esp_fill_random(out,n);
    bootloader_random_disable();
    return 0;
#else
    return RAND_bytes(out,(int)n)==1?0:EP_CRYPTO;
#endif
}
int ep_aes_block(const uint8_t key[16],const uint8_t in[16],uint8_t out[16]) {
#ifdef ESP_PLATFORM
    psa_key_attributes_t a=PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t id=0; size_t n=0;
    psa_set_key_type(&a,PSA_KEY_TYPE_AES); psa_set_key_bits(&a,128);
    psa_set_key_usage_flags(&a,PSA_KEY_USAGE_ENCRYPT|PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&a,PSA_ALG_ECB_NO_PADDING);
    psa_status_t r=psa_import_key(&a,key,16,&id);
    if(r==PSA_SUCCESS) r=psa_cipher_encrypt(id,PSA_ALG_ECB_NO_PADDING,in,16,out,16,&n);
    if(id) psa_destroy_key(id);
    psa_reset_key_attributes(&a);
    return r==PSA_SUCCESS&&n==16?0:EP_CRYPTO;
#else
    EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new(); int n=0,m=0;
    if(!c) return EP_CRYPTO;
    int ok=EVP_EncryptInit_ex(c,EVP_aes_128_ecb(),NULL,key,NULL)&&EVP_CIPHER_CTX_set_padding(c,0)&&
        EVP_EncryptUpdate(c,out,&n,in,16)&&EVP_EncryptFinal_ex(c,out+n,&m);
    EVP_CIPHER_CTX_free(c); return ok&&n+m==16?0:EP_CRYPTO;
#endif
}
static int aes_decrypt(const uint8_t key[16],const uint8_t in[16],uint8_t out[16]) {
#ifdef ESP_PLATFORM
    psa_key_attributes_t a=PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t id=0; size_t n=0;
    psa_set_key_type(&a,PSA_KEY_TYPE_AES); psa_set_key_bits(&a,128);
    psa_set_key_usage_flags(&a,PSA_KEY_USAGE_DECRYPT); psa_set_key_algorithm(&a,PSA_ALG_ECB_NO_PADDING);
    psa_status_t r=psa_import_key(&a,key,16,&id);
    if(r==PSA_SUCCESS) r=psa_cipher_decrypt(id,PSA_ALG_ECB_NO_PADDING,in,16,out,16,&n);
    if(id) psa_destroy_key(id);
    psa_reset_key_attributes(&a); return r==PSA_SUCCESS&&n==16?0:EP_CRYPTO;
#else
    EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new(); int n=0,m=0;
    if(!c) return EP_CRYPTO;
    int ok=EVP_DecryptInit_ex(c,EVP_aes_128_ecb(),NULL,key,NULL)&&EVP_CIPHER_CTX_set_padding(c,0)&&
        EVP_DecryptUpdate(c,out,&n,in,16)&&EVP_DecryptFinal_ex(c,out+n,&m);
    EVP_CIPHER_CTX_free(c); return ok&&n+m==16?0:EP_CRYPTO;
#endif
}
int ep_sha1(const uint8_t *in,size_t n,uint8_t out[20]) {
#ifdef ESP_PLATFORM
    size_t len=0; return psa_hash_compute(PSA_ALG_SHA_1,in,n,out,20,&len)==PSA_SUCCESS&&len==20?0:EP_CRYPTO;
#else
    unsigned len=0; return EVP_Digest(in,n,out,&len,EVP_sha1(),NULL)&&len==20?0:EP_CRYPTO;
#endif
}
int ep_cipher(bool aes,bool triple,bool dec,const uint8_t *key,size_t keylen,
              const uint8_t *iv,const uint8_t *in,size_t n,uint8_t *out) {
    size_t b=aes?16:8;
    if(n%b || (aes&&keylen!=16) || (!aes&&triple&&keylen!=16&&keylen!=24) || (!aes&&!triple&&keylen!=8)) return EP_FORMAT;
    uint8_t chain[16]={0},x[16],tmp[16],saved[16]; int r=0;
    if(iv) memcpy(chain,iv,b);
    for(size_t pos=0;pos<n;pos+=b) {
        memcpy(saved,in+pos,b); memcpy(x,saved,b);
        if(!dec&&iv) for(size_t j=0;j<b;j++) x[j]^=chain[j];
        if(aes) r=dec?aes_decrypt(key,x,tmp):ep_aes_block(key,x,tmp);
        else if(triple) {
            const uint8_t *k3=keylen==24?key+16:key;
            ep_des_block(dec?k3:key,dec,x,tmp);
            ep_des_block(key+8,!dec,tmp,x);
            ep_des_block(dec?key:k3,dec,x,tmp);
        } else ep_des_block(key,dec,x,tmp);
        if(r) break;
        if(dec&&iv) for(size_t j=0;j<b;j++) tmp[j]^=chain[j];
        memcpy(out+pos,tmp,b); memcpy(chain,dec?saved:tmp,b);
    }
    ep_zero(x,sizeof(x));ep_zero(tmp,sizeof(tmp));ep_zero(saved,sizeof(saved));ep_zero(chain,sizeof(chain));
    return r;
}
static void dbl(uint8_t k[16]) {
    unsigned carry=k[0]>>7;
    for(unsigned i=0;i<15;i++) k[i]=(uint8_t)((k[i]<<1)|(k[i+1]>>7));
    k[15]<<=1; if(carry) k[15]^=0x87;
}
int ep_cmac(const uint8_t key[16],const uint8_t *in,size_t n,uint8_t out[16]) {
    uint8_t k[16]={0},x[16]={0},z[16]; int r=ep_aes_block(key,k,k);
    if(r) return r;
    dbl(k); size_t blocks=n?(n+15)/16:1;
    for(size_t i=0;i+1<blocks;i++) {
        for(unsigned j=0;j<16;j++) z[j]=x[j]^in[i*16+j];
        if((r=ep_aes_block(key,z,x))) goto done;
    }
    size_t last=n-(blocks-1)*16;
    memset(z,0,16); if(last) memcpy(z,in+(blocks-1)*16,last);
    if(last<16) { z[last]=0x80; dbl(k); }
    for(unsigned j=0;j<16;j++) z[j]^=k[j]^x[j];
    r=ep_aes_block(key,z,out);
done:
    ep_zero(k,16);ep_zero(x,16);ep_zero(z,16);return r;
}
