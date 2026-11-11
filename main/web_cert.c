#include "esp_random.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "nvs.h"
#include "psa/crypto.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
/* Kept alive for the HTTPS server lifetime. Never logged. */
unsigned char hyp_cert[2048], hyp_key[1024];
char hyp_fingerprint[96];
bool hyp_cert_init(nvs_handle_t nv) {
  size_t cn = sizeof(hyp_cert), kn = sizeof(hyp_key);
  esp_err_t ce = nvs_get_blob(nv, "cert", hyp_cert, &cn),
            ke = nvs_get_blob(nv, "key", hyp_key, &kn);
  if (ce == ESP_ERR_NVS_NOT_FOUND && ke == ESP_ERR_NVS_NOT_FOUND) {
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t id = 0;
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&a, 256);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&a, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    if (psa_generate_key(&a, &id) != PSA_SUCCESS)
      return false;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    mbedtls_x509write_cert crt;
    mbedtls_x509write_crt_init(&crt);
    int r = mbedtls_pk_copy_from_psa(id, &pk);
    psa_destroy_key(id);
    if (!r)
      r = mbedtls_pk_write_key_pem(&pk, hyp_key, sizeof(hyp_key));
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt, &pk);
    mbedtls_x509write_crt_set_issuer_key(&crt, &pk);
    unsigned char serial[16];
    esp_fill_random(serial, sizeof(serial));
    serial[0] &= 0x7f;
    serial[0] |= 1;
    if (!r)
      r = mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial));
    if (!r)
      r = mbedtls_x509write_crt_set_subject_name(&crt, "CN=wirelesshyp.local");
    if (!r)
      r = mbedtls_x509write_crt_set_issuer_name(&crt, "CN=wirelesshyp.local");
    /* No trusted RTC at provisioning: fixed release epoch, ten-year validity.
     */
    if (!r)
      r = mbedtls_x509write_crt_set_validity(&crt, "20261101000000",
                                             "20361101000000");
    const unsigned char san[] = {0x30, 0x13, 0x82, 0x11, 'w', 'i', 'r',
                                 'e',  'l',  'e',  's',  's', 'h', 'y',
                                 'p',  '.',  'l',  'o',  'c', 'a', 'l'};
    if (!r)
      r = mbedtls_x509write_crt_set_extension(&crt, "\x55\x1d\x11", 3, 0, san,
                                              sizeof(san));
    if (!r)
      r = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
    if (!r)
      r = mbedtls_x509write_crt_pem(&crt, hyp_cert, sizeof(hyp_cert));
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&pk);
    if (r)
      return false;
    cn = strlen((char *)hyp_cert) + 1;
    kn = strlen((char *)hyp_key) + 1;
    if (nvs_set_blob(nv, "cert", hyp_cert, cn) != ESP_OK ||
        nvs_set_blob(nv, "key", hyp_key, kn) != ESP_OK ||
        nvs_commit(nv) != ESP_OK)
      return false;
  } else if (ce != ESP_OK || ke != ESP_OK || !cn || !kn || hyp_cert[cn - 1] ||
             hyp_key[kn - 1])
    return false;
  mbedtls_x509_crt c;
  mbedtls_x509_crt_init(&c);
  int r = mbedtls_x509_crt_parse(&c, hyp_cert, cn);
  unsigned char hash[32];
  size_t hn = 0;
  if (!r && psa_hash_compute(PSA_ALG_SHA_256, c.raw.p, c.raw.len, hash,
                             sizeof(hash), &hn) != PSA_SUCCESS)
    r = -1;
  mbedtls_x509_crt_free(&c);
  if (r)
    return false;
  for (int i = 0; i < 32; i++) {
    snprintf(hyp_fingerprint + i * 3, 4, i == 31 ? "%02X" : "%02X:", hash[i]);
  }
  return true;
}
