/*
 * Copyright (C) 2003-2005 Samuel Mimram
 *
 * This file is part of Ocaml-ssl.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * Libssl bindings for OCaml.
 *
 * @author Samuel Mimram
 */

/* $Id$ */

/*
 * WARNING: because of thread callbacks, all ssl functions should be in
 * blocking sections.
 */

#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <caml/alloc.h>
#include <caml/callback.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/signals.h>
#include <caml/unixsupport.h>

#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#ifdef WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

// SSL
/* Some definitions from Ocaml-SSL */
#define Cert_val(v) (*((X509**)Data_custom_val(v)))
#define RSA_val(v) (*((RSA**)Data_custom_val(v)))
#define EVP_val(v) (*((EVP_PKEY**)Data_custom_val(v)))
#define Ctx_val(v) (*((SSL_CTX**)Data_custom_val(v)))
#define SSL_val(v) (*((SSL**)Data_custom_val(v)))
#define ONELINE_NAME(X) X509_NAME_oneline(X, 0, 0)


/*********************************
 * Certificate-related functions *
 *********************************/

#define Cert_val(v) (*((X509**)Data_custom_val(v)))

static void finalize_cert(value block)
{
  X509 *cert = Cert_val(block);
  X509_free(cert);
}

static struct custom_operations cert_ops =
{
  "ocaml_ssl_cert",
  finalize_cert,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default
};

CAMLprim value ocaml_ssl_ext_gen_rsa (value len) {
  value block;
  CAMLparam1(len);
  RSA *rsa = NULL;
  int length = Int_val(len);

  caml_enter_blocking_section();

  rsa = RSA_generate_key (length, 65537l, NULL, NULL); 
  if(!rsa) {
    caml_leave_blocking_section();
    caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
  }

  caml_leave_blocking_section();

  block = caml_alloc(sizeof(RSA*), 0);
  RSA_val(block) = rsa;
  return block;
}

CAMLprim value ocaml_ssl_sign_pub_key(value pubKey, value privKey, 
        value issuer, value subject, value delay) {
    value block;
    CAMLparam5(pubKey,privKey,issuer,subject, delay);

    EVP_PKEY *pub = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pub, RSA_val(pubKey));
    EVP_PKEY *priv = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(priv, RSA_val(privKey));

    char *str_issuer = String_val(issuer);
    char *str_sub = String_val(subject);
    X509 *cert = X509_new();
    BIO* mem = NULL;
    BUF_MEM *buf;
    time_t duration = Int_val(delay);

    caml_enter_blocking_section();

    if (!pub || !priv) {
        caml_leave_blocking_section();
        fprintf(stderr, "failed to allocate EVP_KEY strucures to store keys\n");
        caml_raise_constant(*caml_named_value("ssl_ext_exn_certificate_error")); 
    }

    if (! cert) {
        EVP_PKEY_free(pub);
        EVP_PKEY_free(priv);
        X509_free(cert);
        caml_leave_blocking_section();
        fprintf(stderr, "failed to create x509 struct\n");
        caml_raise_constant(*caml_named_value("ssl_ext_exn_certificate_error")); 
    }

    if (! X509_set_version(cert, 2)){ 
        EVP_PKEY_free(pub);
        EVP_PKEY_free(priv);
        X509_free(cert); 
        caml_leave_blocking_section();
        fprintf(stderr, "X509_set_version failed\n"); 
        caml_raise_constant(*caml_named_value("ssl_ext_exn_certificate_error"));
    }
    if (! X509_set_pubkey(cert, pub)){ 
        X509_free(cert);
        EVP_PKEY_free(priv);
        caml_leave_blocking_section();
        fprintf(stderr, "X509_set_pubkey failed\n"); 
        caml_raise_constant(*caml_named_value("ssl_ext_exn_certificate_error"));
    }

    if (! ASN1_INTEGER_set(X509_get_serialNumber(cert), 1)) { 
        X509_free(cert);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        caml_leave_blocking_section();
        fprintf(stderr, "ASN1_INTEGER_set failed\n");
        caml_raise_constant(*caml_named_value("ssl_ext_exn_certificate_error"));
    }
    /* Make the certificate valid a day before in case we are in different timezones 
     * or the clocks are out of synch */
    if (! ASN1_TIME_set(X509_get_notBefore(cert), time(NULL) - 24*3600)) { 
        X509_free(cert);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        caml_leave_blocking_section();
        fprintf(stderr, "ASN1_TIME_set failed for notBefore\n"); 
        caml_raise_constant(*caml_named_value("ssl_ext_exn_certificate_error"));
    }
    if (! ASN1_TIME_set(X509_get_notAfter(cert), time(NULL) + duration)) {
        X509_free(cert);
        EVP_PKEY_free(pub);
        EVP_PKEY_free(priv);
        caml_leave_blocking_section();
        fprintf(stderr, "ASN1_TIME_set failed for notAfter\n");
        caml_raise_constant(*caml_named_value("ssl_ext_exn_certificate_error"));
    }

    char *name = strtok(str_sub, ",");
    char *val = NULL;
    X509_NAME *x509_name = X509_NAME_new();
    while (name != NULL) {
        val = strchr(name, '=');
        if (val != NULL) {
            *val = '\0'; val++;
            X509_NAME_add_entry_by_txt(x509_name, name, MBSTRING_ASC, val, -1, -1, 0);
        }
        name = strtok (NULL, ",");
    }
    X509_set_subject_name(cert, x509_name);
    X509_NAME_free(x509_name);

    x509_name = X509_NAME_new();
    name = strtok(str_issuer, ",");
    while (name != NULL) {
        val = strchr(name, '=');
        if (val != NULL) {
            *val = '\0'; val++;
            X509_NAME_add_entry_by_txt(x509_name, name, MBSTRING_ASC, val, -1, -1, 0);
        }
        name = strtok (NULL, ",");
    }
    X509_set_issuer_name(cert, x509_name);
    X509_NAME_free(x509_name);

    /* Parse the subject and issuer string. \; will sperate entries and = will sperate
     * key values. 
     * X509_NAME_add_entry_by_txt(self, key,
     *        (SvUTF8(sv_val) ? MBSTRING_UTF8 : MBSTRING_ASC),
     *        (unsigned char*) val, -1, -1, 0))*/

    if(!X509_sign(cert, priv, EVP_sha1()) ) {
        X509_free(cert);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        caml_leave_blocking_section();
        fprintf(stderr, "Failed to sign the certificate\n");
        caml_raise_constant(*caml_named_value("ssl_ext_exn_certificate_error"));
    }

    EVP_PKEY_free(pub);
    EVP_PKEY_free(priv);

    mem = BIO_new(BIO_s_mem());
    if (! mem) {
        X509_free(cert);
        caml_leave_blocking_section();
        fprintf(stderr,"Cannot allocate BIO \n");
        caml_raise_constant(*caml_named_value("ssl_ext_exn_certificate_error"));
    }

    if (! (PEM_write_bio_X509(mem, cert) && (BIO_write(mem, "\0", 1) > 0)) ) {
        X509_free(cert);
        BIO_free(mem);
        caml_leave_blocking_section();
        fprintf(stderr,"X509_CRL_print failed \n");
        caml_raise_constant(*caml_named_value("ssl_ext_exn_certificate_error")); 
    }

    if( (! BIO_get_mem_ptr(mem, &buf)) || (buf == NULL)) {
        X509_free(cert);
        BIO_free(mem);
        caml_leave_blocking_section();
        fprintf(stderr,"BIO_get_mem_ptr failed\n" );
        caml_raise_constant(*caml_named_value("ssl_ext_exn_certificate_error")); 
    }

    X509_free(cert);
    caml_leave_blocking_section();

    CAMLreturn(caml_copy_string(buf->data));
}

CAMLprim value ocaml_ssl_read_certificate(value vfilename)
{
    value block;
    char *filename = String_val(vfilename);
    X509 *cert = NULL;
    FILE *fh = NULL;

    if((fh = fopen(filename, "r")) == NULL)
        caml_raise_constant(*caml_named_value("ssl_ext_exn_certificate_error"));

    caml_enter_blocking_section();
    if((PEM_read_X509(fh, &cert, 0, 0)) == NULL)
    {
        fclose(fh);
        caml_leave_blocking_section();
        caml_raise_constant(*caml_named_value("ssl_ext_exn_certificate_error"));
    }
    fclose(fh);
    caml_leave_blocking_section();

    block = caml_alloc_custom(&cert_ops, sizeof(X509*), 0, 1);
    Cert_val(block) = cert;
    return block;
}

CAMLprim value ocaml_ssl_write_certificate(value vfilename, value certificate)
{
    CAMLparam2(vfilename, certificate);
    char *filename = String_val(vfilename);
    X509 *cert = Cert_val(certificate);
    FILE *fh = NULL;

    if((fh = fopen(filename, "w")) == NULL)
        caml_raise_constant(*caml_named_value("ssl_ext_exn_certificate_error"));

    caml_enter_blocking_section();
    if(PEM_write_X509(fh, cert) == 0)
    {
        fclose(fh);
        caml_leave_blocking_section();
        caml_raise_constant(*caml_named_value("ssl_ext_exn_certificate_error"));
    }
    fclose(fh);
    caml_leave_blocking_section();

    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_get_certificate(value socket)
{
    CAMLparam1(socket);
    SSL *ssl = SSL_val(socket);

    caml_enter_blocking_section();
    X509 *cert = SSL_get_peer_certificate(ssl);
    caml_leave_blocking_section();

    if (!cert)
        caml_raise_constant(*caml_named_value("ssl_ext_exn_certificate_error"));

    CAMLlocal1(block);
    block = caml_alloc_final(2, finalize_cert, 0, 1);
    (*((X509 **) Data_custom_val(block))) = cert;
    CAMLreturn(block);
}

CAMLprim value ocaml_ssl_get_issuer(value certificate)
{
    CAMLparam1(certificate);
    X509 *cert = Cert_val(certificate);

    caml_enter_blocking_section();
    char *issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    caml_leave_blocking_section();
    if (!issuer) caml_raise_not_found ();

    CAMLreturn(caml_copy_string(issuer));
}

CAMLprim value ocaml_ssl_get_subject(value certificate)
{
    CAMLparam1(certificate);
    X509 *cert = Cert_val(certificate);

    caml_enter_blocking_section();
    char *subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    caml_leave_blocking_section();
    if (subject == NULL) caml_raise_not_found ();

    CAMLreturn(caml_copy_string(subject));
}

CAMLprim value ocaml_ssl_ctx_load_verify_locations(value context, value ca_file, value ca_path)
{
    CAMLparam3(context, ca_file, ca_path);
    SSL_CTX *ctx = Ctx_val(context);
    char *CAfile = String_val(ca_file);
    char *CApath = String_val(ca_path);

    if(*CAfile == 0)
        CAfile = NULL;
    if(*CApath == 0)
        CApath = NULL;

    caml_enter_blocking_section();
    if(SSL_CTX_load_verify_locations(ctx, CAfile, CApath) != 1)
    {
        caml_leave_blocking_section();
        caml_invalid_argument("cafile or capath");
    }
    caml_leave_blocking_section();

    CAMLreturn(Val_unit);
}


// RSA

#define RSA_val(v) (*((RSA**)Data_custom_val(v)))

CAMLprim value ocaml_ssl_ext_rsa_read_privkey(value vfilename)
{
    value block;
    char *filename = String_val(vfilename);
    RSA *rsa = NULL;
    FILE *fh;

    if((fh = fopen(filename, "r")) == NULL) {
        fprintf(stderr, "failed to open key %s\n", filename);
        caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
    }

    caml_enter_blocking_section();
    if((PEM_read_RSAPrivateKey(fh, &rsa, PEM_def_callback, NULL)) == NULL)
    {
        fprintf(stderr, "failed to load key %s\n", filename);
        fclose(fh);
        caml_leave_blocking_section();
        caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
    }
    fclose(fh);
    caml_leave_blocking_section();

    block = caml_alloc(sizeof(RSA*), 0);
    RSA_val(block) = rsa;
    return block;
}


CAMLprim value ocaml_ssl_ext_new_rsa_key(value vfilename) {
    value block;
    RSA *rsa = NULL;
    caml_enter_blocking_section();
    rsa = RSA_new();
    if(rsa == NULL) {
        caml_leave_blocking_section();
        caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
    }
    caml_leave_blocking_section();

    block = caml_alloc(sizeof(RSA*), 0);
    RSA_val(block) = rsa;
    return block;
}
CAMLprim value ocaml_ssl_ext_free_rsa_key(value key) {
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    RSA_free(rsa);
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_write_privkey(value vfilename, value key) {
    CAMLparam2(vfilename, key);
    RSA *rsa = RSA_val(key);
    char *filename = String_val(vfilename);
    FILE *fh = NULL;

    if((fh = fopen(filename, "w")) == NULL) {
        caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
    }

    caml_enter_blocking_section();
    if((PEM_write_RSAPrivateKey(fh, rsa, NULL, NULL, 0, PEM_def_callback, NULL)) == NULL)
    {
        fclose(fh);
        caml_leave_blocking_section();
        caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
    }
    fclose(fh);
    caml_leave_blocking_section();

    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_write_pubkey(value vfilename, value key) {
    CAMLparam2(vfilename, key);
    RSA *rsa = RSA_val(key);
    char *filename = String_val(vfilename);
    FILE *fh = NULL;

    if((fh = fopen(filename, "w")) == NULL) {
        caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
    }

    caml_enter_blocking_section();
    if(PEM_write_RSAPublicKey(fh, rsa) == NULL){
        fclose(fh);
        caml_leave_blocking_section();
        caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
    }
    fclose(fh);
    caml_leave_blocking_section();
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_get_pem_pubkey(value key) {
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    BIO* mem = NULL;
    BUF_MEM *buf;

    caml_leave_blocking_section();
    mem = BIO_new(BIO_s_mem());
    if (! mem) {
        caml_leave_blocking_section();
        fprintf(stderr,"Cannot allocate BIO \n");
        caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
    }

    if (! (PEM_write_bio_RSAPublicKey(mem, rsa) && (BIO_write(mem, "\0", 1) > 0)) ) {
    // if (! (PEM_write_bio_RSA_PUBKEY(mem, rsa) && (BIO_write(mem, "\0", 1) > 0)) ) {
        BIO_free(mem);
        caml_leave_blocking_section();
        fprintf(stderr,"RSA_pub_write failed \n");
        caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error")); 
    }

    if( (! BIO_get_mem_ptr(mem, &buf)) || (buf == NULL)) {
        BIO_free(mem);
        caml_leave_blocking_section();
        fprintf(stderr,"BIO_get_mem_ptr failed\n" );
        caml_raise_constant(*caml_named_value("ssl_ext_exn_certificate_error")); 
    }

    caml_leave_blocking_section();

    CAMLreturn(caml_copy_string(buf->data));
}

/* CAMLprim value ocaml_ssl_ext_write_pubkey(value vfilename, value key) {
   CAMLparam2(vfilename, key);
   EVP_PKEY *evp_key = RSA_val(key);
   char *filename = String_val(vfilename);
   FILE *fh = NULL;

   if((fh = fopen(filename, "w")) == NULL) {
   caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
   }

   caml_enter_blocking_section();
   if(PEM_write_PublicKey(fh, rsa) == NULL){
   fclose(fh);
   caml_leave_blocking_section();
   caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
   }
   fclose(fh);
   caml_leave_blocking_section();
   CAMLreturn(Val_unit);
   }  */



CAMLprim value ocaml_ssl_ext_rsa_read_pubkey(value vfilename)
{
    value block;
    char *filename = String_val(vfilename);
    RSA *rsa = NULL;
    FILE *fh = NULL;

    if((fh = fopen(filename, "r")) == NULL)
        caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));

    caml_enter_blocking_section();
    if((PEM_read_RSA_PUBKEY(fh, &rsa, PEM_def_callback, NULL)) == NULL)
    {
        fclose(fh);
        caml_leave_blocking_section();
        caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
    }
    fclose(fh);
    caml_leave_blocking_section();

    block = caml_alloc(sizeof(RSA*), 0);
    RSA_val(block) = rsa;
    return block;
}

CAMLprim value ocaml_ssl_ext_rsa_get_size(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    int size = 0;
    caml_enter_blocking_section();
    size = RSA_size(rsa);
    caml_leave_blocking_section();
    CAMLreturn(Val_int(size));
}


CAMLprim value ocaml_ssl_ext_rsa_get_n(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    char *ret = "";
    if (rsa->n)
      ret = BN_bn2hex(rsa->n);
    CAMLreturn(caml_copy_string(String_val(ret)));
}

CAMLprim value ocaml_ssl_ext_rsa_set_n(value key, value val) {
    CAMLparam2(key, val);
    RSA *rsa = RSA_val(key);
    char *hex_val = String_val(val);
    caml_enter_blocking_section();
    BN_hex2bn(&rsa->n, hex_val);
    caml_leave_blocking_section();
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_get_e(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    char *ret = "";
    if (rsa->e) 
      ret = BN_bn2hex(rsa->e);
    CAMLreturn(caml_copy_string(String_val(ret)));
}

CAMLprim value ocaml_ssl_ext_rsa_set_e(value key, value val) {
    CAMLparam2(key, val);
    RSA *rsa = RSA_val(key);
    char *hex_val = String_val(val);
    BN_hex2bn(&rsa->e, hex_val);
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_get_d(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    char *ret = "";
    if (rsa->d) 
      ret = BN_bn2hex(rsa->d);
    CAMLreturn(caml_copy_string(String_val(ret)));
}

CAMLprim value ocaml_ssl_ext_rsa_set_d(value key, value val) {
    CAMLparam2(key, val);
    RSA *rsa = RSA_val(key);
    char *hex_val = String_val(val);
    BN_hex2bn(&rsa->d, hex_val);
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_get_p(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    char *ret = "";
    if (rsa->p)
      ret = BN_bn2hex(rsa->p);
    CAMLreturn(caml_copy_string(String_val(ret)));    
}
CAMLprim value ocaml_ssl_ext_rsa_set_p(value key, value val) {
    CAMLparam2(key, val);
    RSA *rsa = RSA_val(key);
    char *hex_val = String_val(val);
    BN_hex2bn(&rsa->p, hex_val);
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_get_q(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    char *ret = "";
    if (rsa->q)
      ret = BN_bn2hex(rsa->q);
    CAMLreturn(caml_copy_string(String_val(ret)));
}

CAMLprim value ocaml_ssl_ext_rsa_set_q(value key, value val) {
    CAMLparam2(key, val);
    RSA *rsa = RSA_val(key);
    char *hex_val = String_val(val);
    BN_hex2bn(&rsa->q, hex_val);
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_get_dp(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    char *ret = "";
    if (rsa->dmp1)
      ret = BN_bn2hex(rsa->dmp1);
    CAMLreturn(caml_copy_string(String_val(ret)));
}
CAMLprim value ocaml_ssl_ext_rsa_set_dp(value key, value val) {
    CAMLparam2(key, val);
    RSA *rsa = RSA_val(key);
    char *hex_val = String_val(val);
    BN_hex2bn(&rsa->dmp1, hex_val);
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_get_dq(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    char *ret = "";
    if (rsa->dmq1)
      ret = BN_bn2hex(rsa->dmq1);
    CAMLreturn(caml_copy_string(String_val(ret)));
}
CAMLprim value ocaml_ssl_ext_rsa_set_dq(value key, value val) {
    CAMLparam2(key, val);
    RSA *rsa = RSA_val(key);
    char *hex_val = String_val(val);
    BN_hex2bn(&rsa->dmq1, hex_val);
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_get_qinv(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    char *ret = "";
    if (rsa->iqmp)
      ret = BN_bn2hex(rsa->iqmp);
    CAMLreturn(caml_copy_string(String_val(ret)));
}
CAMLprim value ocaml_ssl_ext_rsa_set_qinv(value key, value val) {
    CAMLparam2(key, val);
    RSA *rsa = RSA_val(key);
    char *hex_val = String_val(val);
    BN_hex2bn(&rsa->iqmp, hex_val);
    CAMLreturn(Val_unit);
}

/////////////////////////////////////////////////////////////
// EVP functions
// /////////////////////////////////////////////////////////
CAMLprim value ocaml_ssl_ext_read_privkey(value vfilename) {
    value block;
    char *filename = String_val(vfilename);
    EVP_PKEY *pkey = NULL;
    FILE *fh = NULL;

    if((fh = fopen(filename, "r")) == NULL)
        caml_raise_constant(*caml_named_value("ssl_ext_exn_evp_error"));

    caml_enter_blocking_section();
    if((PEM_read_PrivateKey(fh, &pkey, PEM_def_callback, NULL)) == NULL)
    {
        fclose(fh);
        caml_leave_blocking_section();
        caml_raise_constant(*caml_named_value("ssl_ext_exn_evp_error"));
    }
    fclose(fh);
    caml_leave_blocking_section();

    block = caml_alloc(sizeof(EVP_PKEY*), 0);
    EVP_val(block) = pkey;
    return block;
}

// EVP_PKEY_type(pkey->type)
// EVP_PKEY_RSA
// EVP_PKEY_DSA
// EVP_PKEY_DH
// EVP_PKEY_EC
///ocaml_ssl_ext_rsa_write_privkey
CAMLprim value ocaml_ssl_ext_write_privkey(value vfilename, value key) {
    CAMLparam2(vfilename, key);
    char *filename = String_val(vfilename);
    RSA *rsa = RSA_val(key);
    FILE *fh = NULL;

    // create an appropriate evp struct
    EVP_PKEY *pkey = EVP_PKEY_new();
    if(EVP_PKEY_set1_RSA(pkey, rsa) == 0 ) {
        EVP_PKEY_free(pkey);
        caml_raise_constant(*caml_named_value("ssl_ext_exn_evp_error"));
    }

    if((fh = fopen(filename, "w")) == NULL)
        caml_raise_constant(*caml_named_value("ssl_ext_exn_evp_error"));

    caml_enter_blocking_section();
    if((PEM_write_PrivateKey(fh, pkey, NULL, NULL, 0, PEM_def_callback, NULL)) == NULL) {
        fclose(fh);
        EVP_PKEY_free(pkey);
        caml_leave_blocking_section();
        caml_raise_constant(*caml_named_value("ssl_ext_exn_evp_error"));
    }
    fclose(fh);
    caml_leave_blocking_section();
    EVP_PKEY_free(pkey);
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_write_pubkey(value vfilename, value key) {
    CAMLparam2(vfilename, key);
    char *filename = String_val(vfilename);
    RSA *rsa = RSA_val(key);
    FILE *fh = NULL;
    // create an appropriate evp struct
    EVP_PKEY *pkey = EVP_PKEY_new();
    if(EVP_PKEY_set1_RSA(pkey, rsa) == 0 ) {
        EVP_PKEY_free(pkey);
        caml_raise_constant(*caml_named_value("ssl_ext_exn_evp_error"));
    }

    if((fh = fopen(filename, "w")) == NULL)
        caml_raise_constant(*caml_named_value("ssl_ext_exn_evp_error"));

    caml_enter_blocking_section();
    if((PEM_write_PUBKEY(fh, pkey)) == NULL) {
        fclose(fh);
        EVP_PKEY_free(pkey);
        caml_leave_blocking_section();
        caml_raise_constant(*caml_named_value("ssl_ext_exn_evp_error"));
    }
    fclose(fh);
    caml_leave_blocking_section();
    EVP_PKEY_free(pkey);
    CAMLreturn(Val_unit);
}


