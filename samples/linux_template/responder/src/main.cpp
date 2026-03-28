/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

extern "C" {
#include "edhoc.h"
#include "sock.h"
#include "compact_ed25519.h"
#include "common/crypto_wrapper.h"
}

static enum ecdh_alg base_dh_alg(enum ecdh_alg alg)
{
    switch (alg) {
    case H_P256_KYBER_LEVEL1:
    case H_P256_KYBER_LEVEL3:
    case H_P256_HQC_LEVEL1:
    case H_P256_BIKE_LEVEL1:
        return P256;
    case H_X25519_KYBER_LEVEL3:
        return X25519;
    default:
        return alg;
    }
}

#define USE_IPV4

static const uint16_t EDHOC_PORT = 56840;
static const char *SERVER_ADDR = "0.0.0.0";

#ifndef METHOD_0
#define METHOD_0 INITIATOR_SK_RESPONDER_SK
#define METHOD_1 INITIATOR_SK_RESPONDER_SDHK
#define METHOD_2 INITIATOR_SDHK_RESPONDER_SK
#define METHOD_3 INITIATOR_SDHK_RESPONDER_SDHK
#endif

#ifndef EDHOC_SUITE_LABEL
#define EDHOC_SUITE_LABEL SUITE_21
#endif

#ifndef EDHOC_METHOD
#define EDHOC_METHOD METHOD_3
#endif

static struct sockaddr_storage g_peer_addr;
static socklen_t g_peer_addr_len = 0;
static bool g_peer_addr_valid = false;

// simple CBOR map {4: 0} and {4: 1} for ID_CREDs (int encoding avoids kid
// bstr round-trip surprises)
static const uint8_t ID_CRED_I_RAW[] = {0xA1, 0x04, 0x00};
static const uint8_t ID_CRED_R_RAW[] = {0xA1, 0x04, 0x01};

static int start_udp_server(int *sockfd)
{
    int err;
    struct sockaddr_in servaddr;
    err = sock_init(SOCK_SERVER, SERVER_ADDR, IPv4, &servaddr,
                    sizeof(servaddr), sockfd);
    return err;
}

enum err ead_process(void *params, struct byte_array *ead13)
{
    return ok;
}

enum err tx(void *sock, struct byte_array *data)
{
    if (!g_peer_addr_valid) {
        fprintf(stderr, "[resp] tx called before peer address is known\n");
        return unexpected_result_from_ext_lib;
    }
    ssize_t n = sendto(*((int *)sock), data->ptr, data->len, 0,
               (struct sockaddr *)&g_peer_addr, g_peer_addr_len);
    if (n < 0 || (size_t)n != data->len) {
        perror("send");
        fprintf(stderr, "[resp] tx failed n=%zd expected=%u\n", n,
            data->len);
        return unexpected_result_from_ext_lib;
    }
    printf("[resp] tx sent %zd bytes\n", n);
    return ok;
}

enum err rx(void *sock, struct byte_array *data)
{
    g_peer_addr_len = sizeof(g_peer_addr);
    ssize_t n = recvfrom(*((int *)sock), data->ptr, data->len, 0,
                 (struct sockaddr *)&g_peer_addr, &g_peer_addr_len);
    if (n < 0) {
        perror("recv");
        fprintf(stderr, "[resp] rx failed\n");
        return unexpected_result_from_ext_lib;
    }
    g_peer_addr_valid = true;
    data->len = (uint32_t)n;
    printf("[resp] rx got %zd bytes\n", n);
    return ok;
}

int main()
{
    int sockfd;
    setvbuf(stdout, NULL, _IOLBF, 0);
    BYTE_ARRAY_NEW(prk_exporter, 32, 32);
    BYTE_ARRAY_NEW(oscore_master_secret, 16, 16);
    BYTE_ARRAY_NEW(oscore_master_salt, 8, 8);
    BYTE_ARRAY_NEW(PRK_out, 32, 32);
    BYTE_ARRAY_NEW(err_msg, 0, 0);

    struct other_party_cred cred_i;
    struct edhoc_responder_context c_r;
    struct suite suite;
    printf("[resp] get_suite\n");
    TRY(get_suite(EDHOC_SUITE_LABEL, &suite));
    printf("[resp] suite ready (label %d)\n", EDHOC_SUITE_LABEL);

    bool static_dh_i = false, static_dh_r = false;
    authentication_type_get((enum method_type)EDHOC_METHOD, &static_dh_i,
                            &static_dh_r);

    // Signature key buffers kept alive for the full scope
    BYTE_ARRAY_NEW(sig_sk_r, ED25519_PRIVATE_KEY_SIZE,
              ED25519_PRIVATE_KEY_SIZE);
    BYTE_ARRAY_NEW(sig_pk_r, ED25519_PUBLIC_KEY_SIZE,
              ED25519_PUBLIC_KEY_SIZE);
    BYTE_ARRAY_NEW(sig_sk_i_dummy, ED25519_PRIVATE_KEY_SIZE,
              ED25519_PRIVATE_KEY_SIZE);
    BYTE_ARRAY_NEW(sig_pk_i, ED25519_PUBLIC_KEY_SIZE,
              ED25519_PUBLIC_KEY_SIZE);

    // Buffers for static DH auth kept alive for full scope
    BYTE_ARRAY_NEW(static_r_sk, 32, 32);
    BYTE_ARRAY_NEW(static_r_pk, 32, 32);

    TRY_EXPECT(start_udp_server(&sockfd), 0);
    printf("[resp] socket ready\n");
    c_r.sock = &sockfd;

    // connection identifier and suites
    uint8_t c_r_raw = 0xA1;
    c_r.c_r = BYTE_ARRAY_INIT(&c_r_raw, 1);
    uint8_t suites_r_arr[1] = {EDHOC_SUITE_LABEL};
    c_r.suites_r.ptr = suites_r_arr;
    c_r.suites_r.len = 1;
    c_r.ead_2 = NULL_ARRAY;
    c_r.ead_4 = NULL_ARRAY;

    // static keys depending on method
    if (static_dh_r) {
        uint32_t seed_r = 0x22222222;
        printf("[resp] static DH keygen\n");
    TRY(ephemeral_dh_key_gen(base_dh_alg(suite.edhoc_ecdh), seed_r, &static_r_sk,
                                 &static_r_pk));
        PRINT_ARRAY("[resp] static sk_r", static_r_sk.ptr, static_r_sk.len);
        PRINT_ARRAY("[resp] static g_r", static_r_pk.ptr, static_r_pk.len);
        c_r.r = static_r_sk;
        c_r.g_r = static_r_pk;
    } else {
        c_r.r = NULL_ARRAY;
        c_r.g_r = NULL_ARRAY;
    }

    if (static_dh_i) {
        BYTE_ARRAY_NEW(static_i_sk_dummy, 32, 32);
        BYTE_ARRAY_NEW(static_i_pk, 32, 32);
        uint32_t seed_i = 0x11111111;
        printf("[resp] static initiator pk\n");
    TRY(ephemeral_dh_key_gen(base_dh_alg(suite.edhoc_ecdh), seed_i,
                                 &static_i_sk_dummy, &static_i_pk));
        PRINT_ARRAY("[resp] static g_i", static_i_pk.ptr, static_i_pk.len);
        cred_i.g = static_i_pk;

        // Debug: compute expected shared secret using r with g_i
        BYTE_ARRAY_NEW(dbg_ss, 32, 32);
        TRY(shared_secret_derive(suite.edhoc_ecdh, &c_r.r, &cred_i.g,
                 dbg_ss.ptr));
        PRINT_ARRAY("[resp] dbg_static_ss (r,g_i)", dbg_ss.ptr, dbg_ss.len);
    } else {
        cred_i.g = NULL_ARRAY;
    }

    // hybrid ephemeral context for responder: g_y = DH pub || KEM ciphertext (if any)
    uint32_t dh_pk_len = get_ecdh_pk_len(suite.edhoc_ecdh);
    uint32_t dh_sk_len = dh_pk_len;
    uint32_t kem_cc_len = get_kem_cc_len(suite.edhoc_ecdh);

    BYTE_ARRAY_NEW(eph_dh_sk, dh_sk_len, dh_sk_len);
    BYTE_ARRAY_NEW(eph_dh_pk, dh_pk_len, dh_pk_len);
    uint32_t seed_eph = 0x44444444;
    printf("[resp] ephemeral DH keygen alg %d\n", suite.edhoc_ecdh);
    TRY(ephemeral_dh_key_gen(base_dh_alg(suite.edhoc_ecdh), seed_eph, &eph_dh_sk, &eph_dh_pk));

    BYTE_ARRAY_NEW(g_y, dh_pk_len + kem_cc_len, dh_pk_len + kem_cc_len);
    BYTE_ARRAY_NEW(y, dh_sk_len, dh_sk_len);
    _memcpy_s(g_y.ptr, g_y.len, eph_dh_pk.ptr, dh_pk_len);
    if (kem_cc_len > 0) {
        memset(g_y.ptr + dh_pk_len, 0, g_y.len - dh_pk_len);
    }
    _memcpy_s(y.ptr, y.len, eph_dh_sk.ptr, dh_sk_len);
    c_r.g_y = g_y;
    c_r.y = y;

    // credentials (minimal CBOR map creds)
    c_r.id_cred_r.ptr = (uint8_t *)ID_CRED_R_RAW;
    c_r.id_cred_r.len = sizeof(ID_CRED_R_RAW);
    c_r.cred_r = c_r.id_cred_r;

    if (static_dh_r) {
        c_r.pk_r = NULL_ARRAY;
        c_r.sk_r = NULL_ARRAY;
    } else {
        uint8_t seed_sig_r[ED25519_SEED_SIZE] = {0x10};
        compact_ed25519_keygen(sig_sk_r.ptr, sig_pk_r.ptr, seed_sig_r);
        c_r.sk_r = sig_sk_r;
        c_r.pk_r = sig_pk_r;
    }

    cred_i.id_cred.ptr = (uint8_t *)ID_CRED_I_RAW;
    cred_i.id_cred.len = sizeof(ID_CRED_I_RAW);
    cred_i.cred = cred_i.id_cred;
    if (static_dh_i) {
        cred_i.pk = cred_i.g;
    } else {
        uint8_t seed_sig_i[ED25519_SEED_SIZE] = {0x20};
        compact_ed25519_keygen(sig_sk_i_dummy.ptr, sig_pk_i.ptr, seed_sig_i);
        cred_i.pk = sig_pk_i;
    }
    cred_i.ca.len = 0;
    cred_i.ca_pk.len = 0;

    struct cred_array cred_i_array = {.len = 1, .ptr = &cred_i};

    printf("[resp] starting edhoc_responder_run\n");
    {
        enum err ret = edhoc_responder_run(&c_r, &cred_i_array, &err_msg,
                                           &PRK_out, tx, rx, ead_process);
        if (ret != ok) {
            printf("[resp] edhoc_responder_run ret=%d\n", ret);
            return ret;
        }
    }
    printf("[resp] edhoc_responder_run completed\n");

    PRINT_ARRAY("PRK_out", PRK_out.ptr, PRK_out.len);

    TRY(prk_out2exporter(SHA_256, &PRK_out, &prk_exporter));
    PRINT_ARRAY("prk_exporter", prk_exporter.ptr, prk_exporter.len);

    TRY(edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &prk_exporter, &oscore_master_secret));
    PRINT_ARRAY("OSCORE Master Secret", oscore_master_secret.ptr, oscore_master_secret.len);

    TRY(edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &prk_exporter, &oscore_master_salt));
    PRINT_ARRAY("OSCORE Master Salt", oscore_master_salt.ptr, oscore_master_salt.len);

    close(sockfd);
    return 0;
}