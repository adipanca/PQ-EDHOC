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
#include <fcntl.h>

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

#define USE_IPV4

static const uint16_t EDHOC_PORT = 56840;
static const char *SERVER_ADDR = "127.0.0.1";

// simple CBOR map {4: 0} and {4: 1} for ID_CREDs (use int to avoid kid
// bstr re-encode issues)
static const uint8_t ID_CRED_I_RAW[] = {0xA1, 0x04, 0x00};
static const uint8_t ID_CRED_R_RAW[] = {0xA1, 0x04, 0x01};
static const uint8_t ID_CRED_R_INT_RAW[] = {0xA1, 0x04, 0x01};
static const uint8_t ID_CRED_R_HASH_RAW[] = {0xA1, 0x04, 0x3A, 0x27, 0x1C,
				      0xE6, 0x14};
static const uint8_t ID_CRED_R_HASH2_RAW[] = {0xA1, 0x04, 0x3A, 0x39, 0xD0,
			       0xE6, 0x14};
static const uint8_t ID_CRED_R_HASH3_RAW[] = {0xA1, 0x04, 0x1A, 0x0B, 0xD4,
			       0x19, 0xEB};

static int start_udp_client(int *sockfd)
{
	int err;
	struct sockaddr_in servaddr;
	err = sock_init(SOCK_CLIENT, SERVER_ADDR, IPv4, &servaddr,
			sizeof(servaddr), sockfd);
	return err;
}

enum err ead_process(void *params, struct byte_array *ead13)
{
	return ok;
}

enum err tx(void *sock, struct byte_array *data)
{
	ssize_t n = send(*((int *)sock), data->ptr, data->len, 0);
	if (n < 0 || (size_t)n != data->len) {
		perror("send");
		return unexpected_result_from_ext_lib;
	}
	printf("[init] tx sent %zd bytes\n", n);
	return ok;
}

enum err rx(void *sock, struct byte_array *data)
{
	ssize_t n = recv(*((int *)sock), data->ptr, data->len, MSG_WAITALL);
	if (n < 0) {
		perror("recv");
		return unexpected_result_from_ext_lib;
	}
	data->len = (uint32_t)n;
	printf("[init] rx got %zd bytes\n", n);
	return ok;
}

static void fill_array_random(struct byte_array *ba)
{
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		perror("/dev/urandom");
		exit(1);
	}
	ssize_t r = read(fd, ba->ptr, ba->len);
	close(fd);
	if ((size_t)r != ba->len) {
		fprintf(stderr, "random read failed\n");
		exit(1);
	}
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

	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;

	struct suite suite;
	PRINTF("[init] get_suite\n");
	TRY(get_suite(EDHOC_SUITE_LABEL, &suite));
	PRINTF("[init] suite ready (label %d)\n", EDHOC_SUITE_LABEL);

	bool static_dh_i = false, static_dh_r = false;
	authentication_type_get((enum method_type)EDHOC_METHOD, &static_dh_i,
				 &static_dh_r);

	// Signature key buffers (kept alive for full function scope)
	BYTE_ARRAY_NEW(sig_sk_i, ED25519_PRIVATE_KEY_SIZE,
		      ED25519_PRIVATE_KEY_SIZE);
	BYTE_ARRAY_NEW(sig_pk_i, ED25519_PUBLIC_KEY_SIZE,
		      ED25519_PUBLIC_KEY_SIZE);
	BYTE_ARRAY_NEW(sig_sk_r_dummy, ED25519_PRIVATE_KEY_SIZE,
		      ED25519_PRIVATE_KEY_SIZE);
	BYTE_ARRAY_NEW(sig_pk_r, ED25519_PUBLIC_KEY_SIZE,
		      ED25519_PUBLIC_KEY_SIZE);

	// Buffers for static DH authentication (kept outside conditional scope to
	// keep their storage alive for the whole function)
	BYTE_ARRAY_NEW(static_i_sk, 32, 32);
	BYTE_ARRAY_NEW(static_i_pk, 32, 32);

	// runtime static keys depending on method
	if (static_dh_i) {
		uint32_t seed_i = 0x11111111;
		PRINTF("[init] static DH keygen\n");
		TRY(ephemeral_dh_key_gen(base_dh_alg(suite.edhoc_ecdh), seed_i, &static_i_sk,
				 &static_i_pk));
		PRINT_ARRAY("[init] static sk_i", static_i_sk.ptr, static_i_sk.len);
		PRINT_ARRAY("[init] static g_i", static_i_pk.ptr, static_i_pk.len);
		c_i.i = static_i_sk;
		c_i.g_i = static_i_pk;
	} else {
		c_i.i = NULL_ARRAY;
		c_i.g_i = NULL_ARRAY;
	}

	// responder static pub key (pre-shared deterministic) for static-DH auth
	if (static_dh_r) {
		BYTE_ARRAY_NEW(static_r_sk_dummy, 32, 32);
		BYTE_ARRAY_NEW(static_r_pk, 32, 32);
		uint32_t seed_r = 0x22222222;
		PRINTF("[init] static responder pk\n");
		TRY(ephemeral_dh_key_gen(base_dh_alg(suite.edhoc_ecdh), seed_r,
				 &static_r_sk_dummy, &static_r_pk));
		PRINT_ARRAY("[init] static g_r", static_r_pk.ptr, static_r_pk.len);
		cred_r.g = static_r_pk; // used for static DH auth

		// Debug: compute expected shared secret using static_i_sk with g_r
		if (static_dh_i) {
			BYTE_ARRAY_NEW(dbg_ss, 32, 32);
			TRY(shared_secret_derive(suite.edhoc_ecdh, &c_i.i, &cred_r.g,
					 dbg_ss.ptr));
			PRINT_ARRAY("[init] dbg_static_ss (i,g_r)", dbg_ss.ptr,
				    dbg_ss.len);
		}
	} else {
		cred_r.g = NULL_ARRAY;
	}

	if (!static_dh_i) {
		uint8_t seed_sig_i[ED25519_SEED_SIZE] = {0x20};
		compact_ed25519_keygen(sig_sk_i.ptr, sig_pk_i.ptr, seed_sig_i);
		c_i.sk_i = sig_sk_i;
		c_i.pk_i = sig_pk_i;
	} else {
		c_i.sk_i = NULL_ARRAY;
		c_i.pk_i = NULL_ARRAY;
	}

	if (!static_dh_r) {
		uint8_t seed_sig_r[ED25519_SEED_SIZE] = {0x10};
		compact_ed25519_keygen(sig_sk_r_dummy.ptr, sig_pk_r.ptr,
				     seed_sig_r);
		cred_r.pk = sig_pk_r;
	} else {
		cred_r.pk = NULL_ARRAY;
	}

	// ephemeral keys (DH and optional KEM for hybrid suites)
	uint32_t dh_pk_len = get_ecdh_pk_len(suite.edhoc_ecdh);
	uint32_t dh_sk_len = dh_pk_len;
	uint32_t kem_pk_len = get_kem_pk_len(suite.edhoc_ecdh);
	uint32_t kem_sk_len = get_kem_sk_len(suite.edhoc_ecdh);

	BYTE_ARRAY_NEW(eph_dh_sk, dh_sk_len, dh_sk_len);
	BYTE_ARRAY_NEW(eph_dh_pk, dh_pk_len, dh_pk_len);
	uint32_t seed_eph = 0x33333333;
	PRINTF("[init] ephemeral DH keygen alg %d\n", suite.edhoc_ecdh);
	TRY(ephemeral_dh_key_gen(base_dh_alg(suite.edhoc_ecdh), seed_eph, &eph_dh_sk,
				 &eph_dh_pk));

	BYTE_ARRAY_NEW(eph_kem_sk, kem_sk_len, kem_sk_len);
	BYTE_ARRAY_NEW(eph_kem_pk, kem_pk_len, kem_pk_len);
	if (kem_pk_len > 0) {
		PRINTF("[init] ephemeral KEM keygen alg %d\n", suite.edhoc_ecdh);
		enum err ret = ephemeral_kem_key_gen(suite.edhoc_ecdh, &eph_kem_sk,
						 &eph_kem_pk);
		if (ret != ok) {
			PRINTF("[init] kem keygen failed ret=%d\n", ret);
			return ret;
		}
	}

	BYTE_ARRAY_NEW(gx, dh_pk_len + kem_pk_len, dh_pk_len + kem_pk_len);
	BYTE_ARRAY_NEW(x, dh_sk_len + kem_sk_len, dh_sk_len + kem_sk_len);
	_memcpy_s(gx.ptr, gx.len, eph_dh_pk.ptr, dh_pk_len);
	_memcpy_s(x.ptr, x.len, eph_dh_sk.ptr, dh_sk_len);
	if (kem_pk_len > 0) {
		memcpy(gx.ptr + dh_pk_len, eph_kem_pk.ptr, kem_pk_len);
		memcpy(x.ptr + dh_sk_len, eph_kem_sk.ptr, kem_sk_len);
	}

	c_i.c_i = BYTE_ARRAY_INIT((uint8_t *)"I", 1);
	c_i.method = (enum method_type)EDHOC_METHOD;
	uint8_t suites_arr[1] = { EDHOC_SUITE_LABEL };
	c_i.suites_i.ptr = suites_arr;
	c_i.suites_i.len = 1;
	c_i.ead_1 = NULL_ARRAY;
	c_i.ead_3 = NULL_ARRAY;
	c_i.id_cred_i.ptr = (uint8_t *)ID_CRED_I_RAW;
	c_i.id_cred_i.len = sizeof(ID_CRED_I_RAW);
	c_i.cred_i = c_i.id_cred_i; // minimal cred
	c_i.g_x = gx;
	c_i.x = x;
	/* sk_i/pk_i already set above depending on method */
	c_i.sock = &sockfd;

	cred_r.id_cred.ptr = (uint8_t *)ID_CRED_R_RAW;
	cred_r.id_cred.len = sizeof(ID_CRED_R_RAW);
	cred_r.cred = cred_r.id_cred;
	/* cred_r.pk set above based on authentication method */
	cred_r.ca.len = 0;
	cred_r.ca_pk.len = 0;

	struct other_party_cred cred_r_alt = cred_r;
	cred_r_alt.id_cred.ptr = (uint8_t *)ID_CRED_R_INT_RAW;
	cred_r_alt.id_cred.len = sizeof(ID_CRED_R_INT_RAW);
	cred_r_alt.cred = cred_r_alt.id_cred;

	struct other_party_cred cred_r_hash = cred_r;
	cred_r_hash.id_cred.ptr = (uint8_t *)ID_CRED_R_HASH_RAW;
	cred_r_hash.id_cred.len = sizeof(ID_CRED_R_HASH_RAW);
	cred_r_hash.cred = cred_r_hash.id_cred;

	struct other_party_cred cred_r_hash2 = cred_r;
	cred_r_hash2.id_cred.ptr = (uint8_t *)ID_CRED_R_HASH2_RAW;
	cred_r_hash2.id_cred.len = sizeof(ID_CRED_R_HASH2_RAW);
	cred_r_hash2.cred = cred_r_hash2.id_cred;

	struct other_party_cred cred_r_hash3 = cred_r;
	cred_r_hash3.id_cred.ptr = (uint8_t *)ID_CRED_R_HASH3_RAW;
	cred_r_hash3.id_cred.len = sizeof(ID_CRED_R_HASH3_RAW);
	cred_r_hash3.cred = cred_r_hash3.id_cred;

	struct other_party_cred cred_r_entries[5] = { cred_r, cred_r_alt,
					      cred_r_hash, cred_r_hash2,
					      cred_r_hash3 };
	struct cred_array cred_r_array = { .len = 5, .ptr = cred_r_entries };

	TRY_EXPECT(start_udp_client(&sockfd), 0);
	PRINTF("[init] socket ready\n");
	PRINTF("[init] starting edhoc_initiator_run\n");
	{
		enum err ret = edhoc_initiator_run(&c_i, &cred_r_array, &err_msg,
					&PRK_out, tx, rx, ead_process);
		if (ret != ok) {
			PRINTF("[init] edhoc_initiator_run ret=%d\n", ret);
			return ret;
		}
	}
	PRINTF("[init] edhoc_initiator_run completed\n");

	PRINT_ARRAY("PRK_out", PRK_out.ptr, PRK_out.len);
	TRY(prk_out2exporter(SHA_256, &PRK_out, &prk_exporter));
	PRINT_ARRAY("prk_exporter", prk_exporter.ptr, prk_exporter.len);
	TRY(edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &prk_exporter,
			   &oscore_master_secret));
	PRINT_ARRAY("OSCORE Master Secret", oscore_master_secret.ptr,
		    oscore_master_secret.len);
	TRY(edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &prk_exporter,
			   &oscore_master_salt));
	PRINT_ARRAY("OSCORE Master Salt", oscore_master_salt.ptr,
		    oscore_master_salt.len);

	close(sockfd);
	return 0;
}
