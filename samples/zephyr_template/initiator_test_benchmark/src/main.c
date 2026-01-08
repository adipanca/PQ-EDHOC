/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdio.h>
#include "edhoc.h"
#include "sock.h"
#include "edhoc_test_vectors_p256_v16.h"

#ifdef USE_SUIT_7
#define MAX_PAYLOAD_SIZE 1500
#define TEST_X5T_NUM 7
#define TEST_X5CHAIN_NUM 8
#define GEN_EPH_KEYS
#define MY_STACK_SIZE 25008
/* size of stack area used by each thread */
#define MAX_MSG_SIZE 3200

/*KYBER LEVEL 1, DILITHIUM LEVEL 2*/
#elif USE_SUIT_12
#define MAX_PAYLOAD_SIZE 3209
#define TEST_X5T_NUM 11
#define TEST_X5CHAIN_NUM 12
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define MY_STACK_SIZE 70000

/*KYBER LEVEL 1, HAWK LEVEL 2*/
#elif USE_SUIT_14
#define MAX_PAYLOAD_SIZE 1500
#define TEST_X5T_NUM 16
#define TEST_X5CHAIN_NUM 16
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
//#define MY_STACK_SIZE 25008
#define MY_STACK_SIZE 30000
/*KYBER LEVEL 1, HAETAE LEVEL 2*/
#elif USE_SUIT_15
#define MAX_PAYLOAD_SIZE 2500
#define TEST_X5T_NUM 17
#define TEST_X5CHAIN_NUM 17
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define MY_STACK_SIZE 80000

/*CIPHER SUIT 2 secp256r1 ECDSA* */
#elif USE_SUIT_2
#define TEST_X5T_NUM 2
#define TEST_X5CHAIN_NUM 3
// #define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define MY_STACK_SIZE 11000
#define MAX_PAYLOAD_SIZE 800
#else
#error "Need to define ciphersuit"

#endif

#ifdef USE_X5CHAIN
#define TEST_VEC_NUM TEST_X5CHAIN_NUM
#elif USE_X5T
#define TEST_VEC_NUM TEST_X5T_NUM
#else
#error "need to define x5chain or x5t"
#endif

/**
 * @brief	Initializes sockets for TCP client.
 * @param
 * @retval	error code
 */
static int start_socket_client(int *sockfd)
{
	/*struct sockaddr_in6 servaddr;
    //const char IPV6_SERVADDR[] = { "::1" };
    const char IPV6_SERVADDR[] = { "2001:db8::2" };
    int r = ipv6_sock_init(SOCK_CLIENT, IPV6_SERVADDR, &servaddr,
                   sizeof(servaddr), sockfd);
    if (r < 0) {
        printf("error during socket initialization (error code: %d)",
               r);
        return -1;
    }*/
	return ok;
}

enum err ead_process(void *params, struct byte_array *ead13)
{
	/*for this sample we are not using EAD*/
	/*to save RAM we use FEATURES += -DEAD_SIZE=0*/
	return ok;
}

/**
 * @brief	Callback function called inside the frontend when data needs to
 * 		be send over the network. You should implement the transport here over the open TCP socket
 *      and send the data contained in the byte_array struct
 * @param	data pointer to the data that needs to be send
 */
enum err tx(void *sock, struct byte_array *data)
{
	return ok;
}

/**
 * @brief	Callback function called inside the frontend when data needs to
 * 		be received over the network. You should implement the receive data over the open TCP socket,
 *      this should wait until data is received and then fill the byte_array struct with the received data
 * @param	data pointer to the data that needs to be received
 */
enum err rx(void *sock, struct byte_array *data)
{
	return ok;
}

int internal_main(void)
{
	int32_t s = 30000;
	printf("sleep for %d msecond after connection in order to have time to start wireshark on bt0\n",
	       s);
	k_msleep(s);

	int sockfd;
	BYTE_ARRAY_NEW(prk_exporter, 32, 32);
	BYTE_ARRAY_NEW(oscore_master_secret, 16, 16);
	BYTE_ARRAY_NEW(oscore_master_salt, 8, 8);
	BYTE_ARRAY_NEW(PRK_out, 32, 32);
	BYTE_ARRAY_NEW(err_msg, 0, 0);

	/* test vector inputs */
	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;

	const uint8_t TEST_VEC_NUM = 2;
	uint8_t vec_num_i = TEST_VEC_NUM - 1;

	c_i.sock = &sockfd;
	c_i.c_i.len = test_vectors[vec_num_i].c_i_len;
	c_i.c_i.ptr = (uint8_t *)test_vectors[vec_num_i].c_i;
	c_i.method = (enum method_type) * test_vectors[vec_num_i].method;
	c_i.suites_i.len = test_vectors[vec_num_i].SUITES_I_len;
	c_i.suites_i.ptr = (uint8_t *)test_vectors[vec_num_i].SUITES_I;
	c_i.ead_1.len = test_vectors[vec_num_i].ead_1_len;
	c_i.ead_1.ptr = (uint8_t *)test_vectors[vec_num_i].ead_1;
	c_i.ead_3.len = test_vectors[vec_num_i].ead_3_len;
	c_i.ead_3.ptr = (uint8_t *)test_vectors[vec_num_i].ead_3;
	c_i.id_cred_i.len = test_vectors[vec_num_i].id_cred_i_len;
	c_i.id_cred_i.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_i;
	c_i.cred_i.len = test_vectors[vec_num_i].cred_i_len;
	c_i.cred_i.ptr = (uint8_t *)test_vectors[vec_num_i].cred_i;
	c_i.g_x.len = test_vectors[vec_num_i].g_x_raw_len;
	c_i.g_x.ptr = (uint8_t *)test_vectors[vec_num_i].g_x_raw;
	c_i.x.len = test_vectors[vec_num_i].x_raw_len;
	c_i.x.ptr = (uint8_t *)test_vectors[vec_num_i].x_raw;
	c_i.g_i.len = test_vectors[vec_num_i].g_i_raw_len;
	c_i.g_i.ptr = (uint8_t *)test_vectors[vec_num_i].g_i_raw;
	c_i.i.len = test_vectors[vec_num_i].i_raw_len;
	c_i.i.ptr = (uint8_t *)test_vectors[vec_num_i].i_raw;
	c_i.sk_i.len = test_vectors[vec_num_i].sk_i_raw_len;
	c_i.sk_i.ptr = (uint8_t *)test_vectors[vec_num_i].sk_i_raw;
	c_i.pk_i.len = test_vectors[vec_num_i].pk_i_raw_len;
	c_i.pk_i.ptr = (uint8_t *)test_vectors[vec_num_i].pk_i_raw;

	cred_r.id_cred.len = test_vectors[vec_num_i].id_cred_r_len;
	cred_r.id_cred.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_r;
	cred_r.cred.len = test_vectors[vec_num_i].cred_r_len;
	cred_r.cred.ptr = (uint8_t *)test_vectors[vec_num_i].cred_r;
	cred_r.g.len = test_vectors[vec_num_i].g_r_raw_len;
	cred_r.g.ptr = (uint8_t *)test_vectors[vec_num_i].g_r_raw;
	cred_r.pk.len = test_vectors[vec_num_i].pk_r_raw_len;
	cred_r.pk.ptr = (uint8_t *)test_vectors[vec_num_i].pk_r_raw;
	cred_r.ca.len = test_vectors[vec_num_i].ca_r_len;
	cred_r.ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca_r;
	cred_r.ca_pk.len = test_vectors[vec_num_i].ca_r_pk_len;
	cred_r.ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_r_pk;

	struct suite suit_in;
	get_suite((enum suite_label)c_i.suites_i.ptr[c_i.suites_i.len - 1],
		  &suit_in);
#ifndef USE_SUIT_2
	PRINTF("use of PQC suits\n");
	uint8_t SK[get_sk_len(suit_in.edhoc_sign)];
	uint8_t PK[get_pk_len(suit_in.edhoc_sign)];
	memcpy(SK, c_i.sk_i.ptr, c_i.sk_i.len);
	memcpy(PK, c_i.pk_i.ptr, c_i.pk_i.len);
	c_i.sk_i.ptr = SK;
	c_i.sk_i.len = get_sk_len(suit_in.edhoc_sign);
	c_i.pk_i.ptr = PK;
	c_i.pk_i.len = get_pk_len(suit_in.edhoc_sign);
#endif

#if defined(GEN_EPH_KEYS) && !defined(USE_SUIT_2)
	uint8_t PQ_public_random[get_kem_pk_len(suit_in.edhoc_ecdh)];
	uint8_t PQ_secret_random[get_kem_sk_len(suit_in.edhoc_ecdh)];
	// PRINTF("Arrive here 2\n");
	c_i.g_x.ptr = PQ_public_random;
	// c_i.g_x.len = PQ_public_random.len;
	c_i.g_x.len = get_kem_pk_len(suit_in.edhoc_ecdh);
	// PRINTF("Arrive here 3\n");
	c_i.x.ptr = PQ_secret_random;
	c_i.x.len = get_kem_sk_len(suit_in.edhoc_ecdh);

#endif

	PRINTF("public ephemeral Key size: %d\n", c_i.g_x.len);
	PRINTF("secret ephemeral Key size: %d\n", c_i.x.len);
// #endif
#if defined(GEN_EPH_KEYS) && !defined(USE_SUIT_2)
	ephemeral_kem_key_gen(suit_in.edhoc_ecdh, &c_i.x, &c_i.g_x);
#endif

	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };

	start_socket_client(&sockfd);
	edhoc_initiator_run(&c_i, &cred_r_array, &err_msg, &PRK_out, tx, rx,
			    ead_process);

	PRINT_ARRAY("PRK_out", PRK_out.ptr, PRK_out.len);

	prk_out2exporter(SHA_256, &PRK_out, &prk_exporter);
	PRINT_ARRAY("prk_exporter", prk_exporter.ptr, prk_exporter.len);

	edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &prk_exporter,
		       &oscore_master_secret);
	PRINT_ARRAY("OSCORE Master Secret", oscore_master_secret.ptr,
		    oscore_master_secret.len);

	edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &prk_exporter,
		       &oscore_master_salt);
	PRINT_ARRAY("OSCORE Master Salt", oscore_master_salt.ptr,
		    oscore_master_salt.len);

	close(sockfd);
	return 0;
}

void main(void)
{
	int r = internal_main();
	if (r != 0) {
		printf("error during initiator run. Error code: %d\n", r);
	}
}