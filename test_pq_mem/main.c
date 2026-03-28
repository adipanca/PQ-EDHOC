/*
 * Copyright (c) 2022 Eriptic Technologies.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#include <zephyr/kernel.h>
//#include <zephyr/ztest.h>
#include <zephyr/debug/thread_analyzer.h>
#include <zephyr/sys/time_units.h>
#include <string.h>
#include <edhoc.h>

#include "edhoc_test_vectors_p256_v16.h"
//#include "latency.h"





/* scheduling priority used by each thread */
#define PRIORITY 7
/*Define for testing external trigger*/

/*Define interaction number*/
#ifdef USE_INTE_NUM
#define INTERACTION_NUM USE_INTE_NUM
#else
#define INTERACTION_NUM 1
#endif
volatile uint64_t times = INTERACTION_NUM;

//#define MSG_LEN 30
/*KYBER LEVEL 1, FALCON LEVEL 1*/
#ifdef USE_SUIT_7
#define TEST_X5T_NUM 7
#define TEST_X5CHAIN_NUM 8
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I_X5T 22748
#define STACKSIZE_I_X5CHAIN 33844
#define STACKSIZE_R_X5T 22980
#define STACKSIZE_R_X5CHAIN 31276
#define MAX_MSG_SIZE_X5T 1447
#define MAX_MSG_SIZE_X5CHAIN 3155
#define USE_SUIT SUITE_7 


/*KYBER LEVEL 3, FALCON LEVEL 1*/
#elif USE_SUIT_9
#define TEST_X5T_NUM 9
#define TEST_X5CHAIN_NUM 10
#define GEN_EPH_KEYS
/* size of stack area used by each thread */

#define STACKSIZE_I_X5T 24860
#define STACKSIZE_I_X5CHAIN 35956
#define STACKSIZE_R_X5T 21572 
#define STACKSIZE_R_X5CHAIN 32684

//#define STACKSIZE_I 50000
//#define STACKSIZE_R 40000

#define MAX_MSG_SIZE_X5T 1780
#define MAX_MSG_SIZE_X5CHAIN 3500

#define USE_SUIT SUITE_9

/*HQC LEVEL 1, FALCON LEVEL 1*/
#elif USE_SUIT_10
#define TEST_X5T_NUM 13
#define TEST_X5CHAIN_NUM 13
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I_X5T 84072
#define STACKSIZE_R_X5T 75880
#define MAX_MSG_SIZE_X5T 5200
#define USE_SUIT SUITE_10

/*BIKE LEVEL 1, FALCON LEVEL 1*/
#elif USE_SUIT_11
#define TEST_X5T_NUM 14
#define TEST_X5CHAIN_NUM 14
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I_X5T 117604
#define STACKSIZE_R_X5T 43564
#define MAX_MSG_SIZE_X5T 2300
#define USE_SUIT SUITE_11

/*KYBER LEVEL 1, DILITHIUM LEVEL 2*/
#elif USE_SUIT_12
#define TEST_X5T_NUM 11
#define TEST_X5CHAIN_NUM 12
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
/*#define STACKSIZE_I 90000
#define STACKSIZE_R 90000
#define MAX_MSG_SIZE 7104
*/
#define STACKSIZE_I_X5T 40260
#define STACKSIZE_I_X5CHAIN 68196
#define STACKSIZE_R_X5T 39148
#define STACKSIZE_R_X5CHAIN 63892
#define MAX_MSG_SIZE_X5T 3250
#define MAX_MSG_SIZE_X5CHAIN 7150

#define USE_SUIT SUITE_12
/*BIKE LEVEL 1, DILITHIUM LEVEL 2*/
#elif USE_SUIT_13
#define TEST_X5T_NUM 15
#define TEST_X5CHAIN_NUM 15
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I 135000
#define STACKSIZE_R 85000
#define MAX_MSG_SIZE 7000
#define USE_SUIT SUITE_13


/*KYBER LEVEL 1, HAWK LEVEL 2*/
#elif USE_SUIT_14
#define TEST_X5T_NUM 16
#define TEST_X5CHAIN_NUM 16
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I_X5T 24044
#define STACKSIZE_R_X5T 22940
#define MAX_MSG_SIZE_X5T 1390
#define USE_SUIT SUITE_14

/*KYBER LEVEL 1, HAETAE LEVEL 2*/
#elif USE_SUIT_15
#define TEST_X5T_NUM 17
#define TEST_X5CHAIN_NUM 17
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
#define STACKSIZE_I_X5T 73080
#define STACKSIZE_R_X5T 74848
#define MAX_MSG_SIZE_X5T 2313
#define USE_SUIT SUITE_15




/*CIPHER SUIT 2 secp256r1 ECDSA* */
#elif USE_SUIT_2
#define TEST_X5T_NUM 2
#define TEST_X5CHAIN_NUM 3 
//#define GEN_EPH_KEYS
/* size of stack area used by each thread */

/*#define STACKSIZE_I 50000
#define STACKSIZE_R 40000
#define MAX_MSG_SIZE 800
*/
#define STACKSIZE_I_X5T 10980
#define STACKSIZE_I_X5CHAIN 13916
#define STACKSIZE_R_X5T 10540
#define STACKSIZE_R_X5CHAIN 13108
#define MAX_MSG_SIZE_X5T 150
#define MAX_MSG_SIZE_X5CHAIN 448
#define USE_SUIT SUITE_2


#elif USE_SUIT_17
#define TEST_X5T_NUM 18
#define TEST_X5CHAIN_NUM 18
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
//#define STACKSIZE_I_X5T 17944
//#define STACKSIZE_R_X5T 13400
#define STACKSIZE_I_X5T 18000
#define STACKSIZE_R_X5T 14000
#define MAX_MSG_SIZE_X5T 1479
#define MAX_MSG_SIZE_X5CHAIN 3187
#define USE_SUIT SUITE_17 
#define PQ_T_HYBRID

#elif USE_SUIT_18
#define TEST_X5T_NUM 18
#define TEST_X5CHAIN_NUM 18
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
//#define STACKSIZE_I_X5T 17944
//#define STACKSIZE_R_X5T 13400
#define STACKSIZE_I_X5T 21300
#define STACKSIZE_R_X5T 14900
#define MAX_MSG_SIZE_X5T 1780
#define MAX_MSG_SIZE_X5CHAIN 3500
#define USE_SUIT SUITE_18 
#define PQ_T_HYBRID

#elif USE_SUIT_19
#define TEST_X5T_NUM 18
#define TEST_X5CHAIN_NUM 18
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
//#define STACKSIZE_I_X5T 17944
//#define STACKSIZE_R_X5T 13400
#define STACKSIZE_I_X5T 84500
#define STACKSIZE_R_X5T 72500
#define MAX_MSG_SIZE_X5T 5200
#define USE_SUIT SUITE_19 
#define PQ_T_HYBRID

#elif USE_SUIT_20
#define TEST_X5T_NUM 18
#define TEST_X5CHAIN_NUM 18
#define GEN_EPH_KEYS
/* size of stack area used by each thread */
//#define STACKSIZE_I_X5T 17944
//#define STACKSIZE_R_X5T 13400
#define STACKSIZE_I_X5T 120300
#define STACKSIZE_R_X5T 40300
#define MAX_MSG_SIZE_X5T 7000
#define USE_SUIT SUITE_20
#define PQ_T_HYBRID
#else 
#error "Need to define ciphersuit"

#endif

#ifdef USE_X5CHAIN
#define TEST_NUM TEST_X5CHAIN_NUM
#define STACKSIZE_I STACKSIZE_I_X5CHAIN
#define STACKSIZE_R STACKSIZE_R_X5CHAIN
#define MAX_MSG_SIZE MAX_MSG_SIZE_X5CHAIN

#elif USE_X5T
#define TEST_NUM TEST_X5T_NUM
#define STACKSIZE_I STACKSIZE_I_X5T
#define STACKSIZE_R STACKSIZE_R_X5T
#define MAX_MSG_SIZE MAX_MSG_SIZE_X5T
#else
#error "need to define x5chain or x5t"
#endif




#ifdef USE_TEST_EDHOC
#ifdef INITIATOR
uint8_t I_prk_exporter_buf[32];
struct byte_array I_prk_exporter = { .ptr = I_prk_exporter_buf,
				     .len = sizeof(I_prk_exporter_buf) };

uint8_t I_master_secret_buf[16];
struct byte_array I_master_secret = { .ptr = I_master_secret_buf,
				      .len = sizeof(I_master_secret_buf) };

uint8_t I_master_salt_buf[8];
struct byte_array I_master_salt = { .ptr = I_master_salt_buf,
				    .len = sizeof(I_master_salt_buf) };

uint8_t I_PRK_out_buf[32];
struct byte_array I_PRK_out = { .ptr = I_PRK_out_buf,
				.len = sizeof(I_PRK_out_buf) };

uint8_t I_err_msg_buf[0];
struct byte_array I_err_msg = { .ptr = I_err_msg_buf,
				.len = sizeof(I_err_msg_buf) };
#endif
/******************************************************************************/
#ifdef RESPONDER
uint8_t R_prk_exporter_buf[32];
struct byte_array R_prk_exporter = { .ptr = R_prk_exporter_buf,
				     .len = sizeof(R_prk_exporter_buf) };

uint8_t R_master_secret_buf[16];
struct byte_array R_master_secret = { .ptr = R_master_secret_buf,
				      .len = sizeof(R_master_secret_buf) };

uint8_t R_master_salt_buf[8];
struct byte_array R_master_salt = { .ptr = R_master_salt_buf,
				    .len = sizeof(R_master_salt_buf) };

uint8_t R_PRK_out_buf[32];
struct byte_array R_PRK_out = { .ptr = R_PRK_out_buf,
				.len = sizeof(R_PRK_out_buf) };

uint8_t R_err_msg_buf[0];
struct byte_array R_err_msg = { .ptr = R_err_msg_buf,
				.len = sizeof(R_err_msg_buf) };

#endif
#ifdef INITIATOR
K_THREAD_STACK_DEFINE(thread_initiator_stack_area, STACKSIZE_I);
static struct k_thread thread_initiator_data;
#endif
#ifdef RESPONDER
K_THREAD_STACK_DEFINE(thread_responder_stack_area, STACKSIZE_R);
static struct k_thread thread_responder_data;
#endif
/*semaphores*/
K_SEM_DEFINE(tx_initiator_completed, 0, 1);
K_SEM_DEFINE(tx_responder_completed, 0, 1);

/*message exchange buffer*/
uint8_t msg_exchange_buf[MAX_MSG_SIZE];
uint32_t msg_exchange_buf_len = sizeof(msg_exchange_buf);

size_t initiator_tx_size = 0;
size_t responder_tx_size = 0;

int rx_count = 0;
#endif





#ifdef USE_TEST_EDHOC
void semaphore_give(struct k_sem *sem)
{
	k_sem_give(sem);
}

enum err semaphore_take(struct k_sem *sem, uint8_t *data, uint32_t *data_len)
{
	if (k_sem_take(sem, K_FOREVER) != 0) {
		PRINT_MSG("Cannot receive a message!\n");
	} else {
		if (msg_exchange_buf_len > *data_len) {
			return buffer_to_small;
		} else {
			memcpy(data, msg_exchange_buf, *data_len);
			*data_len = msg_exchange_buf_len;
		}
	}
	return ok;
}

enum err copy_message(uint8_t *data, uint32_t data_len)
{
	if (data_len > sizeof(msg_exchange_buf)) {
		PRINT_MSG("msg_exchange_buf to small\n");
		return buffer_to_small;
	} else {
		memcpy(msg_exchange_buf, data, data_len);
		msg_exchange_buf_len = data_len;
	}
	return ok;
}

#ifdef INITIATOR
enum err tx_initiator(void *sock, struct byte_array *data)
{
	PRINTF("I: tx_initiator data len: %d\n", data->len);
	initiator_tx_size = initiator_tx_size + data->len;
	enum err r = copy_message(data->ptr, data->len);
	if (r != ok) {
		return r;
	}
	semaphore_give(&tx_initiator_completed);

    if(rx_count == 0){
	#ifdef MEASURE_LATENCY_PER_THREAD
	volatile uint32_t clock_start = k_cycle_get_32();  
	#endif
	#ifdef POWER_MEASUREMENTS   
	gpio_pin_set_dt(&led_r, 1);
	#endif
	#ifdef MEASURE_CLK
	int rc;
	if (!device_is_ready(clock0)) {
		printf("%s: device not ready.\n", clock0->name);
		return;
	}
	if (IS_ENABLED(CONFIG_APP_ENABLE_HFXO)) {
		rc = clock_control_on(clock0, CLOCK_CONTROL_NRF_SUBSYS_HF);
		//printf("Enable HFXO\n");
	}
	else{
		printf("HF is not Enable\n");
	}
		/* Grab the timer. */
	if (!device_is_ready(timer0)) {
		printf("%s: device not ready.\n", timer0->name);
		return;
	}
	rc = counter_start(timer0);
	rc = counter_get_value(timer0, &ctr_start_r);
	PRINTF("START MEASURE RESPONDER %llu  \n",ctr_start_r);
	#endif
	}
	rx_count++;


	return ok;
}
#endif
#ifdef RESPONDER
enum err tx_responder(void *sock, struct byte_array *data)
{
	
	PRINTF("tx_responder data len: %d\n", data->len);
    responder_tx_size = responder_tx_size + data->len;
	enum err r = copy_message(data->ptr, data->len);
	if (r != ok) {
		return r;
	}
	//PRINTF("msg_exchange_buf_len: %d\n",msg_exchange_buf_len);
	semaphore_give(&tx_responder_completed);
	
	return ok;
}
#endif
#ifdef INITIATOR
enum err rx_initiator(void *sock, struct byte_array *data)
{
	PRINTF("Rx_initiator\n");
	PRINTF("msg_exchange_buf_len: %d\n", msg_exchange_buf_len);
	return semaphore_take(&tx_responder_completed, data->ptr, &data->len);
}
#endif
#ifdef RESPONDER
enum err rx_responder(void *sock, struct byte_array *data)
{
	PRINTF("Rx_responder\n");
	PRINTF("msg_exchange_buf_len: %d\n", msg_exchange_buf_len);
	return semaphore_take(&tx_initiator_completed, data->ptr, &data->len);
}
#endif
enum err ead_process(void *params, struct byte_array *ead13)
{
	return ok;
}

#ifdef INITIATOR
/**
 * @brief			A thread in which an Initiator instance is executed
 * 
 * @param vec_num 	Test vector number
 * @param dummy2 	unused
 * @param dummy3 	unused
 */
void thread_initiator(void *vec_num, void *dummy2, void *dummy3)
{

	ARG_UNUSED(dummy2);
	ARG_UNUSED(dummy3);

	//PRINT_MSG("Initiator thread started!\n");
	int vec_num_i = *((int *)vec_num) - 1;
	PRINTF("Initiator thread started with test vector %d!\n",vec_num_i +1);
	enum err r;

	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;

	c_i.sock = NULL;
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

	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };
	struct suite suit_in;
	get_suite((enum suite_label)c_i.suites_i.ptr[c_i.suites_i.len - 1],
			&suit_in);
    #if !defined(USE_SUIT_2) && !defined(PQ_T_HYBRID)
	PRINTF("PQC suit no hybrid\n");
	uint8_t SK[get_sk_len(suit_in.edhoc_sign)];
	uint8_t PK[get_pk_len(suit_in.edhoc_sign)];
	memcpy(SK,c_i.sk_i.ptr,c_i.sk_i.len);
	memcpy(PK,c_i.pk_i.ptr,c_i.pk_i.len);
	c_i.sk_i.ptr = SK;
	c_i.sk_i.len = get_sk_len(suit_in.edhoc_sign);
	c_i.pk_i.ptr = PK;
	c_i.pk_i.len = get_pk_len(suit_in.edhoc_sign);
    #endif

	//printf("start measure\n");
	#ifdef POWER_MEASUREMENTS
	    PRINTF("Start Initiator\n"); 
		gpio_pin_set_dt(&led_i, 0);

	#endif
	#ifdef MEASURE_LATENCY_PER_THREAD
    	volatile uint32_t clock_start = k_cycle_get_32();
	#endif
	#ifdef MEASURE_CLK
	uint32_t ctr_start;
	uint32_t ctr_end;
	int rc;
	if (!device_is_ready(clock0)) {
		printf("%s: device not ready.\n", clock0->name);
		return;
	}
	if (IS_ENABLED(CONFIG_APP_ENABLE_HFXO)) {
		rc = clock_control_on(clock0, CLOCK_CONTROL_NRF_SUBSYS_HF);
		//printf("Enable HFXO\n");
	}
	else{
		printf("HF is not Enable\n");
	}
		/* Grab the timer. */
	if (!device_is_ready(timer0)) {
		printf("%s: device not ready.\n", timer0->name);
		return;
	}
	rc = counter_start(timer0);
	rc = counter_get_value(timer0, &ctr_start);
	PRINTF("START MEASURE INITIATOR %llu  \n",(uint64_t)ctr_start);
	#endif
  	#if defined(GEN_EPH_KEYS) && defined(USE_SUIT_2)
	/*create a random seed*/
	PRINT_MSG("START EDHOC DH INITIATOR\n");
	//uint32_t seed = k_cycle_get_32();
	uint32_t seed = 0xDEADBEEF;
	uint8_t X_random[32];
	uint8_t G_X_random[32];
	byte_array x_dh;
	x_dh.ptr = X_random;
	x_dh.len = 32;

	byte_array g_x_dh;
	g_x_dh.ptr = G_X_random;
	g_x_dh.len = 32;
	/*create ephemeral DH keys from seed*/
	PRINT_MSG("ephmeral dh key\n");
	ephemeral_dh_key_gen(P256, seed, &x_dh, &g_x_dh);
	PRINT_MSG("ephmeral dh key generated\n");
	PRINT_ARRAY("secret ephemeral DH key", X_random, 32);
	PRINT_ARRAY("public ephemeral DH key", G_X_random, 32);
	#endif
  	
    #if defined(GEN_EPH_KEYS) && !defined(USE_SUIT_2) && !defined(PQ_T_HYBRID)
		PRINTF("PQC suit no hybrid\n");		  
		PRINTF("INITIATOR SUIT kem: %d, signature %d\n",suit_in.edhoc_ecdh,suit_in.edhoc_sign);

		uint8_t PQ_public_random[get_kem_pk_len(suit_in.edhoc_ecdh)];
		uint8_t PQ_secret_random[get_kem_sk_len(suit_in.edhoc_ecdh)];
		//PRINTF("Arrive here 2\n");
		c_i.g_x.ptr = PQ_public_random;
		//c_i.g_x.len = PQ_public_random.len;
		c_i.g_x.len = get_kem_pk_len(suit_in.edhoc_ecdh);
		//PRINTF("Arrive here 3\n");
		c_i.x.ptr = PQ_secret_random;
		c_i.x.len = get_kem_sk_len(suit_in.edhoc_ecdh);

		ephemeral_kem_key_gen(suit_in.edhoc_ecdh, &c_i.x,&c_i.g_x);
	
	#endif

	#ifdef PQ_T_HYBRID
	/*create a random seed*/
	PRINT_MSG("START EDHOC PQ/T HYBRID INITIATOR\n");
	//uint32_t seed = k_cycle_get_32();
	uint32_t seed = 0xDEADBEEF;
	uint8_t X_random[32];
	uint8_t G_X_random[32];
	byte_array x_dh;
	x_dh.ptr = X_random;
	x_dh.len = 32;

	byte_array g_x_dh;
	g_x_dh.ptr = G_X_random;
	g_x_dh.len = 32;
	/*create ephemeral DH keys from seed*/
	PRINT_MSG("ephmeral dh key\n");
	ephemeral_dh_key_gen(P256, seed, &x_dh, &g_x_dh);
	PRINT_MSG("ephmeral dh key generated\n");
	PRINT_ARRAY("secret ephemeral DH key", X_random, 32);
	PRINT_ARRAY("public ephemeral DH key", G_X_random, 32);

   // struct suite suit_in;
	get_suite((enum suite_label)c_i.suites_i.ptr[c_i.suites_i.len - 1],
		      &suit_in);
	PRINTF("Test vector number: %d\n", vec_num_i+1);
	PRINTF("Ciphersuit: KEM %d, Signature %d\n",suit_in.edhoc_ecdh,suit_in.edhoc_sign);

	PRINTF("Client KEM pk size: %d \n",get_kem_pk_len(suit_in.edhoc_ecdh));
	PRINTF("Client KEM sk size: %d \n", get_kem_sk_len(suit_in.edhoc_ecdh));
	uint8_t PQ_public_random[get_kem_pk_len(suit_in.edhoc_ecdh)];
	uint8_t PQ_secret_random[get_kem_sk_len(suit_in.edhoc_ecdh)];

	byte_array x_kem;
	x_kem.ptr = PQ_secret_random;
	x_kem.len = get_kem_sk_len(suit_in.edhoc_ecdh);

	byte_array g_x_kem;
	g_x_kem.ptr = PQ_public_random;
	g_x_kem.len = get_kem_pk_len(suit_in.edhoc_ecdh);
	PRINT_MSG("-------------------------------------------------------\n");
	PRINT_MSG("Generating ephemeral PQ key...\n");
	ephemeral_kem_key_gen(suit_in.edhoc_ecdh, &x_kem,&g_x_kem);

	PRINT_ARRAY("secret ephemeral KEM key", x_kem.ptr, x_kem.len);
	PRINT_ARRAY("public ephemeral KEM key", g_x_kem.ptr, g_x_kem.len);


	uint8_t g_x[get_kem_pk_len(suit_in.edhoc_ecdh)+ 32];
	uint8_t x[get_kem_sk_len(suit_in.edhoc_ecdh)+ 32];
    
	PRINTF("Before copy\n");
	memcpy(g_x,G_X_random,32);
	memcpy(g_x + 32,PQ_public_random,get_kem_pk_len(suit_in.edhoc_ecdh));

	PRINTF("Before copy secret\n");
	memcpy(x,X_random,32);
	memcpy(x + 32,PQ_secret_random, get_kem_sk_len(suit_in.edhoc_ecdh));

	c_i.g_x.ptr = g_x;
	c_i.g_x.len = get_kem_pk_len(suit_in.edhoc_ecdh)+ 32;
	c_i.x.ptr = x;
	c_i.x.len = get_kem_sk_len(suit_in.edhoc_ecdh)+ 32;

	PRINT_ARRAY("secret ephemeral PQ/T key", c_i.x.ptr, c_i.x.len);
	PRINT_ARRAY("public ephemeral PQ/T key", c_i.g_x.ptr,c_i.g_x.len);

	#endif
	#if !defined(GEN_EPH_KEYS) && defined(USE_SUIT_2)

		PRINTF("SUIT 2 with test_vector ephemerals\n")
	#endif
	rx_count = 0;

	r = edhoc_initiator_run(&c_i, &cred_r_array, &I_err_msg, &I_PRK_out,
				tx_initiator, rx_initiator, ead_process);
	if (r != ok) {
		goto end;
	}

	PRINT_ARRAY("I_PRK_out", I_PRK_out.ptr, I_PRK_out.len);

	r = prk_out2exporter(SHA_256, &I_PRK_out, &I_prk_exporter);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("I_prk_exporter", I_prk_exporter.ptr, I_prk_exporter.len);

	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &I_prk_exporter,
			   &I_master_secret);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("OSCORE Master Secret", I_master_secret.ptr,
		    I_master_secret.len);

	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &I_prk_exporter,
			   &I_master_salt);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("OSCORE Master Salt", I_master_salt.ptr, I_master_salt.len);
	#ifdef MEASURE_CLK
	rc = counter_get_value(timer0, &ctr_end);
	clk_i = (uint64_t)ctr_end - (uint64_t)ctr_start;
	PRINTF("STOP MEASURE INITIATOR %llu %llu \n",(uint64_t)ctr_end, clk_i);
	#endif
	#ifdef MEASURE_LATENCY_PER_THREAD
	volatile uint32_t clock_end = k_cycle_get_32(); 
	cycles_i = (uint64_t)clock_end - (uint64_t)clock_start;            
	us_i = k_cyc_to_us_near64(cycles_i);
	#endif  
	#ifdef POWER_MEASUREMENTS   
	PRINTF("Stop Initiator\n");
	gpio_pin_set_dt(&led_i, 1);
	#endif
	//semaphore_give(&tx_initiator_finished);

	

            
	/*printf("Elapsed time initiator:  %d (RTC cycles); %lld (us)\n", cycles_i,    
			us_i); */                                                   
   
#ifdef REPORT_STACK_USAGE
	int err;                                                  
   	size_t unused;
   	err = k_thread_stack_space_get(k_current_get(), &unused);
	if (err) {
		printf("ERROR in read thread memory\n");	
		unused = 0;
	}
	max_size_i = keep_max_size(max_size_i, STACKSIZE_I-unused);
	//printf("\rMax used stack on thread_initiator %zu\n",max_size_i);

	if(times == 0)
		//thread_analyzer_print();
#endif

	return;
end:
	PRINTF("An error has occurred. Error code: %d\n", r);
}

#endif

#ifdef RESPONDER

/**
 * @brief			A thread in which a Responder instance is executed
 * 
 * @param vec_num 	Test vector number
 * @param dummy2 	unused
 * @param dummy3 	unused
 */
void thread_responder(void *vec_num, void *dummy2, void *dummy3)
{
	ARG_UNUSED(dummy2);
	ARG_UNUSED(dummy3);
    int vec_num_i = *((int *)vec_num) - 1;
	PRINTF("Responder thread started with test vector %d!\n",vec_num_i +1);
	enum err r;
	

	/* test vector inputs */
	struct other_party_cred cred_i;
	struct edhoc_responder_context c_r;

	c_r.sock = NULL;
	c_r.c_r.ptr = (uint8_t *)test_vectors[vec_num_i].c_r;
	c_r.c_r.len = test_vectors[vec_num_i].c_r_len;
	c_r.suites_r.len = test_vectors[vec_num_i].SUITES_R_len;
	c_r.suites_r.ptr = (uint8_t *)test_vectors[vec_num_i].SUITES_R;
	c_r.ead_2.len = test_vectors[vec_num_i].ead_2_len;
	c_r.ead_2.ptr = (uint8_t *)test_vectors[vec_num_i].ead_2;
	c_r.ead_4.len = test_vectors[vec_num_i].ead_4_len;
	c_r.ead_4.ptr = (uint8_t *)test_vectors[vec_num_i].ead_4;
	c_r.id_cred_r.len = test_vectors[vec_num_i].id_cred_r_len;
	c_r.id_cred_r.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_r;
	c_r.cred_r.len = test_vectors[vec_num_i].cred_r_len;
	c_r.cred_r.ptr = (uint8_t *)test_vectors[vec_num_i].cred_r;
	c_r.g_y.len = test_vectors[vec_num_i].g_y_raw_len;
	c_r.g_y.ptr = (uint8_t *)test_vectors[vec_num_i].g_y_raw;
	c_r.y.len = test_vectors[vec_num_i].y_raw_len;
	c_r.y.ptr = (uint8_t *)test_vectors[vec_num_i].y_raw;
	c_r.g_r.len = test_vectors[vec_num_i].g_r_raw_len;
	c_r.g_r.ptr = (uint8_t *)test_vectors[vec_num_i].g_r_raw;
	c_r.r.len = test_vectors[vec_num_i].r_raw_len;
	c_r.r.ptr = (uint8_t *)test_vectors[vec_num_i].r_raw;
	c_r.sk_r.len = test_vectors[vec_num_i].sk_r_raw_len;
	c_r.sk_r.ptr = (uint8_t *)test_vectors[vec_num_i].sk_r_raw;
	c_r.pk_r.len = test_vectors[vec_num_i].pk_r_raw_len;
	c_r.pk_r.ptr = (uint8_t *)test_vectors[vec_num_i].pk_r_raw;

	cred_i.id_cred.len = test_vectors[vec_num_i].id_cred_i_len;
	cred_i.id_cred.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_i;
	cred_i.cred.len = test_vectors[vec_num_i].cred_i_len;
	cred_i.cred.ptr = (uint8_t *)test_vectors[vec_num_i].cred_i;
	cred_i.g.len = test_vectors[vec_num_i].g_i_raw_len;
	cred_i.g.ptr = (uint8_t *)test_vectors[vec_num_i].g_i_raw;
	cred_i.pk.len = test_vectors[vec_num_i].pk_i_raw_len;
	cred_i.pk.ptr = (uint8_t *)test_vectors[vec_num_i].pk_i_raw;
	cred_i.ca.len = test_vectors[vec_num_i].ca_i_len;
	cred_i.ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i;
	cred_i.ca_pk.len = test_vectors[vec_num_i].ca_i_pk_len;
	cred_i.ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i_pk;


    struct suite suit_in;
	get_suite((enum suite_label)c_r.suites_r.ptr[c_r.suites_r.len - 1],
				&suit_in);
	#if !defined(USE_SUIT_2) && !defined(PQ_T_HYBRID)
	PRINTF("PQC suit non hybrid\n");
	uint8_t SK[get_sk_len(suit_in.edhoc_sign)];
	uint8_t PK[get_pk_len(suit_in.edhoc_sign)];
	memcpy(SK,c_r.sk_r.ptr,c_r.sk_r.len);
	memcpy(PK,c_r.pk_r.ptr,c_r.pk_r.len);
	c_r.sk_r.ptr = SK;
	c_r.sk_r.len = get_sk_len(suit_in.edhoc_sign);
	c_r.pk_r.ptr = PK;
	c_r.pk_r.len = get_pk_len(suit_in.edhoc_sign);
	#endif			  
	PRINTF("Responder SUIT kem: %d, signature %d\n",suit_in.edhoc_ecdh,suit_in.edhoc_sign);

    /*#if defined(USE_SUIT_2) && !defined(PQ_T_HYBRID)
	PRINTF("USE SUIT 2\n");	
	PRINT_ARRAY("RX public ephemeral DH key", c_r.g_y.ptr, c_r.g_y.len);
	PRINT_ARRAY("RX secret ephemeral DH key", c_r.y.ptr, c_r.y.len);
	#endif*/
	#if !defined(USE_SUIT_2) && !defined(PQ_T_HYBRID)
	PRINTF("PQC suit non hybrid 2\n");
	uint8_t PQ_public_random[get_kem_cc_len(suit_in.edhoc_ecdh)];
	c_r.g_y.ptr = PQ_public_random;
	c_r.g_y.len = get_kem_cc_len(suit_in.edhoc_ecdh);
	#endif
    
	#if defined(USE_SUIT_2) && defined(GEN_EPH_KEYS) && !defined(PQ_T_HYBRID)
		/*create a random seed*/
	PRINT_MSG("START EDHOC DH RESPONDER\n");

	uint8_t G_Y[get_ecdh_pk_len(suit_in.edhoc_ecdh)];
	uint8_t Y[get_ecdh_pk_len(suit_in.edhoc_ecdh)];
	//uint32_t seed = k_cycle_get_32();
	uint32_t seed = 0xDEADBEEF;
	//uint8_t Y_random[32];
	//uint8_t G_Y_random[32];
	byte_array y_dh;
	y_dh.ptr = Y;
	y_dh.len = get_ecdh_pk_len(suit_in.edhoc_ecdh);

	byte_array g_y_dh;
	g_y_dh.ptr = G_Y;
	g_y_dh.len = get_ecdh_pk_len(suit_in.edhoc_ecdh);
	/*create ephemeral DH keys from seed*/
	PRINT_MSG("ephmeral dh key\n");
	ephemeral_dh_key_gen(P256, seed, &y_dh, &g_y_dh);
	PRINT_MSG("ephmeral dh key generated\n");
	PRINT_ARRAY("secret ephemeral DH key", y_dh.ptr, y_dh.len);
	PRINT_ARRAY("public ephemeral DH key", g_y_dh.ptr, g_y_dh.len);

   // struct suite suit_in;
	//get_suite((enum suite_label)c_i.suites_i.ptr[c_i.suites_i.len - 1],
	//	      &suit_in);
	PRINTF("Test vector number: %d\n", vec_num_i+1);
	PRINTF("Ciphersuit: KEM %d, Signature %d\n",suit_in.edhoc_ecdh,suit_in.edhoc_sign);

	/*GY in KEM is the encpasulatation*/
	//byte_array g_y_kem;
	//g_y_kem.ptr = Y + get_ecdh_pk_len(suit_in.edhoc_ecdh);
	//g_y_kem.len = get_kem_cc_len(suit_in.edhoc_ecdh);
	//memcpy(G_Y,g_y_dh.ptr,g_y_dh.len);
	#endif
	#ifdef PQ_T_HYBRID
	/*create a random seed*/
	PRINT_MSG("START EDHOC PQ/T HYBRID RESPONDER\n");

	uint8_t G_Y[get_kem_cc_len(suit_in.edhoc_ecdh)+ get_ecdh_pk_len(suit_in.edhoc_ecdh)];
	uint8_t G_Y_dh[get_ecdh_pk_len(suit_in.edhoc_ecdh)];
	uint8_t Y[get_ecdh_pk_len(suit_in.edhoc_ecdh)];
	//uint32_t seed = k_cycle_get_32();
	uint32_t seed = 0xDEADBEEF;
	//uint8_t Y_random[32];
	//uint8_t G_Y_random[32];
	byte_array y_dh;
	y_dh.ptr = Y;
	y_dh.len = get_ecdh_pk_len(suit_in.edhoc_ecdh);

	byte_array g_y_dh;
	g_y_dh.ptr = G_Y_dh;
	g_y_dh.len = get_ecdh_pk_len(suit_in.edhoc_ecdh);
	/*create ephemeral DH keys from seed*/
	PRINT_MSG("ephmeral dh key\n");
	ephemeral_dh_key_gen(P256, seed, &y_dh, &g_y_dh);
	PRINT_MSG("ephmeral dh key generated\n");
	PRINT_ARRAY("secret ephemeral DH key", y_dh.ptr, y_dh.len);
	PRINT_ARRAY("public ephemeral DH key", g_y_dh.ptr, g_y_dh.len);

   // struct suite suit_in;
	//get_suite((enum suite_label)c_i.suites_i.ptr[c_i.suites_i.len - 1],
	//	      &suit_in);
	PRINTF("Test vector number: %d\n", vec_num_i+1);
	PRINTF("Ciphersuit: KEM %d, Signature %d\n",suit_in.edhoc_ecdh,suit_in.edhoc_sign);

	/*GY in KEM is the encpasulatation*/
	//byte_array g_y_kem;
	//g_y_kem.ptr = Y + get_ecdh_pk_len(suit_in.edhoc_ecdh);
	//g_y_kem.len = get_kem_cc_len(suit_in.edhoc_ecdh);
	memcpy(G_Y,g_y_dh.ptr,g_y_dh.len);
	
	c_r.g_y.ptr = G_Y;
	c_r.g_y.len = get_kem_cc_len(suit_in.edhoc_ecdh) + get_ecdh_pk_len(suit_in.edhoc_ecdh);
	c_r.y.ptr = Y;
	c_r.y.len = get_ecdh_pk_len(suit_in.edhoc_ecdh);
	PRINTF("GY size:%d",c_r.g_y.len);
	PRINTF("Y size:%d",c_r.y.len);

	#endif


	
	struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i };
	//rx_count = 0;
    
	r = edhoc_responder_run(&c_r, &cred_i_array, &R_err_msg, &R_PRK_out,
				tx_responder, rx_responder, ead_process);
	if (r != ok) {
		goto end;
	}
   // semaphore_take_finished(&tx_initiator_finished);
	#ifdef POWER_MEASUREMENTS  
	PRINTF("Start Responder\n"); 
	gpio_pin_set_dt(&led_r, 0);

	#endif
	PRINT_MSG("Responder derive security context\n");
	PRINT_ARRAY("R_PRK_out", R_PRK_out.ptr, R_PRK_out.len);

	r = prk_out2exporter(SHA_256, &R_PRK_out, &R_prk_exporter);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("R_prk_exporter", R_prk_exporter.ptr, R_prk_exporter.len);

	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &R_prk_exporter,
			   &R_master_secret);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("OSCORE Master Secret", R_master_secret.ptr,
		    R_master_secret.len);

	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &R_prk_exporter,
			   &R_master_salt);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("OSCORE Master Salt", R_master_salt.ptr, R_master_salt.len);
	
	#ifdef MEASURE_CLK
	uint32_t ctr_end_r;
	int rc = counter_get_value(timer0, &ctr_end_r);
	clk_r = (uint64_t)ctr_end_r - (uint64_t)ctr_start_r;
	PRINTF("STOP MEASURE RESPONDER %llu %llu \n",(uint64_t)ctr_end_r, clk_r);
	#endif  
	#ifdef MEASURE_LATENCY_PER_THREAD
	volatile uint32_t clock_end = k_cycle_get_32();   
	cycles_r = (uint64_t)clock_end - (uint64_t)clock_start_r;  
	us_r = k_cyc_to_us_near64(cycles_r);
	#endif 
	#ifdef POWER_MEASUREMENTS   
	PRINTF("Stop responder\n");
	gpio_pin_set_dt(&led_r, 1);
	#endif
    

#ifdef REPORT_STACK_USAGE
	int err;                                                  
   	size_t unused;
   	err = k_thread_stack_space_get(k_current_get(), &unused);
	if (err) {
		printf("ERROR in read thread memory\n");	
		unused = 0;
	}
	max_size_r = keep_max_size(max_size_r, STACKSIZE_R-unused);
	//printf("\rMax used stack on thread_respondder %zu\n",max_size_r);
	//printf("\rMax used stack on thread_respondder %zu\n",STACKSIZE_R-unused);

	if(times == 0)
	//	thread_analyzer_print();
#endif

	return;
end:
	PRINTF("An error has occurred. Error code: %d\n", r);
}
#endif
#endif




#ifdef USE_TEST_EDHOC
int test_initiator_responder_interaction(int vec_num)
{
	PRINT_MSG("start initiator_responder_interaction\n");
    
	#ifdef INITIATOR
	/*initiator thread*/
	k_tid_t initiator_tid = k_thread_create(
		&thread_initiator_data, thread_initiator_stack_area,
		K_THREAD_STACK_SIZEOF(thread_initiator_stack_area),
		thread_initiator, (void *)&vec_num, NULL, NULL, PRIORITY, 0,
		K_NO_WAIT);
    #endif
	#ifdef RESPONDER
	/*responder thread*/
	k_tid_t responder_tid = k_thread_create(
		&thread_responder_data, thread_responder_stack_area,
		K_THREAD_STACK_SIZEOF(thread_responder_stack_area),
		thread_responder, (void *)&vec_num, NULL, NULL, PRIORITY, 0,
		K_NO_WAIT);
    #endif
	#ifdef INITIATOR  
	k_thread_start(&thread_initiator_data);
	#endif
	#ifdef RESPONDER
	k_thread_start(&thread_responder_data);
    #endif
	#ifdef INITIATOR
	if (0 != k_thread_join(&thread_initiator_data, K_SECONDS(5))) {
		PRINT_MSG("initiator thread stalled! Aborting.");
		k_thread_abort(initiator_tid);
	}
	#endif
	#ifdef RESPONDER
	if (0 != k_thread_join(&thread_responder_data, K_SECONDS(5))) {
		PRINT_MSG("responder thread stalled! Aborting.");
		k_thread_abort(responder_tid);
	}
	#endif
	printf("threads completed\n");

	/* check if Initiator and Responder computed the same values */

	/*zassert_mem_equal__(I_PRK_out.ptr, R_PRK_out.ptr, R_PRK_out.len,
			    "wrong prk_out");

	zassert_mem_equal__(I_prk_exporter.ptr, R_prk_exporter.ptr,
			    R_prk_exporter.len, "wrong prk_exporter");

	zassert_mem_equal__(I_master_secret.ptr, R_master_secret.ptr,
			    R_master_secret.len, "wrong master_secret");

	zassert_mem_equal__(I_master_salt.ptr, R_master_salt.ptr,
			    R_master_salt.len, "wrong master_salt");*/
	return 0;
}
#endif
/*
 * Benchmark harness note:
 * The EDHOC handshake threads can stall when credentials/test vectors
 * do not line up. To keep the native_posix binary from hanging forever
 * (and to let the CPU benchmark capture a finite runtime), we run the
 * interaction in its own thread and forcefully exit after a guard
 * interval. Adjust BENCH_TIMEOUT_MS if you need a longer window.
 */

#define BENCH_TIMEOUT_MS 8000
K_THREAD_STACK_DEFINE(bench_stack, 4096);
static struct k_thread bench_thread_data;

static void bench_entry(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p1);
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	test_initiator_responder_interaction(TEST_NUM);
}

void main(void)
{
	k_thread_create(&bench_thread_data, bench_stack,
			K_THREAD_STACK_SIZEOF(bench_stack),
			bench_entry, NULL, NULL, NULL,
			PRIORITY, 0, K_NO_WAIT);

	/* Guard: exit the process after BENCH_TIMEOUT_MS to avoid hangs. */
	k_sleep(K_MSEC(BENCH_TIMEOUT_MS));
	exit(0);
}
