/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdint.h>
#include <string.h>

#include "edhoc/buffer_sizes.h"
#include "edhoc/edhoc_cose.h"
#include "edhoc/hkdf_info.h"
#include "edhoc/okm.h"
#include "edhoc/suites.h"
#include "edhoc/signature_or_mac_msg.h"
#include "edhoc/bstr_encode_decode.h"
#include "edhoc/int_encode_decode.h"

#include "common/print_util.h"
#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"

#include "cbor/edhoc_encode_enc_structure.h"
#include "cbor/edhoc_encode_sig_structure.h"

static struct signature_or_mac_stats sig_stats;

/**
 * @brief 			Forms a serialized data structure from a set of 
 * 				data items and computes a MAC over it.
 * 
 * @param[in] prk 		The key to be used for the mac.
 * @param[in] c_r 		Connection identifier of the requester
 * @param[in] th 		Transcript hash.
 * @param[in] id_cred 		ID of the credential.
 * @param[in] cred 		The credential.
 * @param[in] ead 		External authorization data.
 * @param mac_label 		An info label.
 * @param static_dh 		True if static DH is used for authentication.
 * @param suite 		The used crypto suite.
 * @param[out] mac 		The computed mac.
 * @return 			Ok or error code.
 */
static enum err mac(const struct byte_array *prk, const struct byte_array *c_r,
		    const struct byte_array *th,
		    const struct byte_array *id_cred,
		    const struct byte_array *cred, const struct byte_array *ead,
		    enum info_label mac_label, bool static_dh,
		    struct suite *suite, struct byte_array *mac)
{
	/*encode th as bstr*/
	BYTE_ARRAY_NEW(th_enc, AS_BSTR_SIZE(HASH_SIZE), AS_BSTR_SIZE(th->len));
	TRY(encode_bstr(th, &th_enc));

	/**/
	PRINTF("MAX ID CRED: %d cred len %d\n",ID_CRED_MAX_SIZE, id_cred->len);
	PRINTF("MAX CRED: %d cred len %d\n", CRED_MAX_SIZE, cred->len );
	PRINTF("PK SIZE: %d\n", PK_SIZE );
	PRINTF("SIGNATURE SIZE: %d\n", SIGNATURE_SIZE );
	
	PRINTF("CONTEXT_MAC_SIZE: %d\n",CONTEXT_MAC_SIZE);
	PRINTF("CONTEXT_MAC len: %d\n",AS_BSTR_SIZE(c_r->len) + id_cred->len + cred->len +
			       ead->len + th_enc.len);
	PRINTF("CR len: %d\n",AS_BSTR_SIZE(c_r->len));
	PRINTF("TH enc len: %d\n",th_enc.len);
	
	BYTE_ARRAY_NEW(context_mac, CONTEXT_MAC_SIZE,
		       AS_BSTR_SIZE(c_r->len) + id_cred->len + cred->len +
			       ead->len + th_enc.len);
	uint32_t capacity = context_mac.len;
	context_mac.len = 0;
	if (c_r->len != 0) {
		BYTE_ARRAY_NEW(c_r_enc, AS_BSTR_SIZE(C_R_SIZE),
			       AS_BSTR_SIZE(c_r->len));
		if (c_r_is_raw_int(c_r)) {
			TRY(encode_int((const int32_t *)c_r->ptr, c_r->len,
				       &c_r_enc));
		} else {
			TRY(encode_bstr(c_r, &c_r_enc));
		}
		TRY(byte_array_append(&context_mac, &c_r_enc, capacity));
	}
	TRY(byte_array_append(&context_mac, id_cred, capacity));
	TRY(byte_array_append(&context_mac, &th_enc, capacity));
	TRY(byte_array_append(&context_mac, cred, capacity));

	if (0 < ead->len) {
		TRY(byte_array_append(&context_mac, ead, capacity));
	}

	PRINT_ARRAY("MAC context", context_mac.ptr, context_mac.len);

	if (static_dh) {
		mac->len = suite->edhoc_mac_len_static_dh;

	} else {
		
		mac->len = get_hash_len(suite->edhoc_hash);
		PRINTF("is not DH, %d\n",mac->len);
	}

	TRY(edhoc_kdf(suite->edhoc_hash, prk, mac_label, &context_mac, mac));

	PRINT_ARRAY("MAC 2/3", mac->ptr, mac->len);
	return ok;
}

/**
 * @brief			Creates a byte array to be ready for signing. 
 * 
 * @param[in] th 		Transcript hash.
 * @param[in] id_cred 		Id of the credential.
 * @param[in] cred 		The credential.
 * @param[in] ead 		External Authorization Data. 
 * @param[in] mac 		Message Authentication Code. 
 * @param[out] out 		The result.
 * @return 			Ok or error code.
 */
static enum err signature_struct_gen(const struct byte_array *th,
				     const struct byte_array *id_cred,
				     const struct byte_array *cred,
				     const struct byte_array *ead,
				     const struct byte_array *mac,
				     struct byte_array *out)
{
	BYTE_ARRAY_NEW(th_enc, AS_BSTR_SIZE(HASH_SIZE),
		       AS_BSTR_SIZE(HASH_SIZE));

	TRY(encode_bstr(th, &th_enc));

	uint32_t tmp_len = th_enc.len + cred->len + ead->len;
	struct byte_array tmp;
	uint8_t tmp_buf[tmp_len];

	if (tmp_len == 0) {
		tmp = NULL_ARRAY;
	} else {
		tmp.ptr = tmp_buf;
		tmp.len = tmp_len;
	}

	memcpy(tmp.ptr, th_enc.ptr, th_enc.len);
	memcpy(tmp.ptr + th_enc.len, cred->ptr, cred->len);
	if (ead->len != 0) {
		memcpy(tmp.ptr + th_enc.len + cred->len, ead->ptr, ead->len);
	}

	uint8_t context_str[] = { "Signature1" };
	struct byte_array str = BYTE_ARRAY_INIT(
		context_str, (uint32_t)strlen((char *)context_str));

	TRY(cose_sig_structure_encode(&str, id_cred, &tmp, mac, out));
	//PRINT_ARRAY("COSE_Sign1 object to be signed", out->ptr, out->len);
	return ok;
}

enum err
signature_or_mac(enum sgn_or_mac_op op, bool static_dh, struct suite *suite,
		 const struct byte_array *sk, const struct byte_array *pk,
		 const struct byte_array *prk, const struct byte_array *c_r,
		 const struct byte_array *th, const struct byte_array *id_cred,
		 const struct byte_array *cred, const struct byte_array *ead,
		 enum info_label mac_label, struct byte_array *signature_or_mac)
{
	if (op == GENERATE) {
		/*we always calculate the mac*/
		TRY(mac(prk, c_r, th, id_cred, cred, ead, mac_label, static_dh,
			suite, signature_or_mac));

		if (static_dh) {
			/*signature_or_mac is mac when the caller of this function authenticates with static DH keys*/
			return ok;
		} else {
			uint32_t sig_struct_size = SIG_STRUCT_SIZE_CALC(
				COSE_SIGN1_STR_LEN, id_cred->len,
				(AS_BSTR_SIZE(th->len) + cred->len + ead->len),
				signature_or_mac->len);
			PRINTF("sig_struct_size=%u SIG_STRUCT_SIZE=%u\n",
			       sig_struct_size, SIG_STRUCT_SIZE);
			/*
			 * Some timing-benchmark credential payloads (suite 9 PQ) exceed the
			 * conservative SIG_STRUCT_SIZE macro. Allocate a VLA large enough for
			 * the computed need to avoid buffer_to_small at runtime.
			 */
			uint32_t sig_struct_buf_size =
				(sig_struct_size > SIG_STRUCT_SIZE) ? sig_struct_size : SIG_STRUCT_SIZE;
			PRINTF("sig_struct_buf_size=%u (th=%u id_cred=%u cred=%u ead=%u mac=%u)\n",
			       sig_struct_buf_size, th->len, id_cred->len, cred->len, ead->len,
			       signature_or_mac->len);
			struct byte_array sign_struct;
			uint8_t sign_struct_buf[sig_struct_buf_size];
			if (sig_struct_size == 0) {
				sign_struct = NULL_ARRAY;
			} else {
				sign_struct.ptr = sign_struct_buf;
				/* Use the full allocated buffer as capacity; the computed size is a
				 * lower bound and can underestimate large CBOR overheads for big
				 * credentials in timing builds (suite 9 PQ). Using the buffer size
				 * avoids buffer_to_small during cbor_encode_sig_structure.
				 */
				sign_struct.len = sig_struct_buf_size;
			}
			TRY(signature_struct_gen(th, id_cred, cred, ead,
						 signature_or_mac,
						 &sign_struct));
			PRINTF("signature_struct_gen ok, sign_struct.len=%u\n",
			       sign_struct.len);
           
			signature_or_mac->len =
			get_signature_len(suite->edhoc_sign);
	        PRINTF("Signature or mac size: %d",signature_or_mac->len);
			
			memset(signature_or_mac->ptr,0,signature_or_mac->len);
			TRY(sign_edhoc(suite->edhoc_sign, sk, pk, &sign_struct,
				 signature_or_mac->ptr, &signature_or_mac->len));
				PRINTF("sign_edhoc ok, signature len=%u\n",
				       signature_or_mac->len);
			PRINT_ARRAY("signature_or_mac (is signature)",
				    signature_or_mac->ptr,
				    signature_or_mac->len);
			sig_stats.signatures_generated++;
		}
	} else { /*we verify here*/
		BYTE_ARRAY_NEW(_mac, HASH_SIZE,
			       get_hash_len(suite->edhoc_hash));

		TRY(mac(prk, c_r, th, id_cred, cred, ead, mac_label, static_dh,
			suite, &_mac));

		if (static_dh) {
			/*signature_or_mac is mac when the caller of this function authenticates with static DH keys*/

			if (0 != memcmp(_mac.ptr, signature_or_mac->ptr,
					signature_or_mac->len)) {
				return mac_authentication_failed;
			}

		} else {
			uint32_t sig_struct_size = SIG_STRUCT_SIZE_CALC(
				COSE_SIGN1_STR_LEN, id_cred->len,
				(AS_BSTR_SIZE(th->len) + cred->len + ead->len),
				_mac.len);
			uint32_t sig_struct_buf_size =
				(sig_struct_size > SIG_STRUCT_SIZE) ? sig_struct_size : SIG_STRUCT_SIZE;
			struct byte_array sign_struct;
			uint8_t sign_struct_buf[sig_struct_buf_size];
			if (sig_struct_size == 0) {
				sign_struct = NULL_ARRAY;
			} else {
				sign_struct.ptr = sign_struct_buf;
				sign_struct.len = sig_struct_buf_size;
			}
			TRY(signature_struct_gen(th, id_cred, cred, ead, &_mac,
						 &sign_struct));

			bool result;

			TRY(verify_edhoc(suite->edhoc_sign, pk,
				   (struct const_byte_array *)&sign_struct,
				   (struct const_byte_array *)signature_or_mac,
				   &result));
			if (!result) {
				return signature_authentication_failed;
			}
			PRINT_MSG("Signature or MAC verification successful!\n");
			sig_stats.signatures_verified++;
		}
	}
	return ok;
}

void signature_or_mac_reset_stats(void)
{
	memset(&sig_stats, 0, sizeof(sig_stats));
}

void signature_or_mac_get_stats(struct signature_or_mac_stats *out)
{
	if (out == NULL) {
		return;
	}
	memcpy(out, &sig_stats, sizeof(sig_stats));
}
