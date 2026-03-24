/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef SAP_CRYPTO_H__
#define SAP_CRYPTO_H__

#include <zephyr/types.h>
#include <psa/crypto.h>

int sap_crypto_init(void);
void sap_crypto_destroy_key(psa_key_id_t *key_id);

int sap_crypto_import_identity_private(const uint8_t *key, size_t key_len,
				       psa_key_id_t *key_id);
int sap_crypto_hash_sha256(const uint8_t *message, size_t message_len,
			   uint8_t *hash, size_t hash_size);
int sap_crypto_verify_identity(const uint8_t *public_key, size_t public_key_len,
			       const uint8_t *message, size_t message_len,
			       const uint8_t *signature, size_t signature_len);
int sap_crypto_sign_identity(psa_key_id_t key_id, const uint8_t *message,
			     size_t message_len, uint8_t *signature,
			     size_t signature_size, size_t *signature_len);

int sap_crypto_generate_ecdh_keypair(psa_key_id_t *key_id);
int sap_crypto_export_public_key(psa_key_id_t key_id, uint8_t *buffer,
				 size_t buffer_size, size_t *buffer_len);
int sap_crypto_calculate_shared_secret(psa_key_id_t key_id,
				       const uint8_t *peer_public_key,
				       size_t peer_public_key_len,
				       uint8_t *secret, size_t secret_size,
				       size_t *secret_len);
int sap_crypto_hkdf_sha256(const uint8_t *secret, size_t secret_len,
			   const uint8_t *salt, size_t salt_len,
			   const uint8_t *info, size_t info_len,
			   uint8_t *output, size_t output_len);
int sap_crypto_import_aes_ccm_key(const uint8_t *key, size_t key_len,
				  psa_key_id_t *key_id);
int sap_crypto_aead_encrypt(psa_key_id_t key_id, const uint8_t *nonce,
			    size_t nonce_len, const uint8_t *aad,
			    size_t aad_len, const uint8_t *plaintext,
			    size_t plaintext_len, uint8_t *ciphertext,
			    size_t ciphertext_size, size_t *ciphertext_len);
int sap_crypto_aead_decrypt(psa_key_id_t key_id, const uint8_t *nonce,
			    size_t nonce_len, const uint8_t *aad,
			    size_t aad_len, const uint8_t *ciphertext,
			    size_t ciphertext_len, uint8_t *plaintext,
			    size_t plaintext_size, size_t *plaintext_len);

#endif /* SAP_CRYPTO_H__ */
