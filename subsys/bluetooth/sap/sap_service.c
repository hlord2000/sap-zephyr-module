/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/logging/log.h>

#include <sap/sap_service.h>
#include "sap_crypto.h"
#include <sap/sap_trace.h>

LOG_MODULE_REGISTER(sap_service, CONFIG_SAP_LOG_LEVEL);

#if defined(CONFIG_BT_L2CAP_TX_MTU)
#define SAP_SECURE_FRAME_BUF_LEN (CONFIG_BT_L2CAP_TX_MTU - 3U)
#else
#define SAP_SECURE_FRAME_BUF_LEN 244U
#endif

#define SAP_SECURE_PLAINTEXT_BUF_LEN \
	(SAP_SECURE_FRAME_BUF_LEN - sizeof(struct sap_secure_header) - SAP_AEAD_TAG_LEN)

#define SAP_PLAINTEXT_FRAME_PAYLOAD_LEN \
	(SAP_SECURE_FRAME_BUF_LEN - sizeof(struct sap_plaintext_header))

#define SAP_APP_PAYLOAD_BUF_LEN MAX(SAP_SECURE_PLAINTEXT_BUF_LEN, SAP_PLAINTEXT_FRAME_PAYLOAD_LEN)

#if defined(CONFIG_BT_L2CAP_TX_MTU)
BUILD_ASSERT(SAP_SECURE_FRAME_BUF_LEN > (sizeof(struct sap_secure_header) + SAP_AEAD_TAG_LEN),
	     "SAP secure frame buffer must leave room for at least one plaintext byte");
BUILD_ASSERT(SAP_SECURE_FRAME_BUF_LEN > sizeof(struct sap_plaintext_header),
	     "SAP plaintext frame buffer must leave room for at least one payload byte");
#endif

#if defined(CONFIG_BT_L2CAP_TX_MTU)
BUILD_ASSERT(sizeof(struct sap_msg_hello) <= (CONFIG_BT_L2CAP_TX_MTU - 3),
	     "SAP hello must fit ATT MTU");
BUILD_ASSERT(sizeof(struct sap_msg_peripheral_challenge) <= (CONFIG_BT_L2CAP_TX_MTU - 3),
	     "Peripheral challenge must fit ATT MTU");
BUILD_ASSERT(sizeof(struct sap_msg_central_auth_oob) <= (CONFIG_BT_L2CAP_TX_MTU - 3),
	     "Central auth must fit ATT MTU");
BUILD_ASSERT(sizeof(struct sap_msg_peripheral_auth_oob) <= (CONFIG_BT_L2CAP_TX_MTU - 3),
	     "Peripheral auth must fit ATT MTU");
#endif

static void sap_trace_auth_packet(const struct sap_session *session,
				  const char *direction,
				  const uint8_t *data, size_t len)
{
#if defined(CONFIG_SAP_PACKET_LOGGING)
	uint8_t version = (len >= 1U) ? data[0] : 0xffU;
	uint8_t type = (len >= 2U) ? data[1] : 0xffU;

	SAP_PACKET_TRACE("PACKET %s %s auth %s(0x%02x) len=%zu version=%u",
			 sap_role_str(session->role), direction,
			 sap_msg_type_str(type), type, len, version);
	SAP_PACKET_DUMP(data, len, "auth bytes");
#else
	ARG_UNUSED(session);
	ARG_UNUSED(direction);
	ARG_UNUSED(data);
	ARG_UNUSED(len);
#endif
}

static void sap_trace_secure_packet(const struct sap_session *session,
				    const char *direction,
				    const uint8_t *data, size_t len)
{
#if defined(CONFIG_SAP_PACKET_LOGGING)
	uint8_t version = 0xffU;
	uint8_t type = 0xffU;
	uint32_t counter = 0U;

	if (sap_use_link_security_transport(session)) {
		if (len >= sizeof(struct sap_plaintext_header)) {
			const struct sap_plaintext_header *header =
				(const struct sap_plaintext_header *)data;

			version = header->version;
			type = header->type;
		}

		SAP_PACKET_TRACE("PACKET %s %s link-protected %s(0x%02x) len=%zu version=%u",
				 sap_role_str(session->role), direction,
				 sap_msg_type_str(type), type, len, version);
		SAP_PACKET_DUMP(data, len, "secure bytes");
		return;
	}

	if (len >= sizeof(struct sap_secure_header)) {
		const struct sap_secure_header *header =
			(const struct sap_secure_header *)data;

		version = header->version;
		type = header->type;
		counter = sys_le32_to_cpu(header->counter_le);
	}

	SAP_PACKET_TRACE("PACKET %s %s secure %s(0x%02x) len=%zu version=%u counter=%u",
			 sap_role_str(session->role), direction,
			 sap_msg_type_str(type), type, len, version, counter);
	SAP_PACKET_DUMP(data, len, "secure bytes");
#else
	ARG_UNUSED(session);
	ARG_UNUSED(direction);
	ARG_UNUSED(data);
	ARG_UNUSED(len);
#endif
}

static void sap_reset_session(struct sap_session *session)
{
	sap_crypto_destroy_key(&session->local_ecdh_key_id);
	sap_crypto_destroy_key(&session->aead_key_id);

	if (session->conn != NULL) {
		bt_conn_unref(session->conn);
	}

	memset(session, 0, sizeof(*session));
}

static void sap_fail(struct sap_session *session, int reason)
{
	if (session->state == SAP_STATE_FAILED) {
		return;
	}

	session->state = SAP_STATE_FAILED;

	if (session->ctx->callbacks.authentication_failed != NULL) {
		session->ctx->callbacks.authentication_failed(session, reason);
	}
}

static void sap_notify_authenticated(struct sap_session *session, const char *trace_msg)
{
	session->state = SAP_STATE_AUTHENTICATED;

	if (trace_msg != NULL) {
		SAP_TRACE("%s", trace_msg);
	}

	if (!session->authenticated_notified &&
	    session->ctx->callbacks.authenticated != NULL) {
		session->authenticated_notified = true;
		session->ctx->callbacks.authenticated(session);
	}
}

static int sap_random(uint8_t *buffer, size_t len)
{
	return (psa_generate_random(buffer, len) == PSA_SUCCESS) ? 0 : -EIO;
}

static int sap_verify_certificate(struct sap_session *session,
				  const struct sap_certificate *cert,
				  uint8_t expected_role_mask)
{
	int err;

	if (cert->body.version != SAP_VERSION) {
		return -EPROTO;
	}

	if ((cert->body.role_mask & expected_role_mask) == 0U) {
		return -EACCES;
	}

	if (cert->body.group_id != session->ctx->policy.expected_group_id) {
		return -EACCES;
	}

	if ((expected_role_mask == SAP_ROLE_MASK_CENTRAL) &&
	    (cert->body.device_id != session->ctx->policy.allowed_central_id)) {
		return -EACCES;
	}

	err = sap_crypto_verify_identity(session->ctx->policy.ca_public_key,
					 session->ctx->policy.ca_public_key_len,
					 (const uint8_t *)&cert->body,
					 sizeof(cert->body), cert->ca_signature,
					 sizeof(cert->ca_signature));
	return err;
}

static void sap_build_nonce(uint8_t *nonce,
			    const uint8_t *base,
			    uint32_t counter,
			    uint8_t type)
{
	memcpy(nonce, base, SAP_AEAD_NONCE_BASE_LEN);
	sys_put_le32(counter, &nonce[SAP_AEAD_NONCE_BASE_LEN]);
	nonce[SAP_AEAD_NONCE_BASE_LEN + sizeof(uint32_t)] = type;
}

static const uint8_t *sap_central_nonce(const struct sap_session *session)
{
	return (session->role == SAP_ROLE_CENTRAL) ? session->local_nonce :
	       session->peer_nonce;
}

static const uint8_t *sap_peripheral_nonce(const struct sap_session *session)
{
	return (session->role == SAP_ROLE_PERIPHERAL) ? session->local_nonce :
	       session->peer_nonce;
}

static const struct sap_cert_body *sap_central_cert_body(const struct sap_session *session)
{
	return (session->role == SAP_ROLE_CENTRAL) ?
		&session->ctx->policy.local_credential->cert.body :
		&session->peer_cert.body;
}

static const struct sap_cert_body *sap_peripheral_cert_body(const struct sap_session *session)
{
	return (session->role == SAP_ROLE_PERIPHERAL) ?
		&session->ctx->policy.local_credential->cert.body :
		&session->peer_cert.body;
}

static const uint8_t *sap_central_ecdh_public(const struct sap_session *session,
					      size_t *len)
{
	if (session->role == SAP_ROLE_CENTRAL) {
		*len = session->local_ecdh_public_len;
		return session->local_ecdh_public;
	}

	*len = session->peer_ecdh_public_len;
	return session->peer_ecdh_public;
}

static const uint8_t *sap_peripheral_ecdh_public(const struct sap_session *session,
						 size_t *len)
{
	if (session->role == SAP_ROLE_PERIPHERAL) {
		*len = session->local_ecdh_public_len;
		return session->local_ecdh_public;
	}

	*len = session->peer_ecdh_public_len;
	return session->peer_ecdh_public;
}

static bool sap_use_ble_sc_oob_pairing(const struct sap_session *session)
{
	return session->ctx->policy.use_ble_sc_oob_pairing;
}

static bool sap_use_link_security_transport(const struct sap_session *session)
{
	return session->ctx->policy.use_link_security_for_secure_transport;
}

static const struct bt_le_oob_sc_data *sap_central_oob_sc(const struct sap_session *session)
{
	return (session->role == SAP_ROLE_CENTRAL) ? &session->local_oob_sc :
	       &session->peer_oob_sc;
}

static const struct bt_le_oob_sc_data *sap_peripheral_oob_sc(const struct sap_session *session)
{
	return (session->role == SAP_ROLE_PERIPHERAL) ? &session->local_oob_sc :
	       &session->peer_oob_sc;
}

static int sap_generate_local_oob(struct sap_session *session)
{
	struct bt_le_oob oob;
	int err;

	if (!sap_use_ble_sc_oob_pairing(session)) {
		return 0;
	}

	if (session->local_oob_ready) {
		return 0;
	}

	err = bt_le_oob_get_local(BT_ID_DEFAULT, &oob);
	if (err != 0) {
		LOG_ERR("SAP local OOB generation failed (%d)", err);
		return err;
	}

	memcpy(&session->local_oob_sc, &oob.le_sc_data, sizeof(session->local_oob_sc));
	session->local_oob_ready = true;
	LOG_INF("SAP local OOB generated for %s", sap_role_str(session->role));
	return 0;
}

static int sap_make_peripheral_challenge_sig(const struct sap_session *session,
					     uint8_t *buffer, size_t size,
					     size_t *len)
{
	size_t needed = 1U + SAP_NONCE_LEN + SAP_NONCE_LEN + sizeof(struct sap_cert_body);

	if (size < needed) {
		return -ENOMEM;
	}

	buffer[0] = SAP_SIG_PERIPHERAL_CHALLENGE;
	memcpy(&buffer[1], sap_central_nonce(session), SAP_NONCE_LEN);
	memcpy(&buffer[1 + SAP_NONCE_LEN], sap_peripheral_nonce(session), SAP_NONCE_LEN);
	memcpy(&buffer[1 + (2U * SAP_NONCE_LEN)], sap_peripheral_cert_body(session),
	       sizeof(struct sap_cert_body));
	*len = needed;

	return 0;
}

static int sap_make_central_auth_sig(const struct sap_session *session,
				     uint8_t *buffer, size_t size,
				     size_t *len)
{
	size_t offset = 0U;
	size_t central_ecdh_public_len;
	uint8_t hash[32];
	const uint8_t *central_ecdh_public =
		sap_central_ecdh_public(session, &central_ecdh_public_len);
	size_t needed = 1U + SAP_NONCE_LEN + SAP_NONCE_LEN +
			sizeof(struct sap_cert_body) + sizeof(struct sap_cert_body) +
			SAP_ECDH_PUBLIC_KEY_LEN;

	if (size < needed) {
		return -ENOMEM;
	}

	buffer[offset++] = SAP_SIG_CENTRAL_AUTH;
	memcpy(&buffer[offset], sap_central_nonce(session), SAP_NONCE_LEN);
	offset += SAP_NONCE_LEN;
	memcpy(&buffer[offset], sap_peripheral_nonce(session), SAP_NONCE_LEN);
	offset += SAP_NONCE_LEN;
	memcpy(&buffer[offset], sap_central_cert_body(session), sizeof(struct sap_cert_body));
	offset += sizeof(struct sap_cert_body);
	memcpy(&buffer[offset], sap_peripheral_cert_body(session), sizeof(struct sap_cert_body));
	offset += sizeof(struct sap_cert_body);
	memcpy(&buffer[offset], central_ecdh_public, central_ecdh_public_len);
	offset += central_ecdh_public_len;

	if (sap_use_ble_sc_oob_pairing(session)) {
		const struct bt_le_oob_sc_data *central_oob = sap_central_oob_sc(session);

		needed += sizeof(struct sap_sc_oob_data_wire);
		if (size < needed) {
			return -ENOMEM;
		}

		memcpy(&buffer[offset], central_oob->r, sizeof(central_oob->r));
		offset += sizeof(central_oob->r);
		memcpy(&buffer[offset], central_oob->c, sizeof(central_oob->c));
		offset += sizeof(central_oob->c);
	}

	if (sap_crypto_hash_sha256(buffer, offset, hash, sizeof(hash)) == 0) {
		LOG_INF("SAP central auth transcript hash role=%s d0=%02x d1=%02x d2=%02x d3=%02x len=%zu",
			sap_role_str(session->role), hash[0], hash[1], hash[2], hash[3], offset);
	}

	*len = offset;
	return 0;
}

static int sap_make_peripheral_auth_sig(const struct sap_session *session,
					uint8_t *buffer, size_t size,
					size_t *len)
{
	size_t offset = 0U;
	size_t central_ecdh_public_len;
	size_t peripheral_ecdh_public_len;
	const uint8_t *central_ecdh_public =
		sap_central_ecdh_public(session, &central_ecdh_public_len);
	const uint8_t *peripheral_ecdh_public =
		sap_peripheral_ecdh_public(session, &peripheral_ecdh_public_len);
	size_t needed = 1U + SAP_NONCE_LEN + SAP_NONCE_LEN +
			sizeof(struct sap_cert_body) + sizeof(struct sap_cert_body) +
			SAP_ECDH_PUBLIC_KEY_LEN + SAP_ECDH_PUBLIC_KEY_LEN;

	if (size < needed) {
		return -ENOMEM;
	}

	buffer[offset++] = SAP_SIG_PERIPHERAL_AUTH;
	memcpy(&buffer[offset], sap_central_nonce(session), SAP_NONCE_LEN);
	offset += SAP_NONCE_LEN;
	memcpy(&buffer[offset], sap_peripheral_nonce(session), SAP_NONCE_LEN);
	offset += SAP_NONCE_LEN;
	memcpy(&buffer[offset], sap_central_cert_body(session), sizeof(struct sap_cert_body));
	offset += sizeof(struct sap_cert_body);
	memcpy(&buffer[offset], sap_peripheral_cert_body(session), sizeof(struct sap_cert_body));
	offset += sizeof(struct sap_cert_body);
	memcpy(&buffer[offset], central_ecdh_public, central_ecdh_public_len);
	offset += central_ecdh_public_len;
	memcpy(&buffer[offset], peripheral_ecdh_public, peripheral_ecdh_public_len);
	offset += peripheral_ecdh_public_len;

	if (sap_use_ble_sc_oob_pairing(session)) {
		const struct bt_le_oob_sc_data *central_oob = sap_central_oob_sc(session);
		const struct bt_le_oob_sc_data *peripheral_oob = sap_peripheral_oob_sc(session);

		needed += (2U * sizeof(struct sap_sc_oob_data_wire));
		if (size < needed) {
			return -ENOMEM;
		}

		memcpy(&buffer[offset], central_oob->r, sizeof(central_oob->r));
		offset += sizeof(central_oob->r);
		memcpy(&buffer[offset], central_oob->c, sizeof(central_oob->c));
		offset += sizeof(central_oob->c);
		memcpy(&buffer[offset], peripheral_oob->r, sizeof(peripheral_oob->r));
		offset += sizeof(peripheral_oob->r);
		memcpy(&buffer[offset], peripheral_oob->c, sizeof(peripheral_oob->c));
		offset += sizeof(peripheral_oob->c);
	}

	*len = offset;
	return 0;
}

static int sap_derive_session_keys(struct sap_session *session)
{
	uint8_t secret[32];
	uint8_t salt[SAP_NONCE_LEN * 2U];
	uint8_t transcript[2U + (2U * SAP_ECDH_PUBLIC_KEY_LEN)];
	uint8_t transcript_hash[32];
	uint8_t info[(sizeof("SAP session") - 1U) + sizeof(transcript_hash)];
	uint8_t material[SAP_AEAD_KEY_LEN];
	size_t central_ecdh_public_len;
	size_t peripheral_ecdh_public_len;
	const struct sap_cert_body *central_cert = sap_central_cert_body(session);
	const struct sap_cert_body *peripheral_cert = sap_peripheral_cert_body(session);
	const uint8_t *central_ecdh_public =
		sap_central_ecdh_public(session, &central_ecdh_public_len);
	const uint8_t *peripheral_ecdh_public =
		sap_peripheral_ecdh_public(session, &peripheral_ecdh_public_len);
	size_t secret_len;
	size_t offset = 0U;
	int err;

	err = sap_crypto_calculate_shared_secret(session->local_ecdh_key_id,
						 session->peer_ecdh_public,
						 session->peer_ecdh_public_len,
						 secret, sizeof(secret),
						 &secret_len);
	if (err != 0) {
		LOG_ERR("SAP shared secret derivation failed (%d)", err);
		return err;
	}

	memcpy(salt, sap_central_nonce(session), SAP_NONCE_LEN);
	memcpy(&salt[SAP_NONCE_LEN], sap_peripheral_nonce(session), SAP_NONCE_LEN);

	transcript[offset++] = central_cert->device_id;
	transcript[offset++] = peripheral_cert->device_id;
	memcpy(&transcript[offset], central_ecdh_public, central_ecdh_public_len);
	offset += central_ecdh_public_len;
	memcpy(&transcript[offset], peripheral_ecdh_public, peripheral_ecdh_public_len);
	offset += peripheral_ecdh_public_len;

	/* CRACEN-backed HKDF on nRF54L15 limits the info field to 128 bytes. */
	err = sap_crypto_hash_sha256(transcript, offset, transcript_hash,
				     sizeof(transcript_hash));
	if (err != 0) {
		LOG_ERR("SAP transcript hash failed (%d)", err);
		memset(secret, 0, sizeof(secret));
		return err;
	}

	offset = 0U;
	memcpy(&info[offset], "SAP session", 11);
	offset += 11U;
	memcpy(&info[offset], transcript_hash, sizeof(transcript_hash));
	offset += sizeof(transcript_hash);

	err = sap_crypto_hkdf_sha256(secret, secret_len, salt, sizeof(salt), info,
				     offset, material, sizeof(material));
	memset(secret, 0, sizeof(secret));
	if (err != 0) {
		LOG_ERR("SAP HKDF failed (%d)", err);
		return err;
	}

	err = sap_crypto_import_aes_ccm_key(material, sizeof(material),
					    &session->aead_key_id);
	if (err != 0) {
		LOG_ERR("SAP AEAD key import failed (%d)", err);
		memset(material, 0, sizeof(material));
		return err;
	}

	memset(material, 0, sizeof(material));
	session->session_key_ready = true;
	session->tx_counter = 0U;
	session->rx_counter = 0U;
	SAP_TRACE("FLOW 6/8 %s derived SAP session material with peer %u using ECDH + HKDF",
		  sap_role_str(session->role), session->peer_cert.body.device_id);

	return 0;
}

static int sap_encrypt_internal(struct sap_session *session, uint8_t msg_type,
				uint32_t counter, const uint8_t *payload,
				size_t len, uint8_t *out, size_t out_size,
				size_t *out_len)
{
	struct sap_secure_header *header = (struct sap_secure_header *)out;
	uint8_t nonce[SAP_AEAD_NONCE_LEN];
	size_t cipher_len;
	int err;

	if (!session->session_key_ready) {
		return -EACCES;
	}

	if (out_size < sizeof(*header) + len + SAP_AEAD_TAG_LEN) {
		return -ENOMEM;
	}

	header->version = SAP_VERSION;
	header->type = msg_type;
	err = sap_random(header->nonce_base, sizeof(header->nonce_base));
	if (err != 0) {
		return err;
	}
	header->counter_le = sys_cpu_to_le32(counter);
	sap_build_nonce(nonce, header->nonce_base, counter, msg_type);

	err = sap_crypto_aead_encrypt(session->aead_key_id, nonce, sizeof(nonce),
				      (const uint8_t *)header, sizeof(*header),
				      payload, len, &out[sizeof(*header)],
				      out_size - sizeof(*header), &cipher_len);
	if (err != 0) {
		return err;
	}

	*out_len = sizeof(*header) + cipher_len;

	return 0;
}

static int sap_pack_plaintext_internal(uint8_t msg_type, const uint8_t *payload,
				       size_t len, uint8_t *out, size_t out_size,
				       size_t *out_len)
{
	struct sap_plaintext_header *header = (struct sap_plaintext_header *)out;

	if (out_size < sizeof(*header) + len) {
		return -ENOMEM;
	}

	header->version = SAP_VERSION;
	header->type = msg_type;
	memcpy(&out[sizeof(*header)], payload, len);
	*out_len = sizeof(*header) + len;
	return 0;
}

static int sap_decrypt_internal(struct sap_session *session, const uint8_t *data,
				size_t len, uint8_t *msg_type, uint8_t *out,
				size_t out_size, size_t *out_len)
{
	const struct sap_secure_header *header =
		(const struct sap_secure_header *)data;
	uint8_t nonce[SAP_AEAD_NONCE_LEN];
	uint32_t counter;
	int err;

	if (len < sizeof(*header) + SAP_AEAD_TAG_LEN) {
		return -EMSGSIZE;
	}

	if (header->version != SAP_VERSION) {
		return -EPROTO;
	}

	counter = sys_le32_to_cpu(header->counter_le);
	if (counter != session->rx_counter) {
		return -EALREADY;
	}

	sap_build_nonce(nonce, header->nonce_base, counter, header->type);
	err = sap_crypto_aead_decrypt(session->aead_key_id, nonce, sizeof(nonce),
				      data, sizeof(*header),
				      &data[sizeof(*header)],
				      len - sizeof(*header), out, out_size,
				      out_len);
	if (err != 0) {
		return err;
	}

	session->rx_counter++;
	*msg_type = header->type;
	return 0;
}

static int sap_unpack_plaintext_internal(const uint8_t *data, size_t len,
					 uint8_t *msg_type, uint8_t *out,
					 size_t out_size, size_t *out_len)
{
	const struct sap_plaintext_header *header =
		(const struct sap_plaintext_header *)data;
	size_t payload_len;

	if (len < sizeof(*header)) {
		return -EMSGSIZE;
	}

	if (header->version != SAP_VERSION) {
		return -EPROTO;
	}

	payload_len = len - sizeof(*header);
	if (payload_len > out_size) {
		return -ENOMEM;
	}

	memcpy(out, &data[sizeof(*header)], payload_len);
	*msg_type = header->type;
	*out_len = payload_len;
	return 0;
}

int sap_init(struct sap_context *ctx, enum sap_role role,
	     const struct sap_policy *policy,
	     const struct sap_callbacks *callbacks)
{
	int err;

	memset(ctx, 0, sizeof(*ctx));
	ctx->role = role;
	ctx->policy = *policy;
	ctx->callbacks = *callbacks;

	err = sap_crypto_init();
	if (err != 0) {
		return err;
	}

	return sap_crypto_import_identity_private(
		policy->local_credential->private_key,
		sizeof(policy->local_credential->private_key),
		&ctx->local_sign_key_id);
}

void sap_uninit(struct sap_context *ctx)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(ctx->sessions); i++) {
		sap_reset_session(&ctx->sessions[i]);
	}

	sap_crypto_destroy_key(&ctx->local_sign_key_id);
}

struct sap_session *sap_on_connected(struct sap_context *ctx, struct bt_conn *conn)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(ctx->sessions); i++) {
		if (!ctx->sessions[i].in_use) {
			ctx->sessions[i].ctx = ctx;
			ctx->sessions[i].conn = bt_conn_ref(conn);
			ctx->sessions[i].role = ctx->role;
			ctx->sessions[i].in_use = true;
			ctx->sessions[i].state = SAP_STATE_IDLE;
			SAP_TRACE("FLOW 1/8 %s allocated SAP session slot", sap_role_str(ctx->role));
			return &ctx->sessions[i];
		}
	}

	return NULL;
}

void sap_on_disconnected(struct sap_context *ctx, struct bt_conn *conn)
{
	struct sap_session *session = sap_session_from_conn(ctx, conn);

	if (session != NULL) {
		SAP_TRACE("FLOW reset-recovery: %s released SAP session for peer %u",
			  sap_role_str(session->role), session->peer_cert.body.device_id);
		sap_reset_session(session);
	}
}

struct sap_session *sap_session_from_conn(struct sap_context *ctx,
					  struct bt_conn *conn)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(ctx->sessions); i++) {
		if (ctx->sessions[i].in_use && (ctx->sessions[i].conn == conn)) {
			return &ctx->sessions[i];
		}
	}

	return NULL;
}

void sap_on_security_changed(struct sap_session *session, bt_security_t level,
			     enum bt_security_err err)
{
	session->security_level = err == 0 ? level : BT_SECURITY_L0;

	if (err == 0 && level >= BT_SECURITY_L2) {
		session->security_ready = true;
		SAP_TRACE("FLOW 2/8 %s BLE security ready at level %u",
			  sap_role_str(session->role), level);

		if (sap_use_ble_sc_oob_pairing(session) &&
		    sap_use_link_security_transport(session) &&
		    level >= BT_SECURITY_L4 &&
		    session->state == SAP_STATE_WAIT_BLE_PAIRING) {
			sap_notify_authenticated(
				session,
				"FLOW 8/8 BLE Secure Connections OOB pairing completed; SAP session authenticated on BLE L4 link");
		}
	} else {
		session->security_ready = false;
		if (err != 0) {
			SAP_TRACE("FLOW 2/8 %s BLE security failed: %s",
				  sap_role_str(session->role), bt_security_err_to_str(err));
		}
	}
}

bool sap_is_authenticated(const struct sap_session *session)
{
	return session->state == SAP_STATE_AUTHENTICATED;
}

int sap_start(struct sap_session *session)
{
	struct sap_msg_hello msg = {
		.version = SAP_VERSION,
		.type = SAP_MSG_HELLO,
	};
	int err;

	if (session->role != SAP_ROLE_CENTRAL) {
		return -ENOTSUP;
	}

	if (session->ctx->policy.require_ble_encryption && !session->security_ready) {
		return -EACCES;
	}

	err = sap_random(session->local_nonce, sizeof(session->local_nonce));
	if (err != 0) {
		return err;
	}

	memcpy(msg.central_nonce, session->local_nonce, sizeof(msg.central_nonce));
	session->state = SAP_STATE_WAIT_PERIPHERAL_CHALLENGE;
	SAP_TRACE("FLOW 3/8 central -> peripheral: HELLO (fresh central nonce)");

	return session->ctx->callbacks.send_auth(session, SAP_MSG_HELLO,
						 (const uint8_t *)&msg, sizeof(msg));
}

static int sap_send_peripheral_challenge(struct sap_session *session)
{
	struct sap_msg_peripheral_challenge msg = {
		.version = SAP_VERSION,
		.type = SAP_MSG_PERIPHERAL_CHALLENGE,
		.cert = {
			.body = { 0 },
			.ca_signature = { 0 },
		},
	};
	uint8_t sign_buf[1U + (2U * SAP_NONCE_LEN) + sizeof(struct sap_cert_body)];
	size_t sign_len;
	size_t sig_len;
	int err;

	memcpy(&msg.cert, &session->ctx->policy.local_credential->cert, sizeof(msg.cert));
	SAP_INFO_IF_NO_DEMO("SAP sending peripheral challenge");

	err = sap_random(session->local_nonce, sizeof(session->local_nonce));
	if (err != 0) {
		return err;
	}

	memcpy(msg.peripheral_nonce, session->local_nonce, sizeof(msg.peripheral_nonce));

	err = sap_make_peripheral_challenge_sig(session, sign_buf, sizeof(sign_buf),
						&sign_len);
	if (err != 0) {
		return err;
	}

	err = sap_crypto_sign_identity(session->ctx->local_sign_key_id, sign_buf,
				       sign_len, msg.signature, sizeof(msg.signature),
				       &sig_len);
	if (err != 0 || sig_len != sizeof(msg.signature)) {
		return -EIO;
	}

	session->state = SAP_STATE_WAIT_CENTRAL_AUTH;
	SAP_TRACE("FLOW 4/8 peripheral %u -> central: PERIPHERAL_CHALLENGE "
		  "(cert role_mask=0x%02x group=0x%02x, signed challenge)",
		  session->ctx->policy.local_credential->cert.body.device_id,
		  session->ctx->policy.local_credential->cert.body.role_mask,
		  session->ctx->policy.local_credential->cert.body.group_id);
	sap_trace_auth_packet(session, "tx", (const uint8_t *)&msg, sizeof(msg));
	return session->ctx->callbacks.send_auth(session,
						 SAP_MSG_PERIPHERAL_CHALLENGE,
						 (const uint8_t *)&msg, sizeof(msg));
}

static int sap_send_central_auth(struct sap_session *session)
{
	union {
		struct sap_msg_central_auth base;
		struct sap_msg_central_auth_oob oob;
	} msg = {
		.base = {
			.version = SAP_VERSION,
			.type = SAP_MSG_CENTRAL_AUTH,
			.cert = {
				.body = { 0 },
				.ca_signature = { 0 },
			},
		},
	};
	uint8_t sign_buf[320];
	uint8_t *signature;
	size_t sign_len;
	size_t sig_len;
	size_t msg_len = sizeof(msg.base);
	int err;

	err = sap_crypto_generate_ecdh_keypair(&session->local_ecdh_key_id);
	if (err != 0) {
		LOG_ERR("SAP central auth key generation failed (%d)", err);
		return err;
	}
	SAP_INFO_IF_NO_DEMO("SAP sending central auth");

	err = sap_crypto_export_public_key(session->local_ecdh_key_id,
					   session->local_ecdh_public,
					   sizeof(session->local_ecdh_public),
					   &session->local_ecdh_public_len);
	if (err != 0) {
		LOG_ERR("SAP central auth public key export failed (%d)", err);
		return err;
	}

	if (sap_use_ble_sc_oob_pairing(session)) {
		err = sap_generate_local_oob(session);
		if (err != 0) {
			return err;
		}

		bt_le_oob_set_sc_flag(true);
	}

	memcpy(&msg.base.cert, &session->ctx->policy.local_credential->cert, sizeof(msg.base.cert));
	memcpy(msg.base.ecdh_public_key, session->local_ecdh_public,
	       session->local_ecdh_public_len);
	if (sap_use_ble_sc_oob_pairing(session)) {
		memcpy(msg.oob.oob_sc.random, session->local_oob_sc.r,
		       sizeof(msg.oob.oob_sc.random));
		memcpy(msg.oob.oob_sc.confirm, session->local_oob_sc.c,
		       sizeof(msg.oob.oob_sc.confirm));
		msg_len = sizeof(msg.oob);
		signature = msg.oob.signature;
	} else {
		signature = msg.base.signature;
	}

	err = sap_make_central_auth_sig(session, sign_buf, sizeof(sign_buf),
					&sign_len);
	if (err != 0) {
		LOG_ERR("SAP central auth transcript build failed (%d)", err);
		return err;
	}

	err = sap_crypto_sign_identity(session->ctx->local_sign_key_id, sign_buf,
				       sign_len, signature, SAP_IDENTITY_SIGNATURE_LEN,
				       &sig_len);
	if (err != 0 || sig_len != SAP_IDENTITY_SIGNATURE_LEN) {
		LOG_ERR("SAP central auth signing failed (%d, sig_len=%zu)", err, sig_len);
		return -EIO;
	}

	session->state = SAP_STATE_WAIT_PERIPHERAL_AUTH;
	SAP_TRACE("FLOW 5/8 central %u -> peripheral: CENTRAL_AUTH "
		  "(role_mask=0x%02x + ephemeral ECDH key + transcript signature)",
		  session->ctx->policy.local_credential->cert.body.device_id,
		  session->ctx->policy.local_credential->cert.body.role_mask);
	sap_trace_auth_packet(session, "tx", (const uint8_t *)&msg, msg_len);
	return session->ctx->callbacks.send_auth(session, SAP_MSG_CENTRAL_AUTH,
						 (const uint8_t *)&msg, msg_len);
}

static int sap_send_peripheral_auth(struct sap_session *session)
{
	union {
		struct sap_msg_peripheral_auth base;
		struct sap_msg_peripheral_auth_oob oob;
	} msg = {
		.base = {
			.version = SAP_VERSION,
			.type = SAP_MSG_PERIPHERAL_AUTH,
		},
	};
	uint8_t sign_buf[384];
	uint8_t *signature;
	size_t sign_len;
	size_t sig_len;
	size_t msg_len = sizeof(msg.base);
	int err;

	err = sap_crypto_generate_ecdh_keypair(&session->local_ecdh_key_id);
	if (err != 0) {
		LOG_ERR("SAP peripheral auth key generation failed (%d)", err);
		return err;
	}
	SAP_INFO_IF_NO_DEMO("SAP sending peripheral auth");

	err = sap_crypto_export_public_key(session->local_ecdh_key_id,
					   session->local_ecdh_public,
					   sizeof(session->local_ecdh_public),
					   &session->local_ecdh_public_len);
	if (err != 0) {
		LOG_ERR("SAP peripheral auth public key export failed (%d)", err);
		return err;
	}

	if (sap_use_ble_sc_oob_pairing(session)) {
		err = sap_generate_local_oob(session);
		if (err != 0) {
			LOG_ERR("SAP peripheral auth local OOB generation failed (%d)", err);
			return err;
		}

		bt_le_oob_set_sc_flag(true);
	} else {
		err = sap_derive_session_keys(session);
		if (err != 0) {
			LOG_ERR("SAP peripheral auth session key derivation failed (%d)", err);
			return err;
		}
	}

	memcpy(msg.base.ecdh_public_key, session->local_ecdh_public,
	       session->local_ecdh_public_len);
	if (sap_use_ble_sc_oob_pairing(session)) {
		memcpy(msg.oob.oob_sc.random, session->local_oob_sc.r,
		       sizeof(msg.oob.oob_sc.random));
		memcpy(msg.oob.oob_sc.confirm, session->local_oob_sc.c,
		       sizeof(msg.oob.oob_sc.confirm));
		msg_len = sizeof(msg.oob);
		signature = msg.oob.signature;
	} else {
		signature = msg.base.signature;
	}

	err = sap_make_peripheral_auth_sig(session, sign_buf, sizeof(sign_buf),
					   &sign_len);
	if (err != 0) {
		LOG_ERR("SAP peripheral auth transcript build failed (%d)", err);
		return err;
	}

	err = sap_crypto_sign_identity(session->ctx->local_sign_key_id, sign_buf,
				       sign_len, signature, SAP_IDENTITY_SIGNATURE_LEN,
				       &sig_len);
	if (err != 0 || sig_len != SAP_IDENTITY_SIGNATURE_LEN) {
		LOG_ERR("SAP peripheral auth signing failed (%d, sig_len=%zu)", err, sig_len);
		return -EIO;
	}

	session->state = sap_use_ble_sc_oob_pairing(session) ?
		SAP_STATE_WAIT_BLE_PAIRING : SAP_STATE_WAIT_CONFIRM;
	SAP_TRACE("FLOW 6/8 peripheral %u -> central: PERIPHERAL_AUTH "
		  "(ephemeral ECDH key + transcript signature%s)",
		  session->ctx->policy.local_credential->cert.body.device_id,
		  sap_use_ble_sc_oob_pairing(session) ? " + BLE SC OOB data" : "");
	sap_trace_auth_packet(session, "tx", (const uint8_t *)&msg, msg_len);
	err = session->ctx->callbacks.send_auth(session, SAP_MSG_PERIPHERAL_AUTH,
						 (const uint8_t *)&msg, msg_len);
	if (err != 0) {
		LOG_ERR("SAP peripheral auth send failed (%d, len=%zu)", err, msg_len);
	}
	return err;
}

static int sap_handle_hello(struct sap_session *session,
			    const struct sap_msg_hello *msg, size_t len)
{
	if (len != sizeof(*msg)) {
		return -EMSGSIZE;
	}

	if (session->ctx->policy.require_ble_encryption && !session->security_ready) {
		return -EACCES;
	}

	memcpy(session->peer_nonce, msg->central_nonce, SAP_NONCE_LEN);
	SAP_INFO_IF_NO_DEMO("SAP received hello");
	SAP_TRACE("FLOW 3/8 peripheral received HELLO and accepted central nonce");
	return sap_send_peripheral_challenge(session);
}

static int sap_handle_peripheral_challenge(struct sap_session *session,
					   const struct sap_msg_peripheral_challenge *msg,
					   size_t len)
{
	uint8_t sign_buf[1U + (2U * SAP_NONCE_LEN) + sizeof(struct sap_cert_body)];
	size_t sign_len;
	int err;

	if (len != sizeof(*msg) || session->state != SAP_STATE_WAIT_PERIPHERAL_CHALLENGE) {
		return -EPROTO;
	}

	err = sap_verify_certificate(session, &msg->cert, SAP_ROLE_MASK_PERIPHERAL);
	if (err != 0) {
		return err;
	}
	SAP_INFO_IF_NO_DEMO("SAP received peripheral challenge");

	memcpy(&session->peer_cert, &msg->cert, sizeof(session->peer_cert));
	memcpy(session->peer_nonce, msg->peripheral_nonce, SAP_NONCE_LEN);

	err = sap_make_peripheral_challenge_sig(session, sign_buf, sizeof(sign_buf),
						&sign_len);
	if (err != 0) {
		return err;
	}

	err = sap_crypto_verify_identity(msg->cert.body.public_key,
					 sizeof(msg->cert.body.public_key),
					 sign_buf, sign_len, msg->signature,
					 sizeof(msg->signature));
	if (err != 0) {
		return err;
	}
	SAP_TRACE("FLOW 4/8 central verified peripheral certificate and challenge "
		  "signature: device_id=%u group=0x%02x",
		  session->peer_cert.body.device_id,
		  session->peer_cert.body.group_id);

	return sap_send_central_auth(session);
}

static int sap_handle_central_auth(struct sap_session *session,
				   const struct sap_msg_central_auth *msg,
				   size_t len)
{
	uint8_t sign_buf[320];
	size_t sign_len;
	const struct sap_msg_central_auth_oob *msg_oob = NULL;
	const struct sap_certificate *cert = NULL;
	const uint8_t *ecdh_public_key = NULL;
	const uint8_t *signature = NULL;
	int err;

	if ((len != sizeof(*msg) && len != sizeof(struct sap_msg_central_auth_oob)) ||
	    session->state != SAP_STATE_WAIT_CENTRAL_AUTH) {
		return -EPROTO;
	}

	if (len == sizeof(struct sap_msg_central_auth_oob)) {
		msg_oob = (const struct sap_msg_central_auth_oob *)msg;
		cert = &msg_oob->cert;
		ecdh_public_key = msg_oob->ecdh_public_key;
		signature = msg_oob->signature;
		memcpy(session->peer_oob_sc.r, msg_oob->oob_sc.random,
		       sizeof(session->peer_oob_sc.r));
		memcpy(session->peer_oob_sc.c, msg_oob->oob_sc.confirm,
		       sizeof(session->peer_oob_sc.c));
		session->peer_oob_ready = true;
	} else {
		cert = &msg->cert;
		ecdh_public_key = msg->ecdh_public_key;
		signature = msg->signature;
	}

	if (sap_use_ble_sc_oob_pairing(session) && !session->peer_oob_ready) {
		return -EPROTO;
	}

	err = sap_verify_certificate(session, cert, SAP_ROLE_MASK_CENTRAL);
	if (err != 0) {
		LOG_ERR("SAP central auth certificate verify failed (%d)", err);
		return err;
	}
	SAP_INFO_IF_NO_DEMO("SAP received central auth");

	memcpy(&session->peer_cert, cert, sizeof(session->peer_cert));
	memcpy(session->peer_ecdh_public, ecdh_public_key, SAP_ECDH_PUBLIC_KEY_LEN);
	session->peer_ecdh_public_len = SAP_ECDH_PUBLIC_KEY_LEN;

	err = sap_make_central_auth_sig(session, sign_buf, sizeof(sign_buf),
					&sign_len);
	if (err != 0) {
		LOG_ERR("SAP central auth transcript build failed on peripheral (%d)", err);
		return err;
	}

	err = sap_crypto_verify_identity(cert->body.public_key,
					 sizeof(cert->body.public_key),
					 sign_buf, sign_len, signature,
					 SAP_IDENTITY_SIGNATURE_LEN);
	if (err != 0) {
		LOG_ERR("SAP central auth transcript verify failed on peripheral (%d)", err);
		return err;
	}
	SAP_TRACE("FLOW 5/8 peripheral verified central certificate and transcript "
		  "signature: device_id=%u group=0x%02x",
		  session->peer_cert.body.device_id,
		  session->peer_cert.body.group_id);

	return sap_send_peripheral_auth(session);
}

static int sap_handle_peripheral_auth(struct sap_session *session,
				      const struct sap_msg_peripheral_auth *msg,
				      size_t len)
{
	uint8_t sign_buf[384];
	size_t sign_len;
	const struct sap_msg_peripheral_auth_oob *msg_oob = NULL;
	const uint8_t *ecdh_public_key = NULL;
	const uint8_t *signature = NULL;
	int err;

	if ((len != sizeof(*msg) && len != sizeof(struct sap_msg_peripheral_auth_oob)) ||
	    session->state != SAP_STATE_WAIT_PERIPHERAL_AUTH) {
		return -EPROTO;
	}

	if (len == sizeof(struct sap_msg_peripheral_auth_oob)) {
		msg_oob = (const struct sap_msg_peripheral_auth_oob *)msg;
		ecdh_public_key = msg_oob->ecdh_public_key;
		signature = msg_oob->signature;
		memcpy(session->peer_oob_sc.r, msg_oob->oob_sc.random,
		       sizeof(session->peer_oob_sc.r));
		memcpy(session->peer_oob_sc.c, msg_oob->oob_sc.confirm,
		       sizeof(session->peer_oob_sc.c));
		session->peer_oob_ready = true;
	} else {
		ecdh_public_key = msg->ecdh_public_key;
		signature = msg->signature;
	}

	if (sap_use_ble_sc_oob_pairing(session) && !session->peer_oob_ready) {
		return -EPROTO;
	}

	memcpy(session->peer_ecdh_public, ecdh_public_key, SAP_ECDH_PUBLIC_KEY_LEN);
	session->peer_ecdh_public_len = SAP_ECDH_PUBLIC_KEY_LEN;
	SAP_INFO_IF_NO_DEMO("SAP received peripheral auth");

	err = sap_make_peripheral_auth_sig(session, sign_buf, sizeof(sign_buf),
					   &sign_len);
	if (err != 0) {
		return err;
	}

	err = sap_crypto_verify_identity(session->peer_cert.body.public_key,
					 sizeof(session->peer_cert.body.public_key),
					 sign_buf, sign_len, signature,
					 SAP_IDENTITY_SIGNATURE_LEN);
	if (err != 0) {
		return err;
	}
	SAP_TRACE("FLOW 6/8 central verified peripheral transcript signature");

	if (sap_use_ble_sc_oob_pairing(session)) {
		if (!session->local_oob_ready || !session->peer_oob_ready) {
			return -EPROTO;
		}

		session->state = SAP_STATE_WAIT_BLE_PAIRING;
		bt_le_oob_set_sc_flag(true);
		SAP_TRACE("FLOW 7/8 central requested BLE Secure Connections OOB pairing");
		err = bt_conn_set_security(session->conn, BT_SECURITY_L4);
		if (err != 0) {
			LOG_ERR("SAP failed to start BLE L4 security (%d)", err);
		}
		return err;
	} else {
		err = sap_derive_session_keys(session);
		if (err != 0) {
			return err;
		}
	}

	session->state = SAP_STATE_WAIT_CONFIRM_TX;
	SAP_TRACE("FLOW 7/8 central -> peripheral: CONFIRM "
		  "(encrypted proof of shared session key)");
	return sap_send_secure(session, SAP_MSG_CONFIRM,
			       (const uint8_t *)SAP_CONFIRM_TEXT,
			       SAP_CONFIRM_TEXT_LEN);
}

int sap_handle_auth_rx(struct sap_session *session, const uint8_t *data, size_t len)
{
	int err = -EPROTO;
	uint8_t version;
	uint8_t type;

	if (len < 2U) {
		sap_trace_auth_packet(session, "rx", data, len);
		sap_fail(session, -EMSGSIZE);
		return -EMSGSIZE;
	}

	version = data[0];
	type = data[1];
	sap_trace_auth_packet(session, "rx", data, len);

	if (version != SAP_VERSION) {
		sap_fail(session, -EPROTO);
		return -EPROTO;
	}

	switch (type) {
	case SAP_MSG_HELLO:
		err = sap_handle_hello(session, (const struct sap_msg_hello *)data, len);
		break;
	case SAP_MSG_PERIPHERAL_CHALLENGE:
		err = sap_handle_peripheral_challenge(
			session, (const struct sap_msg_peripheral_challenge *)data, len);
		break;
	case SAP_MSG_CENTRAL_AUTH:
		err = sap_handle_central_auth(session,
					      (const struct sap_msg_central_auth *)data,
					      len);
		break;
	case SAP_MSG_PERIPHERAL_AUTH:
		err = sap_handle_peripheral_auth(
			session, (const struct sap_msg_peripheral_auth *)data, len);
		break;
	default:
		err = -EPROTO;
		break;
	}

	if (err != 0) {
		sap_fail(session, err);
	}

	return err;
}

int sap_send_secure(struct sap_session *session, uint8_t msg_type,
		    const uint8_t *payload, size_t len)
{
	uint8_t buffer[SAP_SECURE_FRAME_BUF_LEN];
	size_t out_len;
	uint32_t counter;
	int err;

	if (sap_use_link_security_transport(session)) {
		if (!sap_is_authenticated(session) || session->security_level < BT_SECURITY_L4) {
			return -EACCES;
		}

		if (len > SAP_PLAINTEXT_FRAME_PAYLOAD_LEN) {
			return -EMSGSIZE;
		}

		err = sap_pack_plaintext_internal(msg_type, payload, len, buffer,
					       sizeof(buffer), &out_len);
		if (err != 0) {
			return err;
		}

		sap_trace_secure_packet(session, "tx", buffer, out_len);
		return session->ctx->callbacks.send_secure(session, msg_type, buffer, out_len);
	}

	if (!session->session_key_ready) {
		return -EACCES;
	}

	if (len > SAP_SECURE_PLAINTEXT_BUF_LEN) {
		return -EMSGSIZE;
	}

	counter = session->tx_counter;
	err = sap_encrypt_internal(session, msg_type, counter, payload, len, buffer,
				   sizeof(buffer), &out_len);
	if (err != 0) {
		return err;
	}

	sap_trace_secure_packet(session, "tx", buffer, out_len);

	err = session->ctx->callbacks.send_secure(session, msg_type, buffer, out_len);
	if (err == 0) {
		session->tx_counter = counter + 1U;
	}

	return err;
}

int sap_handle_secure_rx(struct sap_session *session, const uint8_t *data, size_t len)
{
	uint8_t plaintext[SAP_APP_PAYLOAD_BUF_LEN];
	uint8_t msg_type;
	size_t plaintext_len;
	int err;

	sap_trace_secure_packet(session, "rx", data, len);

	if (sap_use_link_security_transport(session)) {
		if (!sap_is_authenticated(session) || session->security_level < BT_SECURITY_L4) {
			sap_fail(session, -EACCES);
			return -EACCES;
		}

		err = sap_unpack_plaintext_internal(data, len, &msg_type, plaintext,
					      sizeof(plaintext), &plaintext_len);
		if (err != 0) {
			sap_fail(session, err);
			return err;
		}
	} else {
		if (!session->session_key_ready) {
			sap_fail(session, -EACCES);
			return -EACCES;
		}

		err = sap_decrypt_internal(session, data, len, &msg_type, plaintext,
					   sizeof(plaintext), &plaintext_len);
		if (err != 0) {
			sap_fail(session, err);
			return err;
		}
	}

	switch (msg_type) {
	case SAP_MSG_CONFIRM:
		if (sap_use_link_security_transport(session)) {
			err = -EPROTO;
			break;
		}

		if ((session->role != SAP_ROLE_PERIPHERAL) ||
		    (session->state != SAP_STATE_WAIT_CONFIRM) ||
		    (plaintext_len != SAP_CONFIRM_TEXT_LEN) ||
		    (memcmp(plaintext, SAP_CONFIRM_TEXT, SAP_CONFIRM_TEXT_LEN) != 0)) {
			err = -EPROTO;
			break;
		}

		SAP_TRACE("FLOW 7/8 peripheral accepted CONFIRM and proved key agreement");
		sap_notify_authenticated(session,
					"FLOW 8/8 peripheral marked SAP session authenticated after confirmed CONFIRM reception");
		err = 0;
		break;

	default:
		if ((session->role == SAP_ROLE_CENTRAL) &&
		    (session->state == SAP_STATE_WAIT_CONFIRM_TX)) {
			sap_notify_authenticated(
				session,
				"FLOW 8/8 central accepted first post-confirm SAP frame and marked SAP session authenticated");
		}

		if (!sap_is_authenticated(session)) {
			err = -EACCES;
			break;
		}

		if (session->ctx->callbacks.secure_payload_received != NULL) {
			session->ctx->callbacks.secure_payload_received(session,
								   msg_type,
								   plaintext,
								   plaintext_len);
		}
		err = 0;
		break;
	}

	if (err != 0) {
		sap_fail(session, err);
	}

	return err;
}

void sap_on_tx_complete(struct sap_session *session, uint8_t msg_type, int err)
{
	if ((session == NULL) || !session->in_use || (session->state == SAP_STATE_FAILED)) {
		return;
	}

	if (err != 0) {
		sap_fail(session, (err < 0) ? err : -EIO);
		return;
	}

	if ((msg_type == SAP_MSG_CONFIRM) &&
	    (session->role == SAP_ROLE_CENTRAL) &&
	    (session->state == SAP_STATE_WAIT_CONFIRM_TX)) {
		sap_notify_authenticated(
			session,
			"FLOW 8/8 central observed ATT confirmation for CONFIRM and marked SAP session authenticated");
	}
}
