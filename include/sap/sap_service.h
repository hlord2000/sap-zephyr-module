/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef SAP_SERVICE_H__
#define SAP_SERVICE_H__

#include <stdbool.h>
#include <psa/crypto.h>
#include <zephyr/bluetooth/conn.h>

#include <sap/sap_protocol.h>

struct sap_context;

struct sap_device_credential {
	uint8_t simulated_device_number;
	uint8_t private_key[SAP_IDENTITY_PRIVATE_KEY_LEN];
	struct sap_certificate cert;
};

enum sap_session_state {
	SAP_STATE_IDLE = 0,
	SAP_STATE_WAIT_PERIPHERAL_CHALLENGE,
	SAP_STATE_WAIT_CENTRAL_AUTH,
	SAP_STATE_WAIT_PERIPHERAL_AUTH,
	SAP_STATE_WAIT_CONFIRM,
	SAP_STATE_WAIT_CONFIRM_TX,
	SAP_STATE_WAIT_BLE_PAIRING,
	SAP_STATE_AUTHENTICATED,
	SAP_STATE_FAILED,
};

struct sap_policy {
	const struct sap_device_credential *local_credential;
	const uint8_t *ca_public_key;
	size_t ca_public_key_len;
	uint8_t expected_group_id;
	uint8_t allowed_central_id;
	bool require_ble_encryption;
	bool use_ble_sc_oob_pairing;
	bool use_link_security_for_secure_transport;
};

struct sap_session {
	struct sap_context *ctx;
	struct bt_conn *conn;
	void *user_data;
	enum sap_role role;
	enum sap_session_state state;
	bool in_use;
	bool security_ready;
	bool session_key_ready;
	bool authenticated_notified;
	bt_security_t security_level;
	struct sap_certificate peer_cert;
	uint8_t local_nonce[SAP_NONCE_LEN];
	uint8_t peer_nonce[SAP_NONCE_LEN];
	uint8_t local_ecdh_public[SAP_ECDH_PUBLIC_KEY_LEN];
	size_t local_ecdh_public_len;
	uint8_t peer_ecdh_public[SAP_ECDH_PUBLIC_KEY_LEN];
	size_t peer_ecdh_public_len;
	struct bt_le_oob_sc_data local_oob_sc;
	struct bt_le_oob_sc_data peer_oob_sc;
	bool local_oob_ready;
	bool peer_oob_ready;
	uint32_t tx_counter;
	uint32_t rx_counter;
	psa_key_id_t local_ecdh_key_id;
	psa_key_id_t aead_key_id;
};

struct sap_callbacks {
	int (*send_auth)(struct sap_session *session, uint8_t msg_type,
			 const uint8_t *data, size_t len);
	int (*send_secure)(struct sap_session *session, uint8_t msg_type,
			   const uint8_t *data, size_t len);
	void (*authenticated)(struct sap_session *session);
	void (*authentication_failed)(struct sap_session *session, int reason);
	void (*secure_payload_received)(struct sap_session *session, uint8_t msg_type,
					const uint8_t *data, size_t len);
};

struct sap_context {
	enum sap_role role;
	struct sap_policy policy;
	struct sap_callbacks callbacks;
	struct sap_session sessions[CONFIG_SAP_MAX_PEERS];
	psa_key_id_t local_sign_key_id;
};

int sap_init(struct sap_context *ctx, enum sap_role role,
	     const struct sap_policy *policy,
	     const struct sap_callbacks *callbacks);
void sap_uninit(struct sap_context *ctx);

struct sap_session *sap_on_connected(struct sap_context *ctx, struct bt_conn *conn);
void sap_on_disconnected(struct sap_context *ctx, struct bt_conn *conn);
struct sap_session *sap_session_from_conn(struct sap_context *ctx,
					  struct bt_conn *conn);

void sap_on_security_changed(struct sap_session *session, bt_security_t level,
			     enum bt_security_err err);
bool sap_is_authenticated(const struct sap_session *session);

int sap_start(struct sap_session *session);
int sap_handle_auth_rx(struct sap_session *session, const uint8_t *data, size_t len);
int sap_handle_secure_rx(struct sap_session *session, const uint8_t *data, size_t len);
void sap_on_tx_complete(struct sap_session *session, uint8_t msg_type, int err);
int sap_send_secure(struct sap_session *session, uint8_t msg_type,
		    const uint8_t *payload, size_t len);

#endif /* SAP_SERVICE_H__ */
