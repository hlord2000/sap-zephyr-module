/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>
#include <zephyr/logging/log.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/hci.h>

#include <bluetooth/gatt_dm.h>

#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
#include <bluetooth/services/dfu_smp.h>
#include <zcbor_common.h>
#include <zcbor_decode.h>
#include <zcbor_encode.h>
#endif

#if defined(CONFIG_SAP_SHELL)
#include <zephyr/shell/shell.h>
#endif

#if defined(CONFIG_SAP_DK_IO)
#include <dk_buttons_and_leds.h>
#endif

#include "demo_protocol.h"
#include <sap/sap_service.h>
#include <sap/sap_trace.h>

LOG_MODULE_REGISTER(sap_central, CONFIG_SAP_LOG_LEVEL);

#define SAP_SCAN_RESTART_DELAY_MS 250
#define SAP_SECURITY_FAILURE_RETRY_MS 1000
#define SAP_REMOTE_LED_MAX 4U
#define SAP_DFU_ECHO_DELAY_MS 200

#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
#define SAP_DFU_CBOR_ENCODER_STATE_NUM 2
#define SAP_DFU_CBOR_DECODER_STATE_NUM 3
#define SAP_DFU_CBOR_MAP_MAX_ELEMENT_CNT 2
#define SAP_DFU_CBOR_BUFFER_SIZE 160
#define SAP_DFU_KEY_LEN_MAX 2
#define SAP_DFU_VALUE_LEN_MAX 96
#define SAP_DFU_ECHO_TEXT_MAX 48
#endif

struct sap_gatt_handles {
	uint16_t auth;
	uint16_t auth_ccc;
	uint16_t secure_tx;
	uint16_t secure_tx_ccc;
	uint16_t secure_rx;
	uint16_t protected_status;
};

#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
struct sap_dfu_buffer {
	struct bt_dfu_smp_header header;
	uint8_t payload[SAP_DFU_CBOR_BUFFER_SIZE];
};
#endif

struct sap_central_peer {
	struct bt_conn *conn;
	struct sap_session *session;
	struct sap_gatt_handles handles;
	struct bt_gatt_subscribe_params auth_sub_params;
	struct bt_gatt_subscribe_params secure_sub_params;
	struct bt_gatt_read_params protected_read_params;
	struct bt_gatt_exchange_params mtu_params;
	bool in_use;
	bool mtu_requested;
	bool mtu_ready;
	bool discovery_ready;
	bool auth_subscribed;
	bool secure_subscribed;
	bool handshake_started;
	bool sap_discovery_retry;
	bool protected_discovery_retry;
	bool protected_service_ready;
#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
	struct bt_dfu_smp dfu_smp;
	struct sap_dfu_buffer dfu_rsp;
	bool dfu_service_ready;
	bool dfu_discovery_retry;
	bool dfu_echo_pending;
	bool dfu_echo_complete;
#endif
};

static struct sap_context sap_ctx;
static struct sap_central_peer peers[CONFIG_SAP_MAX_PEERS];
static struct bt_conn *conn_connecting;
static bool scanning_active;
static bool scan_restart_pending;
static const uint8_t sap_service_uuid[] = {
	BT_UUID_SAP_SERVICE_VAL,
};

#if defined(CONFIG_SAP_SHELL)
static const char *session_state_str(enum sap_session_state state)
{
	switch (state) {
	case SAP_STATE_IDLE:
		return "idle";
	case SAP_STATE_WAIT_PERIPHERAL_CHALLENGE:
		return "wait_peripheral_challenge";
	case SAP_STATE_WAIT_CENTRAL_AUTH:
		return "wait_central_auth";
	case SAP_STATE_WAIT_PERIPHERAL_AUTH:
		return "wait_peripheral_auth";
	case SAP_STATE_WAIT_CONFIRM:
		return "wait_confirm";
	case SAP_STATE_WAIT_CONFIRM_ACK:
		return "wait_confirm_ack";
	case SAP_STATE_AUTHENTICATED:
		return "authenticated";
	case SAP_STATE_FAILED:
		return "failed";
	default:
		return "unknown";
	}
}
#endif

#if defined(CONFIG_SAP_SHELL) || defined(CONFIG_SAP_DK_IO)
static int led_index_for_peer_id(uint8_t peer_id)
{
	if ((peer_id == 0U) || (peer_id > SAP_REMOTE_LED_MAX)) {
		return -ENOENT;
	}

	return (int)(peer_id - 1U);
}

static const char *led_name_for_peer_id(uint8_t peer_id)
{
	switch (peer_id) {
	case 1:
		return "LED1";
	case 2:
		return "LED2";
	case 3:
		return "LED3";
	case 4:
		return "LED4";
	default:
		return "none";
	}
}
#endif

#if defined(CONFIG_SAP_DK_IO)
static void set_remote_led_state(uint8_t peer_id, bool active)
{
	int led_index;
	int err;

	led_index = led_index_for_peer_id(peer_id);
	if (led_index < 0) {
		SAP_TRACE("FLOW app-io: peripheral %u has no LED assignment on the central",
			  peer_id);
		return;
	}

	err = dk_set_led((uint8_t)led_index, active ? 1U : 0U);
	if (err != 0) {
		LOG_WRN("Failed to set %s for peripheral %u (%d)",
			led_name_for_peer_id(peer_id), peer_id, err);
		return;
	}

	SAP_TRACE("FLOW app-io: central mapped peripheral %u button state %u onto %s",
		  peer_id, active ? 1U : 0U, led_name_for_peer_id(peer_id));
}
#else
static void set_remote_led_state(uint8_t peer_id, bool active)
{
	ARG_UNUSED(peer_id);
	ARG_UNUSED(active);
}
#endif

static void clear_remote_led(uint8_t peer_id)
{
	set_remote_led_state(peer_id, false);
}

static void start_sap_service_discovery(struct sap_central_peer *peer);
static void discover_protected_service(struct sap_central_peer *peer);
#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
static void discover_dfu_service(struct sap_central_peer *peer);
static int send_dfu_echo(struct sap_central_peer *peer, const char *text);
static void dfu_echo_work_fn(struct k_work *work);
#endif
static void gatt_retry_fn(struct k_work *work);
static void scan_restart_fn(struct k_work *work);
K_WORK_DELAYABLE_DEFINE(gatt_retry_work, gatt_retry_fn);
K_WORK_DELAYABLE_DEFINE(scan_restart_work, scan_restart_fn);
#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
K_WORK_DELAYABLE_DEFINE(dfu_echo_work, dfu_echo_work_fn);
#endif

static bool ad_has_sap_service_cb(struct bt_data *data, void *user_data)
{
	bool *found = user_data;
	size_t offset;

	if ((data->type != BT_DATA_UUID128_ALL) &&
	    (data->type != BT_DATA_UUID128_SOME)) {
		return true;
	}

	for (offset = 0U; (offset + sizeof(sap_service_uuid)) <= data->data_len;
	     offset += sizeof(sap_service_uuid)) {
		if (memcmp(&data->data[offset], sap_service_uuid,
			   sizeof(sap_service_uuid)) == 0) {
			*found = true;
			return false;
		}
	}

	return true;
}

static void schedule_gatt_retry(void)
{
	(void)k_work_reschedule(&gatt_retry_work, K_MSEC(100));
}

#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
static void schedule_dfu_echo(k_timeout_t delay)
{
	(void)k_work_reschedule(&dfu_echo_work, delay);
}
#endif

static bool should_clear_bond(enum bt_security_err err)
{
	switch (err) {
	case BT_SECURITY_ERR_AUTH_FAIL:
	case BT_SECURITY_ERR_PIN_OR_KEY_MISSING:
	case BT_SECURITY_ERR_AUTH_REQUIREMENT:
	case BT_SECURITY_ERR_KEY_REJECTED:
		return true;
	default:
		return false;
	}
}

static void clear_bond_on_security_failure(struct bt_conn *conn,
					   enum bt_security_err err)
{
	int clear_err;

	if (!IS_ENABLED(CONFIG_BT_SETTINGS) || !should_clear_bond(err)) {
		return;
	}

	clear_err = bt_unpair(BT_ID_DEFAULT, bt_conn_get_dst(conn));
	if (clear_err == 0) {
		LOG_WRN("Cleared stale bond after security failure: %s",
			bt_security_err_to_str(err));
	} else if (clear_err != -ENOENT) {
		LOG_WRN("Failed to clear stale bond (%d)", clear_err);
	}
}

static struct sap_central_peer *peer_from_conn(struct bt_conn *conn)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(peers); i++) {
		if (peers[i].in_use && peers[i].conn == conn) {
			return &peers[i];
		}
	}

	return NULL;
}

#if defined(CONFIG_SAP_SHELL)
static struct sap_central_peer *peer_from_device_id(uint8_t peer_id)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(peers); i++) {
		if (!peers[i].in_use || (peers[i].session == NULL)) {
			continue;
		}

		if (!sap_is_authenticated(peers[i].session)) {
			continue;
		}

		if (peers[i].session->peer_cert.body.device_id == peer_id) {
			return &peers[i];
		}
	}

	return NULL;
}
#endif

static size_t active_peer_count(void)
{
	size_t i;
	size_t count = 0U;

	for (i = 0; i < ARRAY_SIZE(peers); i++) {
		if (peers[i].in_use) {
			count++;
		}
	}

	return count;
}

static void start_scan(void);
static void start_att_setup(struct sap_central_peer *peer);

static void schedule_scan_restart(k_timeout_t delay)
{
	scan_restart_pending = true;
	(void)k_work_reschedule(&scan_restart_work, delay);
}

static void maybe_start_handshake(struct sap_central_peer *peer)
{
	int err;

	if (peer->handshake_started || !peer->mtu_ready || !peer->discovery_ready ||
	    !peer->auth_subscribed || !peer->secure_subscribed ||
	    !peer->session->security_ready) {
		return;
	}

	peer->handshake_started = true;
	err = sap_start(peer->session);
	if (err != 0) {
		LOG_ERR("Failed to start SAP handshake (%d)", err);
		(void)bt_conn_disconnect(peer->conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	}
}

static int send_auth(struct sap_session *session, const uint8_t *data, size_t len)
{
	struct sap_central_peer *peer = session->user_data;

	return bt_gatt_write_without_response(peer->conn, peer->handles.auth, data,
					      len, false);
}

static int send_secure(struct sap_session *session, const uint8_t *data, size_t len)
{
	struct sap_central_peer *peer = session->user_data;

	return bt_gatt_write_without_response(peer->conn, peer->handles.secure_rx,
					      data, len, false);
}

#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
static void dfu_smp_on_error(struct bt_dfu_smp *dfu_smp, int err)
{
	struct sap_central_peer *peer = CONTAINER_OF(dfu_smp, struct sap_central_peer,
						     dfu_smp);

	LOG_ERR("DFU SMP client error on peer %u (%d)",
		peer->session != NULL ? peer->session->peer_cert.body.device_id : 0U,
		err);
}

static const struct bt_dfu_smp_init_params dfu_smp_init_params = {
	.error_cb = dfu_smp_on_error,
};

static void dfu_start_next_step(struct sap_central_peer *peer)
{
	if ((peer == NULL) || !peer->in_use || (peer->session == NULL) ||
	    !sap_is_authenticated(peer->session) || peer->dfu_service_ready) {
		return;
	}

	discover_dfu_service(peer);
}

static void dfu_echo_rsp_proc(struct bt_dfu_smp *dfu_smp)
{
	struct sap_central_peer *peer = CONTAINER_OF(dfu_smp, struct sap_central_peer, dfu_smp);
	const struct bt_dfu_smp_rsp_state *rsp_state = bt_dfu_smp_rsp_state(dfu_smp);
	uint8_t *buf = (uint8_t *)&peer->dfu_rsp;

	if (rsp_state->offset + rsp_state->chunk_size > sizeof(peer->dfu_rsp)) {
		LOG_ERR("DFU SMP response overflow on peer %u",
			peer->session->peer_cert.body.device_id);
		return;
	}

	memcpy(buf + rsp_state->offset, rsp_state->data, rsp_state->chunk_size);

	if (!bt_dfu_smp_rsp_total_check(dfu_smp)) {
		return;
	}

	if (peer->dfu_rsp.header.op != 3U ||
	    peer->dfu_rsp.header.group_h8 != 0U ||
	    peer->dfu_rsp.header.group_l8 != 0U ||
	    peer->dfu_rsp.header.id != 0U) {
		LOG_ERR("Unexpected DFU SMP echo response from peer %u",
			peer->session->peer_cert.body.device_id);
		return;
	}

	{
		size_t payload_len = (((size_t)peer->dfu_rsp.header.len_h8) << 8) |
				      peer->dfu_rsp.header.len_l8;
		zcbor_state_t zsd[SAP_DFU_CBOR_DECODER_STATE_NUM];
		struct zcbor_string value = {0};
		char key[SAP_DFU_KEY_LEN_MAX];
		char response[SAP_DFU_VALUE_LEN_MAX];
		bool ok;

		zcbor_new_decode_state(zsd, ARRAY_SIZE(zsd), peer->dfu_rsp.payload, payload_len,
				       1, NULL, 0);

		ok = zcbor_map_start_decode(zsd);
		ok = ok && zcbor_tstr_decode(zsd, &value);
		if (!ok || (value.len != 1U) || (value.value[0] != 'r')) {
			LOG_ERR("Failed to decode DFU SMP echo key from peer %u",
				peer->session->peer_cert.body.device_id);
			return;
		}

		key[0] = value.value[0];
		key[1] = '\0';

		ok = zcbor_tstr_decode(zsd, &value);
		ok = ok && zcbor_map_end_decode(zsd);
		if (!ok || (value.len >= sizeof(response))) {
			LOG_ERR("Failed to decode DFU SMP echo value from peer %u",
				peer->session->peer_cert.body.device_id);
			return;
		}

		memcpy(response, value.value, value.len);
		response[value.len] = '\0';

		peer->dfu_echo_complete = true;
		LOG_INF("DFU SMP echo from peripheral %u: %s=%s",
			peer->session->peer_cert.body.device_id, key, response);
		SAP_TRACE("FLOW post-auth: central verified gated DFU SMP service on peer %u",
			  peer->session->peer_cert.body.device_id);
	}
}

static int send_dfu_echo(struct sap_central_peer *peer, const char *text)
{
	struct sap_dfu_buffer smp_cmd;
	zcbor_state_t zse[SAP_DFU_CBOR_ENCODER_STATE_NUM];
	size_t payload_len;

	if ((peer == NULL) || !peer->in_use || (peer->session == NULL)) {
		return -ENOTCONN;
	}

	if (!peer->dfu_service_ready) {
		return -EAGAIN;
	}

	memset(&smp_cmd, 0, sizeof(smp_cmd));
	memset(&peer->dfu_rsp, 0, sizeof(peer->dfu_rsp));

	zcbor_new_encode_state(zse, ARRAY_SIZE(zse), smp_cmd.payload,
			       sizeof(smp_cmd.payload), 0);

	if (!zcbor_map_start_encode(zse, SAP_DFU_CBOR_MAP_MAX_ELEMENT_CNT) ||
	    !zcbor_tstr_put_lit(zse, "d") ||
	    !zcbor_tstr_put_term(zse, text, strlen(text) + 1U) ||
	    !zcbor_map_end_encode(zse, SAP_DFU_CBOR_MAP_MAX_ELEMENT_CNT)) {
		return -EFAULT;
	}

	payload_len = (size_t)(zse->payload - smp_cmd.payload);
	smp_cmd.header.op = 2U;
	smp_cmd.header.flags = 0U;
	smp_cmd.header.len_h8 = (uint8_t)((payload_len >> 8) & 0xffU);
	smp_cmd.header.len_l8 = (uint8_t)(payload_len & 0xffU);
	smp_cmd.header.group_h8 = 0U;
	smp_cmd.header.group_l8 = 0U;
	smp_cmd.header.seq = 0U;
	smp_cmd.header.id = 0U;

	return bt_dfu_smp_command(&peer->dfu_smp, dfu_echo_rsp_proc,
				  sizeof(smp_cmd.header) + payload_len, &smp_cmd);
}

static void dfu_echo_work_fn(struct k_work *work)
{
	size_t i;
	bool retry_needed = false;

	ARG_UNUSED(work);

	for (i = 0; i < ARRAY_SIZE(peers); i++) {
		struct sap_central_peer *peer = &peers[i];
		char echo_text[SAP_DFU_ECHO_TEXT_MAX];
		int err;

		if (!peer->in_use || !peer->dfu_service_ready || !peer->dfu_echo_pending ||
		    peer->dfu_echo_complete || (peer->session == NULL) ||
		    !sap_is_authenticated(peer->session)) {
			continue;
		}

		snprintk(echo_text, sizeof(echo_text), "sap-dfu-%u",
			 peer->session->peer_cert.body.device_id);
		err = send_dfu_echo(peer, echo_text);
		if (err == 0) {
			peer->dfu_echo_pending = false;
			SAP_TRACE("FLOW post-auth: central sent DFU SMP echo probe to peer %u",
				  peer->session->peer_cert.body.device_id);
			continue;
		}

		if ((err == -EAGAIN) || (err == -EBUSY) || (err == -ENOMEM)) {
			retry_needed = true;
			continue;
		}

		peer->dfu_echo_pending = false;
		LOG_ERR("Failed to send DFU SMP echo to peer %u (%d)",
			peer->session->peer_cert.body.device_id, err);
	}

	if (retry_needed) {
		schedule_dfu_echo(K_MSEC(SAP_DFU_ECHO_DELAY_MS));
	}
}
#endif

static uint8_t auth_notif_cb(struct bt_conn *conn,
			     struct bt_gatt_subscribe_params *params,
			     const void *data, uint16_t length)
{
	struct sap_central_peer *peer = CONTAINER_OF(params, struct sap_central_peer,
						     auth_sub_params);
	int err;

	if (data == NULL) {
		return BT_GATT_ITER_STOP;
	}

	err = sap_handle_auth_rx(peer->session, data, length);
	if (err != 0) {
		LOG_ERR("SAP auth notification failed (%d)", err);
		(void)bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	}

	return BT_GATT_ITER_CONTINUE;
}

static uint8_t secure_notif_cb(struct bt_conn *conn,
			       struct bt_gatt_subscribe_params *params,
			       const void *data, uint16_t length)
{
	struct sap_central_peer *peer = CONTAINER_OF(params, struct sap_central_peer,
						     secure_sub_params);
	int err;

	if (data == NULL) {
		return BT_GATT_ITER_STOP;
	}

	err = sap_handle_secure_rx(peer->session, data, length);
	if (err != 0) {
		LOG_ERR("SAP secure notification failed (%d)", err);
		(void)bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	}

	return BT_GATT_ITER_CONTINUE;
}

static uint8_t protected_read_cb(struct bt_conn *conn, uint8_t err,
				 struct bt_gatt_read_params *params,
				 const void *data, uint16_t length)
{
	struct sap_central_peer *peer = CONTAINER_OF(params, struct sap_central_peer,
						     protected_read_params);
	ARG_UNUSED(conn);

	if (err != 0U) {
		LOG_ERR("Protected service read failed (0x%02x)", err);
#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
		dfu_start_next_step(peer);
#endif
		return BT_GATT_ITER_STOP;
	}

	if (data != NULL && length > 0U) {
		peer->protected_service_ready = true;
		LOG_INF("Protected service payload: %.*s", length, (const char *)data);
		SAP_TRACE("FLOW post-auth: central successfully read the gated protected characteristic");
	}

#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
	dfu_start_next_step(peer);
#endif

	return BT_GATT_ITER_STOP;
}

static int assign_sap_handles(struct bt_gatt_dm *dm, struct sap_gatt_handles *handles)
{
	const struct bt_gatt_dm_attr *svc_attr = bt_gatt_dm_service_get(dm);
	const struct bt_gatt_service_val *svc =
		bt_gatt_dm_attr_service_val(svc_attr);
	const struct bt_gatt_dm_attr *chrc;
	const struct bt_gatt_dm_attr *desc;

	if (bt_uuid_cmp(svc->uuid, BT_UUID_SAP_SERVICE) != 0) {
		return -ENOTSUP;
	}

	memset(handles, 0, sizeof(*handles));

	chrc = bt_gatt_dm_char_by_uuid(dm, BT_UUID_SAP_AUTH);
	desc = bt_gatt_dm_desc_by_uuid(dm, chrc, BT_UUID_SAP_AUTH);
	handles->auth = desc->handle;
	desc = bt_gatt_dm_desc_by_uuid(dm, chrc, BT_UUID_GATT_CCC);
	handles->auth_ccc = desc->handle;

	chrc = bt_gatt_dm_char_by_uuid(dm, BT_UUID_SAP_SECURE_TX);
	desc = bt_gatt_dm_desc_by_uuid(dm, chrc, BT_UUID_SAP_SECURE_TX);
	handles->secure_tx = desc->handle;
	desc = bt_gatt_dm_desc_by_uuid(dm, chrc, BT_UUID_GATT_CCC);
	handles->secure_tx_ccc = desc->handle;

	chrc = bt_gatt_dm_char_by_uuid(dm, BT_UUID_SAP_SECURE_RX);
	desc = bt_gatt_dm_desc_by_uuid(dm, chrc, BT_UUID_SAP_SECURE_RX);
	handles->secure_rx = desc->handle;

	return 0;
}

static void protected_service_discovered(struct bt_gatt_dm *dm, void *context)
{
	struct sap_central_peer *peer = context;
	const struct bt_gatt_dm_attr *chrc;
	const struct bt_gatt_dm_attr *desc;
	int err;

	chrc = bt_gatt_dm_char_by_uuid(dm, BT_UUID_SAP_DEMO_PROTECTED_STATUS);
	desc = bt_gatt_dm_desc_by_uuid(dm, chrc, BT_UUID_SAP_DEMO_PROTECTED_STATUS);
	peer->handles.protected_status = desc->handle;

	bt_gatt_dm_data_release(dm);
	SAP_TRACE("FLOW post-auth: central discovered the protected service on peer %u",
		  peer->session->peer_cert.body.device_id);

	peer->protected_read_params.func = protected_read_cb;
	peer->protected_read_params.handle_count = 1U;
	peer->protected_read_params.single.handle = peer->handles.protected_status;
	peer->protected_read_params.single.offset = 0U;

	err = bt_gatt_read(peer->conn, &peer->protected_read_params);
	if (err != 0) {
		LOG_ERR("Failed to read protected characteristic (%d)", err);
	}
}

static void protected_service_not_found(struct bt_conn *conn, void *context)
{
	struct sap_central_peer *peer = context;

	ARG_UNUSED(conn);
	LOG_WRN("Protected service not found after SAP auth");
	if (peer != NULL && peer->in_use) {
		peer->protected_discovery_retry = true;
		schedule_gatt_retry();
	}
}

static void protected_discovery_error(struct bt_conn *conn, int err, void *context)
{
	struct sap_central_peer *peer = context;

	ARG_UNUSED(conn);
	LOG_ERR("GATT discovery failed (%d)", err);
	if (peer != NULL && peer->in_use) {
		peer->protected_discovery_retry = true;
		schedule_gatt_retry();
	}
}

static const struct bt_gatt_dm_cb protected_dm_cb = {
	.completed = protected_service_discovered,
	.service_not_found = protected_service_not_found,
	.error_found = protected_discovery_error,
};

#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
static void dfu_service_discovered(struct bt_gatt_dm *dm, void *context)
{
	struct sap_central_peer *peer = context;

	int err = bt_dfu_smp_handles_assign(dm, &peer->dfu_smp);
	bt_gatt_dm_data_release(dm);
	if (err != 0) {
		LOG_ERR("Failed to assign DFU SMP handles (%d)", err);
		return;
	}

	peer->dfu_service_ready = true;
	peer->dfu_echo_pending = true;
	LOG_INF("DFU SMP service discovered on peripheral %u",
		peer->session->peer_cert.body.device_id);
	SAP_TRACE("FLOW post-auth: central discovered the gated DFU SMP service on peer %u",
		  peer->session->peer_cert.body.device_id);
	schedule_dfu_echo(K_MSEC(SAP_DFU_ECHO_DELAY_MS));
}

static void dfu_service_not_found(struct bt_conn *conn, void *context)
{
	struct sap_central_peer *peer = context;

	ARG_UNUSED(conn);
	LOG_WRN("DFU SMP service not found after SAP auth");
	if (peer != NULL && peer->in_use) {
		peer->dfu_discovery_retry = true;
		schedule_gatt_retry();
	}
}

static void dfu_discovery_error(struct bt_conn *conn, int err, void *context)
{
	struct sap_central_peer *peer = context;

	ARG_UNUSED(conn);
	LOG_ERR("DFU SMP discovery failed (%d)", err);
	if (peer != NULL && peer->in_use) {
		peer->dfu_discovery_retry = true;
		schedule_gatt_retry();
	}
}

static const struct bt_gatt_dm_cb dfu_dm_cb = {
	.completed = dfu_service_discovered,
	.service_not_found = dfu_service_not_found,
	.error_found = dfu_discovery_error,
};
#endif

static void discover_protected_service(struct sap_central_peer *peer)
{
	int err;

	peer->protected_discovery_retry = false;
	err = bt_gatt_dm_start(peer->conn, BT_UUID_SAP_DEMO_PROTECTED_SERVICE,
			       &protected_dm_cb, peer);
	if ((err == -EALREADY) || (err == -EBUSY)) {
		peer->protected_discovery_retry = true;
		schedule_gatt_retry();
		return;
	}

	if (err != 0) {
		LOG_ERR("Protected service discovery failed to start (%d)", err);
	}
}

#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
static void discover_dfu_service(struct sap_central_peer *peer)
{
	int err;

	peer->dfu_discovery_retry = false;
	err = bt_gatt_dm_start(peer->conn, BT_UUID_DFU_SMP_SERVICE, &dfu_dm_cb, peer);
	if ((err == -EALREADY) || (err == -EBUSY)) {
		peer->dfu_discovery_retry = true;
		schedule_gatt_retry();
		return;
	}

	if (err != 0) {
		LOG_ERR("DFU SMP discovery failed to start (%d)", err);
	}
}
#endif

static void on_authenticated(struct sap_session *session)
{
	char payload[32];
	int len;
	int err;

	LOG_INF("SAP authenticated with peripheral %u", session->peer_cert.body.device_id);
	SAP_TRACE("FLOW post-auth: central now allows protected-service access for peer %u",
		  session->peer_cert.body.device_id);
	clear_remote_led(session->peer_cert.body.device_id);

	len = snprintk(payload, sizeof(payload), "hello-%u",
		       session->peer_cert.body.device_id);
	err = sap_send_secure(session, SAP_DEMO_MSG_TEXT,
			      (const uint8_t *)payload, (size_t)len);
	if (err != 0) {
		LOG_ERR("Failed to send secure payload (%d)", err);
	}

	discover_protected_service(session->user_data);

	if (active_peer_count() < CONFIG_SAP_MAX_PEERS) {
		start_scan();
	}
}

static void on_auth_failed(struct sap_session *session, int reason)
{
	LOG_ERR("SAP auth failed on central side (%d)", reason);
	clear_remote_led(session->peer_cert.body.device_id);
	if (session->conn != NULL) {
		(void)bt_conn_disconnect(session->conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	}
}

static void on_secure_payload(struct sap_session *session, uint8_t msg_type,
			      const uint8_t *data, size_t len)
{
	if (msg_type == SAP_DEMO_MSG_TEXT_ACK) {
		LOG_INF("Secure ACK from peripheral %u: %.*s",
			session->peer_cert.body.device_id, len, (const char *)data);
		return;
	}

	if (msg_type == SAP_DEMO_MSG_BUTTON_STATE) {
		bool pressed;

		if (len != 1U) {
			LOG_WRN("Ignoring malformed button state from peripheral %u",
				session->peer_cert.body.device_id);
			return;
		}

		pressed = (data[0] != 0U);
		LOG_INF("Peripheral %u button state: %s",
			session->peer_cert.body.device_id,
			pressed ? "pressed" : "released");
		set_remote_led_state(session->peer_cert.body.device_id, pressed);
		return;
	}

	LOG_INF("Secure payload from peripheral %u: %.*s",
		session->peer_cert.body.device_id, len, (const char *)data);
}

static void discover_completed(struct bt_gatt_dm *dm, void *context)
{
	struct sap_central_peer *peer = context;
	int err;

	err = assign_sap_handles(dm, &peer->handles);
	if (err != 0) {
		bt_gatt_dm_data_release(dm);
		LOG_ERR("Failed to assign SAP handles (%d)", err);
		(void)bt_conn_disconnect(peer->conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
		return;
	}

	bt_gatt_dm_data_release(dm);
	peer->discovery_ready = true;

	peer->auth_sub_params.notify = auth_notif_cb;
	peer->auth_sub_params.value = BT_GATT_CCC_NOTIFY;
	peer->auth_sub_params.value_handle = peer->handles.auth;
	peer->auth_sub_params.ccc_handle = peer->handles.auth_ccc;
	atomic_set_bit(peer->auth_sub_params.flags, BT_GATT_SUBSCRIBE_FLAG_VOLATILE);
	err = bt_gatt_subscribe(peer->conn, &peer->auth_sub_params);
	if (err == 0) {
		peer->auth_subscribed = true;
	}

	peer->secure_sub_params.notify = secure_notif_cb;
	peer->secure_sub_params.value = BT_GATT_CCC_NOTIFY;
	peer->secure_sub_params.value_handle = peer->handles.secure_tx;
	peer->secure_sub_params.ccc_handle = peer->handles.secure_tx_ccc;
	atomic_set_bit(peer->secure_sub_params.flags,
		       BT_GATT_SUBSCRIBE_FLAG_VOLATILE);
	err = bt_gatt_subscribe(peer->conn, &peer->secure_sub_params);
	if (err == 0) {
		peer->secure_subscribed = true;
	}

	maybe_start_handshake(peer);
}

static void service_not_found(struct bt_conn *conn, void *context)
{
	struct sap_central_peer *peer = context;

	ARG_UNUSED(conn);
	LOG_ERR("SAP service not found");
	if (peer != NULL && peer->conn != NULL) {
		(void)bt_conn_disconnect(peer->conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	}
}

static void sap_discovery_error(struct bt_conn *conn, int err, void *context)
{
	struct sap_central_peer *peer = context;

	ARG_UNUSED(conn);
	LOG_ERR("SAP service discovery failed (%d)", err);
	if (peer != NULL && peer->conn != NULL) {
		(void)bt_conn_disconnect(peer->conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	}
}

static const struct bt_gatt_dm_cb sap_dm_cb = {
	.completed = discover_completed,
	.service_not_found = service_not_found,
	.error_found = sap_discovery_error,
};

static void mtu_exchange_cb(struct bt_conn *conn, uint8_t err,
			    struct bt_gatt_exchange_params *params)
{
	struct sap_central_peer *peer = peer_from_conn(conn);

	ARG_UNUSED(params);

	if (peer == NULL) {
		return;
	}

	if (err != 0U) {
		LOG_WRN("MTU exchange failed (%u)", err);
	}

	peer->mtu_ready = true;
	start_sap_service_discovery(peer);
}

static void start_att_setup(struct sap_central_peer *peer)
{
	int mtu_err;

	if (peer->mtu_requested) {
		return;
	}

	peer->mtu_requested = true;
	peer->mtu_params.func = mtu_exchange_cb;

	mtu_err = bt_gatt_exchange_mtu(peer->conn, &peer->mtu_params);
	if (mtu_err != 0) {
		peer->mtu_ready = true;
		start_sap_service_discovery(peer);
	}
}

static void start_sap_service_discovery(struct sap_central_peer *peer)
{
	int err;

	if ((peer == NULL) || !peer->in_use || peer->discovery_ready) {
		return;
	}

	peer->sap_discovery_retry = false;
	err = bt_gatt_dm_start(peer->conn, BT_UUID_SAP_SERVICE, &sap_dm_cb, peer);
	if ((err == -EALREADY) || (err == -EBUSY)) {
		peer->sap_discovery_retry = true;
		schedule_gatt_retry();
		return;
	}

	if (err != 0) {
		LOG_ERR("Failed to start SAP service discovery (%d)", err);
		(void)bt_conn_disconnect(peer->conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	}
}

static void gatt_retry_fn(struct k_work *work)
{
	size_t i;

	ARG_UNUSED(work);

	for (i = 0; i < ARRAY_SIZE(peers); i++) {
		struct sap_central_peer *peer = &peers[i];

		if (!peer->in_use) {
			continue;
		}

		if (peer->sap_discovery_retry) {
			start_sap_service_discovery(peer);
		}

		if (peer->protected_discovery_retry) {
			discover_protected_service(peer);
		}

#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
		if (peer->dfu_discovery_retry) {
			discover_dfu_service(peer);
		}
#endif
	}
}

static void scan_restart_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	if (!scan_restart_pending) {
		return;
	}

	if (scanning_active || active_peer_count() >= CONFIG_SAP_MAX_PEERS) {
		scan_restart_pending = false;
		return;
	}

	if (conn_connecting != NULL) {
		(void)k_work_reschedule(&scan_restart_work, K_MSEC(100));
		return;
	}

	start_scan();
	if (scanning_active) {
		scan_restart_pending = false;
	}
}

static void device_found(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
			 struct net_buf_simple *ad)
{
	struct bt_conn_le_create_param create_param = BT_CONN_LE_CREATE_PARAM_INIT(
		BT_CONN_LE_OPT_NONE,
		BT_GAP_SCAN_FAST_INTERVAL,
		BT_GAP_SCAN_FAST_INTERVAL);
	const struct bt_le_conn_param *conn_param = BT_LE_CONN_PARAM_DEFAULT;
	struct bt_conn *existing_conn;
	char addr_str[BT_ADDR_LE_STR_LEN];
	int err;
	bool has_sap_service = false;

	ARG_UNUSED(ad);

	if (conn_connecting != NULL || active_peer_count() >= CONFIG_SAP_MAX_PEERS) {
		return;
	}

	if ((type != BT_GAP_ADV_TYPE_ADV_IND) &&
	    (type != BT_GAP_ADV_TYPE_ADV_DIRECT_IND) &&
	    (type != BT_GAP_ADV_TYPE_EXT_ADV)) {
		return;
	}

	bt_data_parse(ad, ad_has_sap_service_cb, &has_sap_service);
	if (!has_sap_service) {
		return;
	}

	bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
	LOG_INF("Found peripheral candidate %s RSSI %d", addr_str, rssi);

	existing_conn = bt_conn_lookup_addr_le(BT_ID_DEFAULT, addr);
	if (existing_conn != NULL) {
		bt_conn_unref(existing_conn);
		SAP_TRACE("FLOW reset-recovery: central ignored advertisement from %s because a connection object already exists",
			  addr_str);
		return;
	}

	err = bt_le_scan_stop();
	if (err != 0) {
		LOG_ERR("Failed to stop scanning (%d)", err);
		return;
	}
	scanning_active = false;

	err = bt_conn_le_create(addr, &create_param, conn_param, &conn_connecting);
	if (err != 0) {
		LOG_ERR("Create connection failed (%d)", err);
		schedule_scan_restart(K_MSEC(SAP_SCAN_RESTART_DELAY_MS));
	}
}

static void start_scan(void)
{
	struct bt_le_scan_param scan_param = {
		.type = BT_LE_SCAN_TYPE_PASSIVE,
		.options = BT_LE_SCAN_OPT_NONE,
		.interval = BT_GAP_SCAN_FAST_INTERVAL,
		.window = BT_GAP_SCAN_FAST_WINDOW,
	};
	int err;

	if (scanning_active || conn_connecting != NULL ||
	    active_peer_count() >= CONFIG_SAP_MAX_PEERS) {
		return;
	}

	err = bt_le_scan_start(&scan_param, device_found);
	if (err == -EALREADY) {
		scanning_active = true;
		return;
	}

	if (err != 0) {
		LOG_ERR("Scan start failed (%d)", err);
		return;
	}

	scanning_active = true;
	LOG_INF("Central scan started");
	SAP_TRACE("FLOW BLE: central scanning for SAP peripherals");
}

static void connected(struct bt_conn *conn, uint8_t err)
{
	struct sap_central_peer *peer = NULL;
	size_t i;
	int sec_err;

	if (conn == conn_connecting) {
		bt_conn_unref(conn_connecting);
		conn_connecting = NULL;
	}

	if (err != 0U) {
		LOG_ERR("Connection failed (0x%02x)", err);
		schedule_scan_restart(K_MSEC(SAP_SCAN_RESTART_DELAY_MS));
		return;
	}

	SAP_TRACE("FLOW 1/8 central BLE link established");

	for (i = 0; i < ARRAY_SIZE(peers); i++) {
		if (!peers[i].in_use) {
			peer = &peers[i];
			memset(peer, 0, sizeof(*peer));
			peer->in_use = true;
			peer->conn = bt_conn_ref(conn);
#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
			(void)bt_dfu_smp_init(&peer->dfu_smp, &dfu_smp_init_params);
#endif
			break;
		}
	}

	if (peer == NULL) {
		LOG_ERR("No peer slots left");
		(void)bt_conn_disconnect(conn, BT_HCI_ERR_CONN_LIMIT_EXCEEDED);
		return;
	}

	peer->session = sap_on_connected(&sap_ctx, conn);
	if (peer->session == NULL) {
		LOG_ERR("Failed to allocate SAP session");
		bt_conn_unref(peer->conn);
		memset(peer, 0, sizeof(*peer));
		(void)bt_conn_disconnect(conn, BT_HCI_ERR_CONN_LIMIT_EXCEEDED);
		return;
	}

	peer->session->user_data = peer;

	if (sap_ctx.policy.require_ble_encryption) {
		sec_err = bt_conn_set_security(conn, BT_SECURITY_L2);
		if (sec_err != 0) {
			LOG_ERR("Failed to request security (%d)", sec_err);
			(void)bt_conn_disconnect(conn, BT_HCI_ERR_AUTH_FAIL);
			return;
		}
	} else {
		peer->session->security_ready = true;
		start_att_setup(peer);
	}
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	struct sap_central_peer *peer = peer_from_conn(conn);
	uint8_t peer_id = 0U;

	LOG_INF("Central disconnected, reason 0x%02x %s",
		reason, bt_hci_err_to_str(reason));

	if (peer != NULL) {
		if (peer->session != NULL) {
			peer_id = peer->session->peer_cert.body.device_id;
		}

#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
		peer->dfu_echo_pending = false;
#endif
		sap_on_disconnected(&sap_ctx, conn);
		bt_conn_unref(peer->conn);
		memset(peer, 0, sizeof(*peer));
	}

	clear_remote_led(peer_id);
	schedule_scan_restart(K_MSEC(SAP_SCAN_RESTART_DELAY_MS));
}

static void security_changed(struct bt_conn *conn, bt_security_t level,
			     enum bt_security_err err)
{
	struct sap_central_peer *peer = peer_from_conn(conn);

	if (peer == NULL) {
		return;
	}

	sap_on_security_changed(peer->session, level, err);
	if (err != 0) {
		clear_bond_on_security_failure(conn, err);
		LOG_ERR("Security failed: %d %s", err, bt_security_err_to_str(err));
		(void)bt_conn_disconnect(conn, BT_HCI_ERR_AUTH_FAIL);
		schedule_scan_restart(K_MSEC(SAP_SECURITY_FAILURE_RETRY_MS));
		return;
	}

	SAP_TRACE("FLOW 2/8 central BLE security satisfied");

	if (!peer->mtu_requested) {
		start_att_setup(peer);
		return;
	}

	maybe_start_handshake(peer);
}

static void recycled(void)
{
	if (scan_restart_pending) {
		SAP_TRACE("FLOW reset-recovery: central connection object recycled, scan can restart");
		(void)k_work_reschedule(&scan_restart_work, K_NO_WAIT);
	}
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected = connected,
	.disconnected = disconnected,
	.security_changed = security_changed,
	.recycled = recycled,
};

#if defined(CONFIG_SAP_SHELL)
static int join_shell_args(size_t argc, char **argv, size_t start_idx,
			   char *buffer, size_t buffer_len)
{
	size_t i;
	size_t used = 0U;

	if ((start_idx >= argc) || (buffer_len == 0U)) {
		return -EINVAL;
	}

	for (i = start_idx; i < argc; i++) {
		size_t arg_len = strlen(argv[i]);

		if ((used != 0U) && (used + 1U >= buffer_len)) {
			return -ENOSPC;
		}

		if (used != 0U) {
			buffer[used++] = ' ';
		}

		if (used + arg_len >= buffer_len) {
			return -ENOSPC;
		}

		memcpy(&buffer[used], argv[i], arg_len);
		used += arg_len;
	}

	buffer[used] = '\0';
	return (int)used;
}

static int send_text_to_peer(struct sap_central_peer *peer, const char *text)
{
	if ((peer == NULL) || (peer->session == NULL)) {
		return -ENOTCONN;
	}

	if (!sap_is_authenticated(peer->session)) {
		return -EACCES;
	}

	return sap_send_secure(peer->session, SAP_DEMO_MSG_TEXT,
			       (const uint8_t *)text, strlen(text));
}

static int cmd_sap_peers(const struct shell *sh, size_t argc, char **argv)
{
	size_t i;
	bool any = false;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	for (i = 0; i < ARRAY_SIZE(peers); i++) {
		struct sap_central_peer *peer = &peers[i];
		uint8_t peer_id;

		if (!peer->in_use || (peer->session == NULL)) {
			continue;
		}

		peer_id = peer->session->peer_cert.body.device_id;
		shell_print(sh,
			    "peer_id=%u state=%s security_ready=%u authenticated=%u protected=%u dfu=%u led=%s",
			    peer_id, session_state_str(peer->session->state),
			    peer->session->security_ready ? 1U : 0U,
			    sap_is_authenticated(peer->session) ? 1U : 0U,
			    peer->protected_service_ready ? 1U : 0U,
#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
			    peer->dfu_service_ready ? 1U : 0U,
#else
			    0U,
#endif
			    led_name_for_peer_id(peer_id));
		any = true;
	}

	if (!any) {
		shell_print(sh, "No SAP peers");
	}

	return 0;
}

static int cmd_sap_send(const struct shell *sh, size_t argc, char **argv)
{
	char payload[160];
	int len;

	len = join_shell_args(argc, argv, 2U, payload, sizeof(payload));
	if (len < 0) {
		shell_error(sh, "Text is too long for one SAP payload");
		return len;
	}

	if (strcmp(argv[1], "all") == 0) {
		size_t i;
		size_t sent = 0U;

		for (i = 0; i < ARRAY_SIZE(peers); i++) {
			int err;

			if (!peers[i].in_use || (peers[i].session == NULL) ||
			    !sap_is_authenticated(peers[i].session)) {
				continue;
			}

			err = send_text_to_peer(&peers[i], payload);
			if (err != 0) {
				shell_error(sh, "Failed to send to peer %u (%d)",
					    peers[i].session->peer_cert.body.device_id, err);
				continue;
			}

			sent++;
		}

		if (sent == 0U) {
			shell_error(sh, "No authenticated peers");
			return -ENOTCONN;
		}

		shell_print(sh, "Sent secure text to %u peer(s): %s", sent, payload);
		return 0;
	}

	{
		char *endptr = NULL;
		unsigned long peer_id_ul = strtoul(argv[1], &endptr, 10);
		struct sap_central_peer *peer;
		int err;

		if ((argv[1][0] == '\0') || (endptr == NULL) || (*endptr != '\0') ||
		    (peer_id_ul > UINT8_MAX)) {
			shell_error(sh, "Peer id must be a decimal number or 'all'");
			return -EINVAL;
		}

		peer = peer_from_device_id((uint8_t)peer_id_ul);
		if (peer == NULL) {
			shell_error(sh, "Peer %lu is not authenticated", peer_id_ul);
			return -ENOTCONN;
		}

		err = send_text_to_peer(peer, payload);
		if (err != 0) {
			shell_error(sh, "Failed to send to peer %lu (%d)", peer_id_ul, err);
			return err;
		}

		shell_print(sh, "Sent secure text to peer %lu: %s", peer_id_ul, payload);
	}

	return 0;
}

#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
static int cmd_sap_dfu_echo(const struct shell *sh, size_t argc, char **argv)
{
	char payload[96];
	char *endptr = NULL;
	unsigned long peer_id_ul;
	struct sap_central_peer *peer;
	int len;
	int err;

	len = join_shell_args(argc, argv, 2U, payload, sizeof(payload));
	if (len < 0) {
		shell_error(sh, "Text is too long for one DFU echo payload");
		return len;
	}

	peer_id_ul = strtoul(argv[1], &endptr, 10);
	if ((argv[1][0] == '\0') || (endptr == NULL) || (*endptr != '\0') ||
	    (peer_id_ul > UINT8_MAX)) {
		shell_error(sh, "Peer id must be a decimal number");
		return -EINVAL;
	}

	peer = peer_from_device_id((uint8_t)peer_id_ul);
	if (peer == NULL) {
		shell_error(sh, "Peer %lu is not authenticated", peer_id_ul);
		return -ENOTCONN;
	}

	err = send_dfu_echo(peer, payload);
	if (err != 0) {
		shell_error(sh, "Failed to send DFU echo to peer %lu (%d)", peer_id_ul, err);
		return err;
	}

	shell_print(sh, "Sent DFU SMP echo to peer %lu: %s", peer_id_ul, payload);
	return 0;
}
#endif

SHELL_STATIC_SUBCMD_SET_CREATE(sap_cmds,
	SHELL_CMD(peers, NULL, "List SAP peer state and LED mapping", cmd_sap_peers),
	SHELL_CMD_ARG(send, NULL, "send <peer_id|all> <text...>", cmd_sap_send, 3, 13),
#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
	SHELL_CMD_ARG(dfu_echo, NULL, "dfu_echo <peer_id> <text...>", cmd_sap_dfu_echo, 3, 13),
#endif
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(sap, &sap_cmds, "SAP demo commands", NULL);
#endif

int sap_central_run(const struct sap_policy *policy)
{
	struct sap_callbacks callbacks = {
		.send_auth = send_auth,
		.send_secure = send_secure,
		.authenticated = on_authenticated,
		.authentication_failed = on_auth_failed,
		.secure_payload_received = on_secure_payload,
	};
	int err;

	err = sap_init(&sap_ctx, SAP_ROLE_CENTRAL, policy, &callbacks);
	if (err != 0) {
		LOG_ERR("Failed to initialize SAP core (%d)", err);
		return 0;
	}

#if defined(CONFIG_SAP_DK_IO)
	err = dk_leds_init();
	if (err != 0) {
		LOG_WRN("Failed to initialize DK LEDs (%d)", err);
	} else {
		(void)dk_set_leds(DK_NO_LEDS_MSK);
	}
#endif

	start_scan();

	return 0;
}
