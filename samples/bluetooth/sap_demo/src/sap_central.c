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
#include <zephyr/sys/byteorder.h>
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
#include <mgmt/mcumgr/util/zcbor_bulk.h>
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
#define SAP_ROOT_ADV_RESTART_DELAY_MS 250
#define SAP_ROOT_UPSTREAM_MAX_CONN 1U
#define SAP_ROOT_STATUS_MAX_LEN \
	(sizeof(struct sap_demo_root_status_response) + \
	 (CONFIG_SAP_MAX_PEERS * sizeof(struct sap_demo_root_status_record)))

#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
#define SAP_MGMT_ERR_EOK 0
#define SAP_MGMT_GROUP_ID_IMAGE 1U
#define SAP_IMG_MGMT_ID_STATE 0U
#define SAP_IMG_MGMT_ID_UPLOAD 1U
#define SAP_IMG_MGMT_DATA_SHA_LEN 32U
#define SAP_DFU_CBOR_ENCODER_STATE_NUM 2
#define SAP_DFU_CBOR_DECODER_STATE_NUM 8
#define SAP_DFU_CBOR_MAP_MAX_ELEMENT_CNT 2
#define SAP_DFU_CBOR_BUFFER_SIZE 1024
#define SAP_DFU_KEY_LEN_MAX 2
#define SAP_DFU_VALUE_LEN_MAX 96
#define SAP_DFU_ECHO_TEXT_MAX 48
#define SAP_DFU_BOOT_HASH_MAX_LEN 64U
#define SAP_DFU_RETRY_DELAY_MS 200
#define SAP_DFU_RETRY_MAX 40U
#define SAP_DFU_DISCOVERY_RETRY_MAX 5U
#endif

enum sap_dfu_request_type {
	SAP_DFU_REQ_NONE = 0,
	SAP_DFU_REQ_ECHO,
	SAP_DFU_REQ_UPLOAD,
	SAP_DFU_REQ_STATE_READ,
	SAP_DFU_REQ_STATE_WRITE,
};

enum sap_root_dfu_retry_action {
	SAP_ROOT_DFU_RETRY_NONE = 0,
	SAP_ROOT_DFU_RETRY_STATE_READ,
	SAP_ROOT_DFU_RETRY_STATE_WRITE,
	SAP_ROOT_DFU_RETRY_ACTIVATE,
};

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
	struct bt_gatt_write_params auth_write_params;
	struct bt_gatt_write_params secure_write_params;
	struct bt_gatt_read_params protected_read_params;
	struct bt_gatt_exchange_params mtu_params;
	struct k_work auth_write_work;
	struct k_work secure_write_work;
	uint8_t auth_tx_buf[sizeof(struct sap_msg_central_auth_oob)];
	uint8_t secure_tx_buf[244];
	uint8_t auth_tx_msg_type;
	uint8_t secure_tx_msg_type;
	uint16_t auth_tx_len;
	uint16_t secure_tx_len;
	bool in_use;
	bool mtu_requested;
	bool mtu_ready;
	bool discovery_ready;
	bool auth_subscribed;
	bool secure_subscribed;
	bool auth_write_queued;
	bool auth_write_pending;
	bool secure_write_queued;
	bool secure_write_pending;
	bool handshake_started;
	bool sap_discovery_retry;
	bool protected_discovery_retry;
	bool protected_service_ready;
	uint8_t observed_pattern_id;
#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
	struct bt_dfu_smp dfu_smp;
	struct sap_dfu_buffer dfu_cmd;
	struct sap_dfu_buffer dfu_rsp;
	enum sap_dfu_request_type dfu_request;
	bool dfu_service_ready;
	bool dfu_discovery_retry;
	bool dfu_echo_pending;
	bool dfu_echo_complete;
	uint8_t dfu_discovery_attempts;
#endif
};

struct sap_indication_ctx {
	struct bt_gatt_indicate_params params;
	struct k_work work;
	struct sap_session *session;
	const struct bt_gatt_attr *attr;
	uint8_t msg_type;
	uint16_t len;
	bool queued;
	bool pending;
	bool use_notify;
	uint8_t buffer[244];
};

struct sap_root_link {
	struct sap_context sap_ctx;
	struct sap_policy policy;
	struct sap_session *session;
	struct bt_conn *conn;
	struct sap_indication_ctx auth_indication;
	struct sap_indication_ctx secure_indication;
	bool connection_active;
	bool advertising_restart_pending;
};

struct sap_root_dfu_transfer {
	bool active;
	bool awaiting_reboot;
	bool permanent;
	uint8_t target_peer_id;
	uint8_t image_num;
	size_t image_size;
	size_t accepted_offset;
	size_t boot_hash_len;
	uint8_t retry_count;
	enum sap_root_dfu_retry_action retry_action;
	uint8_t upload_sha[SAP_IMG_MGMT_DATA_SHA_LEN];
	uint8_t boot_hash[SAP_DFU_BOOT_HASH_MAX_LEN];
};

static struct sap_context sap_ctx;
static struct sap_central_peer peers[CONFIG_SAP_MAX_PEERS];
static struct sap_root_link root_link;
static struct sap_root_dfu_transfer root_dfu;
static struct bt_conn *conn_connecting;
static bool scanning_active;
static bool scan_restart_pending;
static bool root_scan_resume_pending;
static const uint8_t sap_ad_flags[] = {
	BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR,
};
static const uint8_t sap_service_uuid[] = {
	BT_UUID_SAP_SERVICE_VAL,
};
static const struct bt_data sap_ad[] = {
	BT_DATA(BT_DATA_FLAGS, sap_ad_flags, sizeof(sap_ad_flags)),
	BT_DATA(BT_DATA_UUID128_ALL, sap_service_uuid, sizeof(sap_service_uuid)),
};

#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
static bool dfu_transport_ready(const struct sap_central_peer *peer)
{
	return (peer != NULL) && peer->dfu_service_ready && peer->dfu_echo_complete;
}
#else
static bool dfu_transport_ready(const struct sap_central_peer *peer)
{
	ARG_UNUSED(peer);

	return false;
}
#endif

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
	case SAP_STATE_WAIT_CONFIRM_TX:
		return "wait_confirm_tx";
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

static ssize_t root_sap_auth_write(struct bt_conn *conn,
				   const struct bt_gatt_attr *attr,
				   const void *buf, uint16_t len,
				   uint16_t offset, uint8_t flags);
static ssize_t root_sap_secure_rx_write(struct bt_conn *conn,
					const struct bt_gatt_attr *attr,
					const void *buf, uint16_t len,
					uint16_t offset, uint8_t flags);

BT_GATT_SERVICE_DEFINE(root_sap_svc,
	BT_GATT_PRIMARY_SERVICE(BT_UUID_SAP_SERVICE),
	BT_GATT_CHARACTERISTIC(BT_UUID_SAP_AUTH,
			       BT_GATT_CHRC_WRITE | BT_GATT_CHRC_WRITE_WITHOUT_RESP |
				       BT_GATT_CHRC_INDICATE,
			       BT_GATT_PERM_WRITE, NULL, root_sap_auth_write, NULL),
	BT_GATT_CCC(NULL, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
	BT_GATT_CHARACTERISTIC(BT_UUID_SAP_SECURE_TX,
			       BT_GATT_CHRC_INDICATE,
			       BT_GATT_PERM_NONE, NULL, NULL, NULL),
	BT_GATT_CCC(NULL, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
	BT_GATT_CHARACTERISTIC(BT_UUID_SAP_SECURE_RX,
			       BT_GATT_CHRC_WRITE | BT_GATT_CHRC_WRITE_WITHOUT_RESP,
			       BT_GATT_PERM_WRITE, NULL, root_sap_secure_rx_write, NULL));

#define SAP_ROOT_AUTH_ATTR_INDEX 2
#define SAP_ROOT_SECURE_TX_ATTR_INDEX 5

static void start_sap_service_discovery(struct sap_central_peer *peer);
static void discover_protected_service(struct sap_central_peer *peer);
static void auth_write_work_fn(struct k_work *work);
static void secure_write_work_fn(struct k_work *work);
static void root_indicate_work_fn(struct k_work *work);
static void root_advertising_start(void);
static int root_send_status_response(void);
#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
static void discover_dfu_service(struct sap_central_peer *peer);
static int send_dfu_echo(struct sap_central_peer *peer, const char *text);
static void dfu_echo_work_fn(struct k_work *work);
static void root_dfu_reset_state(void);
static bool dfu_is_retryable(int err);
static void schedule_root_dfu_retry(enum sap_root_dfu_retry_action action);
static void root_dfu_retry_fn(struct k_work *work);
static void dfu_echo_rsp_proc(struct bt_dfu_smp *dfu_smp);
static int send_dfu_upload_chunk(struct sap_central_peer *peer,
				 const uint8_t *data, size_t len);
static int send_dfu_state_read(struct sap_central_peer *peer);
static int send_dfu_state_write(struct sap_central_peer *peer);
static int send_dfu_activate(struct sap_central_peer *peer);
static int parse_state_read_response(struct sap_central_peer *peer, uint8_t *hash,
				     size_t *hash_len, int32_t *status,
				     bool *selected_pending, bool *selected_permanent);
static int parse_state_response(struct sap_central_peer *peer, int32_t *status);
#endif
static void gatt_retry_fn(struct k_work *work);
static void scan_restart_fn(struct k_work *work);
static void root_advertising_retry_fn(struct k_work *work);
K_WORK_DELAYABLE_DEFINE(gatt_retry_work, gatt_retry_fn);
K_WORK_DELAYABLE_DEFINE(scan_restart_work, scan_restart_fn);
K_WORK_DELAYABLE_DEFINE(root_advertising_retry_work, root_advertising_retry_fn);
#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
K_WORK_DELAYABLE_DEFINE(dfu_echo_work, dfu_echo_work_fn);
K_WORK_DELAYABLE_DEFINE(root_dfu_retry_work, root_dfu_retry_fn);
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

static bool scan_addr_is_local(const bt_addr_le_t *addr)
{
	struct bt_le_oob oob;
	int err;

	err = bt_le_oob_get_local(BT_ID_DEFAULT, &oob);
	if (err != 0) {
		return false;
	}

	return bt_addr_le_cmp(addr, &oob.addr) == 0;
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

static uint8_t selected_leaf_id(void)
{
	return root_dfu.target_peer_id;
}

static int led_index_for_peer_id_u8(uint8_t peer_id)
{
	int idx = led_index_for_peer_id(peer_id);

	return (idx < 0) ? 0 : (idx + 1);
}

#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
static bool dfu_upload_chunk_fits_in_mtu(uint16_t mtu, size_t chunk_len, bool first_chunk)
{
	static const uint8_t zero_chunk[SAP_DFU_CBOR_BUFFER_SIZE];
	struct sap_dfu_buffer smp_cmd;
	zcbor_state_t zse[SAP_DFU_CBOR_ENCODER_STATE_NUM];
	size_t payload_len;
	uint32_t map_count;
	bool ok;

	memset(&smp_cmd, 0, sizeof(smp_cmd));

	zcbor_new_encode_state(zse, ARRAY_SIZE(zse), smp_cmd.payload,
			       sizeof(smp_cmd.payload), 0);
	map_count = first_chunk ? 10U : 6U;

	ok = zcbor_map_start_encode(zse, map_count) &&
	     zcbor_tstr_put_lit(zse, "image") &&
	     zcbor_uint32_put(zse, 0U) &&
	     zcbor_tstr_put_lit(zse, "data") &&
	     zcbor_bstr_encode_ptr(zse, zero_chunk, chunk_len) &&
	     zcbor_tstr_put_lit(zse, "off") &&
	     zcbor_size_put(zse, first_chunk ? 0U : UINT32_MAX);
	if (ok && first_chunk) {
		ok = zcbor_tstr_put_lit(zse, "len") &&
		     zcbor_size_put(zse, UINT32_MAX) &&
		     zcbor_tstr_put_lit(zse, "sha") &&
		     zcbor_bstr_encode_ptr(zse, zero_chunk,
					   SAP_IMG_MGMT_DATA_SHA_LEN);
	}
	if (ok) {
		ok = zcbor_map_end_encode(zse, map_count);
	}
	if (!ok) {
		return false;
	}

	payload_len = (size_t)(zse->payload - smp_cmd.payload);
	return (sizeof(smp_cmd.header) + payload_len) <= mtu;
}

static uint16_t dfu_chunk_limit_for_peer(const struct sap_central_peer *peer)
{
	size_t low;
	size_t high;
	size_t mid;
	size_t best_first = 0U;
	size_t best_later = 0U;
	uint16_t att_payload_budget;

	if ((peer == NULL) || !peer->dfu_service_ready || (peer->dfu_smp.conn == NULL)) {
		return 0U;
	}

	att_payload_budget = bt_gatt_get_mtu(peer->dfu_smp.conn);
	if (att_payload_budget <= 3U) {
		return 0U;
	}
	att_payload_budget -= 3U;
	high = MIN(sizeof(((struct sap_dfu_buffer *)0)->payload),
		   (size_t)att_payload_budget);

	low = 0U;
	while (low <= high) {
		mid = low + ((high - low) / 2U);
		if (dfu_upload_chunk_fits_in_mtu(att_payload_budget, mid, true)) {
			best_first = mid;
			low = mid + 1U;
		} else if (mid == 0U) {
			break;
		} else {
			high = mid - 1U;
		}
	}

	low = 0U;
	high = MIN(sizeof(((struct sap_dfu_buffer *)0)->payload),
		   (size_t)att_payload_budget);
	while (low <= high) {
		mid = low + ((high - low) / 2U);
		if (dfu_upload_chunk_fits_in_mtu(att_payload_budget, mid, false)) {
			best_later = mid;
			low = mid + 1U;
		} else if (mid == 0U) {
			break;
		} else {
			high = mid - 1U;
		}
	}

	return (uint16_t)MIN(best_first, best_later);
}
#else
static uint16_t dfu_chunk_limit_for_peer(const struct sap_central_peer *peer)
{
	ARG_UNUSED(peer);

	return 0U;
}
#endif

static int root_send_status_response(void)
{
	struct sap_demo_root_status_response *rsp;
	struct sap_session *session = root_link.session;
	uint8_t payload[SAP_ROOT_STATUS_MAX_LEN];
	size_t i;
	size_t count = 0U;

	if ((session == NULL) || !sap_is_authenticated(session)) {
		return -ENOTCONN;
	}

	rsp = (struct sap_demo_root_status_response *)payload;
	rsp->selected_peer_id = selected_leaf_id();

	for (i = 0; i < ARRAY_SIZE(peers); i++) {
		struct sap_central_peer *peer = &peers[i];
		struct sap_demo_root_status_record *record;
		uint8_t flags = 0U;
		uint8_t peer_id = 0U;

		if (!peer->in_use || (peer->session == NULL)) {
			continue;
		}

		peer_id = peer->session->peer_cert.body.device_id;
		record = &rsp->records[count];
		record->peer_id = peer_id;
		record->state = (uint8_t)peer->session->state;
		if (sap_is_authenticated(peer->session)) {
			flags |= SAP_DEMO_ROOT_PEER_AUTHENTICATED;
		}
		if (peer->protected_service_ready) {
			flags |= SAP_DEMO_ROOT_PEER_PROTECTED_READY;
		}
	#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
		if (dfu_transport_ready(peer)) {
			flags |= SAP_DEMO_ROOT_PEER_DFU_READY;
		}
	#endif
		if (peer_id == selected_leaf_id()) {
			flags |= SAP_DEMO_ROOT_PEER_SELECTED;
		}
		if (led_index_for_peer_id(peer_id) >= 0) {
			flags |= SAP_DEMO_ROOT_PEER_LED_ASSIGNED;
		}
		record->flags = flags;
		record->led_index = (uint8_t)led_index_for_peer_id_u8(peer_id);
		record->pattern_id = peer->observed_pattern_id;
		record->dfu_chunk_limit_le =
			sys_cpu_to_le16(dfu_chunk_limit_for_peer(peer));
		count++;
	}

	rsp->peer_count = (uint8_t)count;

	return sap_send_secure(session, SAP_DEMO_MSG_ROOT_STATUS_RSP,
			       payload,
			       sizeof(*rsp) + (count * sizeof(struct sap_demo_root_status_record)));
}

static int root_send_select_response(uint8_t status)
{
	struct sap_demo_root_select_response rsp = {
		.status = status,
		.selected_peer_id = selected_leaf_id(),
	};

	if ((root_link.session == NULL) || !sap_is_authenticated(root_link.session)) {
		return -ENOTCONN;
	}

	return sap_send_secure(root_link.session, SAP_DEMO_MSG_ROOT_SELECT_RSP,
			       (const uint8_t *)&rsp, sizeof(rsp));
}

static int root_send_dfu_progress(uint8_t status, uint8_t peer_id,
				  size_t accepted_offset, size_t image_size)
{
	struct sap_demo_root_dfu_progress rsp = {
		.status = status,
		.peer_id = peer_id,
		.accepted_offset_le = sys_cpu_to_le32((uint32_t)accepted_offset),
		.image_size_le = sys_cpu_to_le32((uint32_t)image_size),
	};

	if ((root_link.session == NULL) || !sap_is_authenticated(root_link.session)) {
		return -ENOTCONN;
	}

	return sap_send_secure(root_link.session, SAP_DEMO_MSG_ROOT_DFU_PROGRESS,
			       (const uint8_t *)&rsp, sizeof(rsp));
}

static int root_send_dfu_result(uint8_t status, uint8_t peer_id, uint32_t detail)
{
	struct sap_demo_root_dfu_result rsp = {
		.status = status,
		.peer_id = peer_id,
		.selected_peer_id = selected_leaf_id(),
		.detail_le = sys_cpu_to_le32(detail),
	};

	if ((root_link.session == NULL) || !sap_is_authenticated(root_link.session)) {
		return -ENOTCONN;
	}

	return sap_send_secure(root_link.session, SAP_DEMO_MSG_ROOT_DFU_RESULT,
			       (const uint8_t *)&rsp, sizeof(rsp));
}

static bool conn_role_is(struct bt_conn *conn, uint8_t expected_role)
{
	struct bt_conn_info info;
	int err;

	err = bt_conn_get_info(conn, &info);
	if (err != 0) {
		return false;
	}

	return info.role == expected_role;
}

static void root_indicate_cb(struct bt_conn *conn,
			     struct bt_gatt_indicate_params *params,
			     uint8_t err)
{
	struct sap_indication_ctx *ctx =
		CONTAINER_OF(params, struct sap_indication_ctx, params);

	ARG_UNUSED(conn);

	if ((ctx->session != NULL) && ctx->session->in_use) {
		sap_on_tx_complete(ctx->session, ctx->msg_type, err);
	}
}

static void root_indicate_destroy(struct bt_gatt_indicate_params *params)
{
	struct sap_indication_ctx *ctx =
		CONTAINER_OF(params, struct sap_indication_ctx, params);

	ctx->pending = false;
}

static void root_indicate_work_fn(struct k_work *work)
{
	struct sap_indication_ctx *ctx =
		CONTAINER_OF(work, struct sap_indication_ctx, work);
	int err;

	if ((ctx->session == NULL) || !ctx->session->in_use ||
	    (ctx->session->conn == NULL) || !ctx->queued || ctx->pending) {
		return;
	}

	ctx->params.attr = ctx->attr;
	ctx->params.func = root_indicate_cb;
	ctx->params.destroy = root_indicate_destroy;
	ctx->params.data = ctx->buffer;
	ctx->params.len = ctx->len;
	ctx->queued = false;
	ctx->pending = true;

	err = bt_gatt_indicate(ctx->session->conn, &ctx->params);
	if (err != 0) {
		ctx->pending = false;
		if ((ctx->session != NULL) && ctx->session->in_use) {
			sap_on_tx_complete(ctx->session, ctx->msg_type, err);
		}
	}
}

static int root_send_indication(struct sap_session *session,
				struct sap_indication_ctx *ctx,
				const struct bt_gatt_attr *attr,
				uint8_t msg_type,
				const uint8_t *data, size_t len)
{
	if (len > sizeof(ctx->buffer)) {
		return -EMSGSIZE;
	}

	if (ctx->pending || ctx->queued) {
		return -EBUSY;
	}

	memcpy(ctx->buffer, data, len);
	ctx->session = session;
	ctx->attr = attr;
	ctx->msg_type = msg_type;
	ctx->len = len;
	ctx->queued = true;
	(void)k_work_submit(&ctx->work);

	return 0;
}

static int root_send_auth(struct sap_session *session, uint8_t msg_type,
			  const uint8_t *data, size_t len)
{
	return root_send_indication(session, &root_link.auth_indication,
				    &root_sap_svc.attrs[SAP_ROOT_AUTH_ATTR_INDEX],
				    msg_type, data, len);
}

static int root_send_secure(struct sap_session *session, uint8_t msg_type,
			    const uint8_t *data, size_t len)
{
	return root_send_indication(session, &root_link.secure_indication,
				    &root_sap_svc.attrs[SAP_ROOT_SECURE_TX_ATTR_INDEX],
				    msg_type, data, len);
}

static void start_scan(void);
static void start_att_setup(struct sap_central_peer *peer);

static void maybe_resume_scan_after_root_adv(void)
{
	if (!root_scan_resume_pending) {
		return;
	}

	root_scan_resume_pending = false;
	start_scan();
}

static void schedule_scan_restart(k_timeout_t delay)
{
	scan_restart_pending = true;
	(void)k_work_reschedule(&scan_restart_work, delay);
}

static void schedule_root_advertising_restart(k_timeout_t delay)
{
	root_link.advertising_restart_pending = true;
	(void)k_work_reschedule(&root_advertising_retry_work, delay);
}

static void root_advertising_start(void)
{
	const char *name = bt_get_name();
	const struct bt_data root_sd[] = {
		BT_DATA(BT_DATA_NAME_COMPLETE, name, strlen(name)),
	};
	int err;

	(void)k_work_cancel_delayable(&root_advertising_retry_work);
	if (root_link.connection_active) {
		root_link.advertising_restart_pending = true;
		return;
	}

	if (conn_connecting != NULL) {
		schedule_root_advertising_restart(K_MSEC(SAP_ROOT_ADV_RESTART_DELAY_MS));
		return;
	}

	if (scanning_active) {
		err = bt_le_scan_stop();
		if ((err != 0) && (err != -EALREADY)) {
			LOG_ERR("Failed to pause scan for root advertising (%d)", err);
			schedule_root_advertising_restart(K_MSEC(SAP_ROOT_ADV_RESTART_DELAY_MS));
			return;
		}

		scanning_active = false;
		root_scan_resume_pending = true;
	}

	err = bt_le_adv_start(BT_LE_ADV_CONN_FAST_1, sap_ad, ARRAY_SIZE(sap_ad),
			      root_sd, ARRAY_SIZE(root_sd));
	if (err == -EALREADY) {
		root_link.advertising_restart_pending = false;
		maybe_resume_scan_after_root_adv();
		return;
	}

	if (err != 0) {
		LOG_ERR("Root advertising failed to start (%d)", err);
		schedule_root_advertising_restart(K_MSEC(SAP_ROOT_ADV_RESTART_DELAY_MS));
		return;
	}

	root_link.advertising_restart_pending = false;
	LOG_INF("Root node advertising for upstream SAP controller");
	SAP_TRACE("FLOW BLE: root advertising SAP upstream access");
	maybe_resume_scan_after_root_adv();
}

static void root_advertising_retry_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	root_advertising_start();
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

static void auth_write_cb(struct bt_conn *conn, uint8_t err,
			  struct bt_gatt_write_params *params)
{
	struct sap_central_peer *peer = CONTAINER_OF(params, struct sap_central_peer,
						     auth_write_params);

	ARG_UNUSED(conn);

	peer->auth_write_pending = false;
	if (err != 0) {
		LOG_ERR("Auth write callback failed err=0x%02x len=%u mtu=%u handle=0x%04x",
			err, peer->auth_tx_len,
			peer->conn != NULL ? bt_gatt_get_mtu(peer->conn) : 0U,
			peer->handles.auth);
	}
	if ((peer->session != NULL) && peer->session->in_use) {
		sap_on_tx_complete(peer->session, peer->auth_tx_msg_type, err);
	}
}

static void secure_write_cb(struct bt_conn *conn, uint8_t err,
			    struct bt_gatt_write_params *params)
{
	struct sap_central_peer *peer = CONTAINER_OF(params, struct sap_central_peer,
						     secure_write_params);

	ARG_UNUSED(conn);

	peer->secure_write_pending = false;
	if ((peer->session != NULL) && peer->session->in_use) {
		sap_on_tx_complete(peer->session, peer->secure_tx_msg_type, err);
	}
}

static void auth_write_work_fn(struct k_work *work)
{
	struct sap_central_peer *peer = CONTAINER_OF(work, struct sap_central_peer,
						     auth_write_work);
	int err;

	if (!peer->in_use || (peer->conn == NULL) || !peer->auth_write_queued ||
	    peer->auth_write_pending) {
		return;
	}

	peer->auth_write_params.func = auth_write_cb;
	peer->auth_write_params.handle = peer->handles.auth;
	peer->auth_write_params.offset = 0U;
	peer->auth_write_params.data = peer->auth_tx_buf;
	peer->auth_write_params.length = peer->auth_tx_len;
	peer->auth_write_queued = false;
	peer->auth_write_pending = true;

	err = bt_gatt_write(peer->conn, &peer->auth_write_params);
	if (err != 0) {
		LOG_ERR("Auth write start failed err=%d len=%u mtu=%u handle=0x%04x",
			err, peer->auth_tx_len, bt_gatt_get_mtu(peer->conn),
			peer->handles.auth);
		peer->auth_write_pending = false;
		if ((peer->session != NULL) && peer->session->in_use) {
			sap_on_tx_complete(peer->session, peer->auth_tx_msg_type, err);
		}
	}
}

static void secure_write_work_fn(struct k_work *work)
{
	struct sap_central_peer *peer = CONTAINER_OF(work, struct sap_central_peer,
						     secure_write_work);
	int err;

	if (!peer->in_use || (peer->conn == NULL) || !peer->secure_write_queued ||
	    peer->secure_write_pending) {
		return;
	}

	peer->secure_write_params.func = secure_write_cb;
	peer->secure_write_params.handle = peer->handles.secure_rx;
	peer->secure_write_params.offset = 0U;
	peer->secure_write_params.data = peer->secure_tx_buf;
	peer->secure_write_params.length = peer->secure_tx_len;
	peer->secure_write_queued = false;
	peer->secure_write_pending = true;

	err = bt_gatt_write(peer->conn, &peer->secure_write_params);
	if (err != 0) {
		peer->secure_write_pending = false;
		if ((peer->session != NULL) && peer->session->in_use) {
			sap_on_tx_complete(peer->session, peer->secure_tx_msg_type, err);
		}
	}
}

static int send_auth(struct sap_session *session, uint8_t msg_type,
		     const uint8_t *data, size_t len)
{
	struct sap_central_peer *peer = session->user_data;

	if (len > sizeof(peer->auth_tx_buf)) {
		return -EMSGSIZE;
	}

	if (peer->auth_write_pending || peer->auth_write_queued) {
		return -EBUSY;
	}

	memcpy(peer->auth_tx_buf, data, len);
	peer->auth_tx_msg_type = msg_type;
	peer->auth_tx_len = len;
	peer->auth_write_queued = true;
	(void)k_work_submit(&peer->auth_write_work);

	return 0;
}

static int send_secure(struct sap_session *session, uint8_t msg_type,
		       const uint8_t *data, size_t len)
{
	struct sap_central_peer *peer = session->user_data;

	if (len > sizeof(peer->secure_tx_buf)) {
		return -EMSGSIZE;
	}

	if (peer->secure_write_pending || peer->secure_write_queued) {
		return -EBUSY;
	}

	memcpy(peer->secure_tx_buf, data, len);
	peer->secure_tx_msg_type = msg_type;
	peer->secure_tx_len = len;
	peer->secure_write_queued = true;
	(void)k_work_submit(&peer->secure_write_work);

	return 0;
}

static uint8_t resolve_target_peer_id(uint8_t requested_peer_id)
{
	return (requested_peer_id != 0U) ? requested_peer_id : selected_leaf_id();
}

static struct sap_central_peer *resolve_dfu_peer(uint8_t requested_peer_id)
{
	uint8_t peer_id = resolve_target_peer_id(requested_peer_id);
	struct sap_central_peer *peer = peer_from_device_id(peer_id);

	if ((peer == NULL) || (peer->session == NULL) ||
	    !sap_is_authenticated(peer->session)) {
		return NULL;
	}

	#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
	if (!dfu_transport_ready(peer)) {
		return NULL;
	}
	#endif

	return peer;
}

static void root_on_authenticated(struct sap_session *session)
{
	LOG_INF("Root authenticated upstream controller %u",
		session->peer_cert.body.device_id);
	SAP_TRACE("FLOW post-auth: root accepted upstream SAP controller %u",
		  session->peer_cert.body.device_id);
}

static void root_on_auth_failed(struct sap_session *session, int reason)
{
	LOG_ERR("Root SAP auth failed on upstream side (%d)", reason);
	if (session->conn != NULL) {
		(void)bt_conn_disconnect(session->conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	}
}

static void root_handle_status_request(void)
{
	int err = root_send_status_response();

	if (err != 0) {
		LOG_WRN("Failed to send root status response (%d)", err);
	}
}

static void root_handle_select_request(const uint8_t *data, size_t len)
{
	const struct sap_demo_root_select_leaf *req;
	struct sap_central_peer *peer;
	uint8_t status = SAP_DEMO_ROOT_STATUS_INVALID;

	if (len != sizeof(*req)) {
		(void)root_send_select_response(status);
		return;
	}

	req = (const struct sap_demo_root_select_leaf *)data;
	LOG_INF("Upstream controller requested leaf select %u", req->peer_id);
	peer = peer_from_device_id(req->peer_id);
	if ((peer == NULL) || (peer->session == NULL) ||
	    !sap_is_authenticated(peer->session)) {
		status = SAP_DEMO_ROOT_STATUS_NO_PEER;
	} else {
		root_dfu.target_peer_id = req->peer_id;
		status = SAP_DEMO_ROOT_STATUS_OK;
	}

	(void)root_send_select_response(status);
}

static void root_handle_dfu_begin(const uint8_t *data, size_t len)
{
#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
	const struct sap_demo_root_dfu_begin *req;
	struct sap_central_peer *peer;
	uint8_t peer_id;

	if (len != sizeof(*req)) {
		(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_INVALID, 0U, 0U);
		return;
	}

	if (root_dfu.active) {
		(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_BUSY, root_dfu.target_peer_id, 0U);
		return;
	}

	req = (const struct sap_demo_root_dfu_begin *)data;
	LOG_INF("Upstream controller started DFU relay for requested leaf %u image_size=%u",
		req->peer_id, (uint32_t)sys_le32_to_cpu(req->image_size_le));
	peer = resolve_dfu_peer(req->peer_id);
	if (peer == NULL) {
		(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_NO_PEER,
					   resolve_target_peer_id(req->peer_id), 0U);
		return;
	}

	peer_id = peer->session->peer_cert.body.device_id;
	root_dfu_reset_state();
	root_dfu.active = true;
	root_dfu.target_peer_id = peer_id;
	root_dfu.image_num = req->image_num;
	root_dfu.image_size = sys_le32_to_cpu(req->image_size_le);
	root_dfu.permanent = false;
	if ((req->boot_hash_len == 0U) ||
	    (req->boot_hash_len > sizeof(root_dfu.boot_hash))) {
		root_dfu_reset_state();
		(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_INVALID, peer_id, 0U);
		return;
	}
	root_dfu.boot_hash_len = req->boot_hash_len;
	memcpy(root_dfu.upload_sha, req->upload_sha256, sizeof(root_dfu.upload_sha));
	memcpy(root_dfu.boot_hash, req->boot_hash, root_dfu.boot_hash_len);
	LOG_INF("Root accepted DFU relay target peer %u boot_hash_len=%u",
		peer_id, root_dfu.boot_hash_len);
	(void)root_send_dfu_progress(SAP_DEMO_ROOT_STATUS_OK, peer_id, 0U, root_dfu.image_size);
#else
	ARG_UNUSED(data);
	ARG_UNUSED(len);
	(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_BAD_STATE, 0U, 0U);
#endif
}

static void root_handle_dfu_chunk(const uint8_t *data, size_t len)
{
#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
	const struct sap_demo_root_dfu_chunk *req;
	struct sap_central_peer *peer;
	uint32_t offset;
	int err;

	if (!root_dfu.active) {
		(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_BAD_STATE, 0U, 0U);
		return;
	}

	if (len <= sizeof(req->offset_le)) {
		(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_INVALID,
					   root_dfu.target_peer_id, 0U);
		return;
	}

	peer = resolve_dfu_peer(root_dfu.target_peer_id);
	if (peer == NULL) {
		(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_NO_PEER,
					   root_dfu.target_peer_id, 0U);
		root_dfu_reset_state();
		return;
	}

	if (peer->dfu_request != SAP_DFU_REQ_NONE) {
		(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_BUSY,
					   root_dfu.target_peer_id, 0U);
		return;
	}

	req = (const struct sap_demo_root_dfu_chunk *)data;
	offset = sys_le32_to_cpu(req->offset_le);
	if (offset != root_dfu.accepted_offset) {
		(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_BAD_STATE,
					   root_dfu.target_peer_id, offset);
		return;
	}
	if ((offset == 0U) ||
	    ((offset + (len - sizeof(req->offset_le))) >= root_dfu.image_size)) {
		LOG_INF("Relaying DFU chunk for peer %u offset=%u payload_len=%u",
			root_dfu.target_peer_id, offset,
			(uint32_t)(len - sizeof(req->offset_le)));
	}

	err = send_dfu_upload_chunk(peer, req->data, len - sizeof(req->offset_le));
	if (err != 0) {
		(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_DFU_ERROR,
					   root_dfu.target_peer_id, (uint32_t)err);
		root_dfu_reset_state();
	}
#else
	ARG_UNUSED(data);
	ARG_UNUSED(len);
#endif
}

static void root_handle_dfu_finish(const uint8_t *data, size_t len)
{
#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
	const struct sap_demo_root_dfu_finish *req;
	struct sap_central_peer *peer;
	int err;

	if (len != sizeof(*req)) {
		(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_INVALID,
					   root_dfu.target_peer_id, 0U);
		return;
	}

	if (!root_dfu.active) {
		(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_BAD_STATE, 0U, 0U);
		return;
	}

	req = (const struct sap_demo_root_dfu_finish *)data;
	peer = resolve_dfu_peer(req->peer_id);
	if ((peer == NULL) ||
	    (peer->session->peer_cert.body.device_id != root_dfu.target_peer_id)) {
		(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_NO_PEER,
					   root_dfu.target_peer_id, 0U);
		root_dfu_reset_state();
		return;
	}

	root_dfu.permanent = req->permanent != 0U;

	if (peer->dfu_request != SAP_DFU_REQ_NONE) {
		schedule_root_dfu_retry(SAP_ROOT_DFU_RETRY_STATE_WRITE);
		return;
	}

	if (root_dfu.accepted_offset != root_dfu.image_size) {
		(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_BAD_STATE,
					   root_dfu.target_peer_id,
					   (uint32_t)root_dfu.accepted_offset);
		return;
	}
	LOG_INF("Upstream controller finished upload for peer %u, resolving image hash",
		root_dfu.target_peer_id);

	err = send_dfu_state_read(peer);
	if (err != 0) {
		if (dfu_is_retryable(err)) {
			schedule_root_dfu_retry(SAP_ROOT_DFU_RETRY_STATE_READ);
			return;
		}

		(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_DFU_ERROR,
					   root_dfu.target_peer_id, (uint32_t)err);
		root_dfu_reset_state();
	}
#else
	ARG_UNUSED(data);
	ARG_UNUSED(len);
#endif
}

static void root_on_secure_payload(struct sap_session *session, uint8_t msg_type,
				   const uint8_t *data, size_t len)
{
	ARG_UNUSED(session);

	switch (msg_type) {
	case SAP_DEMO_MSG_TEXT:
		LOG_INF("Secure payload from upstream controller: %.*s", len,
			(const char *)data);
		break;
	case SAP_DEMO_MSG_ROOT_STATUS_REQ:
		root_handle_status_request();
		break;
	case SAP_DEMO_MSG_ROOT_SELECT_LEAF:
		root_handle_select_request(data, len);
		break;
	case SAP_DEMO_MSG_ROOT_DFU_BEGIN:
		root_handle_dfu_begin(data, len);
		break;
	case SAP_DEMO_MSG_ROOT_DFU_CHUNK:
		root_handle_dfu_chunk(data, len);
		break;
	case SAP_DEMO_MSG_ROOT_DFU_FINISH:
		root_handle_dfu_finish(data, len);
		break;
	default:
		LOG_WRN("Unsupported upstream SAP app message 0x%02x", msg_type);
		break;
	}
}

static ssize_t root_sap_auth_write(struct bt_conn *conn,
				   const struct bt_gatt_attr *attr,
				   const void *buf, uint16_t len,
				   uint16_t offset, uint8_t flags)
{
	struct sap_session *session;
	int err;

	ARG_UNUSED(attr);
	ARG_UNUSED(flags);

	if (offset != 0U) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	session = sap_session_from_conn(&root_link.sap_ctx, conn);
	if (session == NULL) {
		return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
	}

	err = sap_handle_auth_rx(session, buf, len);
	if (err != 0) {
		return BT_GATT_ERR(BT_ATT_ERR_AUTHORIZATION);
	}

	return len;
}

static ssize_t root_sap_secure_rx_write(struct bt_conn *conn,
					const struct bt_gatt_attr *attr,
					const void *buf, uint16_t len,
					uint16_t offset, uint8_t flags)
{
	struct sap_session *session;
	int err;

	ARG_UNUSED(attr);
	ARG_UNUSED(flags);

	if (offset != 0U) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	session = sap_session_from_conn(&root_link.sap_ctx, conn);
	if (session == NULL) {
		return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
	}

	err = sap_handle_secure_rx(session, buf, len);
	if (err != 0) {
		return BT_GATT_ERR(BT_ATT_ERR_AUTHORIZATION);
	}

	return len;
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

static bool dfu_is_retryable(int err)
{
	return (err == -EAGAIN) || (err == -EBUSY) || (err == -ENOMEM);
}

static void schedule_root_dfu_retry(enum sap_root_dfu_retry_action action)
{
	if (root_dfu.retry_action != action) {
		root_dfu.retry_count = 0U;
	}

	root_dfu.retry_action = action;
	if (root_dfu.retry_count < UINT8_MAX) {
		root_dfu.retry_count++;
	}

	(void)k_work_reschedule(&root_dfu_retry_work, K_MSEC(SAP_DFU_RETRY_DELAY_MS));
}

static void root_dfu_reset_state(void)
{
	(void)k_work_cancel_delayable(&root_dfu_retry_work);
	memset(&root_dfu, 0, sizeof(root_dfu));
}

static void root_dfu_retry_fn(struct k_work *work)
{
	struct sap_central_peer *peer;
	int err;

	ARG_UNUSED(work);

	if (!root_dfu.active) {
		return;
	}

	peer = resolve_dfu_peer(root_dfu.target_peer_id);
	if (peer == NULL) {
		(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_NO_PEER,
					   root_dfu.target_peer_id, 0U);
		root_dfu_reset_state();
		return;
	}

	if (peer->dfu_request != SAP_DFU_REQ_NONE) {
		if (root_dfu.retry_count >= SAP_DFU_RETRY_MAX) {
			(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_DFU_ERROR,
						   root_dfu.target_peer_id, (uint32_t)(-EBUSY));
			root_dfu_reset_state();
			return;
		}

		schedule_root_dfu_retry(root_dfu.retry_action);
		return;
	}

	switch (root_dfu.retry_action) {
	case SAP_ROOT_DFU_RETRY_STATE_READ:
		err = send_dfu_state_read(peer);
		break;
	case SAP_ROOT_DFU_RETRY_STATE_WRITE:
		err = send_dfu_state_write(peer);
		break;
	case SAP_ROOT_DFU_RETRY_ACTIVATE:
		err = send_dfu_activate(peer);
		break;
	default:
		return;
	}

	if (err == 0) {
		root_dfu.retry_action = SAP_ROOT_DFU_RETRY_NONE;
		root_dfu.retry_count = 0U;
		return;
	}

	if (dfu_is_retryable(err) && (root_dfu.retry_count < SAP_DFU_RETRY_MAX)) {
		schedule_root_dfu_retry(root_dfu.retry_action);
		return;
	}

	(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_DFU_ERROR,
				   root_dfu.target_peer_id, (uint32_t)err);
	root_dfu_reset_state();
}

static void dfu_response_reset(struct sap_central_peer *peer)
{
	memset(&peer->dfu_rsp, 0, sizeof(peer->dfu_rsp));
}

static int dfu_response_append(struct sap_central_peer *peer)
{
	const struct bt_dfu_smp_rsp_state *rsp_state = bt_dfu_smp_rsp_state(&peer->dfu_smp);
	uint8_t *buf = (uint8_t *)&peer->dfu_rsp;

	if (rsp_state->offset + rsp_state->chunk_size > sizeof(peer->dfu_rsp)) {
		return -ENOMEM;
	}

	memcpy(buf + rsp_state->offset, rsp_state->data, rsp_state->chunk_size);
	return bt_dfu_smp_rsp_total_check(&peer->dfu_smp) ? 1 : 0;
}

static int parse_upload_response(struct sap_central_peer *peer,
				 size_t *accepted_offset,
				 int32_t *status,
				 bool *match_valid,
				 bool *match)
{
	size_t payload_len = (((size_t)peer->dfu_rsp.header.len_h8) << 8) |
			      peer->dfu_rsp.header.len_l8;
	zcbor_state_t zsd[SAP_DFU_CBOR_DECODER_STATE_NUM];
	size_t decoded = 0U;
	int rc;
	int32_t status_code = SAP_MGMT_ERR_EOK;
	size_t offset = SIZE_MAX;
	bool hash_match = false;
	struct zcbor_map_decode_key_val decode[] = {
		ZCBOR_MAP_DECODE_KEY_DECODER("off", zcbor_size_decode, &offset),
		ZCBOR_MAP_DECODE_KEY_DECODER("rc", zcbor_int32_decode, &status_code),
		ZCBOR_MAP_DECODE_KEY_DECODER("match", zcbor_bool_decode, &hash_match),
	};

	zcbor_new_decode_state(zsd, ARRAY_SIZE(zsd), peer->dfu_rsp.payload, payload_len,
			       1, NULL, 0);

	rc = zcbor_map_decode_bulk(zsd, decode, ARRAY_SIZE(decode), &decoded);
	if ((rc != 0) || (offset == SIZE_MAX)) {
		return -EINVAL;
	}

	*accepted_offset = offset;
	*status = status_code;
	*match_valid = (decoded == ARRAY_SIZE(decode));
	*match = hash_match;
	return 0;
}

static int parse_state_response(struct sap_central_peer *peer, int32_t *status)
{
	size_t payload_len = (((size_t)peer->dfu_rsp.header.len_h8) << 8) |
			      peer->dfu_rsp.header.len_l8;
	zcbor_state_t zsd[SAP_DFU_CBOR_DECODER_STATE_NUM];
	struct zcbor_string key = {0};
	int32_t status_code = SAP_MGMT_ERR_EOK;
	bool ok;

	zcbor_new_decode_state(zsd, ARRAY_SIZE(zsd), peer->dfu_rsp.payload, payload_len,
			       1, NULL, 0);

	ok = zcbor_map_start_decode(zsd);
	if (!ok) {
		return -EINVAL;
	}

	ok = zcbor_tstr_decode(zsd, &key);
	if (!ok) {
		return -EINVAL;
	}

	if ((key.len == 2U) && (memcmp(key.value, "rc", 2U) == 0)) {
		ok = zcbor_int32_decode(zsd, &status_code) &&
		     zcbor_map_end_decode(zsd);
		if (!ok) {
			return -EINVAL;
		}
	}

	*status = status_code;
	return 0;
}

static int parse_state_read_response(struct sap_central_peer *peer, uint8_t *hash,
				     size_t *hash_len, int32_t *status,
				     bool *selected_pending, bool *selected_permanent)
{
	size_t payload_len = (((size_t)peer->dfu_rsp.header.len_h8) << 8) |
			      peer->dfu_rsp.header.len_l8;
	zcbor_state_t zsd[SAP_DFU_CBOR_DECODER_STATE_NUM];
	struct zcbor_string top_key = {0};
	struct zcbor_string version = {0};
	struct zcbor_string hash_value = {0};
	uint32_t image_num = 0U;
	uint32_t slot_num = UINT32_MAX;
	int32_t status_code = SAP_MGMT_ERR_EOK;
	size_t decoded = 0U;
	bool bootable = false;
	bool pending = false;
	bool confirmed = false;
	bool active = false;
	bool permanent = false;
	bool ok;
	int rc;
	struct zcbor_map_decode_key_val decode[] = {
		ZCBOR_MAP_DECODE_KEY_DECODER("version", zcbor_tstr_decode, &version),
		ZCBOR_MAP_DECODE_KEY_DECODER("hash", zcbor_bstr_decode, &hash_value),
		ZCBOR_MAP_DECODE_KEY_DECODER("slot", zcbor_uint32_decode, &slot_num),
		ZCBOR_MAP_DECODE_KEY_DECODER("image", zcbor_uint32_decode, &image_num),
		ZCBOR_MAP_DECODE_KEY_DECODER("bootable", zcbor_bool_decode, &bootable),
		ZCBOR_MAP_DECODE_KEY_DECODER("pending", zcbor_bool_decode, &pending),
		ZCBOR_MAP_DECODE_KEY_DECODER("confirmed", zcbor_bool_decode, &confirmed),
		ZCBOR_MAP_DECODE_KEY_DECODER("active", zcbor_bool_decode, &active),
		ZCBOR_MAP_DECODE_KEY_DECODER("permanent", zcbor_bool_decode, &permanent),
	};

	zcbor_new_decode_state(zsd, ARRAY_SIZE(zsd), peer->dfu_rsp.payload, payload_len,
			       1, NULL, 0);

	ok = zcbor_map_start_decode(zsd) &&
	     zcbor_tstr_decode(zsd, &top_key);
	if (!ok) {
		return -EINVAL;
	}

	if ((top_key.len == 2U) && (memcmp(top_key.value, "rc", 2U) == 0)) {
		ok = zcbor_int32_decode(zsd, &status_code) &&
		     zcbor_map_end_decode(zsd);
		if (!ok) {
			return -EINVAL;
		}

		*status = status_code;
		return 0;
	}

	if ((top_key.len != 6U) || (memcmp(top_key.value, "images", 6U) != 0)) {
		return -EINVAL;
	}

	if (!zcbor_list_start_decode(zsd)) {
		return -EINVAL;
	}

	while (true) {
		decoded = 0U;
		version.len = 0U;
		hash_value.len = 0U;
		image_num = 0U;
		slot_num = UINT32_MAX;
		bootable = false;
		pending = false;
		confirmed = false;
		active = false;
		permanent = false;
		zcbor_map_decode_bulk_reset(decode, ARRAY_SIZE(decode));

		rc = zcbor_map_decode_bulk(zsd, decode, ARRAY_SIZE(decode), &decoded);
		if (rc != 0) {
			return -ENOENT;
		}

		if ((hash_value.len == 0U) ||
		    (hash_value.len > SAP_DFU_BOOT_HASH_MAX_LEN) ||
		    (version.len == 0U) ||
		    !zcbor_map_decode_bulk_key_found(decode, ARRAY_SIZE(decode), "slot")) {
			return -EINVAL;
		}

		if (active) {
			continue;
		}

		if (zcbor_map_decode_bulk_key_found(decode, ARRAY_SIZE(decode), "image") &&
		    (image_num != root_dfu.image_num)) {
			continue;
		}

		LOG_INF("Root selected leaf DFU slot peer %u image=%u slot=%u active=%u pending=%u confirmed=%u permanent=%u version=%.*s",
			peer->session->peer_cert.body.device_id,
			image_num, slot_num, active ? 1U : 0U, pending ? 1U : 0U,
			confirmed ? 1U : 0U, permanent ? 1U : 0U,
			(int)version.len, version.value);
		if (selected_pending != NULL) {
			*selected_pending = pending;
		}
		if (selected_permanent != NULL) {
			*selected_permanent = permanent;
		}
		memcpy(hash, hash_value.value, hash_value.len);
		*hash_len = hash_value.len;
		*status = SAP_MGMT_ERR_EOK;
		return 0;
	}
}

static int send_dfu_upload_chunk(struct sap_central_peer *peer,
				 const uint8_t *data, size_t len)
{
	struct sap_dfu_buffer *smp_cmd;
	zcbor_state_t zse[SAP_DFU_CBOR_ENCODER_STATE_NUM];
	size_t payload_len;
	bool ok;
	uint32_t map_count;
	int err;

	if ((peer == NULL) || !peer->dfu_service_ready || !root_dfu.active) {
		return -EAGAIN;
	}

	smp_cmd = &peer->dfu_cmd;
	memset(smp_cmd, 0, sizeof(*smp_cmd));
	dfu_response_reset(peer);

	zcbor_new_encode_state(zse, ARRAY_SIZE(zse), smp_cmd->payload,
			       sizeof(smp_cmd->payload), 0);
	map_count = (root_dfu.accepted_offset == 0U) ? 10U : 6U;

	ok = zcbor_map_start_encode(zse, map_count) &&
	     zcbor_tstr_put_lit(zse, "image") &&
	     zcbor_uint32_put(zse, root_dfu.image_num) &&
	     zcbor_tstr_put_lit(zse, "data") &&
	     zcbor_bstr_encode_ptr(zse, data, len) &&
	     zcbor_tstr_put_lit(zse, "off") &&
	     zcbor_size_put(zse, root_dfu.accepted_offset);
	if (ok && (root_dfu.accepted_offset == 0U)) {
		ok = zcbor_tstr_put_lit(zse, "len") &&
		     zcbor_size_put(zse, root_dfu.image_size) &&
		     zcbor_tstr_put_lit(zse, "sha") &&
		     zcbor_bstr_encode_ptr(zse, root_dfu.upload_sha,
					   sizeof(root_dfu.upload_sha));
	}
	if (ok) {
		ok = zcbor_map_end_encode(zse, map_count);
	}
	if (!ok) {
		return -ENOMEM;
	}

	payload_len = (size_t)(zse->payload - smp_cmd->payload);
	smp_cmd->header.op = 2U;
	smp_cmd->header.flags = 0U;
	smp_cmd->header.len_h8 = (uint8_t)((payload_len >> 8) & 0xffU);
	smp_cmd->header.len_l8 = (uint8_t)(payload_len & 0xffU);
	smp_cmd->header.group_h8 = 0U;
	smp_cmd->header.group_l8 = SAP_MGMT_GROUP_ID_IMAGE;
	smp_cmd->header.seq = 0U;
	smp_cmd->header.id = SAP_IMG_MGMT_ID_UPLOAD;
	err = bt_dfu_smp_command(&peer->dfu_smp, dfu_echo_rsp_proc,
				 sizeof(smp_cmd->header) + payload_len, smp_cmd);
	if (err == 0) {
		peer->dfu_request = SAP_DFU_REQ_UPLOAD;
	}

	return err;
}

static int send_dfu_state_read(struct sap_central_peer *peer)
{
	struct sap_dfu_buffer *smp_cmd;
	zcbor_state_t zse[SAP_DFU_CBOR_ENCODER_STATE_NUM];
	size_t payload_len;
	bool ok;
	int err;

	if ((peer == NULL) || !peer->dfu_service_ready || !root_dfu.active) {
		return -EAGAIN;
	}

	smp_cmd = &peer->dfu_cmd;
	memset(smp_cmd, 0, sizeof(*smp_cmd));
	dfu_response_reset(peer);

	zcbor_new_encode_state(zse, ARRAY_SIZE(zse), smp_cmd->payload,
			       sizeof(smp_cmd->payload), 0);
	ok = zcbor_map_start_encode(zse, 1U) &&
	     zcbor_map_end_encode(zse, 1U);
	if (!ok) {
		return -ENOMEM;
	}

	payload_len = (size_t)(zse->payload - smp_cmd->payload);
	smp_cmd->header.op = 0U;
	smp_cmd->header.flags = 0U;
	smp_cmd->header.len_h8 = (uint8_t)((payload_len >> 8) & 0xffU);
	smp_cmd->header.len_l8 = (uint8_t)(payload_len & 0xffU);
	smp_cmd->header.group_h8 = 0U;
	smp_cmd->header.group_l8 = SAP_MGMT_GROUP_ID_IMAGE;
	smp_cmd->header.seq = 0U;
	smp_cmd->header.id = SAP_IMG_MGMT_ID_STATE;
	err = bt_dfu_smp_command(&peer->dfu_smp, dfu_echo_rsp_proc,
				 sizeof(smp_cmd->header) + payload_len, smp_cmd);
	if (err == 0) {
		peer->dfu_request = SAP_DFU_REQ_STATE_READ;
		LOG_INF("Root requested DFU image state read on peer %u",
			peer->session->peer_cert.body.device_id);
	}

	return err;
}

static int send_dfu_state_write(struct sap_central_peer *peer)
{
	struct sap_dfu_buffer *smp_cmd;
	zcbor_state_t zse[SAP_DFU_CBOR_ENCODER_STATE_NUM];
	size_t payload_len;
	uint32_t map_count = 4U;
	bool ok;
	int err;

	if ((peer == NULL) || !peer->dfu_service_ready || !root_dfu.active) {
		return -EAGAIN;
	}

	smp_cmd = &peer->dfu_cmd;
	memset(smp_cmd, 0, sizeof(*smp_cmd));
	dfu_response_reset(peer);

	zcbor_new_encode_state(zse, ARRAY_SIZE(zse), smp_cmd->payload,
			       sizeof(smp_cmd->payload), 0);
	ok = zcbor_map_start_encode(zse, map_count) &&
	     zcbor_tstr_put_lit(zse, "confirm") &&
	     zcbor_bool_put(zse, root_dfu.permanent) &&
	     zcbor_tstr_put_lit(zse, "hash") &&
	     zcbor_bstr_encode_ptr(zse, root_dfu.boot_hash, root_dfu.boot_hash_len) &&
	     zcbor_map_end_encode(zse, map_count);
	if (!ok) {
		return -ENOMEM;
	}

	payload_len = (size_t)(zse->payload - smp_cmd->payload);
	LOG_HEXDUMP_INF(root_dfu.boot_hash, root_dfu.boot_hash_len, "Root DFU state write hash");
	LOG_HEXDUMP_INF(smp_cmd->payload, payload_len, "Root DFU state write payload");
	smp_cmd->header.op = 2U;
	smp_cmd->header.flags = 0U;
	smp_cmd->header.len_h8 = (uint8_t)((payload_len >> 8) & 0xffU);
	smp_cmd->header.len_l8 = (uint8_t)(payload_len & 0xffU);
	smp_cmd->header.group_h8 = 0U;
	smp_cmd->header.group_l8 = SAP_MGMT_GROUP_ID_IMAGE;
	smp_cmd->header.seq = 0U;
	smp_cmd->header.id = SAP_IMG_MGMT_ID_STATE;
	err = bt_dfu_smp_command(&peer->dfu_smp, dfu_echo_rsp_proc,
				 sizeof(smp_cmd->header) + payload_len, smp_cmd);
	if (err == 0) {
		peer->dfu_request = SAP_DFU_REQ_STATE_WRITE;
		LOG_INF("Root requested DFU image state update on peer %u permanent=%u",
			peer->session->peer_cert.body.device_id,
			root_dfu.permanent ? 1U : 0U);
	}

	return err;
}

static int send_dfu_activate(struct sap_central_peer *peer)
{
	uint8_t payload;
	int err;

	if ((peer == NULL) || !root_dfu.active || (peer->session == NULL) ||
	    !sap_is_authenticated(peer->session)) {
		return -EAGAIN;
	}

	payload = root_dfu.permanent ? 1U : 0U;
	err = send_secure(peer->session, SAP_DEMO_MSG_DFU_APPLY, &payload,
			  sizeof(payload));
	if (err == 0) {
		root_dfu.awaiting_reboot = true;
		LOG_INF("Root requested cold DFU apply on peer %u permanent=%u",
			peer->session->peer_cert.body.device_id,
			root_dfu.permanent ? 1U : 0U);
	}

	return err;
}

static void dfu_echo_rsp_proc(struct bt_dfu_smp *dfu_smp)
{
	struct sap_central_peer *peer = CONTAINER_OF(dfu_smp, struct sap_central_peer, dfu_smp);
	int append_rc;

	append_rc = dfu_response_append(peer);
	if (append_rc < 0) {
		LOG_ERR("DFU SMP response overflow on peer %u",
			peer->session->peer_cert.body.device_id);
		return;
	}
	if (append_rc == 0) {
		return;
	}

	if ((((peer->dfu_rsp.header.op == 3U) &&
	      (peer->dfu_request != SAP_DFU_REQ_STATE_READ)) ||
	     ((peer->dfu_rsp.header.op == 1U) &&
	      (peer->dfu_request == SAP_DFU_REQ_STATE_READ))) &&
	    (peer->dfu_rsp.header.group_h8 == 0U) &&
	    (peer->dfu_rsp.header.group_l8 == SAP_MGMT_GROUP_ID_IMAGE)) {
		switch (peer->dfu_request) {
		case SAP_DFU_REQ_UPLOAD: {
			size_t accepted_offset = 0U;
			int32_t status = -EINVAL;
			bool match_valid = false;
			bool match = false;
			int err = parse_upload_response(peer, &accepted_offset, &status,
						       &match_valid, &match);

			if ((err == 0) && (status == SAP_MGMT_ERR_EOK)) {
				root_dfu.accepted_offset = accepted_offset;
				if ((accepted_offset == root_dfu.image_size) && match_valid) {
					LOG_INF("Root DFU relay final image check for peer %u: %s",
						peer->session->peer_cert.body.device_id,
						match ? "match" : "mismatch");
					if (!match) {
						(void)root_send_dfu_result(
							SAP_DEMO_ROOT_STATUS_DFU_ERROR,
							peer->session->peer_cert.body.device_id,
							(uint32_t)(-EILSEQ));
						root_dfu_reset_state();
						break;
					}
				}
				if ((accepted_offset == 0U) ||
				    (accepted_offset == root_dfu.image_size)) {
					LOG_INF("Root DFU relay progress peer %u accepted=%u/%u",
						peer->session->peer_cert.body.device_id,
						(uint32_t)accepted_offset,
						(uint32_t)root_dfu.image_size);
				}
				(void)root_send_dfu_progress(SAP_DEMO_ROOT_STATUS_OK,
							    peer->session->peer_cert.body.device_id,
							    accepted_offset,
							    root_dfu.image_size);
			} else {
				(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_DFU_ERROR,
							   peer->session->peer_cert.body.device_id,
							   (uint32_t)(err != 0 ? err : status));
				root_dfu_reset_state();
			}
			break;
		}
		case SAP_DFU_REQ_STATE_READ: {
			uint8_t resolved_hash[SAP_DFU_BOOT_HASH_MAX_LEN];
			size_t resolved_hash_len = 0U;
			int32_t status = -EINVAL;
			bool selected_pending = false;
			bool selected_permanent = false;
			size_t payload_len = (((size_t)peer->dfu_rsp.header.len_h8) << 8) |
					     peer->dfu_rsp.header.len_l8;
			int err = parse_state_read_response(peer, resolved_hash,
							      &resolved_hash_len, &status,
							      &selected_pending,
							      &selected_permanent);

			if ((err == 0) && (status == SAP_MGMT_ERR_EOK)) {
				memcpy(root_dfu.boot_hash, resolved_hash, resolved_hash_len);
				root_dfu.boot_hash_len = resolved_hash_len;
				LOG_INF("Root resolved leaf DFU hash for peer %u len=%u",
					peer->session->peer_cert.body.device_id,
					(uint32_t)resolved_hash_len);
				LOG_HEXDUMP_INF(resolved_hash, resolved_hash_len,
						"Root resolved leaf DFU hash");
				if (selected_pending &&
				    (!root_dfu.permanent || selected_permanent)) {
					LOG_INF("Root leaf DFU slot for peer %u is already pending with the requested boot state, activating directly",
						peer->session->peer_cert.body.device_id);
					schedule_root_dfu_retry(SAP_ROOT_DFU_RETRY_ACTIVATE);
					break;
				}
				schedule_root_dfu_retry(SAP_ROOT_DFU_RETRY_STATE_WRITE);
				break;
			}

			LOG_ERR("Root DFU state read parse failed for peer %u err=%d status=%d op=%u id=%u len=%u",
				peer->session->peer_cert.body.device_id, err, status,
				peer->dfu_rsp.header.op, peer->dfu_rsp.header.id,
				(uint32_t)payload_len);
			LOG_HEXDUMP_INF(peer->dfu_rsp.payload, payload_len,
					"Root DFU state read payload");
			(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_DFU_ERROR,
						   peer->session->peer_cert.body.device_id,
						   (uint32_t)(err != 0 ? err : status));
			root_dfu_reset_state();
			break;
		}
		case SAP_DFU_REQ_STATE_WRITE: {
			int32_t status = -EINVAL;
			int err = parse_state_response(peer, &status);

			if ((err == 0) && (status == SAP_MGMT_ERR_EOK)) {
				schedule_root_dfu_retry(SAP_ROOT_DFU_RETRY_ACTIVATE);
				break;
			}

			(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_DFU_ERROR,
						   peer->session->peer_cert.body.device_id,
						   (uint32_t)(err != 0 ? err : status));
			root_dfu_reset_state();
			break;
		}
		default:
			break;
		}
		peer->dfu_request = SAP_DFU_REQ_NONE;
		return;
	}

	if (peer->dfu_rsp.header.group_l8 != 0U || peer->dfu_rsp.header.id != 0U) {
		LOG_ERR("Unexpected DFU SMP response from peer %u op=%u group=%u id=%u req=%u",
			peer->session->peer_cert.body.device_id,
			peer->dfu_rsp.header.op,
			peer->dfu_rsp.header.group_l8,
			peer->dfu_rsp.header.id,
			peer->dfu_request);
		if (root_dfu.active && (peer->dfu_request != SAP_DFU_REQ_ECHO)) {
			(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_DFU_ERROR,
						   peer->session->peer_cert.body.device_id,
						   (uint32_t)(-EBADMSG));
			root_dfu_reset_state();
		}
		peer->dfu_request = SAP_DFU_REQ_NONE;
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
			peer->dfu_request = SAP_DFU_REQ_NONE;
			return;
		}

		key[0] = value.value[0];
		key[1] = '\0';

		ok = zcbor_tstr_decode(zsd, &value);
		ok = ok && zcbor_map_end_decode(zsd);
		if (!ok || (value.len >= sizeof(response))) {
			LOG_ERR("Failed to decode DFU SMP echo value from peer %u",
				peer->session->peer_cert.body.device_id);
			peer->dfu_request = SAP_DFU_REQ_NONE;
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
	peer->dfu_request = SAP_DFU_REQ_NONE;
}

static int send_dfu_echo(struct sap_central_peer *peer, const char *text)
{
	struct sap_dfu_buffer *smp_cmd;
	zcbor_state_t zse[SAP_DFU_CBOR_ENCODER_STATE_NUM];
	size_t payload_len;
	int err;

	if ((peer == NULL) || !peer->in_use || (peer->session == NULL)) {
		return -ENOTCONN;
	}

	if (!peer->dfu_service_ready) {
		return -EAGAIN;
	}

	smp_cmd = &peer->dfu_cmd;
	memset(smp_cmd, 0, sizeof(*smp_cmd));
	memset(&peer->dfu_rsp, 0, sizeof(peer->dfu_rsp));

	zcbor_new_encode_state(zse, ARRAY_SIZE(zse), smp_cmd->payload,
			       sizeof(smp_cmd->payload), 0);

	if (!zcbor_map_start_encode(zse, SAP_DFU_CBOR_MAP_MAX_ELEMENT_CNT) ||
	    !zcbor_tstr_put_lit(zse, "d") ||
	    !zcbor_tstr_put_term(zse, text, strlen(text) + 1U) ||
	    !zcbor_map_end_encode(zse, SAP_DFU_CBOR_MAP_MAX_ELEMENT_CNT)) {
		return -EFAULT;
	}

	payload_len = (size_t)(zse->payload - smp_cmd->payload);
	smp_cmd->header.op = 2U;
	smp_cmd->header.flags = 0U;
	smp_cmd->header.len_h8 = (uint8_t)((payload_len >> 8) & 0xffU);
	smp_cmd->header.len_l8 = (uint8_t)(payload_len & 0xffU);
	smp_cmd->header.group_h8 = 0U;
	smp_cmd->header.group_l8 = 0U;
	smp_cmd->header.seq = 0U;
	smp_cmd->header.id = 0U;
	err = bt_dfu_smp_command(&peer->dfu_smp, dfu_echo_rsp_proc,
				 sizeof(smp_cmd->header) + payload_len, smp_cmd);
	if (err == 0) {
		peer->dfu_request = SAP_DFU_REQ_ECHO;
	}

	return err;
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

		if ((err == -EAGAIN) || (err == -EBUSY) || (err == -ENOMEM) || (err > 0)) {
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
		const char *payload = data;
		const char *pattern = NULL;
		uint16_t i;

		for (i = 0U; i < length; i++) {
			if (payload[i] == 'p') {
				pattern = &payload[i];
			}
		}

		peer->protected_service_ready = true;
		LOG_INF("Protected service payload: %.*s", length, (const char *)data);
		SAP_TRACE("FLOW post-auth: central successfully read the gated protected characteristic");
		if ((pattern != NULL) && ((pattern + 1) < (payload + length))) {
			peer->observed_pattern_id = (uint8_t)strtoul(pattern + 1, NULL, 10);
		}
		(void)root_send_status_response();
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
	peer->dfu_discovery_attempts = 0U;
	peer->dfu_echo_complete = false;
	peer->dfu_echo_pending = true;
	LOG_INF("DFU SMP service discovered on peripheral %u",
		peer->session->peer_cert.body.device_id);
	SAP_TRACE("FLOW post-auth: central discovered the gated DFU SMP service on peer %u",
		  peer->session->peer_cert.body.device_id);
	(void)root_send_status_response();
	schedule_dfu_echo(K_MSEC(SAP_DFU_ECHO_DELAY_MS));
}

static void dfu_service_not_found(struct bt_conn *conn, void *context)
{
	struct sap_central_peer *peer = context;

	ARG_UNUSED(conn);

	if (peer != NULL && peer->in_use) {
		peer->dfu_discovery_attempts++;
		if (peer->dfu_discovery_attempts < SAP_DFU_DISCOVERY_RETRY_MAX) {
			peer->dfu_discovery_retry = true;
			schedule_gatt_retry();
			return;
		}

		LOG_INF("Peripheral %u does not expose the gated DFU SMP service",
			peer->session != NULL ? peer->session->peer_cert.body.device_id : 0U);
		peer->dfu_service_ready = false;
		peer->dfu_echo_pending = false;
		peer->dfu_echo_complete = false;
		peer->dfu_discovery_retry = false;
		(void)root_send_status_response();
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
	(void)root_send_status_response();

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
	peer->auth_sub_params.value = BT_GATT_CCC_INDICATE;
	peer->auth_sub_params.value_handle = peer->handles.auth;
	peer->auth_sub_params.ccc_handle = peer->handles.auth_ccc;
	atomic_set_bit(peer->auth_sub_params.flags, BT_GATT_SUBSCRIBE_FLAG_VOLATILE);
	err = bt_gatt_subscribe(peer->conn, &peer->auth_sub_params);
	if (err == 0) {
		peer->auth_subscribed = true;
	}

	peer->secure_sub_params.notify = secure_notif_cb;
	peer->secure_sub_params.value = BT_GATT_CCC_INDICATE;
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

	if (scan_addr_is_local(addr)) {
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

	if (!conn_role_is(conn, BT_CONN_ROLE_CENTRAL)) {
		return;
	}

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
			k_work_init(&peer->auth_write_work, auth_write_work_fn);
			k_work_init(&peer->secure_write_work, secure_write_work_fn);
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

	if (peer == NULL) {
		return;
	}

	LOG_INF("Central disconnected, reason 0x%02x %s",
		reason, bt_hci_err_to_str(reason));

	if (peer != NULL) {
		(void)k_work_cancel(&peer->auth_write_work);
		(void)k_work_cancel(&peer->secure_write_work);
		if (peer->session != NULL) {
			peer_id = peer->session->peer_cert.body.device_id;
		}

#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
		peer->dfu_echo_pending = false;
#endif
		if (IS_ENABLED(CONFIG_SAP_USE_BLE_SC_OOB_PAIRING)) {
			bt_le_oob_set_sc_flag(false);
		}
		sap_on_disconnected(&sap_ctx, conn);
		bt_conn_unref(peer->conn);
		memset(peer, 0, sizeof(*peer));
	}

#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
	if (root_dfu.active && (peer_id == root_dfu.target_peer_id)) {
		if (root_dfu.awaiting_reboot) {
			(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_OK, peer_id, 0U);
		} else {
			(void)root_send_dfu_result(SAP_DEMO_ROOT_STATUS_DFU_ERROR, peer_id,
						   (uint32_t)reason);
		}
		root_dfu_reset_state();
	}
#endif

	clear_remote_led(peer_id);
	(void)root_send_status_response();
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

static struct sap_session *session_for_oob_conn(struct bt_conn *conn)
{
	struct sap_session *session = sap_session_from_conn(&sap_ctx, conn);

	if (session != NULL) {
		return session;
	}

	return sap_session_from_conn(&root_link.sap_ctx, conn);
}

static void pairing_oob_data_request(struct bt_conn *conn,
				     struct bt_conn_oob_info *oob_info)
{
	struct sap_session *session = session_for_oob_conn(conn);
	int err;

	if (session == NULL || !session->ctx->policy.use_ble_sc_oob_pairing) {
		LOG_ERR("Central OOB request has no SAP OOB session");
		bt_conn_auth_cancel(conn);
		return;
	}

	if (oob_info->type != BT_CONN_OOB_LE_SC || !session->local_oob_ready ||
	    !session->peer_oob_ready) {
		LOG_ERR("Central OOB request invalid type=%u local=%u peer=%u",
			oob_info->type, session->local_oob_ready, session->peer_oob_ready);
		bt_conn_auth_cancel(conn);
		return;
	}

	LOG_INF("Central OOB data request config=%u", oob_info->lesc.oob_config);
	err = bt_le_oob_set_sc_data(conn, &session->local_oob_sc, &session->peer_oob_sc);
	if (err != 0) {
		LOG_ERR("Failed to apply central LE SC OOB data (%d)", err);
		bt_conn_auth_cancel(conn);
	}
}

static void pairing_cancel(struct bt_conn *conn)
{
	ARG_UNUSED(conn);
}

static const struct bt_conn_auth_cb auth_cb = {
	.oob_data_request = pairing_oob_data_request,
	.cancel = pairing_cancel,
};

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

static void root_connected(struct bt_conn *conn, uint8_t err)
{
	int sec_err;

	if (!conn_role_is(conn, BT_CONN_ROLE_PERIPHERAL)) {
		return;
	}

	if (err != 0U) {
		LOG_ERR("Upstream controller connection failed (0x%02x)", err);
		schedule_root_advertising_restart(K_MSEC(SAP_ROOT_ADV_RESTART_DELAY_MS));
		return;
	}

	if (root_link.conn != NULL) {
		(void)bt_conn_disconnect(conn, BT_HCI_ERR_CONN_LIMIT_EXCEEDED);
		return;
	}

	root_link.connection_active = true;
	root_link.advertising_restart_pending = false;
	root_scan_resume_pending = false;
	(void)k_work_cancel_delayable(&root_advertising_retry_work);
	root_link.conn = bt_conn_ref(conn);
	root_link.session = sap_on_connected(&root_link.sap_ctx, conn);
	if (root_link.session == NULL) {
		LOG_ERR("No upstream SAP session slots left");
		bt_conn_unref(root_link.conn);
		root_link.conn = NULL;
		root_link.connection_active = false;
		(void)bt_conn_disconnect(conn, BT_HCI_ERR_CONN_LIMIT_EXCEEDED);
		return;
	}

	if (root_link.policy.require_ble_encryption) {
		sec_err = bt_conn_set_security(conn, BT_SECURITY_L2);
		if (sec_err != 0) {
			LOG_ERR("Failed to request upstream security (%d)", sec_err);
			(void)bt_conn_disconnect(conn, BT_HCI_ERR_AUTH_FAIL);
			return;
		}
	} else {
		root_link.session->security_ready = true;
	}

	SAP_TRACE("FLOW 1/8 root BLE link established for upstream controller");
}

static void root_disconnected(struct bt_conn *conn, uint8_t reason)
{
	if (conn != root_link.conn) {
		return;
	}

	LOG_INF("Upstream controller disconnected, reason 0x%02x %s",
		reason, bt_hci_err_to_str(reason));

	(void)k_work_cancel(&root_link.auth_indication.work);
	(void)k_work_cancel(&root_link.secure_indication.work);
	root_link.auth_indication.queued = false;
	root_link.auth_indication.pending = false;
	root_link.auth_indication.use_notify = false;
	root_link.auth_indication.session = NULL;
	root_link.secure_indication.queued = false;
	root_link.secure_indication.pending = false;
	root_link.secure_indication.use_notify = false;
	root_link.secure_indication.session = NULL;

	if (root_link.session != NULL) {
		sap_on_disconnected(&root_link.sap_ctx, conn);
		root_link.session = NULL;
	}
	if (root_link.conn != NULL) {
		bt_conn_unref(root_link.conn);
		root_link.conn = NULL;
	}
	root_link.connection_active = false;

	if (root_dfu.active && !root_dfu.awaiting_reboot) {
		root_dfu_reset_state();
	}

	schedule_root_advertising_restart(K_MSEC(SAP_ROOT_ADV_RESTART_DELAY_MS));
}

static void root_security_changed(struct bt_conn *conn, bt_security_t level,
				  enum bt_security_err err)
{
	if ((root_link.session == NULL) || (conn != root_link.conn)) {
		return;
	}

	sap_on_security_changed(root_link.session, level, err);
	if (err != 0) {
		if (!root_link.policy.require_ble_encryption) {
			root_link.session->security_ready = true;
			SAP_TRACE("FLOW BLE: root ignored optional upstream security failure and kept SAP available");
			return;
		}

		clear_bond_on_security_failure(conn, err);
		LOG_ERR("Upstream security failed: %d %s", err,
			bt_security_err_to_str(err));
		(void)bt_conn_disconnect(conn, BT_HCI_ERR_AUTH_FAIL);
		schedule_root_advertising_restart(K_MSEC(SAP_SECURITY_FAILURE_RETRY_MS));
		return;
	}

	SAP_TRACE("FLOW 2/8 root BLE security satisfied for upstream controller");
}

static void root_recycled(void)
{
	if (root_link.advertising_restart_pending && !root_link.connection_active) {
		SAP_TRACE("FLOW reset-recovery: root connection object recycled, advertising can restart");
		(void)k_work_reschedule(&root_advertising_retry_work, K_NO_WAIT);
	}
}

BT_CONN_CB_DEFINE(root_conn_callbacks) = {
	.connected = root_connected,
	.disconnected = root_disconnected,
	.security_changed = root_security_changed,
	.recycled = root_recycled,
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
			    "peer_id=%u state=%s security_ready=%u authenticated=%u protected=%u dfu=%u led=%s pattern=%u selected=%u",
			    peer_id, session_state_str(peer->session->state),
			    peer->session->security_ready ? 1U : 0U,
			    sap_is_authenticated(peer->session) ? 1U : 0U,
			    peer->protected_service_ready ? 1U : 0U,
	#if defined(CONFIG_SAP_DEMO_DFU_CLIENT)
			    dfu_transport_ready(peer) ? 1U : 0U,
	#else
			    0U,
	#endif
			    led_name_for_peer_id(peer_id),
			    peer->observed_pattern_id,
			    (peer_id == selected_leaf_id()) ? 1U : 0U);
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
	struct sap_callbacks root_callbacks = {
		.send_auth = root_send_auth,
		.send_secure = root_send_secure,
		.authenticated = root_on_authenticated,
		.authentication_failed = root_on_auth_failed,
		.secure_payload_received = root_on_secure_payload,
	};
	int err;

	err = sap_init(&sap_ctx, SAP_ROLE_CENTRAL, policy, &callbacks);
	if (err != 0) {
		LOG_ERR("Failed to initialize SAP core (%d)", err);
		return 0;
	}

	if (IS_ENABLED(CONFIG_SAP_USE_BLE_SC_OOB_PAIRING)) {
		err = bt_conn_auth_cb_register(&auth_cb);
		if (err != 0) {
			LOG_ERR("Failed to register OOB auth callbacks (%d)", err);
			return 0;
		}
	}

	memset(&root_link, 0, sizeof(root_link));
	root_link.policy = *policy;
	root_link.policy.allowed_central_id = CONFIG_SAP_UPSTREAM_ALLOWED_CENTRAL_ID;
	root_link.policy.require_ble_encryption =
		IS_ENABLED(CONFIG_SAP_UPSTREAM_REQUIRE_BLE_ENCRYPTION);
	root_link.policy.use_ble_sc_oob_pairing = false;
	root_link.policy.use_link_security_for_secure_transport = false;
	err = sap_init(&root_link.sap_ctx, SAP_ROLE_PERIPHERAL, &root_link.policy,
		       &root_callbacks);
	if (err != 0) {
		LOG_ERR("Failed to initialize upstream SAP core (%d)", err);
		return 0;
	}

	k_work_init(&root_link.auth_indication.work, root_indicate_work_fn);
	k_work_init(&root_link.secure_indication.work, root_indicate_work_fn);

#if defined(CONFIG_SAP_DK_IO)
	err = dk_leds_init();
	if (err != 0) {
		LOG_WRN("Failed to initialize DK LEDs (%d)", err);
	} else {
		(void)dk_set_leds(DK_NO_LEDS_MSK);
	}
#endif

	start_scan();
	root_advertising_start();

	return 0;
}
