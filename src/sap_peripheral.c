/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/util.h>
#include <zephyr/logging/log.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/hci.h>

#if defined(CONFIG_SAP_SHELL)
#include <zephyr/shell/shell.h>
#endif

#if defined(CONFIG_SAP_DK_IO)
#include <dk_buttons_and_leds.h>
#endif

#include "sap_service.h"
#include "sap_trace.h"

LOG_MODULE_REGISTER(sap_peripheral, CONFIG_SAP_LOG_LEVEL);

#define SAP_ADV_RESTART_DELAY_MS 250
#define SAP_SECURITY_FAILURE_RETRY_MS 1000

#if defined(CONFIG_SAP_DK_IO)
#define SAP_BUTTON_MASK DK_BTN1_MSK
#endif

static struct sap_context sap_ctx;
static bool protected_registered;
static bool connection_active;
static bool advertising_restart_pending;
static void advertising_start(void);

static void advertising_retry_fn(struct k_work *work);
K_WORK_DELAYABLE_DEFINE(advertising_retry_work, advertising_retry_fn);

#if defined(CONFIG_SAP_DK_IO)
static bool button_pressed;
static void button_report_fn(struct k_work *work);
K_WORK_DEFINE(button_report_work, button_report_fn);
#endif

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

static ssize_t sap_auth_write(struct bt_conn *conn,
			      const struct bt_gatt_attr *attr,
			      const void *buf, uint16_t len, uint16_t offset,
			      uint8_t flags);
static ssize_t sap_secure_rx_write(struct bt_conn *conn,
				   const struct bt_gatt_attr *attr,
				   const void *buf, uint16_t len, uint16_t offset,
				   uint8_t flags);
static ssize_t protected_status_read(struct bt_conn *conn,
				     const struct bt_gatt_attr *attr,
				     void *buf, uint16_t len, uint16_t offset);

BT_GATT_SERVICE_DEFINE(sap_svc,
	BT_GATT_PRIMARY_SERVICE(BT_UUID_SAP_SERVICE),
	BT_GATT_CHARACTERISTIC(BT_UUID_SAP_AUTH,
			       BT_GATT_CHRC_WRITE_WITHOUT_RESP | BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_WRITE, NULL, sap_auth_write, NULL),
	BT_GATT_CCC(NULL, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
	BT_GATT_CHARACTERISTIC(BT_UUID_SAP_SECURE_TX,
			       BT_GATT_CHRC_NOTIFY,
			       BT_GATT_PERM_NONE, NULL, NULL, NULL),
	BT_GATT_CCC(NULL, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
	BT_GATT_CHARACTERISTIC(BT_UUID_SAP_SECURE_RX,
			       BT_GATT_CHRC_WRITE_WITHOUT_RESP,
			       BT_GATT_PERM_WRITE, NULL, sap_secure_rx_write, NULL));

static struct bt_gatt_attr protected_attrs[] = {
	BT_GATT_PRIMARY_SERVICE(BT_UUID_SAP_PROTECTED_SERVICE),
	BT_GATT_CHARACTERISTIC(BT_UUID_SAP_PROTECTED_STATUS,
			       BT_GATT_CHRC_READ,
			       BT_GATT_PERM_READ,
			       protected_status_read, NULL, NULL),
};

static struct bt_gatt_service protected_svc = BT_GATT_SERVICE(protected_attrs);

#define SAP_AUTH_ATTR_INDEX 2
#define SAP_SECURE_TX_ATTR_INDEX 5

#if defined(CONFIG_SAP_SHELL) || defined(CONFIG_SAP_DK_IO)
static struct sap_session *active_session(bool require_authenticated)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(sap_ctx.sessions); i++) {
		struct sap_session *session = &sap_ctx.sessions[i];

		if (!session->in_use || (session->conn == NULL)) {
			continue;
		}

		if (require_authenticated && !sap_is_authenticated(session)) {
			continue;
		}

		return session;
	}

	return NULL;
}
#endif

static void protected_service_disable(void)
{
	if (!protected_registered) {
		return;
	}

	(void)bt_gatt_service_unregister(&protected_svc);
	protected_registered = false;
}

static void protected_service_enable(void)
{
	int err;

	if (protected_registered) {
		return;
	}

	err = bt_gatt_service_register(&protected_svc);
	if (err != 0) {
		LOG_ERR("Failed to register protected service (%d)", err);
		return;
	}

	protected_registered = true;
	LOG_INF("Protected service registered");
	SAP_TRACE("FLOW post-auth: peripheral exposed the protected service after SAP success");
}

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

static int send_auth(struct sap_session *session, const uint8_t *data, size_t len)
{
	return bt_gatt_notify(session->conn, &sap_svc.attrs[SAP_AUTH_ATTR_INDEX], data,
			      len);
}

static int send_secure(struct sap_session *session, const uint8_t *data, size_t len)
{
	return bt_gatt_notify(session->conn, &sap_svc.attrs[SAP_SECURE_TX_ATTR_INDEX],
			      data, len);
}

static void on_authenticated(struct sap_session *session)
{
	LOG_INF("SAP authenticated with central %u", session->peer_cert.body.device_id);
	SAP_TRACE("FLOW post-auth: peripheral now allows protected-service access for central %u",
		  session->peer_cert.body.device_id);
	protected_service_enable();

#if defined(CONFIG_SAP_DK_IO)
	(void)k_work_submit(&button_report_work);
#endif
}

static void on_auth_failed(struct sap_session *session, int reason)
{
	LOG_ERR("SAP auth failed on peripheral side (%d)", reason);
	protected_service_disable();
	if (session->conn != NULL) {
		(void)bt_conn_disconnect(session->conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	}
}

static void on_secure_payload(struct sap_session *session, uint8_t msg_type,
			      const uint8_t *data, size_t len)
{
	char response[48];
	int resp_len;

	if (msg_type != SAP_MSG_SECURE_DATA) {
		return;
	}

	LOG_INF("Secure payload from central: %.*s", len, (const char *)data);
	SAP_TRACE("FLOW post-auth: peripheral accepted encrypted application payload from central");
	resp_len = snprintk(response, sizeof(response), "ack-%u",
			    session->ctx->policy.local_credential->cert.body.device_id);
	(void)sap_send_secure(session, SAP_MSG_SECURE_ACK,
			      (const uint8_t *)response, (size_t)resp_len);
}

#if defined(CONFIG_SAP_DK_IO)
static void button_report_fn(struct k_work *work)
{
	struct sap_session *session;
	uint8_t payload;
	int err;

	ARG_UNUSED(work);

	session = active_session(true);
	if (session == NULL) {
		return;
	}

	payload = button_pressed ? 1U : 0U;
	err = sap_send_secure(session, SAP_MSG_BUTTON_STATE, &payload, sizeof(payload));
	if (err != 0) {
		LOG_ERR("Failed to send secure button state (%d)", err);
		return;
	}

	SAP_TRACE("FLOW app-io: peripheral sent button 1 state %u to the central",
		  payload);
}

static void button_changed(uint32_t button_state, uint32_t has_changed)
{
	if ((has_changed & SAP_BUTTON_MASK) == 0U) {
		return;
	}

	button_pressed = (button_state & SAP_BUTTON_MASK) != 0U;
	(void)k_work_submit(&button_report_work);
}
#endif

static ssize_t sap_auth_write(struct bt_conn *conn,
			      const struct bt_gatt_attr *attr,
			      const void *buf, uint16_t len, uint16_t offset,
			      uint8_t flags)
{
	struct sap_session *session;
	int err;

	ARG_UNUSED(attr);
	ARG_UNUSED(flags);

	if (offset != 0U) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	session = sap_session_from_conn(&sap_ctx, conn);
	if (session == NULL) {
		return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
	}

	err = sap_handle_auth_rx(session, buf, len);
	if (err != 0) {
		return BT_GATT_ERR(BT_ATT_ERR_AUTHORIZATION);
	}

	return len;
}

static ssize_t sap_secure_rx_write(struct bt_conn *conn,
				   const struct bt_gatt_attr *attr,
				   const void *buf, uint16_t len, uint16_t offset,
				   uint8_t flags)
{
	struct sap_session *session;
	int err;

	ARG_UNUSED(attr);
	ARG_UNUSED(flags);

	if (offset != 0U) {
		return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET);
	}

	session = sap_session_from_conn(&sap_ctx, conn);
	if (session == NULL) {
		return BT_GATT_ERR(BT_ATT_ERR_UNLIKELY);
	}

	err = sap_handle_secure_rx(session, buf, len);
	if (err != 0) {
		return BT_GATT_ERR(BT_ATT_ERR_AUTHORIZATION);
	}

	return len;
}

static ssize_t protected_status_read(struct bt_conn *conn,
				     const struct bt_gatt_attr *attr,
				     void *buf, uint16_t len, uint16_t offset)
{
	struct sap_session *session;
	char message[48];
	int msg_len;

	ARG_UNUSED(attr);

	session = sap_session_from_conn(&sap_ctx, conn);
	if (session == NULL || !sap_is_authenticated(session)) {
		return BT_GATT_ERR(BT_ATT_ERR_AUTHORIZATION);
	}

	msg_len = snprintk(message, sizeof(message), "peripheral-%u-ready",
			   session->ctx->policy.local_credential->cert.body.device_id);

	return bt_gatt_attr_read(conn, attr, buf, len, offset, message, msg_len);
}

static void advertising_retry_fn(struct k_work *work)
{
	ARG_UNUSED(work);
	advertising_start();
}

static void schedule_advertising_restart(k_timeout_t delay)
{
	advertising_restart_pending = true;
	(void)k_work_reschedule(&advertising_retry_work, delay);
}

static void advertising_start(void)
{
	int err;

	(void)k_work_cancel_delayable(&advertising_retry_work);
	if (connection_active) {
		advertising_restart_pending = true;
		return;
	}

	err = bt_le_adv_start(BT_LE_ADV_CONN_FAST_1, sap_ad, ARRAY_SIZE(sap_ad),
			      NULL, 0);
	if (err == -EALREADY) {
		advertising_restart_pending = false;
		return;
	}

	if (err != 0) {
		LOG_ERR("Advertising failed to start (%d)", err);
		schedule_advertising_restart(K_MSEC(SAP_ADV_RESTART_DELAY_MS));
		return;
	}

	advertising_restart_pending = false;
	LOG_INF("SAP peripheral advertising");
	SAP_TRACE("FLOW BLE: peripheral advertising SAP service UUID only");
}

static void connected(struct bt_conn *conn, uint8_t err)
{
	struct sap_session *session;

	if (err != 0U) {
		LOG_ERR("Peripheral connection failed (0x%02x)", err);
		connection_active = false;
		schedule_advertising_restart(K_MSEC(SAP_ADV_RESTART_DELAY_MS));
		return;
	}

	connection_active = true;
	SAP_TRACE("FLOW 1/8 peripheral BLE link established");
	advertising_restart_pending = false;
	(void)k_work_cancel_delayable(&advertising_retry_work);

	session = sap_on_connected(&sap_ctx, conn);
	if (session == NULL) {
		LOG_ERR("No SAP session slots left");
		connection_active = false;
		(void)bt_conn_disconnect(conn, BT_HCI_ERR_CONN_LIMIT_EXCEEDED);
		return;
	}
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	LOG_INF("Peripheral disconnected reason 0x%02x %s", reason,
		bt_hci_err_to_str(reason));
	connection_active = false;
	protected_service_disable();
	sap_on_disconnected(&sap_ctx, conn);
	schedule_advertising_restart(K_MSEC(SAP_ADV_RESTART_DELAY_MS));
}

static void security_changed(struct bt_conn *conn, bt_security_t level,
			     enum bt_security_err err)
{
	struct sap_session *session = sap_session_from_conn(&sap_ctx, conn);

	if (session != NULL) {
		sap_on_security_changed(session, level, err);
	}

	if (err != 0) {
		clear_bond_on_security_failure(conn, err);
		LOG_ERR("Security failed: %d %s", err, bt_security_err_to_str(err));
		(void)bt_conn_disconnect(conn, BT_HCI_ERR_AUTH_FAIL);
		schedule_advertising_restart(K_MSEC(SAP_SECURITY_FAILURE_RETRY_MS));
		return;
	}

	if (session != NULL) {
		SAP_TRACE("FLOW 2/8 peripheral BLE security satisfied");
	}
}

static void recycled(void)
{
	if (advertising_restart_pending && !connection_active) {
		SAP_TRACE("FLOW reset-recovery: peripheral connection object recycled, advertising can restart");
		(void)k_work_reschedule(&advertising_retry_work, K_NO_WAIT);
	}
}

BT_CONN_CB_DEFINE(peripheral_conn_callbacks) = {
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

static int send_text_to_central(const char *text)
{
	struct sap_session *session = active_session(true);

	if (session == NULL) {
		return -ENOTCONN;
	}

	return sap_send_secure(session, SAP_MSG_SECURE_DATA,
			       (const uint8_t *)text, strlen(text));
}

static int cmd_sap_status(const struct shell *sh, size_t argc, char **argv)
{
	struct sap_session *session = active_session(false);
	unsigned int button_state = 0U;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	if (session == NULL) {
		shell_print(sh, "No active SAP session");
		return 0;
	}

	#if defined(CONFIG_SAP_DK_IO)
	button_state = button_pressed ? 1U : 0U;
	#endif

	shell_print(sh, "connected=1 authenticated=%u central_id=%u button1=%u",
		    sap_is_authenticated(session) ? 1U : 0U,
		    session->peer_cert.body.device_id,
		    button_state);
	return 0;
}

static int cmd_sap_send(const struct shell *sh, size_t argc, char **argv)
{
	char payload[160];
	int err;

	err = join_shell_args(argc, argv, 1U, payload, sizeof(payload));
	if (err < 0) {
		shell_error(sh, "Text is too long for one SAP payload");
		return err;
	}

	err = send_text_to_central(payload);
	if (err != 0) {
		shell_error(sh, "Failed to send secure text (%d)", err);
		return err;
	}

	shell_print(sh, "Sent secure text to central: %s", payload);
	return 0;
}

#if defined(CONFIG_SAP_DK_IO)
static int cmd_sap_button(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argc);

	if (strcmp(argv[1], "pressed") == 0) {
		button_pressed = true;
	} else if (strcmp(argv[1], "released") == 0) {
		button_pressed = false;
	} else if (strcmp(argv[1], "toggle") == 0) {
		button_pressed = !button_pressed;
	} else {
		shell_error(sh, "Use 'pressed', 'released', or 'toggle'");
		return -EINVAL;
	}

	(void)k_work_submit(&button_report_work);
	shell_print(sh, "Peripheral button 1 state is now %s",
		    button_pressed ? "pressed" : "released");
	return 0;
}
#endif

SHELL_STATIC_SUBCMD_SET_CREATE(sap_cmds,
	SHELL_CMD(status, NULL, "Show current SAP peripheral status", cmd_sap_status),
	SHELL_CMD_ARG(send, NULL, "send <text...>", cmd_sap_send, 2, 14),
#if defined(CONFIG_SAP_DK_IO)
	SHELL_CMD_ARG(button, NULL, "button <pressed|released|toggle>", cmd_sap_button, 2, 0),
#endif
	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(sap, &sap_cmds, "SAP demo commands", NULL);
#endif

int sap_peripheral_run(const struct sap_policy *policy)
{
	struct sap_callbacks callbacks = {
		.send_auth = send_auth,
		.send_secure = send_secure,
		.authenticated = on_authenticated,
		.authentication_failed = on_auth_failed,
		.secure_payload_received = on_secure_payload,
	};
	int err;

	err = sap_init(&sap_ctx, SAP_ROLE_PERIPHERAL, policy, &callbacks);
	if (err != 0) {
		LOG_ERR("Failed to initialize SAP core (%d)", err);
		return 0;
	}

#if defined(CONFIG_SAP_DK_IO)
	err = dk_buttons_init(button_changed);
	if (err != 0) {
		LOG_WRN("Failed to initialize DK buttons (%d)", err);
	} else {
		button_pressed = (dk_get_buttons() & SAP_BUTTON_MASK) != 0U;
	}
#endif

	advertising_start();
	return 0;
}
