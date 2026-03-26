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
#include <zephyr/drivers/gpio.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/sys/printk.h>

#if defined(CONFIG_HAS_NORDIC_RAM_CTRL)
#include <helpers/nrfx_ram_ctrl.h>
#endif

#if defined(CONFIG_ARM_NONSECURE_FIRMWARE) && defined(CONFIG_SOC_SERIES_NRF54L)
#include <hal/nrf_ctrlap.h>
#endif

#if defined(CONFIG_SAP_DEMO_DFU_SERVER)
#include <bootutil/boot_request.h>
#include <zephyr/mgmt/mcumgr/transport/smp_bt.h>
#endif

#if defined(CONFIG_PARTITION_MANAGER_ENABLED)
#include <pm_config.h>
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

LOG_MODULE_REGISTER(sap_peripheral, CONFIG_SAP_LOG_LEVEL);

#define ACTIVE_IMAGE 0

#if defined(CONFIG_PARTITION_MANAGER_ENABLED)
#define SLOT_A_FLASH_AREA_ID PM_MCUBOOT_PRIMARY_ID
#define SLOT_B_FLASH_AREA_ID PM_MCUBOOT_SECONDARY_ID

#ifdef CONFIG_NCS_IS_VARIANT_IMAGE
#define IS_SLOT_A 0
#define IS_SLOT_B 1
#else
#define IS_SLOT_A 1
#define IS_SLOT_B 0
#endif
#else
#define CODE_PARTITION DT_CHOSEN(zephyr_code_partition)
#define CODE_PARTITION_OFFSET FIXED_PARTITION_NODE_OFFSET(CODE_PARTITION)
#define SLOT_A_PARTITION slot0_partition
#define SLOT_B_PARTITION slot1_partition
#define SLOT_A_OFFSET FIXED_PARTITION_OFFSET(SLOT_A_PARTITION)
#define SLOT_B_OFFSET FIXED_PARTITION_OFFSET(SLOT_B_PARTITION)
#define SLOT_A_SIZE FIXED_PARTITION_SIZE(SLOT_A_PARTITION)
#define SLOT_B_SIZE FIXED_PARTITION_SIZE(SLOT_B_PARTITION)
#define SLOT_A_FLASH_AREA_ID FIXED_PARTITION_ID(SLOT_A_PARTITION)
#define SLOT_B_FLASH_AREA_ID FIXED_PARTITION_ID(SLOT_B_PARTITION)
#define IS_SLOT_A \
	(CODE_PARTITION_OFFSET >= SLOT_A_OFFSET && \
	 CODE_PARTITION_OFFSET < SLOT_A_OFFSET + SLOT_A_SIZE)
#define IS_SLOT_B \
	(CODE_PARTITION_OFFSET >= SLOT_B_OFFSET && \
	 CODE_PARTITION_OFFSET < SLOT_B_OFFSET + SLOT_B_SIZE)
#endif

#define SAP_ADV_RESTART_DELAY_MS 250
#define SAP_SECURITY_FAILURE_RETRY_MS 1000
#define SAP_STATUS_LED_ON_MS 120
#define SAP_STATUS_LED_OFF_MS 880
#define SAP_STATUS_LED_GAP_MS 120
#define SAP_STATUS_LED_DOUBLE_OFF_MS 640

#if defined(CONFIG_SAP_DK_IO)
#define SAP_BUTTON_MASK DK_BTN1_MSK
#endif

static const struct gpio_dt_spec status_led = GPIO_DT_SPEC_GET_OR(DT_ALIAS(led0), gpios, {0});

static struct sap_context sap_ctx;
static bool protected_registered;
#if defined(CONFIG_SAP_DEMO_DFU_SERVER)
static bool dfu_registered;
static bool dfu_apply_permanent;
#endif
static bool connection_active;
static bool advertising_restart_pending;
static bool status_led_ready;
static uint8_t status_led_phase;
volatile uint32_t sap_peripheral_adv_stage;
volatile int sap_peripheral_adv_err;
volatile uint32_t sap_peripheral_adv_calls;
static void advertising_start(void);

static void advertising_retry_fn(struct k_work *work);
K_WORK_DELAYABLE_DEFINE(advertising_retry_work, advertising_retry_fn);
static void status_led_work_fn(struct k_work *work);
K_WORK_DELAYABLE_DEFINE(status_led_work, status_led_work_fn);

#if defined(CONFIG_SAP_DEMO_DFU_SERVER)
static void dfu_apply_work_fn(struct k_work *work);
K_WORK_DELAYABLE_DEFINE(dfu_apply_work, dfu_apply_work_fn);
#endif

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

struct sap_indication_ctx {
	struct bt_gatt_indicate_params params;
	struct k_work work;
	struct sap_session *session;
	const struct bt_gatt_attr *attr;
	uint8_t msg_type;
	uint16_t len;
	bool queued;
	bool pending;
	uint8_t buffer[244];
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
			       BT_GATT_CHRC_WRITE | BT_GATT_CHRC_WRITE_WITHOUT_RESP |
				       BT_GATT_CHRC_NOTIFY | BT_GATT_CHRC_INDICATE,
			       BT_GATT_PERM_WRITE, NULL, sap_auth_write, NULL),
	BT_GATT_CCC(NULL, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
	BT_GATT_CHARACTERISTIC(BT_UUID_SAP_SECURE_TX,
			       BT_GATT_CHRC_NOTIFY | BT_GATT_CHRC_INDICATE,
			       BT_GATT_PERM_NONE, NULL, NULL, NULL),
	BT_GATT_CCC(NULL, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
	BT_GATT_CHARACTERISTIC(BT_UUID_SAP_SECURE_RX,
			       BT_GATT_CHRC_WRITE | BT_GATT_CHRC_WRITE_WITHOUT_RESP,
			       BT_GATT_PERM_WRITE, NULL, sap_secure_rx_write, NULL));

static struct bt_gatt_attr protected_attrs[] = {
	BT_GATT_PRIMARY_SERVICE(BT_UUID_SAP_DEMO_PROTECTED_SERVICE),
	BT_GATT_CHARACTERISTIC(BT_UUID_SAP_DEMO_PROTECTED_STATUS,
			       BT_GATT_CHRC_READ,
			       BT_GATT_PERM_READ,
			       protected_status_read, NULL, NULL),
};

static struct bt_gatt_service protected_svc = BT_GATT_SERVICE(protected_attrs);

#define SAP_AUTH_ATTR_INDEX 2
#define SAP_SECURE_TX_ATTR_INDEX 5

static struct sap_indication_ctx auth_indication;
static struct sap_indication_ctx secure_indication;

static void status_led_set(bool on)
{
	if (!status_led_ready) {
		return;
	}

	(void)gpio_pin_set_dt(&status_led, on ? 1 : 0);
}

static void status_led_work_fn(struct k_work *work)
{
	k_timeout_t delay = K_MSEC(SAP_STATUS_LED_OFF_MS);

	ARG_UNUSED(work);

	if (!status_led_ready) {
		return;
	}

	switch (CONFIG_SAP_DEMO_LED_PATTERN_ID) {
	case 2:
		switch (status_led_phase) {
		case 0:
			status_led_set(true);
			delay = K_MSEC(SAP_STATUS_LED_ON_MS);
			status_led_phase = 1U;
			break;
		case 1:
			status_led_set(false);
			delay = K_MSEC(SAP_STATUS_LED_GAP_MS);
			status_led_phase = 2U;
			break;
		case 2:
			status_led_set(true);
			delay = K_MSEC(SAP_STATUS_LED_ON_MS);
			status_led_phase = 3U;
			break;
		default:
			status_led_set(false);
			delay = K_MSEC(SAP_STATUS_LED_DOUBLE_OFF_MS);
			status_led_phase = 0U;
			break;
		}
		break;
	case 1:
	default:
		if (status_led_phase == 0U) {
			status_led_set(true);
			delay = K_MSEC(SAP_STATUS_LED_ON_MS);
			status_led_phase = 1U;
		} else {
			status_led_set(false);
			delay = K_MSEC(SAP_STATUS_LED_OFF_MS);
			status_led_phase = 0U;
		}
		break;
	}

	(void)k_work_reschedule(&status_led_work, delay);
}

static void status_led_start(void)
{
	if (!status_led_ready) {
		return;
	}

	status_led_phase = 0U;
	(void)k_work_reschedule(&status_led_work, K_NO_WAIT);
}

static void status_led_init(void)
{
	int err;

	if (!gpio_is_ready_dt(&status_led)) {
		return;
	}

	err = gpio_pin_configure_dt(&status_led, GPIO_OUTPUT_INACTIVE);
	if (err != 0) {
		LOG_WRN("Failed to configure status LED (%d)", err);
		return;
	}

	status_led_ready = true;
	status_led_set(false);
}

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

#if defined(CONFIG_SAP_DEMO_DFU_SERVER)
static void dfu_service_disable(void)
{
	int err;

	err = smp_bt_unregister();
	if ((err != 0) && (err != -ENOENT)) {
		LOG_WRN("Failed to unregister DFU SMP service (%d)", err);
		return;
	}

	dfu_registered = false;

	if (err == 0) {
		LOG_INF("DFU SMP service unregistered");
		SAP_TRACE("FLOW post-auth: peripheral hid the DFU SMP service");
	}
}

static void dfu_service_enable(void)
{
	int err;

	if (dfu_registered) {
		return;
	}

	err = smp_bt_register();
	if (err == -EALREADY) {
		dfu_registered = true;
	} else if (err != 0) {
		LOG_ERR("Failed to register DFU SMP service (%d)", err);
		return;
	} else {
		dfu_registered = true;
	}

	LOG_INF("DFU SMP service registered");
	SAP_TRACE("FLOW post-auth: peripheral exposed the DFU SMP service after SAP success");
}
#else
static void dfu_service_disable(void)
{
}

static void dfu_service_enable(void)
{
}
#endif

static void gated_services_disable(void)
{
	dfu_service_disable();
	protected_service_disable();
}

static void gated_services_enable(void)
{
	protected_service_enable();
	dfu_service_enable();
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

static void indicate_cb(struct bt_conn *conn,
			struct bt_gatt_indicate_params *params, uint8_t err)
{
	struct sap_indication_ctx *ctx = CONTAINER_OF(params, struct sap_indication_ctx,
						      params);

	ARG_UNUSED(conn);

	if (err != 0) {
		LOG_ERR("Peripheral indicate callback failed err=0x%02x len=%u msg_type=%u",
			err, ctx->len, ctx->msg_type);
	}
	if ((ctx->session != NULL) && ctx->session->in_use) {
		sap_on_tx_complete(ctx->session, ctx->msg_type, err);
	}
}

static void indicate_destroy(struct bt_gatt_indicate_params *params)
{
	struct sap_indication_ctx *ctx = CONTAINER_OF(params, struct sap_indication_ctx,
						      params);

	ctx->pending = false;
}

static void indicate_work_fn(struct k_work *work)
{
	struct sap_indication_ctx *ctx = CONTAINER_OF(work, struct sap_indication_ctx, work);
	int err;

	if ((ctx->session == NULL) || !ctx->session->in_use || (ctx->session->conn == NULL) ||
	    !ctx->queued || ctx->pending) {
		return;
	}

	ctx->params.attr = ctx->attr;
	ctx->params.func = indicate_cb;
	ctx->params.destroy = indicate_destroy;
	ctx->params.data = ctx->buffer;
	ctx->params.len = ctx->len;
	ctx->queued = false;
	ctx->pending = true;

	err = bt_gatt_indicate(ctx->session->conn, &ctx->params);
	if (err != 0) {
		LOG_ERR("Peripheral bt_gatt_indicate failed err=%d len=%u msg_type=%u",
			err, ctx->len, ctx->msg_type);
		ctx->pending = false;
		if ((ctx->session != NULL) && ctx->session->in_use) {
			sap_on_tx_complete(ctx->session, ctx->msg_type, err);
		}
	}
}

static int send_indication(struct sap_session *session, struct sap_indication_ctx *ctx,
			   const struct bt_gatt_attr *attr, uint8_t msg_type,
			   const uint8_t *data, size_t len)
{
	if (len > sizeof(ctx->buffer)) {
		LOG_ERR("Peripheral indication too large len=%u max=%u msg_type=%u",
			(uint32_t)len, (uint32_t)sizeof(ctx->buffer), msg_type);
		return -EMSGSIZE;
	}

	if (ctx->pending || ctx->queued) {
		LOG_ERR("Peripheral indication busy pending=%u queued=%u msg_type=%u",
			ctx->pending, ctx->queued, msg_type);
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

static int send_auth(struct sap_session *session, uint8_t msg_type,
		     const uint8_t *data, size_t len)
{
	return send_indication(session, &auth_indication, &sap_svc.attrs[SAP_AUTH_ATTR_INDEX],
			      msg_type, data, len);
}

static int send_secure(struct sap_session *session, uint8_t msg_type,
		       const uint8_t *data, size_t len)
{
	return send_indication(session, &secure_indication,
			      &sap_svc.attrs[SAP_SECURE_TX_ATTR_INDEX], msg_type,
			      data, len);
}

static void on_authenticated(struct sap_session *session)
{
	LOG_INF("SAP authenticated with central %u", session->peer_cert.body.device_id);
	SAP_TRACE("FLOW post-auth: peripheral now allows protected-service access for central %u",
		  session->peer_cert.body.device_id);
	gated_services_enable();

#if defined(CONFIG_SAP_DK_IO)
	(void)k_work_submit(&button_report_work);
#endif
}

static void on_auth_failed(struct sap_session *session, int reason)
{
	LOG_ERR("SAP auth failed on peripheral side (%d)", reason);
	gated_services_disable();
	if (session->conn != NULL) {
		(void)bt_conn_disconnect(session->conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
	}
}

static void on_secure_payload(struct sap_session *session, uint8_t msg_type,
			      const uint8_t *data, size_t len)
{
	ARG_UNUSED(session);

	if (msg_type == SAP_DEMO_MSG_TEXT) {
		LOG_INF("Secure payload from central: %.*s", len, (const char *)data);
		SAP_TRACE("FLOW post-auth: peripheral accepted encrypted application payload from central");
		return;
	}

#if defined(CONFIG_SAP_DEMO_DFU_SERVER)
	if (msg_type == SAP_DEMO_MSG_DFU_APPLY) {
		if (len != 1U) {
			LOG_ERR("Invalid DFU apply request length %u", (uint32_t)len);
			return;
		}

		dfu_apply_permanent = data[0] != 0U;
		LOG_INF("Received DFU apply request: permanent=%u",
			dfu_apply_permanent ? 1U : 0U);
		(void)k_work_reschedule(&dfu_apply_work, K_MSEC(100));
		return;
	}
#endif

	return;
}

#if defined(CONFIG_SAP_DEMO_DFU_SERVER)
static int request_uploaded_image_boot(void)
{
#if defined(CONFIG_MCUBOOT_BOOTLOADER_MODE_DIRECT_XIP)
	enum boot_slot target_slot = BOOT_SLOT_NONE;

	if (IS_SLOT_A) {
		target_slot = BOOT_SLOT_SECONDARY;
	} else if (IS_SLOT_B) {
		target_slot = BOOT_SLOT_PRIMARY;
	} else {
		LOG_ERR("Cannot determine current direct-XIP slot");
		return -EINVAL;
	}

	LOG_INF("Requesting direct-XIP boot preference for slot %s",
		(target_slot == BOOT_SLOT_SECONDARY) ? "B" : "A");
	return boot_request_set_preferred_slot(ACTIVE_IMAGE, target_slot);
#else
	return boot_request_upgrade(dfu_apply_permanent ? 1 : 0);
#endif
}

static void reboot_after_dfu_apply(void)
{
#if defined(CONFIG_HAS_NORDIC_RAM_CTRL)
	nrfx_ram_ctrl_power_enable_all_set(true);
	nrfx_ram_ctrl_retention_enable_all_set(true);
#endif

#if defined(CONFIG_ARM_NONSECURE_FIRMWARE) && defined(CONFIG_SOC_SERIES_NRF54L)
	LOG_INF("Triggering nRF54L CTRLAP pin reset");
	nrf_ctrlap_reset_trigger(NRF_CTRLAP, NRF_CTRLAP_RESET_PIN);
	for (;;) {
	}
#else
	sys_reboot(SYS_REBOOT_COLD);
#endif
}

static void dfu_apply_work_fn(struct k_work *work)
{
	int err;

	ARG_UNUSED(work);

	err = request_uploaded_image_boot();
	if (err != 0) {
		LOG_ERR("Failed to mark uploaded image for boot (%d)", err);
		return;
	}

	LOG_INF("Marked uploaded image for next boot, rebooting");
	reboot_after_dfu_apply();
}
#endif

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
	err = sap_send_secure(session, SAP_DEMO_MSG_BUTTON_STATE,
			      &payload, sizeof(payload));
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
		LOG_ERR("Rejecting auth write with offset=%u len=%u", offset, len);
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

	msg_len = snprintk(message, sizeof(message), "peripheral-%u-ready-p%u",
			   session->ctx->policy.local_credential->cert.body.device_id,
			   CONFIG_SAP_DEMO_LED_PATTERN_ID);

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

	printk("SAPDBG peripheral advertising_start active=%u stage=%u calls=%u\n",
	       connection_active, sap_peripheral_adv_stage, sap_peripheral_adv_calls);
	sap_peripheral_adv_calls++;
	sap_peripheral_adv_stage = 1U;
	sap_peripheral_adv_err = 0;
	(void)k_work_cancel_delayable(&advertising_retry_work);
	if (connection_active) {
		advertising_restart_pending = true;
		sap_peripheral_adv_stage = 2U;
		return;
	}

	err = bt_le_adv_start(BT_LE_ADV_CONN_FAST_1, sap_ad, ARRAY_SIZE(sap_ad),
			      NULL, 0);
	printk("SAPDBG peripheral bt_le_adv_start err=%d\n", err);
	sap_peripheral_adv_err = err;
	if (err == -EALREADY) {
		advertising_restart_pending = false;
		sap_peripheral_adv_stage = 3U;
		return;
	}

	if (err != 0) {
		LOG_ERR("Advertising failed to start (%d)", err);
		sap_peripheral_adv_stage = 4U;
		schedule_advertising_restart(K_MSEC(SAP_ADV_RESTART_DELAY_MS));
		return;
	}

	advertising_restart_pending = false;
	sap_peripheral_adv_stage = 5U;
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
	(void)k_work_cancel(&auth_indication.work);
	(void)k_work_cancel(&secure_indication.work);
	auth_indication.queued = false;
	auth_indication.pending = false;
	auth_indication.session = NULL;
	secure_indication.queued = false;
	secure_indication.pending = false;
	secure_indication.session = NULL;
	gated_services_disable();
	if (IS_ENABLED(CONFIG_SAP_USE_BLE_SC_OOB_PAIRING)) {
		bt_le_oob_set_sc_flag(false);
	}
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

static void pairing_oob_data_request(struct bt_conn *conn,
				     struct bt_conn_oob_info *oob_info)
{
	struct sap_session *session = sap_session_from_conn(&sap_ctx, conn);
	int err;

	if (session == NULL || !session->ctx->policy.use_ble_sc_oob_pairing) {
		LOG_ERR("Peripheral OOB request has no SAP OOB session");
		bt_conn_auth_cancel(conn);
		return;
	}

	if (oob_info->type != BT_CONN_OOB_LE_SC || !session->local_oob_ready ||
	    !session->peer_oob_ready) {
		LOG_ERR("Peripheral OOB request invalid type=%u local=%u peer=%u",
			oob_info->type, session->local_oob_ready, session->peer_oob_ready);
		bt_conn_auth_cancel(conn);
		return;
	}

	LOG_INF("Peripheral OOB data request config=%u", oob_info->lesc.oob_config);
	err = bt_le_oob_set_sc_data(conn, &session->local_oob_sc, &session->peer_oob_sc);
	if (err != 0) {
		LOG_ERR("Failed to apply peripheral LE SC OOB data (%d)", err);
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

	return sap_send_secure(session, SAP_DEMO_MSG_TEXT,
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

	shell_print(sh, "connected=1 authenticated=%u protected=%u dfu=%u central_id=%u button1=%u pattern=%u",
		    sap_is_authenticated(session) ? 1U : 0U,
#if defined(CONFIG_SAP_DEMO_DFU_SERVER)
		    protected_registered ? 1U : 0U,
		    dfu_registered ? 1U : 0U,
#else
		    protected_registered ? 1U : 0U,
		    0U,
#endif
		    session->peer_cert.body.device_id,
		    button_state,
		    CONFIG_SAP_DEMO_LED_PATTERN_ID);
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
	printk("SAPDBG peripheral sap_init err=%d\n", err);
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

	k_work_init(&auth_indication.work, indicate_work_fn);
	k_work_init(&secure_indication.work, indicate_work_fn);

	dfu_service_disable();
	status_led_init();
	status_led_start();
	printk("SAPDBG peripheral services initialized\n");

#if defined(CONFIG_SAP_DK_IO)
	err = dk_buttons_init(button_changed);
	if (err != 0) {
		LOG_WRN("Failed to initialize DK buttons (%d)", err);
	} else {
		button_pressed = (dk_get_buttons() & SAP_BUTTON_MASK) != 0U;
	}
#endif

	advertising_start();
	printk("SAPDBG peripheral run done\n");
	return 0;
}
