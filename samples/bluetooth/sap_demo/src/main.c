/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <stdio.h>

#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>

#include <sap/sap_service.h>
#include <sap/sap_trace.h>

#include "demo_credentials.h"

LOG_MODULE_REGISTER(sap_main, CONFIG_SAP_LOG_LEVEL);

#if defined(CONFIG_SAP_ROLE_CENTRAL)
int sap_central_run(const struct sap_policy *policy);
#endif

#if defined(CONFIG_SAP_ROLE_PERIPHERAL)
int sap_peripheral_run(const struct sap_policy *policy);
#endif

static void set_name(enum sap_role role, const struct sap_device_credential *credential)
{
	char name[24];
	int err;

	snprintk(name, sizeof(name), "SAP-%c-%u",
		 (role == SAP_ROLE_CENTRAL) ? 'C' : 'P',
		 credential->cert.body.device_id);

	err = bt_set_name(name);
	if (err != 0) {
		LOG_WRN("Failed to set dynamic device name (%d)", err);
	}
}

static void pairing_complete(struct bt_conn *conn, bool bonded)
{
	struct bt_conn_info info;
	int err;

	err = bt_conn_get_info(conn, &info);
	if (err == 0) {
		LOG_INF("BLE pairing complete: bonded=%u level=%u key_size=%u",
			bonded, info.security.level, info.security.enc_key_size);
		return;
	}

	LOG_INF("BLE pairing complete: bonded=%u", bonded);
}

static void pairing_failed(struct bt_conn *conn, enum bt_security_err err)
{
	ARG_UNUSED(conn);
	LOG_ERR("BLE pairing failed: %d %s", err, bt_security_err_to_str(err));
}

static struct bt_conn_auth_info_cb auth_info_cb = {
	.pairing_complete = pairing_complete,
	.pairing_failed = pairing_failed,
};

int main(void)
{
	enum sap_role role = IS_ENABLED(CONFIG_SAP_ROLE_CENTRAL) ?
		SAP_ROLE_CENTRAL : SAP_ROLE_PERIPHERAL;
	const struct sap_device_credential *local_credential;
	struct sap_policy policy;
	size_t ca_len;
	int err;

	local_credential = demo_credentials_select(role);
	memset(&policy, 0, sizeof(policy));
	policy.local_credential = local_credential;
	policy.ca_public_key = demo_credentials_ca_public_key(&ca_len);
	policy.ca_public_key_len = ca_len;
	policy.expected_group_id = CONFIG_SAP_EXPECTED_GROUP_ID;
	policy.allowed_central_id = CONFIG_SAP_ALLOWED_CENTRAL_ID;
	policy.require_ble_encryption = IS_ENABLED(CONFIG_SAP_REQUIRE_BLE_ENCRYPTION);

	err = bt_enable(NULL);
	if (err != 0) {
		LOG_ERR("Bluetooth init failed (%d)", err);
		return 0;
	}

	if (IS_ENABLED(CONFIG_SETTINGS)) {
		err = settings_load();
		if (err != 0) {
			LOG_ERR("Settings load failed (%d)", err);
			return 0;
		}

		if (IS_ENABLED(CONFIG_SAP_DEMO_LOGGING)) {
			SAP_TRACE("FLOW 0/8 Bluetooth settings restored from NVS");
		}
	}

	err = bt_conn_auth_info_cb_register(&auth_info_cb);
	if (err != 0) {
		LOG_ERR("Failed to register pairing diagnostics (%d)", err);
		return 0;
	}

	set_name(role, local_credential);

	LOG_INF("SAP sample starting as %s, local device id %u",
		(role == SAP_ROLE_CENTRAL) ? "central" : "peripheral",
		local_credential->cert.body.device_id);
	if (IS_ENABLED(CONFIG_SAP_DEMO_LOGGING)) {
		SAP_TRACE("FLOW 0/8 local policy: group=0x%02x allowed_central=%u ble_encryption=%u",
			  policy.expected_group_id, policy.allowed_central_id,
			  policy.require_ble_encryption);
	}

	if (IS_ENABLED(CONFIG_SAP_REQUIRE_BLE_ENCRYPTION) &&
	    IS_ENABLED(CONFIG_BOARD_NRF54L15BSIM)) {
		LOG_WRN("BLE encryption is enabled on nrf54l15bsim even though local BabbleSim validation is not reliable");
	}

#if defined(CONFIG_SAP_ROLE_CENTRAL)
	return sap_central_run(&policy);
#else
	return sap_peripheral_run(&policy);
#endif
}
