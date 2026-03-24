/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef SAP_CREDENTIALS_H__
#define SAP_CREDENTIALS_H__

#include <zephyr/types.h>

#include "sap_protocol.h"

struct sap_device_credential {
	uint8_t simulated_device_number;
	uint8_t private_key[SAP_IDENTITY_PRIVATE_KEY_LEN];
	struct sap_certificate cert;
};

const struct sap_device_credential *sap_credentials_select(enum sap_role role);
const uint8_t *sap_credentials_ca_public_key(size_t *len);

#endif /* SAP_CREDENTIALS_H__ */
