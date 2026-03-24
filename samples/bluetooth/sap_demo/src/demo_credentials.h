/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef SAP_CREDENTIALS_H__
#define SAP_CREDENTIALS_H__

#include <zephyr/types.h>

#include <sap/sap_service.h>

const struct sap_device_credential *demo_credentials_select(enum sap_role role);
const uint8_t *demo_credentials_ca_public_key(size_t *len);

#endif /* SAP_CREDENTIALS_H__ */
