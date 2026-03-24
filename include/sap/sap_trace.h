/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#ifndef SAP_TRACE_H__
#define SAP_TRACE_H__

#include <zephyr/logging/log.h>

#include <sap/sap_protocol.h>

#define SAP_TRACE_COLOR_PREFIX "\x1b[1;96m[SAP FLOW]\x1b[0m "
#define SAP_PACKET_TRACE_COLOR_PREFIX "\x1b[1;93m[SAP PACKET]\x1b[0m "

static inline const char *sap_role_str(enum sap_role role)
{
	switch (role) {
	case SAP_ROLE_CENTRAL:
		return "central";
	case SAP_ROLE_PERIPHERAL:
		return "peripheral";
	default:
		return "unknown";
	}
}

static inline const char *sap_msg_type_str(uint8_t type)
{
	switch (type) {
	case SAP_MSG_HELLO:
		return "HELLO";
	case SAP_MSG_PERIPHERAL_CHALLENGE:
		return "PERIPHERAL_CHALLENGE";
	case SAP_MSG_CENTRAL_AUTH:
		return "CENTRAL_AUTH";
	case SAP_MSG_PERIPHERAL_AUTH:
		return "PERIPHERAL_AUTH";
	case SAP_MSG_CONFIRM:
		return "CONFIRM";
	default:
		return (type >= SAP_APP_MSG_TYPE_MIN) ? "APP" : "UNKNOWN";
	}
}

#if defined(CONFIG_SAP_DEMO_LOGGING)
#define SAP_TRACE(...) LOG_DBG(SAP_TRACE_COLOR_PREFIX __VA_ARGS__)
#else
#define SAP_TRACE(...) do { } while (0)
#endif

#if defined(CONFIG_SAP_DEMO_LOGGING)
#define SAP_INFO_IF_NO_DEMO(...) do { } while (0)
#else
#define SAP_INFO_IF_NO_DEMO(...) LOG_INF(__VA_ARGS__)
#endif

#if defined(CONFIG_SAP_PACKET_LOGGING)
#define SAP_PACKET_TRACE(...) LOG_DBG(SAP_PACKET_TRACE_COLOR_PREFIX __VA_ARGS__)
#define SAP_PACKET_DUMP(data, len, label) \
	LOG_HEXDUMP_DBG(data, len, SAP_PACKET_TRACE_COLOR_PREFIX label)
#else
#define SAP_PACKET_TRACE(...) do { } while (0)
#define SAP_PACKET_DUMP(data, len, label) do { } while (0)
#endif

#endif /* SAP_TRACE_H__ */
