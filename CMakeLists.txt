#
# Copyright (c) 2026
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

if(CONFIG_SAP)
  zephyr_include_directories(include)
  zephyr_library()
  zephyr_library_include_directories(
    subsys/bluetooth/sap
  )
  zephyr_library_sources(
    subsys/bluetooth/sap/sap_crypto.c
    subsys/bluetooth/sap/sap_service.c
  )
endif()
