#
# Copyright (c) 2026
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(sap)

target_sources(app PRIVATE
  src/main.c
  src/sap_crypto.c
  src/sap_credentials.c
  src/sap_service.c
)

target_sources_ifdef(CONFIG_SAP_ROLE_CENTRAL app PRIVATE src/sap_central.c)
target_sources_ifdef(CONFIG_SAP_ROLE_PERIPHERAL app PRIVATE src/sap_peripheral.c)
