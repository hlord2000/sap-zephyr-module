#
# Copyright (c) 2026
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(sap_demo)

target_sources(app PRIVATE
  src/main.c
  src/demo_credentials.c
)

target_sources_ifdef(CONFIG_SAP_ROLE_CENTRAL app PRIVATE src/sap_central.c)
target_sources_ifdef(CONFIG_SAP_ROLE_PERIPHERAL app PRIVATE src/sap_peripheral.c)
target_include_directories(app PRIVATE src)

if(CONFIG_SAP_DEMO_DFU_CLIENT)
  target_include_directories(app PRIVATE
    ${ZEPHYR_BASE}/subsys/mgmt/mcumgr/util/include
  )
  target_sources(app PRIVATE
    ${ZEPHYR_BASE}/subsys/mgmt/mcumgr/util/src/zcbor_bulk.c
  )
endif()

if(CONFIG_SAP_DEMO_DFU_SERVER AND CONFIG_NRF_MCUBOOT_BOOT_REQUEST)
  target_include_directories(app PRIVATE
    ${WEST_TOPDIR}/bootloader/mcuboot/boot/bootutil/include
    ${WEST_TOPDIR}/bootloader/mcuboot/boot/zephyr/include
  )
endif()
