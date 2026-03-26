#
# Copyright (c) 2026
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

if(SB_CONFIG_BOOTLOADER_MCUBOOT AND
   "${BOARD}${BOARD_QUALIFIERS}" STREQUAL "nrf54l15dk/nrf54l15/cpuapp/ns")
  set(PM_STATIC_YML_FILE
    ${CMAKE_CURRENT_LIST_DIR}/pm_static_nrf54l15dk_nrf54l15_cpuapp_ns_mcuboot.yml
    CACHE INTERNAL "")
endif()

if(SB_CONFIG_BOOTLOADER_MCUBOOT AND
   "${BOARD}${BOARD_QUALIFIERS}" STREQUAL "xiao_nrf54l15/nrf54l15/cpuapp/ns")
  set(PM_STATIC_YML_FILE
    ${CMAKE_CURRENT_LIST_DIR}/pm_static_xiao_nrf54l15_nrf54l15_cpuapp_ns.yml
    CACHE INTERNAL "")
endif()

if("${BOARD}${BOARD_QUALIFIERS}" STREQUAL "xiao_nrf54l15/nrf54l15/cpuapp" OR
   "${BOARD}${BOARD_QUALIFIERS}" STREQUAL "xiao_nrf54l15/nrf54l15/cpuapp/ns")
  add_overlay_dts(
    mcuboot
    ${CMAKE_CURRENT_LIST_DIR}/sysbuild/boards/xiao_nrf54l15_nrf54l15_cpuapp_mcuboot.overlay)
endif()

if(SB_CONFIG_MCUBOOT_BUILD_DIRECT_XIP_VARIANT)
  if("${BOARD}${BOARD_QUALIFIERS}" STREQUAL "xiao_nrf54l15/nrf54l15/cpuapp/ns")
    set_config_bool(mcuboot CONFIG_RETAINED_MEM y)
    set_config_bool(mcuboot CONFIG_RETENTION y)
    set_config_bool(mcuboot CONFIG_NRF_MCUBOOT_BOOT_REQUEST y)
    set_config_bool(mcuboot CONFIG_CRC y)
    set_config_bool(mcuboot_secondary_app CONFIG_NRF_MCUBOOT_BOOT_REQUEST n)
    set_config_bool(mcuboot_secondary_app CONFIG_NCS_MCUBOOT_BOOT_REQUEST_TEST_SETS_BOOT_PREFERENCE n)
    add_overlay_dts(
      mcuboot_secondary_app
      ${CMAKE_CURRENT_LIST_DIR}/sysbuild/mcuboot_secondary_app/boards/xiao_nrf54l15_nrf54l15_cpuapp_ns.overlay)
  endif()
endif()
