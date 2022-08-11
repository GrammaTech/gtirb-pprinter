set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE)

set(CPACK_DEB_COMPONENT_INSTALL ON)

set(LIB_COMPONENTS pprinter_library layout_library)
set(DEV_COMPONENTS pprinter_headers layout_headers cmake_config cmake_target)
set(DRIVER_COMPONENTS pprinter_driver layout_driver)

set(CPACK_GTIRB_PPRINTER_DEB_VERSION
    "${CPACK_GTIRB_PPRINTER_VERSION}-${CPACK_DEBIAN_PACKAGE_RELEASE}")
set(CPACK_GTIRB_DEB_VERSION
    "${CPACK_GTIRB_VERSION}-${CPACK_DEBIAN_PACKAGE_RELEASE}")

set(CPACK_GTIRB_PPRINTER_SUFFIX "")
set(CPACK_GTIRB_SUFFIX "")
set(CPACK_CAPSTONE_PKG_SUFFIX "")

if(CPACK_GTIRB_PPRINTER_STABLE_PKG_NAME)
  string(REGEX REPLACE "^[0-9]+:" "" CPACK_CAPSTONE_PKG_SUFFIX
                       "${CPACK_CAPSTONE_PKG_VERSION}")
  set(CPACK_GTIRB_PPRINTER_SUFFIX "-${CPACK_GTIRB_PPRINTER_VERSION}")
  set(CPACK_GTIRB_SUFFIX "-${CPACK_GTIRB_VERSION}")
  set(CPACK_CAPSTONE_PKG_SUFFIX "-${CPACK_CAPSTONE_PKG_SUFFIX}")
endif()

if("${CPACK_GTIRB_PPRINTER_PACKAGE}" STREQUAL "deb-lib")
  set(CPACK_DEBIAN_PACKAGE_NAME
      "libgtirb-pprinter${CPACK_GTIRB_PPRINTER_SUFFIX}")
  set(CPACK_PACKAGE_FILE_NAME "libgtirb-pprinter")
  set(CPACK_COMPONENTS_ALL ${LIB_COMPONENTS})
  if("${CPACK_DEBIAN_PACKAGE_RELEASE}" STREQUAL "focal")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "gcc, libstdc++6, libc6, libgcc1, libgtirb${CPACK_GTIRB_SUFFIX} (=${CPACK_GTIRB_DEB_VERSION}), libboost-filesystem1.71.0, libcapstone-dev${CPACK_CAPSTONE_PKG_SUFFIX} (=${CPACK_CAPSTONE_PKG_VERSION})"
    )
  else()
    message(
      SEND_ERROR "Unknown / missing value for CPACK_DEBIAN_PACKAGE_RELEASE.")
  endif()
elseif("${CPACK_GTIRB_PPRINTER_PACKAGE}" STREQUAL "deb-lib-dbg")
  set(CPACK_DEBIAN_PACKAGE_NAME
      "libgtirb-pprinter-dbg${CPACK_GTIRB_PPRINTER_SUFFIX}")
  set(CPACK_PACKAGE_FILE_NAME "libgtirb-pprinter-dbg")
  set(CPACK_COMPONENTS_ALL pprinter-debug-file layout-debug-file)
  set(CPACK_DEBIAN_PACKAGE_DEPENDS
      "libgtirb-pprinter${CPACK_GTIRB_PPRINTER_SUFFIX} (=${CPACK_GTIRB_PPRINTER_DEB_VERSION})"
  )
elseif("${CPACK_GTIRB_PPRINTER_PACKAGE}" STREQUAL "deb-dev")
  set(CPACK_DEBIAN_PACKAGE_NAME
      "libgtirb-pprinter-dev${CPACK_GTIRB_PPRINTER_SUFFIX}")
  set(CPACK_PACKAGE_FILE_NAME "libgtirb-pprinter-dev")
  set(CPACK_COMPONENTS_ALL ${DEV_COMPONENTS})
  if("${CPACK_DEBIAN_PACKAGE_RELEASE}" STREQUAL "focal")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb-dev${CPACK_GTIRB_SUFFIX} (=${CPACK_GTIRB_DEB_VERSION}), libgtirb-pprinter${CPACK_GTIRB_PPRINTER_SUFFIX} (=${CPACK_GTIRB_PPRINTER_DEB_VERSION}), libboost-dev, libcapstone-dev${CPACK_CAPSTONE_PKG_SUFFIX} (=${CPACK_CAPSTONE_PKG_VERSION})"
    )
  else()
    message(
      SEND_ERROR "Unknown / missing value for CPACK_DEBIAN_PACKAGE_RELEASE.")
  endif()

elseif("${CPACK_GTIRB_PPRINTER_PACKAGE}" STREQUAL "deb-driver")
  set(CPACK_DEBIAN_PACKAGE_NAME "gtirb-pprinter${CPACK_GTIRB_PPRINTER_SUFFIX}")
  set(CPACK_PACKAGE_FILE_NAME "gtirb-pprinter")
  set(CPACK_COMPONENTS_ALL ${DRIVER_COMPONENTS})
  if("${CPACK_DEBIAN_PACKAGE_RELEASE}" STREQUAL "focal")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb${CPACK_GTIRB_SUFFIX} (=${CPACK_GTIRB_DEB_VERSION}), libgtirb-pprinter${CPACK_GTIRB_PPRINTER_SUFFIX} (=${CPACK_GTIRB_PPRINTER_DEB_VERSION}), libboost-filesystem1.71.0, libboost-program-options1.71.0, libcapstone-dev${CPACK_CAPSTONE_PKG_SUFFIX} (=${CPACK_CAPSTONE_PKG_VERSION})"
    )
  else()
    message(
      SEND_ERROR "Unknown / missing value for CPACK_DEBIAN_PACKAGE_RELEASE.")
  endif()
elseif("${CPACK_GTIRB_PPRINTER_PACKAGE}" STREQUAL "deb-driver-dbg")
  set(CPACK_DEBIAN_PACKAGE_NAME
      "gtirb-pprinter-dbg${CPACK_GTIRB_PPRINTER_SUFFIX}")
  set(CPACK_PACKAGE_FILE_NAME "gtirb-pprinter-dbg")
  set(CPACK_COMPONENTS_ALL pprinter-driver-debug-file layout-driver-debug-file)
  set(CPACK_DEBIAN_PACKAGE_DEPENDS
      "gtirb-pprinter${CPACK_GTIRB_PPRINTER_SUFFIX} (=${CPACK_GTIRB_PPRINTER_DEB_VERSION})"
  )
endif()
