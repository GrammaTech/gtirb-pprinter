set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE)

set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_RPM_COMPONENT_INSTALL ON)

set(LIB_COMPONENTS pprinter_library layout_library)
set(DEV_COMPONENTS pprinter_headers layout_headers cmake_config cmake_target)
set(DRIVER_COMPONENTS pprinter_driver layout_driver)

set(CPACK_GTIRB_PPRINTER_DEB_VERSION
    "${CPACK_GTIRB_PPRINTER_VERSION}-${CPACK_DEBIAN_PACKAGE_RELEASE}")
set(CPACK_GTIRB_DEB_VERSION
    "${CPACK_GTIRB_VERSION}-${CPACK_DEBIAN_PACKAGE_RELEASE}")

set(CPACK_GTIRB_PPRINTER_SUFFIX "")
set(CPACK_GTIRB_SUFFIX "")

if("${CPACK_GTIRB_PPRINTER_STABLE_PKG_NAME}")
  set(CPACK_GTIRB_PPRINTER_SUFFIX "-${CPACK_GTIRB_PPRINTER_DEB_VERSION}")
  set(CPACK_GTIRB_SUFFIX "-${CPACK_GTIRB_DEB_VERSION}")
endif()

if("${CPACK_GTIRB_PPRINTER_PACKAGE}" STREQUAL "deb-lib")
  set(CPACK_DEBIAN_PACKAGE_NAME
      "libgtirb-pprinter${CPACK_GTIRB_PPRINTER_SUFFIX}")
  set(CPACK_PACKAGE_FILE_NAME "libgtirb-pprinter")
  set(CPACK_COMPONENTS_ALL ${LIB_COMPONENTS})
  if("${CPACK_DEBIAN_PACKAGE_RELEASE}" STREQUAL "focal")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb${CPACK_GTIRB_SUFFIX} (=${CPACK_GTIRB_DEB_VERSION}), libboost-filesystem1.71.0, libcapstone-dev (=${CPACK_CAPSTONE_PKG_VERSION})"
    )
  else()
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb${CPACK_GTIRB_SUFFIX} (=${CPACK_GTIRB_DEB_VERSION}), libboost (>=1.67) | libboost1.67, libcapstone-dev (=${CPACK_CAPSTONE_PKG_VERSION})"
    )
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
        "libstdc++6, libc6, libgcc1, libgtirb-dev${CPACK_GTIRB_SUFFIX} (=${CPACK_GTIRB_DEB_VERSION}), libgtirb-pprinter${CPACK_GTIRB_PPRINTER_SUFFIX} (=${CPACK_GTIRB_PPRINTER_DEB_VERSION}), libboost-dev, libcapstone-dev (=${CPACK_CAPSTONE_PKG_VERSION})"
    )
  else()
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb-dev${CPACK_GTIRB_SUFFIX} (=${CPACK_GTIRB_DEB_VERSION}), libgtirb-pprinter${CPACK_GTIRB_PPRINTER_SUFFIX} (=${CPACK_GTIRB_PPRINTER_DEB_VERSION}), libboost-dev (>=1.67) | libboost1.67-dev, libcapstone-dev (=${CPACK_CAPSTONE_PKG_VERSION})"
    )
  endif()

elseif("${CPACK_GTIRB_PPRINTER_PACKAGE}" STREQUAL "deb-driver")
  set(CPACK_DEBIAN_PACKAGE_NAME "gtirb-pprinter${CPACK_GTIRB_PPRINTER_SUFFIX}")
  set(CPACK_PACKAGE_FILE_NAME "gtirb-pprinter")
  set(CPACK_COMPONENTS_ALL ${DRIVER_COMPONENTS})
  if("${CPACK_DEBIAN_PACKAGE_RELEASE}" STREQUAL "focal")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb${CPACK_GTIRB_SUFFIX} (=${CPACK_GTIRB_DEB_VERSION}), libgtirb-pprinter${CPACK_GTIRB_PPRINTER_SUFFIX} (=${CPACK_GTIRB_PPRINTER_DEB_VERSION}), libboost-filesystem1.71.0, libboost-program-options1.71.0, libcapstone-dev (=${CPACK_CAPSTONE_PKG_VERSION})"
    )
  else()
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb${CPACK_GTIRB_SUFFIX} (=${CPACK_GTIRB_DEB_VERSION}), libgtirb-pprinter${CPACK_GTIRB_PPRINTER_SUFFIX} (=${CPACK_GTIRB_PPRINTER_DEB_VERSION}), libboost (>=1.67) | libboost1.67, libcapstone-dev (=${CPACK_CAPSTONE_PKG_VERSION})"
    )
  endif()
elseif("${CPACK_GTIRB_PPRINTER_PACKAGE}" STREQUAL "deb-driver-dbg")
  set(CPACK_DEBIAN_PACKAGE_NAME
      "gtirb-pprinter-dbg${CPACK_GTIRB_PPRINTER_SUFFIX}")
  set(CPACK_PACKAGE_FILE_NAME "gtirb-pprinter-dbg")
  set(CPACK_COMPONENTS_ALL pprinter-driver-debug-file layout-driver-debug-file)
  set(CPACK_DEBIAN_PACKAGE_DEPENDS
      "gtirb-pprinter${CPACK_GTIRB_PPRINTER_SUFFIX} (=${CPACK_GTIRB_PPRINTER_DEB_VERSION})"
  )

  # RPM packages
elseif("${CPACK_GTIRB_PPRINTER_PACKAGE}" STREQUAL "rpm-lib")
  set(CPACK_RPM_FILE_NAME "libgtirb-pprinter.rpm")
  set(CPACK_RPM_PACKAGE_NAME "libgtirb-pprinter")
  set(CPACK_RPM_PACKAGE_REQUIRES
      "libgtirb = ${CPACK_GTIRB_VERSION}, capstone-devel = ${CPACK_CAPSTONE_PKG_VERSION}, boost169 = 1.69.0"
  )
  set(CPACK_RPM_DEBUGINFO_PACKAGE ON)
  set(CPACK_RPM_DEBUGINFO_FILE_NAME "libgtirb-pprinter-debuginfo.rpm")
  set(CPACK_COMPONENTS_ALL ${LIB_COMPONENTS})
elseif("${CPACK_GTIRB_PPRINTER_PACKAGE}" STREQUAL "rpm-dev")
  set(CPACK_RPM_FILE_NAME "libgtirb-pprinter-devel.rpm")
  set(CPACK_RPM_PACKAGE_NAME "libgtirb-pprinter-devel")
  set(CPACK_RPM_PACKAGE_REQUIRES
      "libgtirb-pprinter = ${CPACK_GTIRB_PPRINTER_VERSION}, libgtirb-devel = ${CPACK_GTIRB_VERSION}, boost169-devel = 1.69.0"
  )
  set(CPACK_COMPONENTS_ALL ${DEV_COMPONENTS})
elseif("${CPACK_GTIRB_PPRINTER_PACKAGE}" STREQUAL "rpm-driver")
  set(CPACK_RPM_PACKAGE_NAME "gtirb-pprinter")
  set(CPACK_PACKAGE_FILE_NAME "gtirb-pprinter")
  set(CPACK_RPM_DEBUGINFO_PACKAGE ON)
  set(CPACK_RPM_DEBUGINFO_FILE_NAME "gtirb-pprinter-debuginfo.rpm")
  set(CPACK_COMPONENTS_ALL ${DRIVER_COMPONENTS})
  set(CPACK_RPM_PACKAGE_DEPENDS
      "libgtirb = ${CPACK_GTIRB_VERSION}, capstone-devel = ${CPACK_CAPSTONE_PKG_VERSION}, libgtirb-pprinter = ${CPACK_GTIRB_PPRINTER_VERSION}"
  )
endif()
