set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE)

set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_RPM_COMPONENT_INSTALL ON)

set(LIB_COMPONENTS pprinter_library layout_library)
set(DEV_COMPONENTS pprinter_headers layout_headers cmake_config cmake_target)
set(DRIVER_COMPONENTS pprinter_driver layout_driver)

if("${CPACK_GTIRB_PPRINTER_PACKAGE}" STREQUAL "deb-lib")
  set(CPACK_DEBIAN_PACKAGE_NAME "libgtirb-pprinter")
  set(CPACK_PACKAGE_FILE_NAME "libgtirb-pprinter")
  set(CPACK_COMPONENTS_ALL ${LIB_COMPONENTS})
  if("${CPACK_DEBIAN_PACKAGE_RELEASE}" STREQUAL "focal")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb (>=${CPACK_GTIRB_VERSION}), libgtirb (<<${CPACK_GTIRB_VERSION_UPPER_BOUND}), libboost-filesystem1.71.0, libcapstone-dev (=1:4.0.1-gt4)"
    )
  else()
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb (>=${CPACK_GTIRB_VERSION}), libgtirb (<<${CPACK_GTIRB_VERSION_UPPER_BOUND}), libboost (>=1.67) | libboost1.67, libcapstone-dev (=1:4.0.1-gt4)"
    )
  endif()
elseif("${CPACK_GTIRB_PPRINTER_PACKAGE}" STREQUAL "deb-lib-dbg")
  set(CPACK_DEBIAN_PACKAGE_NAME "libgtirb-pprinter-dbg")
  set(CPACK_PACKAGE_FILE_NAME "libgtirb-pprinter-dbg")
  set(CPACK_COMPONENTS_ALL pprinter-debug-file layout-debug-file)
  set(CPACK_DEBIAN_PACKAGE_DEPENDS
      "libgtirb-pprinter (=${CPACK_GTIRB_PPRINTER_VERSION}-${CPACK_DEBIAN_PACKAGE_RELEASE})"
  )
elseif("${CPACK_GTIRB_PPRINTER_PACKAGE}" STREQUAL "deb-dev")
  set(CPACK_DEBIAN_PACKAGE_NAME "libgtirb-pprinter-dev")
  set(CPACK_PACKAGE_FILE_NAME "libgtirb-pprinter-dev")
  set(CPACK_COMPONENTS_ALL ${DEV_COMPONENTS})
  if("${CPACK_DEBIAN_PACKAGE_RELEASE}" STREQUAL "focal")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb-dev (>=${CPACK_GTIRB_VERSION}), libgtirb-dev (<<${CPACK_GTIRB_VERSION_UPPER_BOUND}), libgtirb-pprinter (=${CPACK_GTIRB_PPRINTER_VERSION}-${CPACK_DEBIAN_PACKAGE_RELEASE}), libboost-dev, libcapstone-dev (=1:4.0.1-gt4)"
    )
  else()
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb-dev (>=${CPACK_GTIRB_VERSION}), libgtirb-dev (<<${CPACK_GTIRB_VERSION_UPPER_BOUND}), libgtirb-pprinter (=${CPACK_GTIRB_PPRINTER_VERSION}-${CPACK_DEBIAN_PACKAGE_RELEASE}), libboost-dev (>=1.67) | libboost1.67-dev, libcapstone-dev (=1:4.0.1-gt4)"
    )
  endif()

elseif("${CPACK_GTIRB_PPRINTER_PACKAGE}" STREQUAL "deb-driver")
  set(CPACK_DEBIAN_PACKAGE_NAME "gtirb-pprinter")
  set(CPACK_PACKAGE_FILE_NAME "gtirb-pprinter")
  set(CPACK_COMPONENTS_ALL ${DRIVER_COMPONENTS})
  if("${CPACK_DEBIAN_PACKAGE_RELEASE}" STREQUAL "focal")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb (>=${CPACK_GTIRB_VERSION}), libgtirb (<<${CPACK_GTIRB_VERSION_UPPER_BOUND}), libgtirb-pprinter (=${CPACK_GTIRB_PPRINTER_VERSION}-${CPACK_DEBIAN_PACKAGE_RELEASE}), libboost-filesystem1.71.0, libboost-program-options1.71.0, libcapstone-dev (=1:4.0.1-gt4)"
    )
  else()
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb (>=${CPACK_GTIRB_VERSION}), libgtirb (<<${CPACK_GTIRB_VERSION_UPPER_BOUND}), libgtirb-pprinter (=${CPACK_GTIRB_PPRINTER_VERSION}-${CPACK_DEBIAN_PACKAGE_RELEASE}), libboost (>=1.67) | libboost1.67, libcapstone-dev (=1:4.0.1-gt4)"
    )
  endif()
elseif("${CPACK_GTIRB_PPRINTER_PACKAGE}" STREQUAL "deb-driver-dbg")
  set(CPACK_DEBIAN_PACKAGE_NAME "gtirb-pprinter-dbg")
  set(CPACK_PACKAGE_FILE_NAME "gtirb-pprinter-dbg")
  set(CPACK_COMPONENTS_ALL pprinter-driver-debug-file layout-driver-debug-file)
  set(CPACK_DEBIAN_PACKAGE_DEPENDS
      "gtirb-pprinter (=${CPACK_GTIRB_PPRINTER_VERSION}-${CPACK_DEBIAN_PACKAGE_RELEASE})"
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
