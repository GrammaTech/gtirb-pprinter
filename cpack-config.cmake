set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE)

if("${CPACK_GTIRB_DEBIAN_PACKAGE}" STREQUAL "lib")
  set(CPACK_DEBIAN_PACKAGE_NAME "libgtirb-pprinter")
  set(CPACK_PACKAGE_FILE_NAME "libgtirb-pprinter")
  set(CPACK_COMPONENTS_ALL pprinter_library layout_library)
  if("${CPACK_DEBIAN_RELEASE}" STREQUAL "focal")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb (>=${CPACK_GTIRB_VERSION}), libgtirb (<<${CPACK_GTIRB_VERSION_UPPER_BOUND}), libboost-filesystem1.71.0, libcapstone-dev (=1:4.0.1-gt3)"
    )
  else()
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb (>=${CPACK_GTIRB_VERSION}), libgtirb (<<${CPACK_GTIRB_VERSION_UPPER_BOUND}), libboost (>=1.67) | libboost1.67, libcapstone-dev (=1:4.0.1-gt3)"
    )
  endif()
elseif("${CPACK_GTIRB_DEBIAN_PACKAGE}" STREQUAL "lib-dbg")
  set(CPACK_DEBIAN_PACKAGE_NAME "libgtirb-pprinter-dbg")
  set(CPACK_PACKAGE_FILE_NAME "libgtirb-pprinter-dbg")
  set(CPACK_COMPONENTS_ALL pprinter-debug-file layout-debug-file)
  set(CPACK_DEBIAN_PACKAGE_DEPENDS
      "libgtirb-pprinter (=${CPACK_GTIRB_PPRINTER_VERSION})")
elseif("${CPACK_GTIRB_DEBIAN_PACKAGE}" STREQUAL "dev")
  set(CPACK_DEBIAN_PACKAGE_NAME "libgtirb-pprinter-dev")
  set(CPACK_PACKAGE_FILE_NAME "libgtirb-pprinter-dev")
  set(CPACK_COMPONENTS_ALL pprinter_headers layout_headers cmake_config
                           cmake_target)
  if("${CPACK_DEBIAN_RELEASE}" STREQUAL "focal")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb-dev (>=${CPACK_GTIRB_VERSION}), libgtirb-dev (<<${CPACK_GTIRB_VERSION_UPPER_BOUND}), libgtirb-pprinter (=${CPACK_GTIRB_PPRINTER_VERSION}), libboost-dev, libcapstone-dev (=1:4.0.1-gt3)"
    )
  else()
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb-dev (>=${CPACK_GTIRB_VERSION}), libgtirb-dev (<<${CPACK_GTIRB_VERSION_UPPER_BOUND}), libgtirb-pprinter (=${CPACK_GTIRB_PPRINTER_VERSION}), libboost-dev (>=1.67) | libboost1.67-dev, libcapstone-dev (=1:4.0.1-gt3)"
    )
  endif()

elseif("${CPACK_GTIRB_DEBIAN_PACKAGE}" STREQUAL "driver")
  set(CPACK_DEBIAN_PACKAGE_NAME "gtirb-pprinter")
  set(CPACK_PACKAGE_FILE_NAME "gtirb-pprinter")
  set(CPACK_COMPONENTS_ALL pprinter_driver layout_driver)
  if("${CPACK_DEBIAN_RELEASE}" STREQUAL "focal")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb (>=${CPACK_GTIRB_VERSION}), libgtirb (<<${CPACK_GTIRB_VERSION_UPPER_BOUND}), libgtirb-pprinter (=${CPACK_GTIRB_PPRINTER_VERSION}), libboost-filesystem1.71.0, libboost-program-options1.71.0, libcapstone-dev (=1:4.0.1-gt3)"
    )
  else()
    set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libstdc++6, libc6, libgcc1, libgtirb (>=${CPACK_GTIRB_VERSION}), libgtirb (<<${CPACK_GTIRB_VERSION_UPPER_BOUND}), libgtirb-pprinter (=${CPACK_GTIRB_PPRINTER_VERSION}), libboost (>=1.67) | libboost1.67, libcapstone-dev (=1:4.0.1-gt3)"
    )
  endif()
elseif("${CPACK_GTIRB_DEBIAN_PACKAGE}" STREQUAL "driver-dbg")
  set(CPACK_DEBIAN_PACKAGE_NAME "gtirb-pprinter-dbg")
  set(CPACK_PACKAGE_FILE_NAME "gtirb-pprinter-dbg")
  set(CPACK_COMPONENTS_ALL pprinter-driver-debug-file layout-driver-debug-file)
  set(CPACK_DEBIAN_PACKAGE_DEPENDS
      "gtirb-pprinter (=${CPACK_GTIRB_PPRINTER_VERSION})")
endif()
