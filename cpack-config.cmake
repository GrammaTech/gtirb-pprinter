set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE)

if("${CPACK_GTIRB_DEBIAN_PACKAGE}" STREQUAL "lib")
  set(CPACK_DEBIAN_PACKAGE_NAME "libgtirb-pprinter")
  set(CPACK_PACKAGE_FILE_NAME "libgtirb-pprinter")
  set(CPACK_COMPONENTS_ALL pprinter_library layout_library)
  set(CPACK_DEBIAN_PACKAGE_DEPENDS
      "libstdc++6, libc6, libgcc1, libgtirb (>=${CPACK_GTIRB_VERSION}), libboost (>=1.67) | libboost1.67, libcapstone-dev (=1:4.0.1-gt1)"
  )
elseif("${CPACK_GTIRB_DEBIAN_PACKAGE}" STREQUAL "dev")
  set(CPACK_DEBIAN_PACKAGE_NAME "libgtirb-pprinter-dev")
  set(CPACK_PACKAGE_FILE_NAME "libgtirb-pprinter-dev")
  set(CPACK_COMPONENTS_ALL pprinter_headers layout_headers cmake_config
                           cmake_target)
  set(CPACK_DEBIAN_PACKAGE_DEPENDS
      "libstdc++6, libc6, libgcc1, libgtirb-dev (>=${CPACK_GTIRB_VERSION}), libgtirb-pprinter (=${CPACK_GTIRB_PPRINTER_VERSION}), libboost-dev (>=1.67) | libboost1.67-dev, libcapstone-dev (=1:4.0.1-gt1)"
  )

elseif("${CPACK_GTIRB_DEBIAN_PACKAGE}" STREQUAL "driver")
  set(CPACK_DEBIAN_PACKAGE_NAME "gtirb-pprinter")
  set(CPACK_PACKAGE_FILE_NAME "gtirb-pprinter")
  set(CPACK_COMPONENTS_ALL pprinter_driver layout_driver)
  set(CPACK_DEBIAN_PACKAGE_DEPENDS
      "libstdc++6, libc6, libgcc1, libgtirb (>=${CPACK_GTIRB_VERSION}), libgtirb-pprinter (=${CPACK_GTIRB_PPRINTER_VERSION}), libboost (>=1.67) | libboost1.67, libcapstone-dev (=1:4.0.1-gt1)"
  )
endif()
