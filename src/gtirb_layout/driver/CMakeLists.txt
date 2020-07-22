set(BINARY_NAME gtirb-layout)

add_executable(${BINARY_NAME} Logger.h gtirb_layout.cpp)

set_target_properties(${BINARY_NAME} PROPERTIES FOLDER "debloat")

target_link_libraries(
  ${BINARY_NAME} PRIVATE ${SYSLIBS} ${EXPERIMENTAL_LIB} ${Boost_LIBRARIES}
                         ${LIBCPP_ABI} gtirb_layout)

install_linux_debug_info(${BINARY_NAME} layout-driver-debug-file)

install(
  TARGETS ${BINARY_NAME}
  DESTINATION bin
  COMPONENT layout_driver)

if(GTIRB_PPRINTER_STATIC_DRIVERS)
  if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
    # We do not want to statically link in the STL here, as MSVC is a bit
    # prickly about STL ABIs.
  else()
    target_link_libraries(${BINARY_NAME} PRIVATE -static-libstdc++
                                                 -static-libgcc)
  endif()
endif()
