set(PRETTY_PRINTER gtirb-pprinter)

add_executable(${PRETTY_PRINTER} Logger.h pretty_printer.cpp)

set_target_properties(${PRETTY_PRINTER} PROPERTIES FOLDER "debloat")

target_link_libraries(
  ${PRETTY_PRINTER} PRIVATE ${SYSLIBS} ${EXPERIMENTAL_LIB} ${Boost_LIBRARIES}
                            ${LIBCPP_ABI} gtirb_pprinter gtirb_layout)

install_linux_debug_info(${PRETTY_PRINTER} pprinter-driver-debug-file)

install(
  TARGETS ${PRETTY_PRINTER}
  DESTINATION bin
  COMPONENT pprinter_driver)

if(NOT BUILD_SHARED_LIBS)
  target_link_libraries(${PRETTY_PRINTER} PRIVATE -static-libstdc++)
endif()
