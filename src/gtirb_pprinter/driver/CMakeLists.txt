set(PRETTY_PRINTER gtirb-pprinter)
set(BINARY_PRINTER gtirb-binary-printer)

add_executable(${PRETTY_PRINTER} Logger.h pretty_printer.cpp)

add_executable(${BINARY_PRINTER} Logger.h binary_printer.cpp)

set_target_properties(${PRETTY_PRINTER} PROPERTIES FOLDER "debloat")
set_target_properties(${BINARY_PRINTER} PROPERTIES FOLDER "debloat")

target_link_libraries(
  ${PRETTY_PRINTER}
  ${SYSLIBS}
  ${EXPERIMENTAL_LIB}
  ${Boost_LIBRARIES}
  ${LIBCPP_ABI}
  gtirb_pprinter
  gtirb_layout)

target_link_libraries(
  ${BINARY_PRINTER}
  ${SYSLIBS}
  ${EXPERIMENTAL_LIB}
  ${Boost_LIBRARIES}
  ${LIBCPP_ABI}
  gtirb_pprinter
  gtirb_layout)

install(TARGETS ${PRETTY_PRINTER} ${BINARY_PRINTER} DESTINATION bin)

if(NOT BUILD_SHARED_LIBS)
  target_link_libraries(${PRETTY_PRINTER} -static-libstdc++)
  target_link_libraries(${BINARY_PRINTER} -static-libstdc++)
endif()
