set(PRETTY_PRINTER gtirb-pprinter)

add_executable(
  ${PRETTY_PRINTER} Logger.h parser.hpp parser.cpp printing_paths.hpp
                    printing_paths.cpp pretty_printer.cpp)

set_target_properties(${PRETTY_PRINTER} PROPERTIES FOLDER "debloat")

target_link_libraries(
  ${PRETTY_PRINTER} PRIVATE ${SYSLIBS} ${EXPERIMENTAL_LIB} ${Boost_LIBRARIES}
                            ${LIBCPP_ABI} gtirb_pprinter gtirb_layout)

install_linux_debug_info(${PRETTY_PRINTER} pprinter-driver-debug-file)

install(
  TARGETS ${PRETTY_PRINTER}
  DESTINATION bin
  COMPONENT pprinter_driver)

if(GTIRB_PPRINTER_STATIC_DRIVERS)
  if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
    # We do not want to statically link in the STL here, as MSVC is a bit
    # prickly about STL ABIs.
  else()
    target_link_libraries(${PRETTY_PRINTER} PRIVATE -static-libstdc++
                                                    -static-libgcc)
  endif()
endif()
