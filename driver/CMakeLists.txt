SET(PRETTY_PRINTER gtirb-pprinter)
SET(BINARY_PRINTER gtirb-binary-printer)

# Required warning suppression (TODO: Remove!)
if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  #add_compile_options(-wd4251)  # Non-exportable template classes.
elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
  add_compile_options(-mtune=generic)
  add_compile_options(-pthread)
elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL Clang)
  add_compile_options(-mtune=generic)
  add_compile_options(-pthread)
endif()

# Unix, but not Cygwin.
IF(UNIX)
  IF (NOT WIN32)
    SET(SYSLIBS
      ${SYSLIBS}
      dl
      pthread)
  ENDIF()
ELSE()
  SET(SYSLIBS
  )
endif()

add_executable(${PRETTY_PRINTER}
    Logger.h
    pretty_printer.cpp
  )

add_executable(${BINARY_PRINTER}
  Logger.h
  binary_printer.cpp
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src)

set_target_properties(${PRETTY_PRINTER} PROPERTIES FOLDER "debloat")
set_target_properties(${BINARY_PRINTER} PROPERTIES FOLDER "debloat")

target_link_libraries(
  ${PRETTY_PRINTER}
  ${SYSLIBS}
  ${EXPERIMENTAL_LIB}
  ${Boost_LIBRARIES}
  ${LIBCPP_ABI}
  gtirb_pprinter
)

target_link_libraries(
  ${BINARY_PRINTER}
  ${SYSLIBS}
  ${EXPERIMENTAL_LIB}
  ${Boost_LIBRARIES}
  ${LIBCPP_ABI}
  gtirb_pprinter
)

install(TARGETS ${PRETTY_PRINTER} ${BINARY_PRINTER} DESTINATION bin)

if(NOT BUILD_SHARED_LIBS)
  target_link_libraries(${PRETTY_PRINTER} -static-libstdc++)
  target_link_libraries(${BINARY_PRINTER} -static-libstdc++)
endif()
