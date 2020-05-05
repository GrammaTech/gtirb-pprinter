set(BINARY_NAME gtirb-layout)

add_executable(${BINARY_NAME} Logger.h gtirb_layout.cpp)

set_target_properties(${BINARY_NAME} PROPERTIES FOLDER "debloat")

target_link_libraries(${BINARY_NAME} ${SYSLIBS} ${EXPERIMENTAL_LIB}
                      ${Boost_LIBRARIES} ${LIBCPP_ABI} gtirb_layout)

install(
  TARGETS ${BINARY_NAME}
  DESTINATION bin
  COMPONENT layout_driver)

if(NOT BUILD_SHARED_LIBS)
  target_link_libraries(${BINARY_NAME} -static-libstdc++)
endif()
