set(PROJECT_NAME gtirb_layout)

# headers
configure_file("${CMAKE_SOURCE_DIR}/include/gtirb_layout/version.h.in"
               "${CMAKE_BINARY_DIR}/include/gtirb_layout/version.h" @ONLY)

set(${PROJECT_NAME}_H
    ${CMAKE_SOURCE_DIR}/include/gtirb_layout/gtirb_layout.hpp
    ${CMAKE_SOURCE_DIR}/include/gtirb_layout/Export.hpp
    ${CMAKE_BINARY_DIR}/include/gtirb_layout/version.h)

# sources
set(${PROJECT_NAME}_SRC gtirb_layout.cpp)

add_library(${PROJECT_NAME} ${${PROJECT_NAME}_H} ${${PROJECT_NAME}_SRC})

set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "debloat")

target_link_libraries(${PROJECT_NAME} ${SYSLIBS} ${Boost_LIBRARIES} gtirb
                      ${CAPSTONE})

# interface
target_include_directories(
  ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>)
target_include_directories(
  ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>)
target_include_directories(
  ${PROJECT_NAME}
  PRIVATE $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include/gtirb_layout>)
target_include_directories(
  ${PROJECT_NAME}
  PRIVATE $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include/gtirb_layout>)

# compile options
target_compile_options(${PROJECT_NAME} PRIVATE -D${PROJECT_NAME}_EXPORTS)

# Copy headers into build directory
install(
  TARGETS ${PROJECT_NAME}
  EXPORT gtirb_pprinterTargets
  INCLUDES
  DESTINATION include
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
install(FILES ${${PROJECT_NAME}_H} DESTINATION include/gtirb_layout)

# subdirectories
add_subdirectory(driver)
add_subdirectory(test)
