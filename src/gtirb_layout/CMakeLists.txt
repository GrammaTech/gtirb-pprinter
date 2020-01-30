set(PROJECT_NAME gtirb_layout)

# headers
configure_file("${CMAKE_SOURCE_DIR}/include/gtirb_layout/version.h.in"
               "${CMAKE_BINARY_DIR}/include/gtirb_layout/version.h" @ONLY)

set(${PROJECT_NAME}_H
    ${CMAKE_SOURCE_DIR}/include/gtirb_layout/gtirb_layout.hpp
    ${CMAKE_SOURCE_DIR}/include/gtirb_layout/Export.hpp
    ${CMAKE_BINARY_DIR}/include/gtirb_layout/version.h)

include_directories("${CMAKE_SOURCE_DIR}/include/gtirb_layout")
include_directories("${CMAKE_BINARY_DIR}/include/gtirb_layout")

# sources
set(${PROJECT_NAME}_SRC gtirb_layout.cpp)

add_library(${PROJECT_NAME} ${${PROJECT_NAME}_H} ${${PROJECT_NAME}_SRC})

set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "debloat")

target_link_libraries(${PROJECT_NAME} ${SYSLIBS} ${Boost_LIBRARIES} gtirb
                      ${CAPSTONE})

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
