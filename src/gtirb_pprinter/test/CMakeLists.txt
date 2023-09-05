set(PROJECT_NAME TestNameParser)

include_directories(${GTEST_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR}/include
                    ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter)

set(${PROJECT_NAME}_SRC parser_test.cpp libraries_test.cpp test_main.cpp
                        ../driver/parser.hpp ../driver/parser.cpp
                        ../driver/printing_paths.hpp ../driver/printing_paths.cpp)

if(UNIX AND NOT WIN32)
  set(SYSLIBS dl)
else()
  set(SYSLIBS)
endif()

add_executable(${PROJECT_NAME} ${${PROJECT_NAME}_SRC})
target_link_libraries(${PROJECT_NAME} ${SYSLIBS} ${Boost_LIBRARIES} gtest
                      gtirb_pprinter)
add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
