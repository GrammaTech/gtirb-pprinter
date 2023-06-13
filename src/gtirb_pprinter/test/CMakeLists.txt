# TODO...
set(PROJECT_NAME TestNameParser)

include_directories(${GTEST_INCLUDE_DIRS})

set(${PROJECT_NAME}_H)

set(${PROJECT_NAME}_SRC parser_test.cpp ../driver/parser.hpp ../driver/parser.cpp)

if(UNIX AND NOT WIN32)
  set(SYSLIBS dl)
else()
  set(SYSLIBS)
endif()

add_executable(${PROJECT_NAME} ${${PROJECT_NAME}_SRC})
target_link_libraries(${PROJECT_NAME} ${SYSLIBS} ${Boost_LIBRARIES} gtest gtest_main)
add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
