set(PROJECT_NAME TestGtirbLayout)

enable_testing()
include_directories(${GTEST_INCLUDE_DIRS})

set(${PROJECT_NAME}_H)

set(${PROJECT_NAME}_SRC layout_test.cpp)

if(UNIX AND NOT WIN32)
  set(SYSLIBS dl)
else()
  set(SYSLIBS)
endif()

add_executable(${PROJECT_NAME} ${${PROJECT_NAME}_SRC})
target_link_libraries(${PROJECT_NAME} ${SYSLIBS} ${Boost_LIBRARIES} gtest gtirb
                      gtirb_layout)
add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
