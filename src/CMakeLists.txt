SET(PROJECT_NAME gtirb_pprinter)

add_compile_options(-DDEBLOAT_${PROJECT_NAME}_EXPORTS)

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

set(${PROJECT_NAME}_H
  AttPrinter.h
  BinaryPrinter.h
  ElfBinaryPrinter.h
  Export.h
  IntelPrinter.h
  PrettyPrinter.h
  string_utils.h
)

set(${PROJECT_NAME}_SRC
  AttPrinter.cpp
  ElfBinaryPrinter.cpp
  IntelPrinter.cpp
  PrettyPrinter.cpp
  string_utils.cpp
)

# Unix, but not Cygwin.
IF(UNIX AND NOT WIN32)
  SET(SYSLIBS
    dl
    pthread
  )
ELSE()
  SET(SYSLIBS
  )
endif()

add_library(${PROJECT_NAME}
    ${${PROJECT_NAME}_H}
    ${${PROJECT_NAME}_SRC}
  )

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "debloat")

if( ${GTIRB_PPRINTER_USE_SYSTEM_BOOST} MATCHES "OFF" )
  add_dependencies(${PROJECT_NAME} Boost)
endif()

target_link_libraries(
  ${PROJECT_NAME}
  ${SYSLIBS}
  ${Boost_LIBRARIES}
    gtirb
    ${CAPSTONE}
)

# Copy headers into build directory
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
  COMMAND "${CMAKE_COMMAND}" -E remove_directory "${CMAKE_BINARY_DIR}/include/")
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_BINARY_DIR}/include/")
add_custom_command(
        TARGET ${PROJECT_NAME} POST_BUILD
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND "${CMAKE_COMMAND}" -E copy
                ${${PROJECT_NAME}_H}
                "${CMAKE_BINARY_DIR}/include/")

install(TARGETS ${PROJECT_NAME} EXPORT gtirb_pprinterTargets
  INCLUDES DESTINATION include
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
set(PUBLIC_HEADERS
  ${CMAKE_SOURCE_DIR}/src/BinaryPrinter.h
  ${CMAKE_SOURCE_DIR}/src/Export.h
  ${CMAKE_SOURCE_DIR}/src/PrettyPrinter.h
  )
install(FILES ${PUBLIC_HEADERS} DESTINATION include)
