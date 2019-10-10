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

# Find our headers without gtirb_pprinter/ prefix
include_directories("${CMAKE_SOURCE_DIR}/include/gtirb_pprinter")

set(PUBLIC_HEADERS
  ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/BinaryPrinter.hpp
  ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/Export.hpp
  ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/PrettyPrinter.hpp
  ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/Syntax.hpp
)

set(${PROJECT_NAME}_H
  ${PUBLIC_HEADERS}
  ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/AttPrettyPrinter.hpp
  ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/ElfBinaryPrinter.hpp
  ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/ElfPrettyPrinter.hpp
  ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/IntelPrettyPrinter.hpp
  ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/MasmPrettyPrinter.hpp
  ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/PePrettyPrinter.hpp
  ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/string_utils.hpp
)

set(${PROJECT_NAME}_SRC
  AttPrettyPrinter.cpp
  ElfBinaryPrinter.cpp
  ElfPrettyPrinter.cpp
  IntelPrettyPrinter.cpp
  MasmPrettyPrinter.cpp
  PePrettyPrinter.cpp
  PrettyPrinter.cpp
  string_utils.cpp
  Syntax.cpp
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

set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "debloat")

target_link_libraries(
  ${PROJECT_NAME}
  ${SYSLIBS}
  ${Boost_LIBRARIES}
  gtirb
  ${CAPSTONE}
)

# Copy headers into build directory
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
  COMMAND "${CMAKE_COMMAND}" -E remove_directory "${CMAKE_BINARY_DIR}/include/gtirb_pprinter")
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_BINARY_DIR}/include/gtirb_pprinter")
add_custom_command(
        TARGET ${PROJECT_NAME} POST_BUILD
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND "${CMAKE_COMMAND}" -E copy
                ${${PROJECT_NAME}_H}
                "${CMAKE_BINARY_DIR}/include/gtirb_pprinter")

install(TARGETS ${PROJECT_NAME} EXPORT gtirb_pprinterTargets
  INCLUDES DESTINATION include
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
install(FILES ${PUBLIC_HEADERS} DESTINATION include/gtirb_pprinter)
