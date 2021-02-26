set(PROJECT_NAME gtirb_pprinter)

# headers
configure_file("${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/version.h.in"
               "${CMAKE_BINARY_DIR}/include/gtirb_pprinter/version.h" @ONLY)

set(${PROJECT_NAME}_H
    ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/AuxDataSchema.hpp
    ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/BinaryPrinter.hpp
    ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/Export.hpp
    ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/file_utils.hpp
    ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/PrettyPrinter.hpp
    ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/Syntax.hpp
    ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/Arm64PrettyPrinter.hpp
    ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/AttPrettyPrinter.hpp
    ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/ElfBinaryPrinter.hpp
    ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/ElfPrettyPrinter.hpp
    ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/IntelPrettyPrinter.hpp
    ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/string_utils.hpp
    ${CMAKE_BINARY_DIR}/include/gtirb_pprinter/version.h
    ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/MasmPrettyPrinter.hpp
    ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/PeBinaryPrinter.hpp
    ${CMAKE_SOURCE_DIR}/include/gtirb_pprinter/PePrettyPrinter.hpp)

# sources
set(${PROJECT_NAME}_SRC
    Arm64PrettyPrinter.cpp
    AttPrettyPrinter.cpp
    BinaryPrinter.cpp
    ElfBinaryPrinter.cpp
    ElfPrettyPrinter.cpp
    file_utils.cpp
    IntelPrettyPrinter.cpp
    PrettyPrinter.cpp
    Registration.cpp
    string_utils.cpp
    Syntax.cpp
    MasmPrettyPrinter.cpp
    PeBinaryPrinter.cpp
    PePrettyPrinter.cpp)

add_library(${PROJECT_NAME} ${${PROJECT_NAME}_H} ${${PROJECT_NAME}_SRC})

set_target_properties(
  ${PROJECT_NAME}
  PROPERTIES VERSION ${GTIRB_PPRINTER_VERSION}
             SOVERSION ${GTIRB_PPRINTER_MAJOR_VERSION}
             FOLDER "debloat")

target_link_libraries(${PROJECT_NAME} PUBLIC ${SYSLIBS} ${Boost_LIBRARIES}
                                             gtirb ${CAPSTONE})

# interface

target_include_directories(
  ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>)
target_include_directories(
  ${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>)
target_include_directories(
  ${PROJECT_NAME}
  PRIVATE $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include/gtirb_pprinter>)
target_include_directories(
  ${PROJECT_NAME}
  PRIVATE $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include/gtirb_pprinter>)

# compile options
target_compile_options(${PROJECT_NAME}
                       PRIVATE -DDEBLOAT_${PROJECT_NAME}_EXPORTS)

install_linux_debug_info(${PROJECT_NAME} pprinter-debug-file)

# Copy headers into build directory
install(
  TARGETS ${PROJECT_NAME}
  COMPONENT pprinter_library
  EXPORT gtirb_pprinterTargets
  INCLUDES
  DESTINATION include
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)
install(
  FILES ${${PROJECT_NAME}_H}
  DESTINATION include/gtirb_pprinter
  COMPONENT pprinter_headers)

# subdirectories
add_subdirectory(driver)
add_subdirectory(test)
