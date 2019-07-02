#
# Cmake Configuration
#

# Need 3.9 to support CXX_STANDARD=17 and protobuf
CMAKE_MINIMUM_REQUIRED(VERSION 3.9.0)

PROJECT(gtirb_pprinter)
set(GTIRB_PPRINTER_VERSION "0.1.1" CACHE STRING "version of gtirb-pprinter" FORCE)

include(CheckFunctionExists)
include(CheckCXXSourceCompiles)
include(CheckIncludeFile)

# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------

# This just sets the builtin BUILD_SHARED_LIBS, but if defaults to ON
# instead of OFF.
option(GTIRB_PPRINTER_BUILD_SHARED_LIBS "Build shared libraries." ON)
option(GTIRB_PPRINTER_USE_SYSTEM_BOOST "Use system-wide installation of Boost." OFF)

if(GTIRB_PPRINTER_BUILD_SHARED_LIBS)
  set(BUILD_SHARED_LIBS ON)
else()
  set(BUILD_SHARED_LIBS OFF)
endif()

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src)
if (WIN32)
  set(CMAKE_DEBUG_POSTFIX          "d" CACHE STRING "add a postfix, usually d on windows")
endif()
set(CMAKE_RELEASE_POSTFIX        ""  CACHE STRING "add a postfix, usually empty on windows")
set(CMAKE_RELWITHDEBINFO_POSTFIX ""  CACHE STRING "add a postfix, usually empty on windows")
set(CMAKE_MINSIZEREL_POSTFIX     ""  CACHE STRING "add a postfix, usually empty on windows")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Handle version initialization
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/version.txt" ver)

string(REGEX MATCH "VERSION_MAJOR ([0-9]*)" _ ${ver})
set(GTIRB_PPRINTER_MAJOR_VERSION ${CMAKE_MATCH_1})

string(REGEX MATCH "VERSION_MINOR ([0-9]*)" _ ${ver})
set(GTIRB_PPRINTER_MINOR_VERSION ${CMAKE_MATCH_1})

string(REGEX MATCH "VERSION_PATCH ([0-9]*)" _ ${ver})
set(GTIRB_PPRINTER_PATCH_VERSION ${CMAKE_MATCH_1})

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/version.h.in"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/version.h"
  @ONLY)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
# Error if it's not available
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Specifically check for gcc-7 or later. gcc-5 is installed on many
# systems and will accept -std=c++17, but does not fully support the
# standard.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "7.0.0")
    message(FATAL_ERROR "gcc 7 or later is required to build gtirb")
  endif()
endif()

# Detect how to use <experimental/filesystem>
set(EXPERIMENTAL_LIB "" CACHE STRING "The library to link with in order to use <experimental/filesystem>.")

if ("${EXPERIMENTAL_LIB}" STREQUAL "")
  set(EXFS_CODE "
  #include <experimental/filesystem>
  int main() {
    std::experimental::filesystem::path p{\"an/example/path\"};
    return std::experimental::filesystem::exists(p);
  }
  ")

  check_cxx_source_compiles("${EXFS_CODE}" EXFS_LINK_NONE)

  if(NOT EXFS_LINK_NONE)
    foreach(EXFS_LIB stdc++fs c++experimental c++fs)
      set(OLD_CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES})
      list(APPEND CMAKE_REQUIRED_LIBRARIES ${EXFS_LIB})
      check_cxx_source_compiles("${EXFS_CODE}" EXFS_LINK_${EXFS_LIB}_OK)
      set(CMAKE_REQUIRED_LIBRARIES ${OLD_CMAKE_REQUIRED_LIBRARIES})

      if(EXFS_LINK_${EXFS_LIB}_OK)
        if(EXPERIMENTAL_LIB)
          message(FATAL_ERROR "multiple candidates for library to link for <experimental/filesystem>: ${EXPERIMENTAL_LIB} and ${EXFS_LIB}. Try giving the correct one explicitly with -DEXPERIMENTAL_LIB.")
        endif()
        set(EXPERIMENTAL_LIB ${EXFS_LIB})
      endif()
    endforeach()

    if (NOT EXPERIMENTAL_LIB)
      message(FATAL_ERROR "could not find library to link for <experimental/filesystem>. Try giving it explicitly with -DEXPERIMENTAL_LIB.")
    endif()
  endif()
endif()

# Base include path for the pretty-printer.
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_compile_options(-DBOOST_CONFIG_SUPPRESS_OUTDATED_MESSAGE)

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  add_compile_options(-D_CRT_SECURE_NO_WARNINGS)
  add_compile_options(-D_MBCS)
  add_compile_options(-D_SCL_SECURE_NO_WARNINGS)
  add_compile_options(-D_WIN32)
  add_compile_options(-D_WINDOWS)
  add_compile_options(-D_WINSOCKAPI_)
  add_compile_options(-DMBCS)
  add_compile_options(-DNOMINMAX)
  add_compile_options(-EHsc)
  add_compile_options(-GR)
  add_compile_options(-MP)
  add_compile_options(-nologo)
  add_compile_options(-W4)
  add_compile_options(-WX)

  add_compile_options(-wd4251) # 'identifier' : class 'type' needs to have dll-interface to be used by clients of class 'type2'
  add_compile_options(-wd4275) # Non-dll interface base classes.
  add_compile_options(-wd4996) # VC8: Deprecated libc functions.
  add_compile_options(-wd4351) # This is a warning about a change in behavior from old versions of visual c++.  We want the new (standard-compliant) behavior, so we don't want the warning.  The warning is that using an array in a class initializer list will cause its elements to be default initialized.

  # Per-configuration options
  add_compile_options($<$<CONFIG:Debug>:-D_DEBUG>)
  add_compile_options($<$<CONFIG:Debug>:-DDEBUG>)
  add_compile_options($<$<CONFIG:Debug>:-MDd>)
  add_compile_options($<$<CONFIG:Debug>:-Ob0>) # Disables inline expansion
  add_compile_options($<$<CONFIG:Debug>:-Od>) # Disables optimization, speeding compilation and simplifying debugging. https://msdn.microsoft.com/en-us/library/k1ack8f1.aspx
  add_compile_options($<$<CONFIG:Debug>:-RTC1>) # Enables run-time error checking.
  add_compile_options($<$<CONFIG:Debug>:-W4>) # Sets warning level.
  add_compile_options($<$<CONFIG:Debug>:-Zi>) # Generates complete debugging information.
  add_compile_options($<$<CONFIG:Debug>:-bigobj>) # enables big obj compilation option

  add_compile_options($<$<CONFIG:RelWithDebInfo>:-D_NDEBUG>)
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-DNDEBUG>)
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-MD>)
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-O2>) # Creates fast code.
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-Ob2>) # The default value. Allows expansion of functions marked as inline, __inline, or __forceinline, and any other function that the compiler chooses.
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-Oi>) # Generates intrinsic functions.
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-Ot>) # Favors fast code.
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-W4>) # Sets warning level.
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-Zi>) # Generates complete debugging information.
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-bigobj>) # enables big obj compilation option

  add_compile_options($<$<CONFIG:Release>:-D_NDEBUG>)
  add_compile_options($<$<CONFIG:Release>:-DNDEBUG>)
  add_compile_options($<$<CONFIG:Release>:-MD>)
  add_compile_options($<$<CONFIG:Release>:-O2>) # Creates fast code.
  add_compile_options($<$<CONFIG:Release>:-Ob2>) # The default value. Allows expansion of functions marked as inline, __inline, or __forceinline, and any other function that the compiler chooses.
  add_compile_options($<$<CONFIG:Release>:-Oi>) # Generates intrinsic functions.
  add_compile_options($<$<CONFIG:Release>:-Ot>) # Favors fast code.
  add_compile_options($<$<CONFIG:Release>:-W4>) # Sets warning level.
  add_compile_options($<$<CONFIG:Release>:-bigobj>) # enables big obj compilation option

  # Shove in some linker flags to support using 64-bit memory.
  # 4099 -PDB 'filename' was not found with 'object/library' or at 'path'; linking object as if no debug info
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /LARGEADDRESSAWARE")

  # Microsoft VCPKG
  set(CMAKE_TOOLCHAIN_FILE "C:/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE PATH "")
  include(${CMAKE_TOOLCHAIN_FILE})
elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
  add_compile_options(-Wall -Wextra -Wpointer-arith -Wshadow)
  add_compile_options(-Werror)
  add_compile_options(-fPIC)
elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL Clang)
  add_compile_options(-Wall -Wextra -Wpointer-arith -Wshadow)
  add_compile_options(-Werror)
  add_compile_options(-fPIC)
endif()

# ---------------------------------------------------------------------------
# gtirb
# ---------------------------------------------------------------------------

find_package(gtirb REQUIRED)

# ---------------------------------------------------------------------------
# Boost
# ---------------------------------------------------------------------------

add_compile_options(-DBOOST_SYSTEM_NO_DEPRECATED)

if( ${GTIRB_PPRINTER_USE_SYSTEM_BOOST} MATCHES "OFF" )
  #Attempt to configure/build boost locally.  
  configure_file(CMakeLists.boost Boost/CMakeLists.txt COPYONLY)
  
  # Initialize CMake files required to build/install boost.
  execute_process(COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" . 
    RESULT_VARIABLE result
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/Boost"
    )
  
  if(result)
    message(WARNING "CMake step for boost failed: ${result}")
  endif()
  
  set(BOOST_INSTALL_DIR "${CMAKE_BINARY_DIR}/Boost-src")
  
  add_subdirectory("${CMAKE_BINARY_DIR}/Boost/"
    "${BOOST_INSTALL_DIR}"
    EXCLUDE_FROM_ALL)
  set( Boost_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/Boost-src/include )

  include_directories(${Boost_INCLUDE_DIRS})

  set( Boost_LIBRARY_DIR ${CMAKE_BINARY_DIR}/Boost-src/lib )

  if(${BUILD_SHARED_LIBS} MATCHES OFF)
    set(Boost_LIBRARIES
      ${Boost_LIBRARY_DIR}/libboost_filesystem.a
      ${Boost_LIBRARY_DIR}/libboost_program_options.a
      ${Boost_LIBRARY_DIR}/libboost_system.a
      )
  elseif(${BUILD_SHARED_LIBS} MATCHES ON)
    set(Boost_LIBRARIES
      ${Boost_LIBRARY_DIR}/libboost_filesystem.so
      ${Boost_LIBRARY_DIR}/libboost_program_options.so
      ${Boost_LIBRARY_DIR}/libboost_system.so
      )
  endif()
else()
  find_package(Boost 1.67 REQUIRED COMPONENTS filesystem program_options system)
  include_directories(${Boost_INCLUDE_DIRS})
endif()


# ---------------------------------------------------------------------------
# capstone
# ---------------------------------------------------------------------------
find_library(CAPSTONE NAMES capstone)
if(NOT CAPSTONE)
  message(FATAL_ERROR "capstone library not found")
else()
  include_directories(${CAPSTONE_INCLUDE_DIRS})
endif()


add_subdirectory(driver)
add_subdirectory(src)

# ---------------------------------------------------------------------------
# Export config for use by other CMake projects
# ---------------------------------------------------------------------------
export(TARGETS gtirb_pprinter FILE "${CMAKE_CURRENT_BINARY_DIR}/gtirb_pprinterTargets.cmake")
file(
  WRITE "${CMAKE_CURRENT_BINARY_DIR}/gtirb_pprinterConfig.cmake"
        "
            include(\"\$\{CMAKE_CURRENT_LIST_DIR\}/gtirb_pprinterTargets.cmake\")
            set_property(
                TARGET gtirb_pprinter
                APPEND PROPERTY
                    INTERFACE_INCLUDE_DIRECTORIES \"${CMAKE_BINARY_DIR}/include\"
            )
        "
    )
export(PACKAGE gtirb_pprinter)

# --- For the installed copy ---
# Main config file for find_package, just includes the targets file.
file(
  WRITE "${CMAKE_CURRENT_BINARY_DIR}/export/gtirb_pprinterConfig.cmake"
        "include(\"\$\{CMAKE_CURRENT_LIST_DIR\}/gtirb_pprinterTargets.cmake\")"
    )
# In this mode, find_package also seems to require a version file
set(version_file "${CMAKE_CURRENT_BINARY_DIR}/gtirb_pprinterConfig-version.cmake")
include(CMakePackageConfigHelpers)
write_basic_package_version_file(${version_file}
                                 VERSION ${GTIRB_PPRINTER_VERSION}
                                 COMPATIBILITY AnyNewerVersion)

# Copy the config files to the install location
install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/export/gtirb_pprinterConfig.cmake
  ${version_file}
  DESTINATION lib/gtirb_pprinter)
# This exports the targets to the install location.
if( ${GTIRB_PPRINTER_USE_SYSTEM_BOOST} MATCHES "OFF" )
  install(DIRECTORY "${Boost_LIBRARY_DIR}/" DESTINATION lib)
endif()

install(EXPORT gtirb_pprinterTargets DESTINATION lib/gtirb_pprinter)
