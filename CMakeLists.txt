#
# Cmake Configuration
#

# Need 3.9 to support CXX_STANDARD=17 and protobuf
cmake_minimum_required(VERSION 3.9.0)

project(gtirb_pprinter)
set(GTIRB_PPRINTER_VERSION
    "0.1.1"
    CACHE STRING "version of gtirb-pprinter" FORCE)

include(CheckFunctionExists)
include(CheckCXXSourceCompiles)
include(CheckIncludeFile)

# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------

# This just sets the builtin BUILD_SHARED_LIBS, but if defaults to ON instead of
# OFF.
option(GTIRB_PPRINTER_BUILD_SHARED_LIBS "Build shared libraries." ON)

if(GTIRB_PPRINTER_BUILD_SHARED_LIBS)
  set(BUILD_SHARED_LIBS ON)
else()
  set(BUILD_SHARED_LIBS OFF)
endif()

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src)
if(WIN32)
  set(CMAKE_DEBUG_POSTFIX
      "d"
      CACHE STRING "add a postfix, usually d on windows")
endif()
set(CMAKE_RELEASE_POSTFIX
    ""
    CACHE STRING "add a postfix, usually empty on windows")
set(CMAKE_RELWITHDEBINFO_POSTFIX
    ""
    CACHE STRING "add a postfix, usually empty on windows")
set(CMAKE_MINSIZEREL_POSTFIX
    ""
    CACHE STRING "add a postfix, usually empty on windows")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Handle version initialization
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/version.txt" ver)

string(REGEX MATCH
             "VERSION_MAJOR ([0-9]*)"
             _
             ${ver})
set(GTIRB_PPRINTER_MAJOR_VERSION ${CMAKE_MATCH_1})

string(REGEX MATCH
             "VERSION_MINOR ([0-9]*)"
             _
             ${ver})
set(GTIRB_PPRINTER_MINOR_VERSION ${CMAKE_MATCH_1})

string(REGEX MATCH
             "VERSION_PATCH ([0-9]*)"
             _
             ${ver})
set(GTIRB_PPRINTER_PATCH_VERSION ${CMAKE_MATCH_1})

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/include/gtirb_pprinter/version.h.in"
               "${CMAKE_CURRENT_SOURCE_DIR}/include/gtirb_pprinter/version.h" @ONLY)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
# Error if it's not available
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Specifically check for gcc-7 or later. gcc-5 is installed on many systems and
# will accept -std=c++17, but does not fully support the standard.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "7.0.0")
    message(FATAL_ERROR "gcc 7 or later is required to build gtirb")
  endif()
endif()

# Detect how to use <experimental/filesystem>
set(EXPERIMENTAL_LIB
    ""
    CACHE STRING
          "The library to link with in order to use <experimental/filesystem>.")

if(NOT EXPERIMENTAL_LIB)
  set(EXFS_CODE "
  #include <experimental/filesystem>
  int main() {
    std::experimental::filesystem::path p{\"an/example/path\"};
    return std::experimental::filesystem::exists(p);
  }
  ")

  if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
    set(CMAKE_REQUIRED_DEFINITIONS "/D_SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING")
  endif()

  check_cxx_source_compiles("${EXFS_CODE}" EXFS_LINK_NONE)

  if(NOT EXFS_LINK_NONE)
    foreach(EXFS_LIB
            stdc++fs
            c++experimental
            c++fs)
      set(OLD_CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES})
      list(APPEND CMAKE_REQUIRED_LIBRARIES ${EXFS_LIB})
      check_cxx_source_compiles("${EXFS_CODE}" EXFS_LINK_${EXFS_LIB}_OK)
      set(CMAKE_REQUIRED_LIBRARIES ${OLD_CMAKE_REQUIRED_LIBRARIES})

      if(EXFS_LINK_${EXFS_LIB}_OK)
        if(EXPERIMENTAL_LIB)
          message(
            FATAL_ERROR
              "multiple candidates for library to link for <experimental/filesystem>: ${EXPERIMENTAL_LIB} and ${EXFS_LIB}. Try giving the correct one explicitly with -DEXPERIMENTAL_LIB."
            )
        endif()
        set(EXPERIMENTAL_LIB ${EXFS_LIB})
      endif()
    endforeach()

    if(NOT EXPERIMENTAL_LIB)
      message(
        FATAL_ERROR
          "could not find library to link for <experimental/filesystem>. Try giving it explicitly with -DEXPERIMENTAL_LIB."
        )
    endif()
  endif()
endif()

# If we're using libc++, we need to manually include libc++abi (unlike with
# using libstdc++, which automatically does this)
include(CheckCXXSourceCompiles)

check_cxx_source_compiles("
  #include <ciso646>
  int main() {
    return _LIBCPP_VERSION;
  }
" USING_LIBCPP)

if(USING_LIBCPP)
  if(BUILD_SHARED_LIBS)
    find_library(LIBCPP_ABI NAMES c++abi)
  else()
    find_library(LIBCPP_ABI NAMES libc++abi.a)
  endif()

  if(NOT LIBCPP_ABI)
    message(FATAL_ERROR "libc++abi not found")
  endif()
endif()

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /D_SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING")
endif()

# Base include path for the pretty-printer.
include_directories(${CMAKE_SOURCE_DIR}/include/gtirb_pprinter)

if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
  add_compile_options(-D_CRT_SECURE_NO_WARNINGS)
  add_compile_options(-D_MBCS)
  add_compile_options(-D_SCL_SECURE_NO_WARNINGS)
  add_compile_options(-D_WIN32)
  add_compile_options(-D_WINDOWS)
  add_compile_options(-DMBCS)
  add_compile_options(-DNOMINMAX)
  add_compile_options(-EHsc)
  add_compile_options(-GR)
  add_compile_options(-MP)
  add_compile_options(-nologo)
  add_compile_options(-W4)
  add_compile_options(-WX)

  add_compile_options(-wd4251) # 'identifier' : class 'type' needs to have dll-
                               # interface to be used by clients of class
                               # 'type2'
  add_compile_options(-wd4275) # Non-dll interface base classes.
  add_compile_options(-wd4996) # VC8: Deprecated libc functions.
  add_compile_options(-wd4351) # This is a warning about a change in behavior
                               # from old versions of visual c++.  We want the
                               # new (standard-compliant) behavior, so we don't
                               # want the warning.  The warning is that using an
                               # array in a class initializer list will cause
                               # its elements to be default initialized.

  # Per-configuration options
  add_compile_options($<$<CONFIG:Debug>:-D_DEBUG>)
  add_compile_options($<$<CONFIG:Debug>:-DDEBUG>)
  add_compile_options($<$<CONFIG:Debug>:-MDd>)
  add_compile_options($<$<CONFIG:Debug>:-Ob0>) # Disables inline expansion
  add_compile_options($<$<CONFIG:Debug>:-Od>) # Disables optimization, speeding
                                              # compilation and simplifying
                                              # debugging.
                                              # https://msdn.microsoft.com/en-
                                              # us/library/k1ack8f1.aspx
  add_compile_options($<$<CONFIG:Debug>:-RTC1>) # Enables run-time error
                                                # checking.
  add_compile_options($<$<CONFIG:Debug>:-W4>) # Sets warning level.
  add_compile_options($<$<CONFIG:Debug>:-Zi>) # Generates complete debugging
                                              # information.
  add_compile_options($<$<CONFIG:Debug>:-bigobj>) # enables big obj compilation
                                                  # option

  add_compile_options($<$<CONFIG:RelWithDebInfo>:-D_NDEBUG>)
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-DNDEBUG>)
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-MD>)
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-O2>) # Creates fast code.
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-Ob2>) # The default value.
                                                        # Allows expansion of
                                                        # functions marked as
                                                        # inline, __inline, or
                                                        # __forceinline, and any
                                                        # other function that
                                                        # the compiler chooses.
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-Oi>) # Generates intrinsic
                                                       # functions.
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-Ot>) # Favors fast code.
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-W4>) # Sets warning level.
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-Zi>) # Generates complete
                                                       # debugging information.
  add_compile_options($<$<CONFIG:RelWithDebInfo>:-bigobj>) # enables big obj
                                                           # compilation option

  add_compile_options($<$<CONFIG:Release>:-D_NDEBUG>)
  add_compile_options($<$<CONFIG:Release>:-DNDEBUG>)
  add_compile_options($<$<CONFIG:Release>:-MD>)
  add_compile_options($<$<CONFIG:Release>:-O2>) # Creates fast code.
  add_compile_options($<$<CONFIG:Release>:-Ob2>) # The default value. Allows
                                                 # expansion of functions marked
                                                 # as inline, __inline, or
                                                 # __forceinline, and any other
                                                 # function that the compiler
                                                 # chooses.
  add_compile_options($<$<CONFIG:Release>:-Oi>) # Generates intrinsic functions.
  add_compile_options($<$<CONFIG:Release>:-Ot>) # Favors fast code.
  add_compile_options($<$<CONFIG:Release>:-W4>) # Sets warning level.
  add_compile_options($<$<CONFIG:Release>:-bigobj>) # enables big obj
                                                    # compilation option

  # Shove in some linker flags to support using 64-bit memory. 4099 -PDB
  # 'filename' was not found with 'object/library' or at 'path'; linking object
  # as if no debug info
  set(CMAKE_SHARED_LINKER_FLAGS
      "${CMAKE_SHARED_LINKER_FLAGS} /LARGEADDRESSAWARE")

elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
  add_compile_options(-Wall
                      -Wextra
                      -Wpointer-arith
                      -Wshadow)
  add_compile_options(-Werror)
  add_compile_options(-fPIC)
elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL Clang)
  add_compile_options(-Wall
                      -Wextra
                      -Wpointer-arith
                      -Wshadow)
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
set(BOOST_COMPONENTS filesystem program_options system)
find_package(Boost 1.67 REQUIRED COMPONENTS ${BOOST_COMPONENTS})

add_compile_options(-DBOOST_CONFIG_SUPPRESS_OUTDATED_MESSAGE)
add_compile_options(-DBOOST_SYSTEM_NO_DEPRECATED)

# Boost versions 1.70.0+ may use Boost's provided CMake support rather than
# CMake's internal Boost support. The former uses "Boost::boost" and so on,
# while the latter uses "Boost_BOOST" and so on. This normalizes the two cases
# to use Boost_INCLUDE_DIRS and Boost_LIBRARIES.
if(TARGET Boost::headers)
  get_target_property(Boost_INCLUDE_DIRS Boost::headers
                      INTERFACE_INCLUDE_DIRECTORIES)
  foreach(BOOST_COMPONENT ${BOOST_COMPONENTS})
    list(APPEND Boost_LIBRARIES Boost::${BOOST_COMPONENT})
  endforeach()
endif()

include_directories(${Boost_INCLUDE_DIRS})

# ---------------------------------------------------------------------------
# capstone
# ---------------------------------------------------------------------------
if(BUILD_SHARED_LIBS)
  find_library(CAPSTONE NAMES capstone)
else()
  find_library(CAPSTONE NAMES libcapstone.a)
endif()

if(NOT CAPSTONE)
  message(
    FATAL_ERROR
      " No Capstone installation found.\n"
      " - If Capstone is not installed, install it from souce.\n"
      "   You can get the latest version of Capstone at:\n"
      "       http://www.capstone-engine.org/\n"
      " - If Capstone is installed, make sure the installation location is in your PATH,\n"
      "   and it is at least version 4.0.1.\n")
endif()

include_directories(${CAPSTONE_INCLUDE_DIRS})

# ---------------------------------------------------------------------------
# Source files
# ---------------------------------------------------------------------------
add_subdirectory(driver)
add_subdirectory(src)

# ---------------------------------------------------------------------------
# Export config for use by other CMake projects
# ---------------------------------------------------------------------------
export(TARGETS gtirb_pprinter
       FILE "${CMAKE_CURRENT_BINARY_DIR}/gtirb_pprinterTargets.cmake")
file(
  WRITE "${CMAKE_CURRENT_BINARY_DIR}/gtirb_pprinterConfig.cmake"
  "
            include(\"\$\{CMAKE_CURRENT_LIST_DIR\}/gtirb_pprinterTargets.cmake\")
            set_property(
                TARGET gtirb_pprinter
                APPEND PROPERTY
                    INTERFACE_INCLUDE_DIRECTORIES \"${CMAKE_BINARY_DIR}/include\"
            )
        ")
export(PACKAGE gtirb_pprinter)

# --- For the installed copy ---
# Main config file for find_package, just includes the targets file.
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/export/gtirb_pprinterConfig.cmake"
     "include(\"\$\{CMAKE_CURRENT_LIST_DIR\}/gtirb_pprinterTargets.cmake\")")
# In this mode, find_package also seems to require a version file
set(version_file
    "${CMAKE_CURRENT_BINARY_DIR}/gtirb_pprinterConfig-version.cmake")
include(CMakePackageConfigHelpers)
write_basic_package_version_file(${version_file}
                                 VERSION ${GTIRB_PPRINTER_VERSION}
                                 COMPATIBILITY AnyNewerVersion)

# Copy the config files to the install location
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/export/gtirb_pprinterConfig.cmake
              ${version_file}
        DESTINATION lib/gtirb_pprinter)

install(EXPORT gtirb_pprinterTargets DESTINATION lib/gtirb_pprinter)
