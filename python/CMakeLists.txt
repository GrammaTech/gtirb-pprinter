function(make_absolute variable path)
  file(READ_SYMLINK "${path}" link_path)
  if(NOT IS_ABSOLUTE "${link_path}")
    get_filename_component(dir "${path}" DIRECTORY)
    set(path "${dir}/${link_path}")
  endif()
  set(${variable}
      "${path}"
      PARENT_SCOPE)
endfunction()

if(GTIRB_PPRINTER_RELEASE_VERSION)
  set(GTIRB_PPRINTER_PYTHON_DEV_SUFFIX "")
else()
  set(GTIRB_PPRINTER_PYTHON_DEV_SUFFIX ".dev")
endif()

# TODO: GTIRB_RELEASE_VERSION or GTIRB_PYTHON_DEV_SUFFIX should come from the
# GTIRB conan files and not get guessed at here.
if(GTIRB_PPRINTER_RELEASE_VERSION)
  set(GTIRB_PYTHON_DEV_SUFFIX "")
else()
  set(GTIRB_PYTHON_DEV_SUFFIX ".dev")
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/setup.py.in
               ${CMAKE_CURRENT_BINARY_DIR}/setup.py @ONLY)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/version.py.in
               ${CMAKE_CURRENT_BINARY_DIR}/version.py @ONLY)

find_library(GTIRB_LIBRARY_PATH gtirb)
make_absolute(GTIRB_LIBRARY_PATH ${GTIRB_LIBRARY_PATH})

find_library(CAPSTONE_LIBRARY_PATH capstone)
make_absolute(CAPSTONE_LIBRARY_PATH ${CAPSTONE_LIBRARY_PATH})

file(GLOB PY_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/gtirb_pprinter/*.py)

add_custom_target(pypprinter ALL DEPENDS ${PY_SOURCES} gtirb-pprinter)
add_custom_command(
  TARGET pypprinter
  COMMAND ${CMAKE_COMMAND} -E copy_directory "${CMAKE_CURRENT_SOURCE_DIR}/src"
          "${CMAKE_CURRENT_BINARY_DIR}/src"
  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_SOURCE_DIR}/README.md"
          "${CMAKE_CURRENT_BINARY_DIR}/"
  COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/version.py"
          "${CMAKE_CURRENT_BINARY_DIR}/src/gtirb_pprinter/"
  COMMAND ${CMAKE_COMMAND} -E make_directory
          "${CMAKE_CURRENT_BINARY_DIR}/src/gtirb_pprinter/.libs/"
  COMMAND
    ${CMAKE_COMMAND} -E copy ${GTIRB_LIBRARY_PATH} ${CAPSTONE_LIBRARY_PATH}
    $<TARGET_FILE:gtirb_layout> $<TARGET_FILE:gtirb_pprinter>
    $<TARGET_SONAME_FILE:gtirb_layout> $<TARGET_SONAME_FILE:gtirb_pprinter>
    "${CMAKE_CURRENT_BINARY_DIR}/src/gtirb_pprinter/.libs/"
  COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:gtirb-pprinter>
          "${CMAKE_CURRENT_BINARY_DIR}/src/gtirb_pprinter/")
if(UNIX AND NOT APPLE)
  add_custom_command(
    TARGET pypprinter
    COMMAND patchelf --set-rpath '$$ORIGIN/.libs'
            "${CMAKE_CURRENT_BINARY_DIR}/src/gtirb_pprinter/gtirb-pprinter"
    COMMAND patchelf --set-rpath '$$ORIGIN'
            "${CMAKE_CURRENT_BINARY_DIR}/src/gtirb_pprinter/.libs/*")
endif()

# Convenience targets for building the python wheel
find_program(PYTHON3 "python3")
add_custom_target(
  python-wheel
  DEPENDS pypprinter
  COMMAND "${PYTHON3}" setup.py bdist_wheel)
