SET(PROJECT_NAME gtirb-pprinter)

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
  Logger.h
)

set(${PROJECT_NAME}_SRC
  main.cpp
)

# Unix, but not Cygwin.
IF(UNIX)
  IF (NOT WIN32)
    SET(SYSLIBS
      ${SYSLIBS}
      dl
      pthread)
  ENDIF()
ELSE()
  SET(SYSLIBS
  )
endif()

add_executable(${PROJECT_NAME}
    ${${PROJECT_NAME}_H}
    ${${PROJECT_NAME}_SRC}
  )

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src)

set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "debloat")

target_link_libraries(
  ${PROJECT_NAME}
  ${SYSLIBS}
  ${EXPERIMENTAL_LIB}
  ${Boost_LIBRARIES}
        gtirb_pprinter
)

install(TARGETS gtirb-pprinter DESTINATION bin)
