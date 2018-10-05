SET(PROJECT_NAME gtirb_pprinter)

add_compile_options(-DDEBLOAT_${PROJECT_NAME}_EXPORTS)

# Required warning suppression (TODO: Remove!)
if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
	#add_compile_options(-wd4251)  # Non-exportable template classes.
elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
	add_compile_options(-mtune=generic)
	add_compile_options(-pthread)
elseif(${CMAKE_CXX_COMPILEUR_ID} STREQUAL Clang)
	add_compile_options(-mtune=generic)
	add_compile_options(-pthread)
endif()

set(${PROJECT_NAME}_H
	DisasmData.h
	Export.h
	PrettyPrinter.h
)

set(${PROJECT_NAME}_SRC
	DisasmData.cpp
	PrettyPrinter.cpp
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

add_library(${PROJECT_NAME} SHARED
		${${PROJECT_NAME}_H}
		${${PROJECT_NAME}_SRC}
	)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
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
  COMMAND "${CMAKE_COMMAND}" -E remove_directory "${CMAKE_BINARY_DIR}/include/")
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_BINARY_DIR}/include/")
add_custom_command(
        TARGET ${PROJECT_NAME} POST_BUILD
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND "${CMAKE_COMMAND}" -E copy
                ${${PROJECT_NAME}_H}
                "${CMAKE_BINARY_DIR}/include/")
