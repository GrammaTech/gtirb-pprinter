SET(PROJECT_NAME debloatDisasm)

# Required warning suppression (TODO: Remove!)
if(${CMAKE_CXX_COMPILER_ID} STREQUAL MSVC)
	#add_compile_options(-wd4251)  # Non-exportable template classes.
elseif(${CMAKE_CXX_COMPILER_ID} STREQUAL GNU)
	add_compile_options(-fpermissive)
	add_compile_options(-mtune=generic)
	add_compile_options(-pthread)
elseif(${CMAKE_CXX_COMPILEUR_ID} STREQUAL Clang)
	add_compile_options(-fpermissive)
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
IF(UNIX AND NOT WIN32)
	SET(SYSLIBS
		dl
		pthread
	)
ELSE()
	SET(SYSLIBS
	)
endif()

# Find to warn the user...
find_program(DEBLOAT_FOUND_DATALOG_DECODER datalog_decoder 
	HINTS $ENV{PATH}
	DOC "datalog_decoder is required to be in your PATH for ${PROJECT_NAME} to execute.")
if(NOT DEBLOAT_FOUND_DATALOG_DECODER)
	message(WARNING "datalog_decoder was not found in your PATH is required for ${PROJECT_NAME} to properly execute.")
endif()

# Find to warn the user...
find_program(DEBLOAT_FOUND_SOUFFLE_DISASM souffle_disasm 
	HINTS $ENV{PATH}
	DOC "souffle_disasm is required to be in your PATH for ${PROJECT_NAME} to execute.")
if(NOT DEBLOAT_FOUND_SOUFFLE_DISASM)
	message(WARNING "souffle_disasm was not found in your PATH is required for ${PROJECT_NAME} to properly execute.")
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
	${Boost_LIBRARIES}
	debloatPrettyPrinter
)
