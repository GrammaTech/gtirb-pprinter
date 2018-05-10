SET(PROJECT_NAME debloatPrettyPrinter)

add_compile_options(-DDEBLOAT_${PROJECT_NAME}_EXPORTS)

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
	DataGroup.h
	DisasmData.h
	DisasmTypes.h
	Export.h
	PrettyPrinter.h
	Table.h
)

set(${PROJECT_NAME}_SRC
	DisasmData.cpp
	PrettyPrinter.cpp
	Table.cpp
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
include_directories(${PROJECT_SOURCE_DIR}/../gt-irb/include)
set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "debloat")

target_link_libraries(
	${PROJECT_NAME} 
	${SYSLIBS}
	${Boost_LIBRARIES}
        ${GTIRB}
)

add_subdirectory(test)
