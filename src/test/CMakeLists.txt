SET(PROJECT_NAME TestPrettyPrinter)

if(DEBLOAT_FOUND_DATALOG_DECODER AND DEBLOAT_FOUND_SOUFFLE_DISASM)
	enable_testing()
	
	include_directories(${GTEST_INCLUDE_DIRS})

	# -------------------------------------------------------------------------
	# -------------------------------------------------------------------------
	
	# Find all example programs.
	# make projects for them.
	# Add them to a variable that will be expanded inside our test case to run it.

	file(GLOB EXAMPLE_SOURCE "./examples/*.c" "./examples/*.cpp")

	foreach(_ex IN LISTS EXAMPLE_SOURCE)
		get_filename_component(TEST_PROJECT_NAME ${_ex} NAME_WE)
		add_executable(${TEST_PROJECT_NAME} ${_ex})
		LIST(APPEND DEBLOAT_TEST_PRETTY_PRINTER_EXAMPLES_TEMP "std::string{\"${TEST_PROJECT_NAME}\"}")
	endforeach()

	# Convert our list to a CSV list for expansion inside the test case.
	string(REPLACE "}std::string{" "}, std::string{" DEBLOAT_TEST_PRETTY_PRINTER_EXAMPLES ${DEBLOAT_TEST_PRETTY_PRINTER_EXAMPLES_TEMP})
	# For debugging # MESSAGE("Examples: " ${DEBLOAT_TEST_PRETTY_PRINTER_EXAMPLES})

	# -------------------------------------------------------------------------
	# -------------------------------------------------------------------------

	add_compile_options(-DDEBUG)
	add_compile_options(-DDEBLOAT_FOUND_DATALOG_DECODER=${DEBLOAT_FOUND_DATALOG_DECODER})
	add_compile_options(-DDEBLOAT_FOUND_SOUFFLE_DISASM=${DEBLOAT_FOUND_SOUFFLE_DISASM})
	add_compile_options(-DDEBLOAT_TEST_PRETTY_PRINTER_EXAMPLES=${DEBLOAT_TEST_PRETTY_PRINTER_EXAMPLES})
	add_compile_options(-DDEBLOAT_TEST_PRETTY_PRINTER_COMPILER_FLAGS=${DEBLOAT_TEST_PRETTY_PRINTER_COMPILER_FLAGS})
	add_compile_options(-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
	add_compile_options(-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
	add_compile_options(-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER})

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
	)

	set(${PROJECT_NAME}_SRC
		PrettyPrinter.test.cpp
	)

	IF(UNIX AND NOT WIN32)
		SET(SYSLIBS
			dl
		)
	ELSE()
		SET(SYSLIBS
		)
	endif()

	add_executable(${PROJECT_NAME} 
		${${PROJECT_NAME}_H}
		${${PROJECT_NAME}_SRC}
	)
	
	add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})
	set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "debloat/test")

	target_link_libraries(
		${PROJECT_NAME} 
		${SYSLIBS}
		${Boost_LIBRARIES}
		gtest 
		gtest_main
		gtirb_pprinter
	)

	add_custom_target(check DEPENDS ${PROJECT_NAME})
	add_custom_command(TARGET check COMMAND POST_BUILD COMMAND $<TARGET_FILE:${PROJECT_NAME}>)

else()
	message(WARNING "Both datalog_decoder and souffle_disasm must be known to CMake to build ${PROJECT_NAME}")
endif()
