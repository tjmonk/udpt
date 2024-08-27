cmake_minimum_required(VERSION 3.10)

include(GNUInstallDirs)

project(udpt
	VERSION 0.1
    DESCRIPTION "UDP Template Engine"
)

add_executable( ${PROJECT_NAME}
	src/udpt.c
)

target_include_directories( ${PROJECT_NAME}
	PRIVATE inc
)

target_link_libraries( ${PROJECT_NAME}
	${CMAKE_THREAD_LIBS_INIT}
	rt
	varserver
)

install(TARGETS ${PROJECT_NAME}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

