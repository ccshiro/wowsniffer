cmake_minimum_required(VERSION 2.8)

project(wowsniffer)

add_subdirectory(dep)
include_directories(dep/minhook/include)

add_library(sniffer SHARED shared_object.cpp pattern_finder.h
	pattern_finder.cpp)
	
target_link_libraries(sniffer
	minhook)

add_executable(wowsniffer wowsniffer.cpp)

install(TARGETS sniffer DESTINATION bin)
install(TARGETS wowsniffer DESTINATION bin)
