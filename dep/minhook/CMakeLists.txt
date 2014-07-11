set(minhook_src
	include/MinHook.h
	src/buffer.h
	src/buffer.cpp
	src/export.cpp
	src/hook.h
	src/hook.cpp
	src/pstdint.h
	src/thread.h
	src/thread.cpp
	src/trampoline.h
	src/trampoline.cpp
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
set(minhook_src
	${minhook_src}
	src/HDE64/include/hde64.h
	src/HDE64/src/hde64.c
	src/HDE64/src/table64.h)
else()
set(minhook_src
	${minhook_src}
	src/HDE32/src/hde32.h
	src/HDE32/src/hde32.c
	src/HDE32/src/table32.c)
endif()

include_directories(include)

add_library(minhook STATIC ${minhook_src})
