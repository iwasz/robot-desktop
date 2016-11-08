CMAKE_MINIMUM_REQUIRED (VERSION 2.4.7 FATAL_ERROR)
project (minimalgatt)

if(COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

add_definitions (-Wl,-z,defs)

SET (CMAKE_C_FLAGS "-Wall -Winvalid-pch -ffunction-sections -fdata-sections")
SET (CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -std=c++11")
SET (CMAKE_C_FLAGS_RELEASE "-Wall -Winvalid-pch -ffunction-sections -fdata-sections -ffast-math -DNDEBUG")
SET (CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -std=c++11")

SET (CMAKE_VERBOSE_MAKEFILE off)

include (FindPkgConfig)
pkg_check_modules (BLUEZ REQUIRED "bluez")
INCLUDE_DIRECTORIES (${BLUEZ_INCLUDE_DIRS})
link_directories(${BLUEZ_LIBRARY_DIRS})

pkg_check_modules (GLIB REQUIRED "glib-2.0")
INCLUDE_DIRECTORIES (${GLIB_INCLUDE_DIRS})
link_directories(${GLIB_LIBRARY_DIRS})

pkg_check_modules (GTK REQUIRED "gtk+-3.0")
INCLUDE_DIRECTORIES (${GTK_INCLUDE_DIRS})
link_directories(${GTK_LIBRARY_DIRS})


INCLUDE_DIRECTORIES ("src/")
LIST (APPEND APP_SOURCES "src/attrib/att.c")
LIST (APPEND APP_SOURCES "src/attrib/att.h")
LIST (APPEND APP_SOURCES "src/attrib/gatt.c")
LIST (APPEND APP_SOURCES "src/attrib/gatt.h")
LIST (APPEND APP_SOURCES "src/attrib/gattrib.c")
LIST (APPEND APP_SOURCES "src/attrib/gattrib.h")
LIST (APPEND APP_SOURCES "src/attrib/gatttool.c")
LIST (APPEND APP_SOURCES "src/attrib/gatttool.h")
LIST (APPEND APP_SOURCES "src/attrib/utils.c")

LIST (APPEND APP_SOURCES "src/lib/uuid.h")
LIST (APPEND APP_SOURCES "src/lib/uuid.c")

LIST (APPEND APP_SOURCES "src/shared/log.h")
LIST (APPEND APP_SOURCES "src/shared/log.c")
LIST (APPEND APP_SOURCES "src/shared/util.h")
LIST (APPEND APP_SOURCES "src/shared/util.c")
LIST (APPEND APP_SOURCES "src/shared/crypto.h")
LIST (APPEND APP_SOURCES "src/shared/crypto.c")
LIST (APPEND APP_SOURCES "src/shared/att-types.h")
LIST (APPEND APP_SOURCES "src/shared/att.h")
LIST (APPEND APP_SOURCES "src/shared/att.c")
LIST (APPEND APP_SOURCES "src/shared/queue.h")
LIST (APPEND APP_SOURCES "src/shared/queue.c")
LIST (APPEND APP_SOURCES "src/shared/io.h")
LIST (APPEND APP_SOURCES "src/shared/io-glib.c")
LIST (APPEND APP_SOURCES "src/shared/timeout.h")
LIST (APPEND APP_SOURCES "src/shared/timeout-glib.c")

LIST (APPEND APP_SOURCES "src/btio/btio.h")
LIST (APPEND APP_SOURCES "src/btio/btio.c")


add_executable (${PROJECT_NAME} ${APP_SOURCES})
TARGET_LINK_LIBRARIES (${PROJECT_NAME} ${GLIB_LIBRARIES})
TARGET_LINK_LIBRARIES (${PROJECT_NAME} ${BLUEZ_LIBRARIES})
TARGET_LINK_LIBRARIES (${PROJECT_NAME} ${GTK_LIBRARIES})
