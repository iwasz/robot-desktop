CMAKE_MINIMUM_REQUIRED (VERSION 2.4.7 FATAL_ERROR)
project (robotctl)

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

pkg_check_modules (NCURSES REQUIRED "ncurses")
INCLUDE_DIRECTORIES (${NCURSES_INCLUDE_DIRS})
link_directories(${NCURSES_LIBRARY_DIRS})

INCLUDE_DIRECTORIES ("src/")
LIST (APPEND APP_SOURCES "src/main.cc")
LIST (APPEND APP_SOURCES "src/bluetooth/BluetoothLE.cc")
LIST (APPEND APP_SOURCES "src/bluetooth/BluetoothLE.h")
LIST (APPEND APP_SOURCES "src/bluetooth/BluetoothException.cc")
LIST (APPEND APP_SOURCES "src/bluetooth/BluetoothException.h")
LIST (APPEND APP_SOURCES "src/Exception.cc")
LIST (APPEND APP_SOURCES "src/Exception.h")

add_executable (${PROJECT_NAME} ${APP_SOURCES})
TARGET_LINK_LIBRARIES (${PROJECT_NAME} ${LIBUSBX_LIBRARIES})
TARGET_LINK_LIBRARIES (${PROJECT_NAME} ${BLUEZ_LIBRARIES})
TARGET_LINK_LIBRARIES (${PROJECT_NAME} ${NCURSES_LIBRARIES})
TARGET_LINK_LIBRARIES (${PROJECT_NAME} pthread)
