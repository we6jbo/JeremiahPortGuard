cmake_minimum_required(VERSION 3.21)

project(JeremiahPortGuard VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)

qt_add_executable(JeremiahPortGuard
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
)

target_link_libraries(JeremiahPortGuard PRIVATE Qt6::Widgets)

install(TARGETS JeremiahPortGuard
    RUNTIME DESTINATION bin
)
