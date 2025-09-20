cmake_minimum_required(VERSION 3.20)
project(PwCheckGUI LANGUAGES CXX)

# Require C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Tell CMake to look for Qt
find_package(Qt6 REQUIRED COMPONENTS Widgets)

# Define the app target and which files it needs
add_executable(PwCheckGUI
    gui_main.cpp
    password_scoring.cpp
    password_scoring.h
)

# Link Qt Widgets library
target_link_libraries(PwCheckGUI PRIVATE Qt6::Widgets)

# On macOS, make a proper .app bundle
if(APPLE)
    set_target_properties(PwCheckGUI PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_GUI_IDENTIFIER com.example.pwcheck
        MACOSX_BUNDLE_BUNDLE_NAME "Password Strength Checker"
    )
endif()
