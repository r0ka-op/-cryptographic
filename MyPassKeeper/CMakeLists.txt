cmake_minimum_required(VERSION 3.5)

project(MyPassKeeper VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

set(PROJECT_SOURCES
        main.cpp
        mainwindow.cpp
        mainwindow.h
        mainwindow.ui
        credentialwidget.h
        credentialwidget.cpp
        credentialwidget.ui
        json/cridentials.json
        json/cridentials_enc.json
        json/cridentials_to_enc.json
)

if(${QT_VERSION_MAJOR} GREATER_EQUAL 6)
    qt_add_executable(MyPassKeeper
        MANUAL_FINALIZATION
        ${PROJECT_SOURCES}

        main.cpp

    )
# Define target properties for Android with Qt 6 as:
#    set_property(TARGET MyPassKeeper APPEND PROPERTY QT_ANDROID_PACKAGE_SOURCE_DIR
#                 ${CMAKE_CURRENT_SOURCE_DIR}/android)
# For more information, see https://doc.qt.io/qt-6/qt-add-executable.html#target-creation
else()
    if(ANDROID)
        add_library(MyPassKeeper SHARED
            ${PROJECT_SOURCES}
        )
# Define properties for Android with Qt 5 after find_package() calls as:
#    set(ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/android")
    else()
        add_executable(MyPassKeeper
            ${PROJECT_SOURCES}
        )
    endif()
endif()

target_link_libraries(MyPassKeeper PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)

#include(FindOpenSSL)
# target_link_libraries(MyPassKeeper PRIVATE ${CMAKE_DL_LIBS} OpenSSL::SSL OpenSSL::Crypto)

target_include_directories(
    MyPassKeeper
    PRIVATE
    D:/Progs/Qt/Tools/OpenSSLv3/Win_x64/include)
target_link_libraries(
    MyPassKeeper
    PRIVATE
    D:/Progs/Qt/Tools/OpenSSLv3/Win_x64/lib/libcrypto.lib)

# Qt for iOS sets MACOSX_BUNDLE_GUI_IDENTIFIER automatically since Qt 6.1.
# If you are developing for iOS or macOS you should consider setting an
# explicit, fixed bundle identifier manually though.
if(${QT_VERSION} VERSION_LESS 6.1.0)
  set(BUNDLE_ID_OPTION MACOSX_BUNDLE_GUI_IDENTIFIER com.example.MyPassKeeper)
endif()
set_target_properties(MyPassKeeper PROPERTIES
    ${BUNDLE_ID_OPTION}
    MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION}
    MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}
    MACOSX_BUNDLE TRUE
    WIN32_EXECUTABLE TRUE
)

include(GNUInstallDirs)
install(TARGETS MyPassKeeper
    BUNDLE DESTINATION .
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(QT_VERSION_MAJOR EQUAL 6)
    qt_finalize_executable(MyPassKeeper)
endif()

#configure_file(
#    json\cridentials.json
#    json\cridentials_enc.json
#)
