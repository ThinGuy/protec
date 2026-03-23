# Project-level configuration.
cmake_minimum_required(VERSION 3.10)
project(runner LANGUAGES CXX)

# The name of the executable created for the application. Change this to change
# the on-disk name of your application.
set(BINARY_NAME "smartcard_diagnostic")
# The unique GTK application identifier for this application. See:
# https://wiki.gnome.org/HowDoI/ChooseApplicationID
set(APPLICATION_ID "com.canonical.smartcard_diagnostic")

# Explicitly opt in to modern CMake behaviors to avoid warnings with recent
# versions of CMake.
cmake_policy(SET CMP0063 NEW)

# Load bundled libraries from the lib/ directory relative to the binary.
set(CMAKE_INSTALL_RPATH "$ORIGIN/lib")

# Root filesystem for cross-building.
if(FLUTTER_TARGET_PLATFORM_SYSROOT)
  set(CMAKE_SYSROOT ${FLUTTER_TARGET_PLATFORM_SYSROOT})
  set(CMAKE_FIND_ROOT_PATH ${CMAKE_SYSROOT})
  set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
  set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
endif()

# Define build configuration options.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE "Debug" CACHE
    STRING "Flutter build mode" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
    "Debug" "Profile" "Release")
endif()

# Compilation settings that should be applied to most targets.
#
# Be cautious about adding new options here, as plugins use this function by
# default. In most cases, you should add new options to specific targets instead
# of modifying this function.
function(APPLY_STANDARD_SETTINGS TARGET)
  target_compile_features(${TARGET} PUBLIC cxx_std_14)
  target_compile_options(${TARGET} PRIVATE -Wall -Werror)
  target_compile_options(${TARGET} PRIVATE "$<$<NOT:$<CONFIG:Debug>>:-O3>")
  target_compile_definitions(${TARGET} PRIVATE "$<$<NOT:$<CONFIG:Debug>>:NDEBUG>")
endfunction()

# Flutter library and target platform files are configurable.
set(FLUTTER_MANAGED_DIR "${CMAKE_CURRENT_SOURCE_DIR}/flutter")
add_subdirectory(${FLUTTER_MANAGED_DIR})

# System-level dependencies.
find_package(PkgConfig REQUIRED)
pkg_check_modules(GTK REQUIRED IMPORTED_TARGET gtk+-3.0)

add_definitions(-DAPPLICATION_ID="${APPLICATION_ID}")

# Application target lives in the runner subdirectory.
add_subdirectory("runner")

# === Install Rules ===
# Use relative DESTINATION paths so cmake --install --prefix <bundle> works
# without requiring root. Absolute paths bake in the configure-time prefix
# and silently ignore --prefix overrides at install time.

# Ensure CMAKE_INSTALL_PREFIX falls back to the bundle directory when Flutter
# does not pass -DCMAKE_INSTALL_PREFIX at configure time.
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/bundle"
    CACHE PATH "Default install location" FORCE)
endif()

install(TARGETS ${BINARY_NAME} RUNTIME DESTINATION "." COMPONENT Runtime)

install(FILES "${FLUTTER_ICU_DATA_FILE}" DESTINATION "." COMPONENT Runtime)

install(FILES "${FLUTTER_LIBRARY}" DESTINATION "lib" COMPONENT Runtime)

foreach(bundled_library ${PLUGIN_BUNDLED_LIBRARIES})
  install(FILES "${bundled_library}"
    DESTINATION "lib"
    COMPONENT Runtime)
endforeach(bundled_library)

# Copy flutter_assets on each install to remove stale files.
set(FLUTTER_ASSET_DIR_NAME "flutter_assets")
install(CODE "
  file(REMOVE_RECURSE \"${CMAKE_INSTALL_PREFIX}/${FLUTTER_ASSET_DIR_NAME}\")
  " COMPONENT Runtime)
install(DIRECTORY "${PROJECT_BUILD_DIR}/${FLUTTER_ASSET_DIR_NAME}"
  DESTINATION "." COMPONENT Runtime)

# Install native assets only if the directory was created during the build.
# Flutter 3.24+ expects this rule but the directory only exists when Dart
# native assets are actually in use.
install(CODE "
  set(_native_assets_dir \"${PROJECT_BUILD_DIR}/native_assets/linux/\")
  if(EXISTS \"\${_native_assets_dir}\")
    file(INSTALL \"\${_native_assets_dir}\"
      DESTINATION \"\${CMAKE_INSTALL_PREFIX}/lib\"
      TYPE DIRECTORY)
  endif()
  " COMPONENT Runtime)
