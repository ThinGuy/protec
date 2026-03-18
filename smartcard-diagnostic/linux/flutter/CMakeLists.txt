# This file controls Flutter-level build steps. It should not be edited.
cmake_minimum_required(VERSION 3.10)

set(EPHEMERAL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ephemeral")

# Configuration provided via flutter tool.
include(${EPHEMERAL_DIR}/generated_config.cmake)

# TODO: Move the rest of this into files in ephemeral. See
# https://github.com/flutter/flutter/issues/57146.
set(FLUTTER_LIBRARY "${EPHEMERAL_DIR}/libflutter_linux_gtk.so")

# Published to parent scope for install step.
set(FLUTTER_ICU_DATA_FILE "${EPHEMERAL_DIR}/icudtl.dat" PARENT_SCOPE)
set(FLUTTER_LIBRARY ${FLUTTER_LIBRARY} PARENT_SCOPE)

# === Flutter Library ===
set(FLUTTER_LIBRARY_HEADERS
  "${EPHEMERAL_DIR}/fl_basic_message_channel.h"
  "${EPHEMERAL_DIR}/fl_binary_codec.h"
  "${EPHEMERAL_DIR}/fl_binary_messenger.h"
  "${EPHEMERAL_DIR}/fl_dart_project.h"
  "${EPHEMERAL_DIR}/fl_engine.h"
  "${EPHEMERAL_DIR}/fl_json_message_codec.h"
  "${EPHEMERAL_DIR}/fl_json_method_codec.h"
  "${EPHEMERAL_DIR}/fl_message_codec.h"
  "${EPHEMERAL_DIR}/fl_method_call.h"
  "${EPHEMERAL_DIR}/fl_method_channel.h"
  "${EPHEMERAL_DIR}/fl_method_codec.h"
  "${EPHEMERAL_DIR}/fl_method_response.h"
  "${EPHEMERAL_DIR}/fl_plugin_registrar.h"
  "${EPHEMERAL_DIR}/fl_plugin_registry.h"
  "${EPHEMERAL_DIR}/fl_standard_message_codec.h"
  "${EPHEMERAL_DIR}/fl_standard_method_codec.h"
  "${EPHEMERAL_DIR}/fl_string_codec.h"
  "${EPHEMERAL_DIR}/fl_value.h"
  "${EPHEMERAL_DIR}/fl_view.h"
  "${EPHEMERAL_DIR}/flutter_linux.h"
)

add_library(flutter SHARED IMPORTED)
set_property(TARGET flutter PROPERTY IMPORTED_LOCATION "${FLUTTER_LIBRARY}")
set_property(TARGET flutter PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${EPHEMERAL_DIR}")

# === Flutter tool backend ===
# _phony_ is a non-existent file to force this command to run every time,
# since currently there's no way to get a full list of source files that
# might affect the build.
add_custom_command(
  OUTPUT ${FLUTTER_LIBRARY} ${FLUTTER_LIBRARY}_phony_
  COMMAND ${CMAKE_COMMAND} -E env
    ${FLUTTER_TOOL_ENVIRONMENT}
    "${FLUTTER_ROOT}/packages/flutter_tools/bin/tool_backend.sh"
    ${FLUTTER_TARGET_PLATFORM} ${CMAKE_BUILD_TYPE}
  VERBATIM
)
add_custom_target(flutter_assemble DEPENDS
  "${FLUTTER_LIBRARY}"
  ${FLUTTER_LIBRARY}_phony_
)
