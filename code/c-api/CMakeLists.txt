# SPDX-FileCopyrightText: 2026 Matthew Klapman
# SPDX-License-Identifier: Apache-2.0
#
# Builds the Rust protocol library as a static archive and exposes it as a
# normal CMake target.
#
# Cargo is invoked rather than reimplemented: it owns the target triple, the
# panic strategy and the dependency graph, and a CMake-side reimplementation of
# any of those would drift from Cargo.toml silently. The custom command always
# runs -- cargo's own freshness check is faster and more correct than anything
# expressible here in file dependencies.

find_program(CARGO cargo HINTS $ENV{HOME}/.cargo/bin REQUIRED)

set(TMFFI_TRIPLE thumbv8m.main-none-eabi)   # RP2350 Cortex-M33, SOFT float
# Soft-float, not eabihf: pico-sdk builds the rest of the image soft-float, and
# mixing float ABIs is a link error rather than a silent hazard. This library
# does no floating point at all -- integer crypto in no_std -- so matching the
# consumer costs nothing.
set(TMFFI_A ${CMAKE_CURRENT_LIST_DIR}/target/${TMFFI_TRIPLE}/release/libtmffi.a)

add_custom_target(tmffi_build ALL
    COMMAND ${CARGO} build --release --target ${TMFFI_TRIPLE}
    WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
    COMMENT "cargo build tmffi (${TMFFI_TRIPLE})"
    VERBATIM)

add_library(tmffi STATIC IMPORTED GLOBAL)
set_target_properties(tmffi PROPERTIES IMPORTED_LOCATION ${TMFFI_A})
target_include_directories(tmffi INTERFACE ${CMAKE_CURRENT_LIST_DIR}/include)
add_dependencies(tmffi tmffi_build)
