# Project
project('saltyrtc-task-relayed-data-ffi-tests', 'c')

# Dependencies
compiler = meson.get_compiler('c')
rust_target_dir = join_paths(meson.source_root(), 'target/debug/')
saltyrtc_task_relayed_data_ffi = compiler.find_library('saltyrtc_task_relayed_data_ffi', dirs : [rust_target_dir])

# Executables
executable('tests', 'tests/tests.c', dependencies : [saltyrtc_task_relayed_data_ffi])
