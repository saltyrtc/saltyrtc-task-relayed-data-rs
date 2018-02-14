# Project
project(
  'saltyrtc-task-relayed-data-ffi-tests',
  'c',
  default_options : ['c_std=c99']
)

# Dependency: SaltyRTC
compiler = meson.get_compiler('c')
rust_target_dir = join_paths(meson.source_root(), 'target/debug/')
saltyrtc_task_relayed_data_ffi = compiler.find_library(
  'saltyrtc_task_relayed_data_ffi',
  dirs : [rust_target_dir]
)

# Dependency: pthread
thread_dep = dependency('threads')

# Executables
executable(
  'tests',
  'tests/tests.c',
  dependencies : [saltyrtc_task_relayed_data_ffi, thread_dep]
)
