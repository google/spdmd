project('spdmwrapper', ['c','cpp'],
        version : '1.0',
        meson_version: '>=0.63.0',
        default_options: [
            'warning_level=3',
            'werror=true',
            'cpp_std=c++20',
            'c_std=c18',
            'tests=' + (meson.is_subproject() ? 'disabled' : 'enabled'),
            ])

libspdm = dependency('libspdm', method : 'pkg-config', required : true)
if libspdm.found()
    # Do something.
    message('libspdm dependency is:  - ', libspdm.name())
    else
    message('libspdm dependency not found ')
    # Do something else.
endif

# Dependencies
libspdmwrapper_ext_dep = [libspdm]

# Include directories
libspdmwrapper_incdir = include_directories(
  'include',
  'library',
)

# Source files
srcfiles = files(
  'library/pcie_doe_transport.c',
  'library/mctp_transport.c',
  'library/libspdm_callbacks.c',
  'library/libspdm_support.c',
  'library/spdm_conn_preconfig.c',
  'library/spdm_conn_management.c',
  'library/spdm_cert_wrapper.c',
  'library/spdm_mea_wrapper.c',
)

if get_option('buildtype') == 'debug'
  add_project_arguments('-DDEBUG', language: 'c')  # For C
  add_project_arguments('-DDEBUG', language: 'cpp') # For C++
endif

feature_map = {
    'spdm-debug-print'                  : '-DLIBSPDM_DEBUG_PRINT_ENABLE',
}

# Get the options status and build a project summary to show which flags are
# being enabled during the configuration time.

foreach option_key,option_value : feature_map
  if(get_option(option_key).enabled())
    if(option_key == 'spdm-debug-print')
      add_project_arguments(option_value,language:'c')
      summary(option_key,option_value, section : 'Enabled Features')
    endif
  endif
endforeach

# Install targets
libspdmwrapper = static_library(
  'spdmwrapper',
  srcfiles,
  include_directories : libspdmwrapper_incdir,
  c_args: ['-Wno-sign-compare', '-Wno-unused-parameter'],
  dependencies: libspdmwrapper_ext_dep,
)

libspdmwrapper_dep = declare_dependency(
  include_directories: libspdmwrapper_incdir,
  link_with: libspdmwrapper)

if get_option('tests').allowed()
  subdir('tests')
endif

import('pkgconfig').generate(
    libspdmwrapper,
    name: meson.project_name(),
    version: meson.project_version(),
    description: 'libspdm wrapper that provides connection management and easier certs and measurements access',
)

# Install headers
install_headers('include/pcie_doe.h')
install_headers('include/spdm_conn.h')
