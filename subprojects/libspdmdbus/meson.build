project('spdmdbus', 'cpp',
        version : '1.0',
        meson_version: '>=0.63.0',
        default_options: [
            'warning_level=3',
            'werror=true',
            'cpp_std=c++20',
            ])

libspdm = dependency('libspdm', required : true)
phosphor_dbus_interfaces = dependency('phosphor-dbus-interfaces')
sdbusplus = dependency('sdbusplus')
sdeventplus = dependency('sdeventplus')
phosphor_logging_dep = dependency('phosphor-logging')

libspdmwrapper_proj = subproject('libspdmwrapper')
libspdmwrapper_dep = libspdmwrapper_proj.get_variable('libspdmwrapper_dep')

# Dependencies
spdm_dbus_dependencies = [
    libspdm,
    libspdmwrapper_dep,
    phosphor_dbus_interfaces,
    phosphor_logging_dep,
    sdbusplus,
    sdeventplus,
]

# Include directories
libspdmdbus_incdir = include_directories(
  'include',
)

# Source files
srcfiles = files(
  'library/certificate.cpp',
  'library/component_integrity.cpp',
  'library/trusted_component.cpp',
)

# Install targets
libspdmdbus = static_library(
  'spdmdbus',
  srcfiles,
  include_directories : libspdmdbus_incdir,
  cpp_args: ['-Wno-sign-compare', '-Wno-unused-parameter'],
  dependencies: spdm_dbus_dependencies,
)

libspdmdbus_dep = declare_dependency(
  include_directories: libspdmdbus_incdir,
  link_with: libspdmdbus)

import('pkgconfig').generate(
    libspdmdbus,
    name: meson.project_name(),
    version: meson.project_version(),
    description: 'C++ implementation of SPDM related D-Bus interfaces',
)

# Install headers
install_headers('include/certificate.hpp')
install_headers('include/component_integrity.hpp')
install_headers('include/trusted_component.hpp')

# TODO Add unit tests
