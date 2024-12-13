project('spdmd', 'c','cpp',
        version : '1.0',
        meson_version: '>=0.63.0',
        default_options: [
            'warning_level=3',
            'werror=true',
            'cpp_std=c++20',
	    'c_std=c18',
            ])

# Validate the c++ Standard
if get_option('cpp_std') != 'c++20'
    error('This project requires c++20 support')
endif

# remove debug information for minsize buildtype
if(get_option('buildtype') == 'minsize')
  add_project_arguments(['-fdata-sections', '-ffunction-sections'], language : 'cpp')
  add_project_arguments('-DNDEBUG', language : 'cpp')
endif

# Disable lto when compiling with no optimization
if(get_option('optimization') == '0')
  add_project_arguments('-fno-lto', language: 'cpp')
  message('Disabling lto & its supported features as optimization is disabled')
endif

incdir = include_directories(
  'include',
  'third_party/',
  'third_party/spdm_device_secret_lib_sample',
)

libspdm = dependency('libspdm')
phosphor_dbus_interfaces = dependency('phosphor-dbus-interfaces')
sdbusplus = dependency('sdbusplus')
sdeventplus = dependency('sdeventplus')
phosphor_logging_dep = dependency('phosphor-logging')
systemd = dependency('systemd')

libspdmdbus_proj = subproject('libspdmdbus') 
libspdmdbus_dep = libspdmdbus_proj.get_variable('libspdmdbus_dep') 

libspdmwrapper_proj = subproject('libspdmwrapper')
libspdmwrapper_dep = libspdmwrapper_proj.get_variable('libspdmwrapper_dep')

# Dependencies
spdmd_dependencies = [
    libspdm,
    libspdmdbus_dep,
    libspdmwrapper_dep,
    phosphor_dbus_interfaces,
    phosphor_logging_dep,
    sdbusplus,
    sdeventplus,
    systemd,
]

# Source files
srcfiles = files(
  'src/spdmd.cpp',
  'src/attester.cpp',
  'src/doe_attester.cpp',
  'src/mctp_attester.cpp',
  'src/support.cpp',
  'third_party/spdm_device_secret_lib_sample/lib.c',
  'third_party/debuglib/libspdm_com_support.c',
  'third_party/debuglib/debuglib.c',
)

systemd_system_unit_dir = systemd.get_variable(pkgconfig: 'systemdsystemunitdir')

bindir = get_option('prefix') + '/' +get_option('bindir')

summary({
          'prefix' : get_option('prefix'),
          'bindir' : bindir,
          'systemd unit directory' : systemd_system_unit_dir
        }, section : 'Directories')

subdir('config')
spdmd_dependencies += conf_h_dep

# Install targets
executable(
  'spdmd',
  srcfiles,
  c_args: ['-Wno-sign-compare', '-Wno-unused-parameter'],
  include_directories : incdir,
  dependencies: spdmd_dependencies,
  install_dir:bindir,
  install : true,
)
