gtest_dep = dependency('gtest', main: true, disabler: true, required: false)
gmock_dep = dependency('gmock', disabler: true, required: false)
if not gtest_dep.found() or not gmock_dep.found()
    gtest_proj = import('cmake').subproject('googletest', required: true)
    gtest_dep = declare_dependency(
            dependencies: [
                dependency('threads'),
                gtest_proj.dependency('gtest'),
                gtest_proj.dependency('gtest_main'),
            ]
        )
        gmock_dep = gtest_proj.dependency('gmock')
endif


tests = [
  'transport/doe_discovery',
]

test_include_dirs = [ libspdmwrapper_incdir ]

foreach t : tests
  test(t, executable(t.underscorify(), t + '.cpp',
                     implicit_include_directories: false,
                     include_directories: test_include_dirs,
                     dependencies: [
                         libspdmwrapper_dep,
                         libspdmwrapper_ext_dep,
                         gtest_dep,
                         gmock_dep],
                     install : true),
       workdir: meson.current_source_dir())
endforeach
