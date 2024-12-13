# Gather the Configuration data

conf_data = configuration_data()
conf_data.set('MESON_INSTALL_PREFIX', get_option('prefix'))
conf_data.set('SPDM_MEASUREMENT_HASH', get_option('minimum-spdm-measurement-hash'))
conf_data.set('SPDM_ASYM_ALGO', get_option('minimum-spdm-asym-algo'))
conf_data.set('SPDMD_DOE_VID_DID_LIST', get_option('spdm-doe-vid-did-list'))
conf_data.set('SPDMD_MCTP_I2C_BINDING_CONF', get_option('spdm-mctp-i2c-binding-conf'))

conf_h_dep = declare_dependency(
    include_directories: include_directories('.'),
    sources: configure_file(
        input: 'spdmd_config.h.in',
        output: 'spdmd_config.h',
        configuration: conf_data
    )
)

# Configure and install systemd unit files

configure_file(input : 'spdmd.service.in',
               output : 'spdmd.service',
               install_dir: systemd_system_unit_dir,
               configuration: conf_data,
               install : true)
