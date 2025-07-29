// This should be a relatively small file as most functionality should be
// implemented in the core igloo driver

enum igloo_base_hypercalls {
    IGLOO_HYP_SETUP_SYSCALL = 0x1337,
    IGLOO_HYPERFS_MAGIC = 0x51ec3692,
};