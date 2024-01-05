ssize_t hypervisor_read(const char *device_name, char *buffer, size_t len, loff_t *offset);
ssize_t hypervisor_write(const char *device_name, const char *buffer, size_t len, loff_t *offset);