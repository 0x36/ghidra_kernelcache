IOReturn releaseAsyncReference64(uint64_t * reference);
void setAsyncReference64(uint64_t * asyncRef, ipc_port * wakePort, mach_vm_address_t callback, uint64_t * refcon, task_t task);
IOReturn releaseNotificationPort( ipc_port * ipc_port);
IOMemoryMap * removeMappingForDescriptor( IOMemoryDescriptor *memory);
IOReturn sendAsyncResult64WithOptions(uint64_t * reference,  IOReturn result, uint64_t *args, UInt32 numArgs,  IOOptionBits options);
OSObject * copyClientEntitlement(task_t task, const char *entitlement);
