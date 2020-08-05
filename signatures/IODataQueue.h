IODataQueue * withEntries(UInt32 numEntries, UInt32 entrySize);
IODataQueue * withCapacity(UInt32 size);
virtual void setNotificationPort(ipc_port *port);
virtual void sendDataAvailableNotification(void);
virtual bool initWithEntries(UInt32 numEntries, UInt32 entrySize);
virtual bool initWithCapacity(UInt32 size);
virtual IOMemoryDescriptor * getMemoryDescriptor(void);
virtual bool enqueue(void *data, UInt32 dataSize);
