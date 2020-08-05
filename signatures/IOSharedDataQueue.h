IOSharedDataQueue * withEntries(UInt32 numEntries, UInt32 entrySize);
IOSharedDataQueue * withCapacity(UInt32 size);
virtual bool setQueueSize(UInt32 size);
virtual void * peek(void);
virtual bool initWithCapacity(UInt32 size);
virtual UInt32 getQueueSize(void);
virtual IOMemoryDescriptor * getMemoryDescriptor(void);
virtual bool enqueue(void *data, UInt32 dataSize);
virtual bool dequeue(void *data, UInt32 *dataSize);
