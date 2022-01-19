virtual const OSMetaClass * getMetaClass();
virtual bool init();
virtual void free();
virtual bool init_1(OSObject *owner, void *action);
virtual bool checkForWork();
virtual void setWorkLoop(IOWorkLoop *workLoop);
virtual void setNext(IOEventSource *next);
virtual IOEventSource *getNext()
virtual void * getAction();
virtual void enable();
virtual void disable();
virtual bool isEnabled();
virtual IOWorkLoop *getWorkLoop();
virtual bool onThread();

