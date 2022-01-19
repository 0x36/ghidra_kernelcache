IOCommandGate * commandGate(void *owner, void *action);
virtual void setWorkLoop(IOWorkLoop *inWorkLoop);
virtual IOReturn runCommand(void *arg0, void *arg1, void *arg2, void *arg3);
virtual IOReturn runAction(void *action, void *arg0, void *arg1, void *arg2, void *arg3);
virtual void commandWakeup(void *event, bool oneThread);
//virtual IOReturn commandSleep(void *event, AbsoluteTime deadline, UInt32 interruptible);
//virtual IOReturn commandSleep(void *event, UInt32 interruptible);
virtual IOReturn attemptCommand(void *arg0, void *arg1, void *arg2, void *arg3);
