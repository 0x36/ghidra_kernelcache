OSString * withCString(char *cString);
OSString * withCStringNoCopy(char *cString);
OSString * withString(OSString *aString);
virtual bool initWithString( OSString *aString);
virtual bool initWithCStringNoCopy( char *cString);
virtual bool initWithCString( char *cString);
virtual unsigned int getLength(void);
virtual char * getCStringNoCopy(void);

