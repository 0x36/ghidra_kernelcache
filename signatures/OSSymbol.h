OSSymbol * withString(OSString *aString);
OSSymbol * withCStringNoCopy(char *cString);
OSSymbol * withCString(char *cString);
OSSymbol * existingSymbolForString(OSString *aString);
OSSymbol * existingSymbolForCString(char *aCString);
virtual bool initWithCString( char *cString);
virtual bool initWithCStringNoCopy(char *cString);
virtual bool initWithString(OSString *aString);
