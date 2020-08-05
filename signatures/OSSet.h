OSSet * withArray(OSArray *array, unsigned int capacity);
OSSet * withCapacity(unsigned int capacity);
OSSet * withObjects(OSObject **objects, unsigned int count, unsigned int capacity);;
OSSet * withSet(OSSet *set, unsigned int capacity);
virtual bool setObject(void *anObject);
virtual bool initWithSet(OSSet *set, unsigned int capacity);
virtual bool initWithObjects(OSObject **objects, unsigned int count, unsigned int capacity);
virtual bool initWithCapacity(unsigned int capacity);
virtual bool initWithArray(OSArray *array, unsigned int capacity);
virtual bool initIterator(void *iterator);
virtual bool getNextObjectForIterator(void *iterator, OSObject **ret);
virtual unsigned int ensureCapacity(unsigned int newCapacity);
virtual void flushCollection(void);


