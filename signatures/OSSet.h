OSSet * withArray(OSArray *array, unsigned int capacity);
OSSet * withCapacity(unsigned int capacity);
OSSet * withObjects(OSObject **objects, unsigned int count, unsigned int capacity);;
OSSet * withSet(OSSet *set, unsigned int capacity);
virtual bool setObject(void *anObject);
virtual bool initWithSet(OSSet *set, unsigned int capacity);
virtual bool initWithObjects(OSObject **objects, unsigned int count, unsigned int capacity);
virtual bool initWithCapacity(unsigned int capacity);
virtual bool initWithArray(OSArray *array, unsigned int capacity);
virtual unsigned int ensureCapacity(unsigned int newCapacity);
virtual void flushCollection(void);
virtual unsigned int iteratorSize();
virtual bool initIterator(void * iterator);
virtual bool getNextObjectForIterator(void * iterator, OSObject ** ret);
virtual void free();
virtual unsigned int getCapacity();
virtual unsigned int getCount();
virtual unsigned int getCapacityIncrement();
virtual unsigned int setCapacityIncrement(unsigned increment);
OSCollection * copyCollection(OSDictionary * cycleDict);
virtual unsigned setOptions(unsigned options,unsigned   mask,void * context);
virtual unsigned int ensureCapacity(unsigned int newCapacity);
virtual bool merge(const OSArray * array);
virtual bool merge_1(const OSSet * set);
virtual void removeObject(const OSMetaClassBase * anObject);
virtual bool containsObject(const OSMetaClassBase * anObject);
virtual bool member(const OSMetaClassBase * anObject);
virtual OSObject * getAnyObject();
virtual bool isEqualTo_1(const OSSet * aSet);
virtual bool isEqualTo(const OSMetaClassBase * anObject);
virtual bool serialize(OSSerialize * serializer);
virtual const OSMetaClass * getMetaClass();



