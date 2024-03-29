OSArray * withArray(OSArray *array, uint32_t capacity);
OSArray * withCapacity(uint32_t capacity);
OSArray * withObjects( OSObject **values, uint32_t count, uint32_t capacity);
virtual unsigned int getCapacity();
virtual unsigned int getCount();
virtual unsigned int getNextIndexOfObject(void *anObject,  unsigned intindex);
virtual OSObject * getObject( unsigned intindex);
virtual bool initWithArray(OSArray *anArray, unsigned int capacity = 0);
virtual bool initWithCapacity( unsigned intcapacity);
virtual bool initWithObjects(OSObject **objects,  unsigned int count,  unsigned int capacity = 0);
virtual bool isEqualTo(void *anArray);
virtual bool merge(OSArray *otherArray);
virtual void removeObject( unsigned intindex);
virtual void replaceObject(  unsigned intindex,  void *anObject);
virtual bool serialize( OSSerialize *serializer);
virtual unsigned int setCapacityIncrement( unsigned increment);
virtual bool init();
virtual void free();
virtual unsigned int iteratorSize();
virtual bool initIterator(void * iterator);
virtual bool getNextObjectForIterator(void * iterator, OSObject ** ret);
virtual unsigned int getCapacityIncrement();
virtual unsigned int setCapacityIncrement(unsigned increment);
void flushCollection();
virtual unsigned setOptions(unsigned options,unsigned   mask,void * context);
OSCollection * copyCollection(OSDictionary * cycleDict);
virtual bool setObject(void *anObject);
virtual bool setObject_1(unsigned int index,const OSMetaClassBase * anObject);
virtual bool isEqualTo_1(const OSArray * anArray);
OSObject * getLastObject();
virtual const OSMetaClass * getMetaClass();
virtual unsigned int ensureCapacity(unsigned int newCapacity);


