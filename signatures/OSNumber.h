OSNumber *  withNumber(unsigned long long value, unsigned int numberOfBits);
OSNumber *  withNumber(char *valueString, unsigned int numberOfBits);
virtual uint16_t unsigned16BitValue(void);
virtual uint32_t unsigned32BitValue(void);
virtual uint64_t unsigned64BitValue(void);
virtual uint8_t unsigned8BitValue(void);
virtual void setValue(unsigned long long value);
virtual bool serialize(OSSerialize *serializer);
virtual unsigned int numberOfBytes(void);
virtual unsigned int numberOfBits(void);
virtual void addValue(long long value);




