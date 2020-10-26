
#define DEBUG_LEVEL_ERROR
#define DEBUG_LEVEL_WARNING
#define DEBUG_LEVEL_INIT
//#define DEBUG_LEVEL_STAT
//#define DEBUG_LEVEL_PACKET

#define DEBUG_FORMAT_PREFIX "[IPIPNIC] "

#define MEM_TAG (ULONG)'PIPI'

//

#ifdef DEBUG_LEVEL_ERROR
#define DBG_ERROR(format, ...) DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, DEBUG_FORMAT_PREFIX "%s(%d): " format, __FILE__, __LINE__, __VA_ARGS__)
#define DBG_FAIL(status) DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, DEBUG_FORMAT_PREFIX "%s(%d): fail = %x\n", __FILE__, __LINE__, status)
#else
#define DBG_ERROR(format, ...)
#define DBG_FAIL(status)
#endif

#ifdef DEBUG_LEVEL_WARNING
#define DBG_WARNING(format, ...) DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL, DEBUG_FORMAT_PREFIX "%s(%d): " format, __FILE__, __LINE__, __VA_ARGS__)
#else
#define DBG_WARNING(format, ...)
#endif

#ifdef DEBUG_LEVEL_INIT
#define DBG_INIT(format, ...) DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, DEBUG_FORMAT_PREFIX format, __VA_ARGS__)
#else
#define DBG_INIT(format, ...)
#endif

#ifdef DEBUG_LEVEL_STAT
#define DBG_STAT(format, ...) DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, DEBUG_FORMAT_PREFIX format, __VA_ARGS__)
#else
#define DBG_STAT(format, ...)
#endif

#ifdef DEBUG_LEVEL_PACKET
#define DBG_PACKET(format, ...) DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_TRACE_LEVEL, DEBUG_FORMAT_PREFIX format, __VA_ARGS__)
#else
#define DBG_PACKET(format, ...)
#endif


#define NDIS_ALLOCMEM(_NdisHandle, size) NdisAllocateMemoryWithTagPriority(_NdisHandle, size, MEM_TAG, LowPoolPriority)

#define NDIS_FREEMEM(ptr) NdisFreeMemory(ptr, 0, 0)

extern NDIS_HANDLE MiniportDriverHandle;

#define ALLOCMEM(size) NdisAllocateMemoryWithTagPriority(MiniportDriverHandle, size, MEM_TAG, LowPoolPriority)

#define FREEMEM(ptr) NdisFreeMemory(ptr, 0, 0)


#define NETWORK_BYTE_ORDER_LONG(x)  ((x<<24) | (x>>24) | ((x<<8)&0xFF0000) | ((x>>8)&0xFF00))

#define NETWORK_BYTE_ORDER_SHORT(x) (((x<<8)&0xFF00) | ((x>>8)&0xFF))


UCHAR GetByte(PMDL Mdl, ULONG Offset);

PVOID GetData(PMDL Mdl, ULONG Offset, ULONG Count, PVOID Buffer);

VOID SetData(PMDL Mdl, ULONG Offset, PVOID Buffer, ULONG Count);
