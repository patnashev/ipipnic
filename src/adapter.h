//
// IPIPNIC-specific
//

#define MAX_PACKET_SIZE 1400

#define NOMINAL_LINK_SPEED 1000000000

#define PRODUCT_STRING "IP-in-IP Adapter"

#define MAJOR_DRIVER_VERSION       2
#define MINOR_DRIVER_VERSION       0

// OID for our configuration data
#define OID_CUSTOM_VIRTUAL_HOSTS 0xFFB8C456

typedef struct _ARPENTRY
{
    UCHAR MAC[ETH_LENGTH_OF_ADDRESS];
	ULONG IP;
}
ARPENTRY, *PARPENTRY;

typedef struct _VIRTUALHOST
{
	ULONG IP;
	ULONG Mask;
	ULONG RemoteIP;
	ULONG LocalIP;
	USHORT RemotePort;
	USHORT LocalPort;
	ULONG Flags;
	PTRANSPORT pTransport;
}
VIRTUALHOST, *PVIRTUALHOST;

#define VIRTUALHOST_FLAG_SIMPLE_FORWARDING 1
#define VIRTUALHOST_FLAG_DYNAMIC 2

typedef struct _LOCALADDRESS
{
	ULONG IP;
}
LOCALADDRESS, *PLOCALADDRESS;

typedef struct _RECEIVE_CONTEXT
{
	PVOID pReceiveItem;
	PVOID pVNIC;
}
RECEIVE_CONTEXT, *PRECEIVE_CONTEXT;

#pragma pack(push, 1)
typedef struct _ARP_PACKET
{
	UCHAR  Destination[ETH_LENGTH_OF_ADDRESS];
	UCHAR  Source[ETH_LENGTH_OF_ADDRESS];
    USHORT FrameType;           // 0x0806
    USHORT hwAddressType;       // 0x0001
    USHORT protoAddressType;    // 0x0800
    UCHAR  hwAddressLength;     // 0x06
    UCHAR  protoAddressLength;  // 0x04
    USHORT Opcode;              // 0x0001 for ARP request, 0x0002 for ARP reply
	UCHAR  hwSource[ETH_LENGTH_OF_ADDRESS];
    ULONG  ipSource;
	UCHAR  hwDestination[ETH_LENGTH_OF_ADDRESS];
    ULONG  ipDestination;
}
ARP_PACKET, *PARP_PACKET;
#pragma pack(pop)

#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY   0

#define ARP_REQUEST NETWORK_BYTE_ORDER_SHORT(1)
#define ARP_REPLY NETWORK_BYTE_ORDER_SHORT(2)

#define IP_HEADER_SIZE 20

#define ETH_CMP_NETWORK_ADDRESSES(_A,_B)        \
    ((*(ULONG UNALIGNED *)&(_A)[2] == *(ULONG UNALIGNED *)&(_B)[2]) &&   \
     (*(USHORT UNALIGNED *)(_A) == *(USHORT UNALIGNED *)(_B)))


VOID GenerateMacAddr(PUCHAR Address);

ULONG UpdateAddresses(PLISTROOT Root, PNETWORK_ADDRESS Address, ULONG Count);

VOID UpdateHosts(PVOID pVNIC, PLISTROOT Root, PUCHAR Data, ULONG Length);

NDIS_STATUS LookupArpEntry(PVOID pVNIC, ULONG ip, PUCHAR mac);

BOOLEAN TestAddress(PVOID pVNIC, ULONG ip);

VOID UpdateDynamicHosts(PVOID pVNIC, ULONG IP, ULONG RemoteIP, USHORT RemotePort);

PNET_BUFFER_LIST AllocNBL(PVOID pVNIC);

VOID FreeNBL(PNET_BUFFER_LIST NBL);

PMDL AllocateMdl(PULONG BufferSize);

VOID FreeMdl(PMDL Mdl);

//
// Virtual NIC
//

#define ETH_IS_LOCALLY_ADMINISTERED(Address) \
    (BOOLEAN)(((PUCHAR)(Address))[0] & ((UCHAR)0x02))

#define ETH_HEADER_SIZE                 14

#define VNIC_DEFAULT_PACKET_LOOKAHEAD   MAX_PACKET_SIZE

#define VNIC_DEFAULT_PACKET_FILTER      NDIS_PACKET_TYPE_DIRECTED | \
                                        NDIS_PACKET_TYPE_BROADCAST

#define VNIC_SUPPORTED_FILTERS          ( \
                                        NDIS_PACKET_TYPE_DIRECTED      | \
                                        NDIS_PACKET_TYPE_BROADCAST     | \
										NDIS_PACKET_TYPE_MULTICAST     | \
										NDIS_PACKET_TYPE_ALL_MULTICAST | \
                                        NDIS_PACKET_TYPE_PROMISCUOUS)

#define VNIC_MAJOR_NDIS_VERSION         6
#define VNIC_MINOR_NDIS_VERSION         0

typedef struct _VNIC
{
	NDIS_HANDLE MiniportAdapterHandle;
	BOOLEAN InterfaceIsRunning;
	ULONG Lookahead;
	ULONG PacketFilter;
    UCHAR PermanentAddress[ETH_LENGTH_OF_ADDRESS];
    UCHAR CurrentAddress[ETH_LENGTH_OF_ADDRESS];
// IPIPNIC-specific
	LISTROOT ArpEntriesList;
	LISTROOT HostsList;
	LISTROOT AddressesList;
	ULONG PrimaryIP;
	NDIS_HANDLE NBLPool;
	LISTROOT NBLList;
	ULONG NBLPending;

	ULONG StatsSendsQueued;
	ULONG StatsSendsFailed;
	ULONG64 StatsSendsCompleted;
	ULONG64 StatsReceivesCompleted;
	ULONG64 StatsBytesSent;
	ULONG64 StatsBytesReceived;
}
VNIC, *PVNIC;


DRIVER_INITIALIZE DriverEntry;

NDIS_STATUS
MpSetOptions(
    IN  NDIS_HANDLE             NdisDriverHandle,
    IN  NDIS_HANDLE             DriverContext
    );

NDIS_STATUS
MPInitialize(
    IN  NDIS_HANDLE                     MiniportAdapterHandle,
    IN  NDIS_HANDLE                     MiniportDriverContext,
    IN  PNDIS_MINIPORT_INIT_PARAMETERS  MiniportInitParameters
    );

VOID
MPHalt(
    IN    NDIS_HANDLE               MiniportAdapterContext,
    IN    NDIS_HALT_ACTION          HaltAction
    );

NDIS_STATUS
MPPause(
    IN  NDIS_HANDLE     MiniportAdapterContext,
    IN  PNDIS_MINIPORT_PAUSE_PARAMETERS  MiniportPauseParameters
    );

NDIS_STATUS
MPRestart(
    IN  NDIS_HANDLE     MiniportAdapterContext,
    IN  PNDIS_MINIPORT_RESTART_PARAMETERS  MiniportRestartParameters
    );

NDIS_STATUS 
MPOidRequest(
    IN NDIS_HANDLE         MiniportAdapterContext,
    IN PNDIS_OID_REQUEST   NdisRequest
    );

VOID 
MPSendNetBufferLists(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN PNET_BUFFER_LIST NetBufferLists,
    IN NDIS_PORT_NUMBER PortNumber,
    IN ULONG SendFlags
    );

VOID
MPReturnNetBufferLists(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN PNET_BUFFER_LIST NetBufferLists,
    IN ULONG ReturnFlags
    );

VOID 
MPCancelSendNetBufferLists(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN PVOID CancelId
    );

NDIS_STATUS
MPQueryInformation(
    IN    PVNIC                     pVNIC,
    IN    PNDIS_OID_REQUEST         NdisRequest
    );

NDIS_STATUS
MPSetInformation(
    IN    PVNIC                     pVNIC,
    IN    PNDIS_OID_REQUEST         NdisRequest
    );

NDIS_STATUS
MPMethodRequest(
    IN    PVNIC                     pVNIC,
    IN    PNDIS_OID_REQUEST         NdisRequest
    );

VOID
MPDevicePnPEvent(
    IN NDIS_HANDLE                 MiniportAdapterContext,
    IN PNET_DEVICE_PNP_EVENT       NetDevicePnPEvent
    );


VOID
MPAdapterShutdown(
    IN NDIS_HANDLE                  MiniportAdapterContext,
    IN NDIS_SHUTDOWN_ACTION         ShutdownAction

    );

DRIVER_UNLOAD MPUnload;
VOID
MPUnload(
    IN    PDRIVER_OBJECT            DriverObject
    );

VOID 
MPCancelOidRequest(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN PVOID       RequestId
    );



/*

// This OID specifies the current driver version.
// The high byte is the major version.
// The low byte is the minor version.
#define VELAN_DRIVER_VERSION            ((MUX_MAJOR_DRIVER_VERSION << 8) + \
                                         (MUX_MINOR_DRIVER_VERSION))

// media type, we use ethernet, change if necessary
#define VELAN_MEDIA_TYPE                NdisMedium802_3

// change to your company name instead of using Microsoft
#define VELAN_VENDOR_DESC               "Microsoft"

// Highest byte is the NIC byte plus three vendor bytes, they are normally
// obtained from the NIC
#define VELAN_VENDOR_ID                 0x00FFFFFF

#define VELAN_MAX_MCAST_LIST            32
#define VELAN_MAX_SEND_PKTS             5

#define ETH_MAX_PACKET_SIZE             1514
#define ETH_MIN_PACKET_SIZE             60
#define ETH_HEADER_SIZE                 14


#define VELAN_SUPPORTED_FILTERS ( \
            NDIS_PACKET_TYPE_DIRECTED      | \
            NDIS_PACKET_TYPE_MULTICAST     | \
            NDIS_PACKET_TYPE_BROADCAST     | \
            NDIS_PACKET_TYPE_PROMISCUOUS   | \
            NDIS_PACKET_TYPE_ALL_MULTICAST)

#define MUX_ADAPTER_PACKET_FILTER           \
            NDIS_PACKET_TYPE_PROMISCUOUS

                                         

#define MIN_PACKET_POOL_SIZE            255
#define MAX_PACKET_POOL_SIZE            4096

typedef UCHAR   MUX_MAC_ADDRESS[6];



//
// Default values:
//
#define MUX_DEFAULT_LINK_SPEED          100000  // in 100s of bits/sec
#define MUX_DEFAULT_LOOKAHEAD_SIZE      512

#define MUX_ACQUIRE_SPIN_LOCK(_pLock, DispatchLevel)     \
    {                                                    \
        if (DispatchLevel)                               \
        {                                                \
            NdisDprAcquireSpinLock(_pLock);              \
        }                                                \
        else                                             \
        {                                                \
            NdisAcquireSpinLock(_pLock);                 \
        }                                                \
    }

#define MUX_RELEASE_SPIN_LOCK(_pLock, DispatchLevel)     \
    {                                                    \
        if (DispatchLevel)                               \
        {                                                \
            NdisDprReleaseSpinLock(_pLock);              \
        }                                                \
        else                                             \
        {                                                \
            NdisReleaseSpinLock(_pLock);                 \
        }                                                \
    }



//
// Macro definitions for others.
//

//
// Is a given power state a low-power state?
//
#define MUX_IS_LOW_POWER_STATE(_PwrState)                       \
            ((_PwrState) > NdisDeviceStateD0)

#define MUX_INIT_ADAPT_RW_LOCK(_pAdapt) \
            NdisInitializeReadWriteLock(&(_pAdapt)->ReadWriteLock)


#define MUX_ACQUIRE_ADAPT_READ_LOCK(_pAdapt, _pLockState)       \
            NdisAcquireReadWriteLock(&(_pAdapt)->ReadWriteLock, \
                                     FALSE,                     \
                                     _pLockState)

#define MUX_RELEASE_ADAPT_READ_LOCK(_pAdapt, _pLockState)       \
            NdisReleaseReadWriteLock(&(_pAdapt)->ReadWriteLock, \
                                     _pLockState)

#define MUX_ACQUIRE_ADAPT_WRITE_LOCK(_pAdapt, _pLockState)      \
            NdisAcquireReadWriteLock(&(_pAdapt)->ReadWriteLock, \
                                     TRUE,                      \
                                     _pLockState)

#define MUX_RELEASE_ADAPT_WRITE_LOCK(_pAdapt, _pLockState)      \
            NdisReleaseReadWriteLock(&(_pAdapt)->ReadWriteLock, \
                                     _pLockState)

#define MUX_INCR_PENDING_RECEIVES(_pVElan)                      \
            NdisInterlockedIncrement((PLONG)&pVElan->OutstandingReceives)

#define MUX_DECR_PENDING_RECEIVES(_pVElan)                      \
            NdisInterlockedDecrement((PLONG)&pVElan->OutstandingReceives)

#define MUX_INCR_PENDING_SENDS(_pVElan)                         \
            NdisInterlockedIncrement((PLONG)&pVElan->OutstandingSends)

#define MUX_DECR_PENDING_SENDS(_pVElan)                         \
            NdisInterlockedDecrement((PLONG)&pVElan->OutstandingSends)

#define MUX_DECR_MULTIPLE_PENDING_RECEIVES(_pVElan, _NumReceives) \
            InterlockedExchangeAdd((PLONG)&_pVElan->OutstandingReceives, \
                                    0 - (LONG) _NumReceives)




#define MUX_INCR_STATISTICS(_pUlongVal)                         \
            NdisInterlockedIncrement((PLONG)_pUlongVal)

#define MUX_INCR_STATISTICS64(_pUlong64Val)                     \
{                                                               \
    PLARGE_INTEGER      _pLargeInt = (PLARGE_INTEGER)_pUlong64Val;\
    if (NdisInterlockedIncrement((PLONG)&_pLargeInt->LowPart) == 0)    \
    {                                                           \
        NdisInterlockedIncrement(&_pLargeInt->HighPart);        \
    }                                                           \
}

#define ASSERT_AT_PASSIVE()                                     \
    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL)
    
#define ASSERT_AT_DISPATCH()                                     \
    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL)



//
// Simple Mutual Exclusion constructs used in preference to
// using KeXXX calls since we don't have Mutex calls in NDIS.
// These can only be called at passive IRQL.
//

typedef struct _MUX_MUTEX
{
    NDIS_MUTEX              Mutex;
    ULONG                   ModuleAndLine;  // useful for debugging

} MUX_MUTEX, *PMUX_MUTEX;

#define MUX_INIT_MUTEX(_pMutex)                                 \
{                                                               \
    NDIS_INIT_MUTEX(&(_pMutex)->Mutex);                         \
    (_pMutex)->ModuleAndLine = 0;                               \
}

#define MUX_ACQUIRE_MUTEX(_pMutex)                              \
{                                                               \
    NDIS_WAIT_FOR_MUTEX(&(_pMutex)->Mutex);                     \
    (_pMutex)->ModuleAndLine = (MODULE_NUMBER << 16) | __LINE__;\
}

#define MUX_RELEASE_MUTEX(_pMutex)                              \
{                                                               \
    (_pMutex)->ModuleAndLine = 0;                               \
    NDIS_RELEASE_MUTEX(&(_pMutex)->Mutex);                      \
}


//
// Global variables
//
extern NDIS_HANDLE           ProtHandle, DriverHandle;
extern NDIS_MEDIUM           MediumArray[1];
extern NDIS_SPIN_LOCK        GlobalLock;
extern MUX_MUTEX             GlobalMutex;
extern LIST_ENTRY            AdapterList;
extern LIST_ENTRY            VElanList;
extern ULONG                 NextVElanNumber;

//
// Module numbers for debugging
//
#define MODULE_MUX          'X'
#define MODULE_PROT         'P'
#define MODULE_MINI         'M'
#define MODULE_MUX_TEST     'T'


*/
