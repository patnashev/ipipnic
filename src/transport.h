
typedef struct _TRANSPORT
{
	ULONG IP;
	USHORT Port;
	LISTROOT VNICList;

	ULONG State;
	PWSK_SOCKET Socket;

	PIRP Irp;
	SOCKADDR_IN Endpoint;
	WSK_CLIENT_DATAGRAM_DISPATCH ClientDispatch;

	LISTROOT SendPool;
	LISTROOT ReceivePool;

	ULONG StatsSendsPending;
	ULONG StatsReceivesPending;
}
TRANSPORT, *PTRANSPORT;

typedef struct _RECEIVEITEM
{
	PTRANSPORT pTransport;
	PWSK_DATAGRAM_INDICATION DataIndication;
	ULONG RefCount;
	KSPIN_LOCK RefLock;
	//ULONG Offset;
	//UCHAR Data[14];
}
RECEIVEITEM, *PRECEIVEITEM;

typedef struct _SENDITEM
{
	PTRANSPORT pTransport;
	PVOID pVNIC;
	PNET_BUFFER_LIST NBL;
	PNET_BUFFER CurrentNetBuffer;
	SOCKADDR_IN Destination;
	LONG AdvanceDelta;
	WSK_BUF WskBuf;
	PRECEIVEITEM pReceiveItem;
	PIRP Irp;
}
SENDITEM, *PSENDITEM;


NTSTATUS Transport_Register();

VOID Transport_Deregister();

VOID Transport_BindingLock(BOOLEAN bWrite, PLOCK_STATE LockState);

VOID Transport_BindingUnlock(PLOCK_STATE LockState);

PTRANSPORT Transport_Bind(PVOID pVNIC, ULONG BindIP, USHORT BindPort);

VOID Transport_Unbind(PVOID pVNIC, PTRANSPORT pTransport);

VOID Transport_Scavenge();

VOID Transport_Open(PVOID WorkItemContext, NDIS_HANDLE NdisIoWorkItemHandle);

VOID Transport_Close(PVOID WorkItemContext, NDIS_HANDLE NdisIoWorkItemHandle);

NTSTATUS Transport_Send(PVOID pVNIC, PTRANSPORT pTransport, PNET_BUFFER_LIST NBL, LONG AdvanceDelta, ULONG IP, USHORT Port);

NTSTATUS WSKAPI Transport_ReceiveFromEvent(PVOID SocketContext, ULONG Flags, PWSK_DATAGRAM_INDICATION DataIndication);

VOID Transport_ReceiveComplete(PRECEIVEITEM pReceiveItem);

VOID Transport_Thread(PVOID StartContext);
