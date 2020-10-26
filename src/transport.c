#include "precomp.h"

#pragma alloc_text(PAGE, Transport_Register)
#pragma alloc_text(PAGE, Transport_Deregister)
#pragma alloc_text(PAGE, Transport_Open)
#pragma alloc_text(PAGE, Transport_Close)

LISTROOT Transports;

// WSK Client Dispatch table that denotes the WSK version
// that the WSK application wants to use and optionally a pointer
// to the WskClientEvent callback function
const WSK_CLIENT_DISPATCH WskAppDispatch = {
  MAKE_WSK_VERSION(1,0), // Use WSK version 1.0
  0,    // Reserved
  NULL  // WskClientEvent callback not required for WSK version 1.0
};

// WSK Registration object
WSK_REGISTRATION WskRegistration;

// Thread
KEVENT evClose;
PFILE_OBJECT pThread;

NTSTATUS Transport_Register()
{
	NTSTATUS Status;
	WSK_CLIENT_NPI wskClientNpi;
	HANDLE ThreadHandle;

	DBG_INIT("Transport_Register()\n");

	ListActivate(MiniportDriverHandle, &Transports, 0);

	// Register the WSK application
	wskClientNpi.ClientContext = NULL;
	wskClientNpi.Dispatch = &WskAppDispatch;
	Status = WskRegister(&wskClientNpi, &WskRegistration);

	if (Status == STATUS_SUCCESS)
	{
		KeInitializeEvent(&evClose, SynchronizationEvent, FALSE);

		Status = PsCreateSystemThread(&ThreadHandle, 0, NULL, NULL, NULL, Transport_Thread, NULL);
		if (!NT_SUCCESS(Status))
		{
			DBG_FAIL(Status);
			WskDeregister(&WskRegistration);
		}
		else
		{
			Status = ObReferenceObjectByHandle(ThreadHandle, 0, NULL, KernelMode, &pThread, NULL);
			if (!NT_SUCCESS(Status))
			{
				DBG_FAIL(Status);
				WskDeregister(&WskRegistration);
			}

			ZwClose(ThreadHandle);
		}
	}

	return Status;
}

VOID Transport_Deregister()
{
	KeSetEvent(&evClose, IO_NO_INCREMENT, FALSE);
	KeWaitForSingleObject(pThread, Executive, KernelMode, FALSE, NULL);
	ObDereferenceObject(pThread);

	while (TRUE)
	{
		Transport_Scavenge();
		if (ListCount(&Transports) > 0)
		{
			LARGE_INTEGER Timeout;
			Timeout.HighPart = -1;
			Timeout.LowPart = -1000000;
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
		}
		else
			break;
	}

	WskDeregister(&WskRegistration);

	DBG_INIT("Transport_Deregister()\n");
}

VOID Transport_BindingLock(BOOLEAN bWrite, PLOCK_STATE LockState)
{
	ListLock(&Transports, bWrite, LockState);
}

VOID Transport_BindingUnlock(PLOCK_STATE LockState)
{
	ListUnlock(&Transports, LockState);
}

PTRANSPORT Transport_Bind(PVOID pVNIC, ULONG BindIP, USHORT BindPort)
{
	PLISTNODE Node;
	LOCK_STATE LockState;
	PTRANSPORT pTransport = NULL;
	NDIS_HANDLE NdisIoWorkItemHandle;

	ListLock(&Transports, FALSE, &LockState);
	for (Node = Transports.First; Node && (((PTRANSPORT)Node->Item)->IP != BindIP || ((PTRANSPORT)Node->Item)->Port != BindPort); Node = Node->Next);
	if (Node)
	{
		pTransport = (PTRANSPORT)Node->Item;
		ListAdd(&pTransport->VNICList, pVNIC);
	}
	ListUnlock(&Transports, &LockState);

	while (pTransport == NULL)
	{
		pTransport = ALLOCMEM(sizeof(TRANSPORT));
		if (pTransport == NULL)
        {
			DBG_FAIL(STATUS_INSUFFICIENT_RESOURCES);
            break;
        }

		RtlZeroMemory(pTransport, sizeof(TRANSPORT));
		pTransport->IP = BindIP;
		pTransport->Port = BindPort;

		ListActivate(MiniportDriverHandle, &pTransport->SendPool, 0);
		ListActivate(MiniportDriverHandle, &pTransport->ReceivePool, 0);

		ListActivate(MiniportDriverHandle, &pTransport->VNICList, 0);
		ListAdd(&pTransport->VNICList, pVNIC);
		ListAdd(&Transports, pTransport);

		DBG_INIT("Transport created\n");
	}

	if (pTransport != NULL && (pTransport->State == 0 || pTransport->State == 3 || pTransport->State == 4))
	{
		NdisIoWorkItemHandle = NdisAllocateIoWorkItem(MiniportDriverHandle);
		if (NdisIoWorkItemHandle != NULL)
		{
			pTransport->State = 1;
			NdisQueueIoWorkItem(NdisIoWorkItemHandle, Transport_Open, pTransport);
		}
		else
        {
			DBG_FAIL(STATUS_INSUFFICIENT_RESOURCES);
			if (pTransport->State == 0)
				pTransport->State = 4;
        }
	}

	return pTransport;
}

VOID Transport_Unbind(PVOID pVNIC, PTRANSPORT pTransport)
{
	ListExtract(&pTransport->VNICList, pVNIC);
}

VOID Transport_Scavenge()
{
	PLISTNODE Node;
	LOCK_STATE LockState;
	PTRANSPORT pTransport;
	PSENDITEM pSendItem;
	NDIS_HANDLE NdisIoWorkItemHandle;

	ListLock(&Transports, TRUE, &LockState);
	do
	{
		pTransport = NULL;

		for (Node = Transports.First; Node; Node = Node->Next)
		{
			pTransport = (PTRANSPORT)Node->Item;
			if (ListCount(&pTransport->VNICList) == 0)
			{
				if (pTransport->State == 2 || pTransport->State == 5)
				{
					NdisIoWorkItemHandle = NdisAllocateIoWorkItem(MiniportDriverHandle);
					if (NdisIoWorkItemHandle != NULL)
					{
						pTransport->State = 3;
						NdisQueueIoWorkItem(NdisIoWorkItemHandle, Transport_Close, pTransport);
					}
				}
				if (pTransport->State == 4)
					break;
			}
			pTransport = NULL;
		}

		if (pTransport != NULL)
		{
			DBG_INIT("%d sends pending, %d receives pending\n", pTransport->StatsSendsPending, pTransport->StatsReceivesPending);
			ListExtract(&Transports, pTransport);
			while (pTransport->SendPool.Count)
			{
				pSendItem = ListRemove(&pTransport->SendPool, LIST_QUEUE);
				IoFreeIrp(pSendItem->Irp);
				FREEMEM(pSendItem);
			}
			ListDeactivate(&pTransport->ReceivePool, TRUE);
			FREEMEM(pTransport);

			DBG_INIT("Transport destroyed\n");
		}

	} while (pTransport != NULL);
	ListUnlock(&Transports, &LockState);
}

NTSTATUS EventComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	KeSetEvent(Context, IO_NO_INCREMENT, FALSE);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

VOID Transport_Open(PVOID WorkItemContext, NDIS_HANDLE NdisIoWorkItemHandle)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PTRANSPORT pTransport = (PTRANSPORT)WorkItemContext;
	LARGE_INTEGER Timeout;
	WSK_PROVIDER_NPI wskProviderNpi;
	KEVENT evComplete;
	WSK_EVENT_CALLBACK_CONTROL EventCallbackControl;
	ULONG State;

	Timeout.HighPart = -1;
	Timeout.LowPart = -250000;
	while (pTransport->State == 3)
		KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

	State = 4;
	do
	{
		Status = WskCaptureProviderNPI(&WskRegistration, WSK_INFINITE_WAIT, &wskProviderNpi);
		if (Status != STATUS_SUCCESS)
		{
			DBG_FAIL(Status);
			break;
		}

		pTransport->Irp = IoAllocateIrp(1, FALSE);
		if (!pTransport->Irp)
		{
			Status = STATUS_INSUFFICIENT_RESOURCES;
			DBG_FAIL(Status);
			WskReleaseProviderNPI(&WskRegistration);
			break;
		}

		pTransport->ClientDispatch.WskReceiveFromEvent = Transport_ReceiveFromEvent;

		KeInitializeEvent(&evComplete, SynchronizationEvent, FALSE);
		IoSetCompletionRoutine(pTransport->Irp, EventComplete, &evComplete, TRUE, TRUE, TRUE);
		if (pTransport->Port == 0xFFFF)
		{
			DBG_INIT("Creating IP socket...\n");
			wskProviderNpi.Dispatch->WskSocket(wskProviderNpi.Client, AF_INET, SOCK_RAW, IPPROTO_IPV4, WSK_FLAG_DATAGRAM_SOCKET, pTransport, &pTransport->ClientDispatch, NULL, NULL, NULL, pTransport->Irp);
			pTransport->Endpoint.sin_family = AF_INET;
			pTransport->Endpoint.sin_port = 0;
			pTransport->Endpoint.sin_addr.S_un.S_addr = pTransport->IP;
		}
		else
		{
			DBG_INIT("Creating UDP socket...\n");
			wskProviderNpi.Dispatch->WskSocket(wskProviderNpi.Client, AF_INET, SOCK_DGRAM, IPPROTO_UDP, WSK_FLAG_DATAGRAM_SOCKET, pTransport, &pTransport->ClientDispatch, NULL, NULL, NULL, pTransport->Irp);
			pTransport->Endpoint.sin_family = AF_INET;
			pTransport->Endpoint.sin_port = pTransport->Port;
			pTransport->Endpoint.sin_addr.S_un.S_addr = pTransport->IP;
		}

		KeWaitForSingleObject(&evComplete, Executive, KernelMode, FALSE, NULL);
		Status = pTransport->Irp->IoStatus.Status;
		if (Status != STATUS_SUCCESS)
		{
			DBG_FAIL(Status);
			IoFreeIrp(pTransport->Irp);
			WskReleaseProviderNPI(&WskRegistration);
			break;
		}

		pTransport->Socket = (PWSK_SOCKET)pTransport->Irp->IoStatus.Information;
		DBG_INIT("Socket created\n");

		IoReuseIrp(pTransport->Irp, STATUS_SUCCESS);
		IoSetCompletionRoutine(pTransport->Irp, EventComplete, &evComplete, TRUE, TRUE, TRUE);
		((PWSK_PROVIDER_LISTEN_DISPATCH)pTransport->Socket->Dispatch)->WskBind(pTransport->Socket, (PSOCKADDR)&pTransport->Endpoint, 0, pTransport->Irp);

		KeWaitForSingleObject(&evComplete, Executive, KernelMode, FALSE, NULL);
		Status = pTransport->Irp->IoStatus.Status;
		if (Status != STATUS_SUCCESS)
		{
			DBG_WARNING("Socket bind fails = %x.\n", Status);
			State = 5;
			break;
		}

		EventCallbackControl.NpiId = &NPI_WSK_INTERFACE_ID;
		EventCallbackControl.EventMask = WSK_EVENT_RECEIVE_FROM;
		Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)pTransport->Socket->Dispatch)->WskControlSocket(pTransport->Socket, WskSetOption, SO_WSK_EVENT_CALLBACK, SOL_SOCKET, sizeof(WSK_EVENT_CALLBACK_CONTROL), &EventCallbackControl, 0, NULL, NULL, NULL);
		if (Status != STATUS_SUCCESS)
		{
			DBG_WARNING("Socket event control fails = %x.\n", Status);
		}

		State = 2;

	} while (FALSE);

	pTransport->State = State;

	NdisFreeIoWorkItem(NdisIoWorkItemHandle);

	DBG_INIT("Transport_Open exits\n");
}

VOID Transport_Close(PVOID WorkItemContext, NDIS_HANDLE NdisIoWorkItemHandle)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PTRANSPORT pTransport = (PTRANSPORT)WorkItemContext;
	LARGE_INTEGER Timeout;
	KEVENT evComplete;

	Timeout.HighPart = -1;
	Timeout.LowPart = -250000;
	while (pTransport->StatsSendsPending > 0)
		KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

	KeInitializeEvent(&evComplete, SynchronizationEvent, FALSE);
	IoReuseIrp(pTransport->Irp, STATUS_SUCCESS);
	IoSetCompletionRoutine(pTransport->Irp, EventComplete, &evComplete, TRUE, TRUE, TRUE);
	((PWSK_PROVIDER_BASIC_DISPATCH)pTransport->Socket->Dispatch)->WskCloseSocket(pTransport->Socket, pTransport->Irp);

	KeWaitForSingleObject(&evComplete, Executive, KernelMode, FALSE, NULL);
	Status = pTransport->Irp->IoStatus.Status;
	if (Status != STATUS_SUCCESS)
	{
		DBG_FAIL(Status);
	}

	IoFreeIrp(pTransport->Irp);
	WskReleaseProviderNPI(&WskRegistration);

	pTransport->State = 4;
	NdisFreeIoWorkItem(NdisIoWorkItemHandle);
	DBG_INIT("Transport_Close exits\n");
}

NTSTATUS SendComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
	PSENDITEM pSendItem = Context;
	PTRANSPORT pTransport = pSendItem->pTransport;

	if (Irp->IoStatus.Status != STATUS_SUCCESS)
		InterlockedIncrement(&((PVNIC)pSendItem->pVNIC)->StatsSendsFailed);
	else
	{
		InterlockedIncrement64(&((PVNIC)pSendItem->pVNIC)->StatsSendsCompleted);
		InterlockedExchangeAdd64(&((PVNIC)pSendItem->pVNIC)->StatsBytesSent, NET_BUFFER_DATA_LENGTH(pSendItem->CurrentNetBuffer));
	}
	InterlockedDecrement(&((PVNIC)pSendItem->pVNIC)->StatsSendsQueued);

	if (pSendItem->WskBuf.Mdl != NET_BUFFER_CURRENT_MDL(pSendItem->CurrentNetBuffer) ||
		pSendItem->WskBuf.Offset != NET_BUFFER_CURRENT_MDL_OFFSET(pSendItem->CurrentNetBuffer) ||
		pSendItem->WskBuf.Length != NET_BUFFER_DATA_LENGTH(pSendItem->CurrentNetBuffer)
		)
		DBG_PACKET("Buffer data changed\n");

	if (pSendItem->AdvanceDelta > 0)
		NdisRetreatNetBufferDataStart(pSendItem->CurrentNetBuffer, pSendItem->AdvanceDelta, 0, NULL);
	if (pSendItem->AdvanceDelta < 0)
		NdisAdvanceNetBufferDataStart(pSendItem->CurrentNetBuffer, -pSendItem->AdvanceDelta, TRUE, FreeMdl);
	pSendItem->CurrentNetBuffer = NET_BUFFER_NEXT_NB(pSendItem->CurrentNetBuffer);

	if (pSendItem->CurrentNetBuffer != NULL)
	{
		pSendItem->WskBuf.Mdl = NET_BUFFER_CURRENT_MDL(pSendItem->CurrentNetBuffer);
		pSendItem->WskBuf.Offset = NET_BUFFER_CURRENT_MDL_OFFSET(pSendItem->CurrentNetBuffer);
		pSendItem->WskBuf.Length = NET_BUFFER_DATA_LENGTH(pSendItem->CurrentNetBuffer);

		IoReuseIrp(pSendItem->Irp, STATUS_SUCCESS);
		IoSetCompletionRoutine(pSendItem->Irp, SendComplete, pSendItem, TRUE, TRUE, TRUE);
		((PWSK_PROVIDER_DATAGRAM_DISPATCH)pTransport->Socket->Dispatch)->WskSendTo(pTransport->Socket, &pSendItem->WskBuf, 0, (PSOCKADDR)&pSendItem->Destination, 0, NULL, pSendItem->Irp);
	}
	else
	{
		NET_BUFFER_LIST_STATUS(pSendItem->NBL) = Irp->IoStatus.Status;
		NdisMSendNetBufferListsComplete(((PVNIC)pSendItem->pVNIC)->MiniportAdapterHandle, pSendItem->NBL, 0);
		ListAdd(&pTransport->SendPool, pSendItem);
		InterlockedDecrement(&pTransport->StatsSendsPending);
	}

	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS Transport_Send(PVOID pVNIC, PTRANSPORT pTransport, PNET_BUFFER_LIST NBL, LONG AdvanceDelta, ULONG IP, USHORT Port)
{
	NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES;
	KIRQL Irql;
	PSENDITEM pSendItem = NULL;

	if (pTransport->State != 2)
	{
		Status = STATUS_UNSUCCESSFUL;
	}
	else
	{
		pSendItem = ListRemove(&pTransport->SendPool, LIST_QUEUE);
		if (pSendItem == NULL)
		{
			pSendItem = ALLOCMEM(sizeof(SENDITEM));
			if (pSendItem != NULL)
			{
				pSendItem->Irp = IoAllocateIrp(1, FALSE);
				if (pSendItem->Irp == NULL)
				{
					FREEMEM(pSendItem);
					pSendItem = NULL;
				}
			}
		}

		if (pSendItem != NULL)
		{
			pSendItem->pTransport = pTransport;
			pSendItem->pVNIC = pVNIC;
			pSendItem->NBL = NBL;
			pSendItem->CurrentNetBuffer = NET_BUFFER_LIST_FIRST_NB(NBL);
			pSendItem->Destination.sin_family = AF_INET;
			pSendItem->Destination.sin_port = Port;
			pSendItem->Destination.sin_addr.S_un.S_addr = IP;
			pSendItem->AdvanceDelta = AdvanceDelta;
			pSendItem->pReceiveItem = NULL;

			pSendItem->WskBuf.Mdl = NET_BUFFER_CURRENT_MDL(pSendItem->CurrentNetBuffer);
			pSendItem->WskBuf.Offset = NET_BUFFER_CURRENT_MDL_OFFSET(pSendItem->CurrentNetBuffer);
			pSendItem->WskBuf.Length = NET_BUFFER_DATA_LENGTH(pSendItem->CurrentNetBuffer);

			IoReuseIrp(pSendItem->Irp, STATUS_SUCCESS);
			IoSetCompletionRoutine(pSendItem->Irp, SendComplete, pSendItem, TRUE, TRUE, TRUE);
			((PWSK_PROVIDER_DATAGRAM_DISPATCH)pTransport->Socket->Dispatch)->WskSendTo(pTransport->Socket, &pSendItem->WskBuf, 0, (PSOCKADDR)&pSendItem->Destination, 0, NULL, pSendItem->Irp);
			
			InterlockedIncrement(&pTransport->StatsSendsPending);
			Status = STATUS_SUCCESS;
		}
	}

	return Status;
}

NTSTATUS ForwardComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
	PSENDITEM pSendItem = Context;
	PTRANSPORT pTransport = pSendItem->pTransport;

	if (Irp->IoStatus.Status == STATUS_SUCCESS)
		DBG_PACKET("Packet forwarded\n");
	
	Transport_ReceiveComplete(pSendItem->pReceiveItem);

	ListAdd(&pTransport->SendPool, pSendItem);
	InterlockedDecrement(&pTransport->StatsSendsPending);

	return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS WSKAPI Transport_ReceiveFromEvent(PVOID SocketContext, ULONG Flags, PWSK_DATAGRAM_INDICATION DataIndication)
{
	PLISTNODE Node;
	LOCK_STATE LockState;
	PTRANSPORT pTransport = (PTRANSPORT)SocketContext;
	PRECEIVEITEM pReceiveItem;
	PVNIC pVNIC;
	PWSK_DATAGRAM_INDICATION cur;
	ULONG Offset;
	//ULONG Length;
	//UCHAR Buffer[32 + ETH_HEADER_SIZE];
	UCHAR Buffer[20];
	PUCHAR pIPHeader;
	ULONG src;
	ULONG dst;
	PNET_BUFFER_LIST NBL;
	PNET_BUFFER NB;
	PRECEIVE_CONTEXT pReceiveContext;
	KIRQL Irql;
	NTSTATUS Status = STATUS_PENDING;
	PLISTNODE HostNode;
	PVIRTUALHOST pVirtualHost;
	PSENDITEM pSendItem;
	ULONG IPFields;

	DBG_PACKET("Receive event\n");

	pReceiveItem = ListRemove(&pTransport->ReceivePool, LIST_QUEUE);
	if (pReceiveItem == NULL)
	{
		pReceiveItem = ALLOCMEM(sizeof(RECEIVEITEM));
		KeInitializeSpinLock(&pReceiveItem->RefLock);
	}

	pReceiveItem->pTransport = pTransport;
	pReceiveItem->DataIndication = DataIndication;
	pReceiveItem->RefCount = 1;

	cur = DataIndication;
	while (cur != NULL)
	{
		if (pTransport->Port == 0xFFFF && ((PSOCKADDR_IN)cur->RemoteAddress)->sin_addr.S_un.S_addr == 0x00007502)
		{
			cur = cur->Next;
			DBG_PACKET("Packet already processed\n");
			continue;
		}
		Offset = cur->Buffer.Offset;
		if (pTransport->Port == 0xFFFF)
			Offset += (GetByte(cur->Buffer.Mdl, Offset) & 0x0F) << 2;

/*		Length = (GetByte(cur->Buffer.Mdl, Offset) & 0x0F) << 2;
		if (Length > 32)
			Length = 32;
		if (Length < 20 || cur->Buffer.Offset + cur->Buffer.Length < Offset + Length || Offset < ETH_HEADER_SIZE)*/
		if (cur->Buffer.Offset + cur->Buffer.Length < Offset + 20 || Offset < 20)
		{
			DBG_WARNING("Invalid packet, offset = %d\n", Offset);
		}
		else
		{
			//pIPHeader = GetData(cur->Buffer.Mdl, Offset, Length, Buffer + ETH_HEADER_SIZE);
			pIPHeader = GetData(cur->Buffer.Mdl, Offset, 20, Buffer);
			if (pIPHeader != NULL && pIPHeader[8] != 0)
			{
				src = *(ULONG *)&pIPHeader[12];
				dst = *(ULONG *)&pIPHeader[16];

				Transport_BindingLock(FALSE, &LockState);

				for (Node = pTransport->VNICList.First; Node; Node = Node->Next)
					UpdateDynamicHosts((PVNIC)Node->Item, src, ((PSOCKADDR_IN)cur->RemoteAddress)->sin_addr.S_un.S_addr, ((PSOCKADDR_IN)cur->RemoteAddress)->sin_port);

				for (Node = pTransport->VNICList.First; Node; Node = Node->Next)
				{
					pVNIC = (PVNIC)Node->Item;
					if (TestAddress(pVNIC, dst))
						break;
					if (pIPHeader[9] != 0x04)
					{
						for (HostNode = pVNIC->HostsList.First; HostNode && dst != ((PVIRTUALHOST)HostNode->Item)->RemoteIP; HostNode = HostNode->Next);
						if (HostNode != NULL)
							break;
					}
				}
				if (Node)
				{
					pVNIC = (PVNIC)Node->Item;
					if (pVNIC->InterfaceIsRunning)
					{
						if (pIPHeader[9] == 0x04)
							Offset += 20;

						ETH_COPY_NETWORK_ADDRESS(Buffer, pVNIC->CurrentAddress);
						ETH_COPY_NETWORK_ADDRESS(Buffer + 6, pVNIC->CurrentAddress);
						Buffer[11]++;
						Buffer[12] = 0x08;
						Buffer[13] = 0x00;
						/*if (Length == 32 && *(ULONG *)&pIPHeader[20] == 0x04080CAA)
						{
							if (pIPHeader != Buffer + ETH_HEADER_SIZE)
							{
								*(ULONG *)&Buffer[ETH_HEADER_SIZE + 0] = *(ULONG *)&pIPHeader[0];
								*(ULONG *)&Buffer[ETH_HEADER_SIZE + 4] = *(ULONG *)&pIPHeader[4];
								*(ULONG *)&Buffer[ETH_HEADER_SIZE + 8] = *(ULONG *)&pIPHeader[8];
							}
							Buffer[ETH_HEADER_SIZE + 0] -= 3;
							if (Buffer[ETH_HEADER_SIZE + 3] < 12)
								Buffer[ETH_HEADER_SIZE + 2]--;
							Buffer[ETH_HEADER_SIZE + 3] -= 12;
							*(ULONG *)&Buffer[ETH_HEADER_SIZE + 12] = *(ULONG *)&pIPHeader[24];
							*(ULONG *)&Buffer[ETH_HEADER_SIZE + 16] = *(ULONG *)&pIPHeader[28];

							Offset -= 2;
							SetData(cur->Buffer.Mdl, Offset, Buffer, 34);
						}
						else*/
						{
							Offset -= 14;
							//pReceiveItem->Offset = Offset;
							//GetData(cur->Buffer.Mdl, Offset, 14, pReceiveItem->Data);
							SetData(cur->Buffer.Mdl, Offset, Buffer, 14);
						}

						NBL = AllocNBL(pVNIC);
						NB = NET_BUFFER_LIST_FIRST_NB(NBL);

						NET_BUFFER_FIRST_MDL(NB) = cur->Buffer.Mdl;
						NET_BUFFER_DATA_LENGTH(NB) = cur->Buffer.Offset + (ULONG)cur->Buffer.Length - Offset;
						NET_BUFFER_DATA_OFFSET(NB) = Offset;
						NET_BUFFER_CURRENT_MDL(NB) = cur->Buffer.Mdl;
						while (MmGetMdlByteCount(NET_BUFFER_CURRENT_MDL(NB)) < Offset)
						{
							Offset -= MmGetMdlByteCount(NET_BUFFER_CURRENT_MDL(NB));
							NET_BUFFER_CURRENT_MDL(NB) = NDIS_MDL_LINKAGE(NET_BUFFER_CURRENT_MDL(NB));
						}
						NET_BUFFER_CURRENT_MDL_OFFSET(NB) = Offset;

						pReceiveContext = (PRECEIVE_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(NBL);
						pReceiveContext->pReceiveItem = pReceiveItem;
						InterlockedIncrement(&pReceiveItem->RefCount);

						NdisMIndicateReceiveNetBufferLists(pVNIC->MiniportAdapterHandle, NBL, 0, 1, NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL);
					}
				}
				else
				{
					pVirtualHost = NULL;
					for (Node = pTransport->VNICList.First; Node; Node = Node->Next)
					{
						pVNIC = (PVNIC)Node->Item;
						for (HostNode = pVNIC->HostsList.First; HostNode && ((PVIRTUALHOST)HostNode->Item)->IP != (dst & ((PVIRTUALHOST)HostNode->Item)->Mask); HostNode = HostNode->Next);
						if (HostNode != NULL)
						{
							pVirtualHost = HostNode->Item;
							for (HostNode = pVNIC->HostsList.First; HostNode && ((PVIRTUALHOST)HostNode->Item)->IP != (pVirtualHost->RemoteIP & ((PVIRTUALHOST)HostNode->Item)->Mask); HostNode = HostNode->Next);
							if (HostNode != NULL)
							{
								pVirtualHost = HostNode->Item;
							}
							break;
						}
					}

					if (pVirtualHost != NULL && pVirtualHost->pTransport != NULL && pVirtualHost->pTransport->State == 2)
					{
						if (pIPHeader[9] != 0x04)
						{
							*(ULONG *)&Buffer[0] = 0x00000045;
							*(ULONG *)&Buffer[4] = 0x00000000;
							*(ULONG *)&Buffer[8] = 0x00000440;
							*(ULONG *)&Buffer[12] = pVNIC->PrimaryIP;
							*(ULONG *)&Buffer[16] = *(ULONG *)&pIPHeader[16];
							Offset -= 20;
							SetData(cur->Buffer.Mdl, Offset, Buffer, 20);
						}
						else
						{
							*(ULONG *)&Buffer[8] = *(ULONG *)&pIPHeader[8];
							Buffer[8]--;
							//(*(USHORT *)&Buffer[10])++;
							*(ULONG *)&Buffer[12] = pVNIC->PrimaryIP;
							SetData(cur->Buffer.Mdl, Offset + 8, Buffer + 8, 8);
						}

						pSendItem = ListRemove(&pVirtualHost->pTransport->SendPool, LIST_QUEUE);
						if (pSendItem == NULL)
						{
							pSendItem = ALLOCMEM(sizeof(SENDITEM));
							if (pSendItem != NULL)
							{
								pSendItem->Irp = IoAllocateIrp(1, FALSE);
								if (pSendItem->Irp == NULL)
								{
									FREEMEM(pSendItem);
									pSendItem = NULL;
								}
							}
						}
						if (pSendItem != NULL)
						{
							pSendItem->pTransport = pVirtualHost->pTransport;
							pSendItem->pVNIC = pVNIC;
							pSendItem->NBL = NULL;
							pSendItem->CurrentNetBuffer = NULL;
							pSendItem->Destination.sin_family = AF_INET;
							pSendItem->Destination.sin_port = pVirtualHost->RemotePort;
							pSendItem->Destination.sin_addr.S_un.S_addr = pVirtualHost->RemoteIP;
							pSendItem->AdvanceDelta = 0;

							pSendItem->pReceiveItem = pReceiveItem;
							InterlockedIncrement(&pReceiveItem->RefCount);

							pSendItem->WskBuf.Length = cur->Buffer.Offset + (ULONG)cur->Buffer.Length - Offset;
							pSendItem->WskBuf.Offset = Offset;
							pSendItem->WskBuf.Mdl = cur->Buffer.Mdl;
							while (MmGetMdlByteCount(pSendItem->WskBuf.Mdl) < pSendItem->WskBuf.Offset)
							{
								pSendItem->WskBuf.Offset -= MmGetMdlByteCount(pSendItem->WskBuf.Mdl);
								pSendItem->WskBuf.Mdl = pSendItem->WskBuf.Mdl->Next;
							}

							IoReuseIrp(pSendItem->Irp, STATUS_SUCCESS);
							IoSetCompletionRoutine(pSendItem->Irp, ForwardComplete, pSendItem, TRUE, TRUE, TRUE);
							((PWSK_PROVIDER_DATAGRAM_DISPATCH)pVirtualHost->pTransport->Socket->Dispatch)->WskSendTo(pVirtualHost->pTransport->Socket, &pSendItem->WskBuf, 0, (PSOCKADDR)&pSendItem->Destination, 0, NULL, pSendItem->Irp);

							InterlockedIncrement(&pVirtualHost->pTransport->StatsSendsPending);
							DBG_PACKET("Forward packet queued\n");
						}

						if (pTransport->Port == 0xFFFF)
						{
							*(ULONG *)&Buffer[0] = 0x00007502;
							SetData(cur->Buffer.Mdl, cur->Buffer.Offset + 12, Buffer, 4);
						}
					}
				}

				Transport_BindingUnlock(&LockState);
			}
		}

		cur = cur->Next;
	}

	KeAcquireSpinLock(&pReceiveItem->RefLock, &Irql);
	InterlockedDecrement(&pReceiveItem->RefCount);
	if (pReceiveItem->RefCount == 0)
	{
		ListAdd(&pTransport->ReceivePool, pReceiveItem);
		Status = STATUS_SUCCESS;
	}
	KeReleaseSpinLock(&pReceiveItem->RefLock, Irql);

	if (Status == STATUS_PENDING)
		InterlockedIncrement(&pTransport->StatsReceivesPending);

	return Status;
}

VOID Transport_ReceiveComplete(PRECEIVEITEM pReceiveItem)
{
	KIRQL Irql;

	KeAcquireSpinLock(&pReceiveItem->RefLock, &Irql);
	InterlockedDecrement(&pReceiveItem->RefCount);
	if (pReceiveItem->RefCount == 0)
	{
		//SetData(pReceiveItem->DataIndication->Buffer.Mdl, pReceiveItem->Offset, pReceiveItem->Data, 14);

		((PWSK_PROVIDER_DATAGRAM_DISPATCH)pReceiveItem->pTransport->Socket->Dispatch)->WskRelease(pReceiveItem->pTransport->Socket, pReceiveItem->DataIndication);
		InterlockedDecrement(&pReceiveItem->pTransport->StatsReceivesPending);
		ListAdd(&pReceiveItem->pTransport->ReceivePool, pReceiveItem);
	}
	KeReleaseSpinLock(&pReceiveItem->RefLock, Irql);
}

NTSTATUS BindComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
	PTRANSPORT pTransport = Context;
	NTSTATUS Status;
	WSK_EVENT_CALLBACK_CONTROL EventCallbackControl;

	if (Irp->IoStatus.Status == STATUS_SUCCESS)
	{
		DBG_INIT("Socket bind succeeds.\n");

		EventCallbackControl.NpiId = &NPI_WSK_INTERFACE_ID;
		EventCallbackControl.EventMask = WSK_EVENT_RECEIVE_FROM;
		Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)pTransport->Socket->Dispatch)->WskControlSocket(pTransport->Socket, WskSetOption, SO_WSK_EVENT_CALLBACK, SOL_SOCKET, sizeof(WSK_EVENT_CALLBACK_CONTROL), &EventCallbackControl, 0, NULL, NULL, NULL);
		if (Status != STATUS_SUCCESS)
		{
			DBG_WARNING("Socket event control fails = %x.\n", Status);
		}

		pTransport->State = 2;
	}
	else
	{
		pTransport->State = 5;
	}
	
	return STATUS_MORE_PROCESSING_REQUIRED;
}

VOID Transport_Thread(PVOID StartContext)
{
	PLISTNODE Node;
	LOCK_STATE LockState;
	PTRANSPORT pTransport;
	NTSTATUS Status = STATUS_TIMEOUT;
	LARGE_INTEGER Timeout;
	Timeout.HighPart = -1;
	Timeout.LowPart = -100000000;

	while (Status == STATUS_TIMEOUT)
	{
		ListLock(&Transports, FALSE, &LockState);
		for (Node = Transports.First; Node; Node = Node->Next)
		{
			if (((PTRANSPORT)Node->Item)->State == 5)
			{
				pTransport = (PTRANSPORT)Node->Item;
				pTransport->State = 1;

				IoReuseIrp(pTransport->Irp, STATUS_SUCCESS);
				IoSetCompletionRoutine(pTransport->Irp, BindComplete, pTransport, TRUE, TRUE, TRUE);
				((PWSK_PROVIDER_LISTEN_DISPATCH)pTransport->Socket->Dispatch)->WskBind(pTransport->Socket, (PSOCKADDR)&pTransport->Endpoint, 0, pTransport->Irp);
			}
			if (((PTRANSPORT)Node->Item)->State == 2)
				DBG_PACKET("%d sends pending, %d receives pending\n", ((PTRANSPORT)Node->Item)->StatsSendsPending, ((PTRANSPORT)Node->Item)->StatsReceivesPending);
		}
		ListUnlock(&Transports, &LockState);

		Status = KeWaitForSingleObject(&evClose, Executive, KernelMode, FALSE, &Timeout);
	}

	DBG_INIT("Transport_Thread exits\n");
}
