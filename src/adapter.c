#include "precomp.h"
#include "mof.h"

// IPIPNIC-specific

UCHAR BaseAddress[ETH_LENGTH_OF_ADDRESS] = {0x02, 0x75, 0x00, 0x00, 0x00, 0x00};

// TODO: Synchronize
VOID GenerateMacAddr(PUCHAR Address)
{
	ULONG i = NETWORK_BYTE_ORDER_LONG(*(ULONG *)&BaseAddress[2]);
	i++;
	*(ULONG *)&BaseAddress[2] = NETWORK_BYTE_ORDER_LONG(i);
	ETH_COPY_NETWORK_ADDRESS(Address, BaseAddress);
}

ULONG UpdateAddresses(PLISTROOT Root, PNETWORK_ADDRESS Address, ULONG Count)
{
	LOCK_STATE LockState;
	ULONG i;
	ULONG retIP = 0;
	PLOCALADDRESS pLocalAddress;

	DBG_INIT("Set address list, count = %d\n", Count);
	ListDeactivate(Root, TRUE);

	ListLock(Root, TRUE, &LockState);
	for (i = 0; i < Count; i++, Address = (PNETWORK_ADDRESS)((PUCHAR)Address + Address->AddressLength + 4))
		if (Address->AddressType == NDIS_PROTOCOL_ID_TCP_IP)
		{
			pLocalAddress = (PLOCALADDRESS)NDIS_ALLOCMEM(Root->NdisHandle, sizeof(LOCALADDRESS));
			if (pLocalAddress)
			{
				pLocalAddress->IP = ((PNETWORK_ADDRESS_IP)Address->Address)->in_addr;
				DBG_INIT("Add IP %x\n", pLocalAddress->IP);
				if (!retIP)
					retIP = pLocalAddress->IP;
				ListAdd(Root, pLocalAddress);
			}
		}
	ListUnlock(Root, &LockState);

	return retIP;
}

VOID UpdateHosts(PVNIC pVNIC, PLISTROOT Root, PUCHAR Data, ULONG Length)
{
	PLISTNODE Node;
	LOCK_STATE LockState;
	LOCK_STATE BindingLockState;
	PVIRTUALHOST pVirtualHost;
	ULONG i;

	DBG_INIT("Set hosts list, count = %d\n", Length/24);

	Transport_BindingLock(TRUE, &BindingLockState);
	Transport_Scavenge();

	ListLock(Root, TRUE, &LockState);
	while (Root->Count)
	{
		pVirtualHost = (PVIRTUALHOST)ListRemove(Root, LIST_QUEUE);
		if (pVirtualHost->pTransport != NULL)
		{
			Transport_Unbind(pVNIC, pVirtualHost->pTransport);
			pVirtualHost->pTransport = NULL;
		}
		NDIS_FREEMEM(pVirtualHost);
	}

	for (i = 0; i < Length/24; i++)
	{
		pVirtualHost = (PVIRTUALHOST)NDIS_ALLOCMEM(Root->NdisHandle, sizeof(VIRTUALHOST));
		if (pVirtualHost)
		{
			NdisMoveMemory(pVirtualHost, Data + i*24, 24);
			DBG_INIT("Add host %x/%x to %x(%d) via %x(%d), flags = %x\n", pVirtualHost->IP, pVirtualHost->Mask, pVirtualHost->RemoteIP, pVirtualHost->RemotePort, pVirtualHost->LocalIP, pVirtualHost->LocalPort, pVirtualHost->Flags);
	
			for (Node = Root->First; Node && (((PVIRTUALHOST)Node->Item)->LocalIP != pVirtualHost->LocalIP || ((PVIRTUALHOST)Node->Item)->LocalPort != pVirtualHost->LocalPort); Node = Node->Next);
			if (Node != NULL)
				pVirtualHost->pTransport = ((PVIRTUALHOST)Node->Item)->pTransport;
			else
				pVirtualHost->pTransport = Transport_Bind(pVNIC, pVirtualHost->LocalIP, pVirtualHost->LocalPort);

			ListAdd(Root, pVirtualHost);
		}
	}
	ListUnlock(Root, &LockState);

	Transport_Scavenge();
	Transport_BindingUnlock(&BindingLockState);
}

NDIS_STATUS LookupArpEntry(PVNIC pVNIC, ULONG ip, PUCHAR mac)
{
	PLISTNODE Node;
	LOCK_STATE LockState;
	ARPENTRY ArpEntry;
	PARPENTRY pArpEntry = NULL;
	VIRTUALHOST VirtualHost;
	PVIRTUALHOST pVirtualHost = NULL;
	ULONG i;
    NDIS_STATUS Status = NDIS_STATUS_FAILURE;

	ListLock(&pVNIC->HostsList, FALSE, &LockState);
	for (Node = pVNIC->HostsList.First; Node && ((PVIRTUALHOST)Node->Item)->IP != (ip & ((PVIRTUALHOST)Node->Item)->Mask); Node = Node->Next);
	if (Node)
	{
		pVirtualHost = &VirtualHost;
		NdisMoveMemory(pVirtualHost, Node->Item, sizeof(VIRTUALHOST));
	}
	ListUnlock(&pVNIC->HostsList, &LockState);

	if (ListCount(&pVNIC->AddressesList) == 0) // Address conflict hack
		pVirtualHost = NULL;

	if (pVirtualHost)
	{
		ListLock(&pVNIC->ArpEntriesList, FALSE, &LockState);
		for (Node = pVNIC->ArpEntriesList.First; Node && ((PARPENTRY)Node->Item)->IP != ip; Node = Node->Next);
		if (Node)
		{
			pArpEntry = &ArpEntry;
			NdisMoveMemory(pArpEntry, Node->Item, sizeof(ARPENTRY));
		}
		ListUnlock(&pVNIC->ArpEntriesList, &LockState);

		if (!pArpEntry)
		{
			pArpEntry = (PARPENTRY)NDIS_ALLOCMEM(pVNIC->MiniportAdapterHandle, sizeof(ARPENTRY));
			if (pArpEntry == NULL)
				return NDIS_STATUS_RESOURCES;
			else
			{
				pArpEntry->IP = ip;
				GenerateMacAddr(pArpEntry->MAC);
				ListAdd(&pVNIC->ArpEntriesList, pArpEntry);
			}
		}

		ETH_COPY_NETWORK_ADDRESS(mac, pArpEntry->MAC);
		Status = NDIS_STATUS_SUCCESS;
	}

	return Status;
}

BOOLEAN TestAddress(PVNIC pVNIC, ULONG ip)
{
	PLISTNODE Node;
	LOCK_STATE LockState;

	ListLock(&pVNIC->AddressesList, FALSE, &LockState);
	for (Node = pVNIC->AddressesList.First; Node && ((PLOCALADDRESS)Node->Item)->IP != ip; Node = Node->Next);
	ListUnlock(&pVNIC->AddressesList, &LockState);
	if (Node != NULL)
		return TRUE;

	return FALSE;
}

VOID UpdateDynamicHosts(PVNIC pVNIC, ULONG IP, ULONG RemoteIP, USHORT RemotePort)
{
	PLISTNODE Node;
	PVIRTUALHOST pVirtualHost = NULL;

	for (Node = pVNIC->HostsList.First; Node; Node = Node->Next)
	{
		pVirtualHost = (PVIRTUALHOST)Node->Item;
		if ((pVirtualHost->Flags & VIRTUALHOST_FLAG_DYNAMIC) != 0 &&
			pVirtualHost->IP == IP && pVirtualHost->Mask == 0xFFFFFFFF &&
			(pVirtualHost->RemoteIP != RemoteIP || pVirtualHost->RemotePort != RemotePort))
		{
			pVirtualHost->RemoteIP = RemoteIP;
			pVirtualHost->RemotePort = RemotePort;
			DBG_INIT("Set host %x to %x(%d)\n", pVirtualHost->IP, pVirtualHost->RemoteIP, pVirtualHost->RemotePort);
		}
	}
}


PNET_BUFFER_LIST AllocNBL(PVNIC pVNIC)
{
	PNET_BUFFER_LIST NBL = NULL;

	NBL = ListRemove(&pVNIC->NBLList, LIST_QUEUE);
	if (NBL == NULL)
	{
		NBL = NdisAllocateNetBufferAndNetBufferList(pVNIC->NBLPool, sizeof(RECEIVE_CONTEXT), 0, NULL, 0, 0);
	}

	return NBL;
}

VOID FreeNBL(PNET_BUFFER_LIST NBL)
{
	NdisFreeNetBufferList(NBL);
}

PMDL AllocateMdl(PULONG BufferSize)
{
	PMDL Mdl;
	PVOID Buffer;

	Buffer = NDIS_ALLOCMEM(MiniportDriverHandle, *BufferSize);
	if (Buffer == NULL)
		return NULL;
	Mdl = NdisAllocateMdl(MiniportDriverHandle, Buffer, *BufferSize);
	if (Mdl == NULL)
		NDIS_FREEMEM(Buffer);
	if (Mdl != NULL)
		DBG_PACKET("MDL %d allocated\n", *BufferSize);
	return Mdl;
}

VOID FreeMdl(PMDL Mdl)
{
	PVOID Buffer;
	ULONG Length;

	NdisQueryMdl(Mdl, &Buffer, &Length, NormalPagePriority);
	DBG_PACKET("MDL %d freed\n", Length);
	NdisFreeMdl(Mdl);
	NDIS_FREEMEM(Buffer);
}

VOID OnArpPacket(PVNIC pVNIC, PNET_BUFFER* CurrentNetBuffer, PNET_BUFFER_LIST* NBLReceive, ULONG* NBLReceiveCount, NDIS_STATUS* Status)
{
    UCHAR MAC[ETH_LENGTH_OF_ADDRESS];
	ARP_PACKET ArpPacket;
	PARP_PACKET pArpPacket;
	PARP_PACKET pArpResponse;
	PNET_BUFFER_LIST NBL;
	PNET_BUFFER NB;
	PMDL Mdl;
	PRECEIVE_CONTEXT pReceiveContext;

	while (*CurrentNetBuffer != NULL)
	{
		pArpPacket = NdisGetDataBuffer(*CurrentNetBuffer, sizeof(ARP_PACKET), &ArpPacket, 1, 0);

		if (pArpPacket != NULL 
			&& pArpPacket->hwAddressType == NETWORK_BYTE_ORDER_SHORT(1)
			&& pArpPacket->protoAddressType == NETWORK_BYTE_ORDER_SHORT(0x0800)
			&& pArpPacket->hwAddressLength == 0x06
			&& pArpPacket->protoAddressLength == 0x04
			&& pArpPacket->Opcode == ARP_REQUEST
			&& pArpPacket->ipDestination != pArpPacket->ipSource
			&& pArpPacket->ipDestination != 0xFFFFFFFF)
		{
			DBG_PACKET("ARP request. Query IP = %x\n", pArpPacket->ipDestination);
			if (!TestAddress(pVNIC, pArpPacket->ipDestination) && LookupArpEntry(pVNIC, pArpPacket->ipDestination, MAC) == NDIS_STATUS_SUCCESS)
			{
				DBG_PACKET("ARP response. Network address is %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", (UINT)MAC[0], (UINT)MAC[1], (UINT)MAC[2], (UINT)MAC[3], (UINT)MAC[4], (UINT)MAC[5]);

				pArpResponse = NDIS_ALLOCMEM(pVNIC->MiniportAdapterHandle, sizeof(ARP_PACKET));
				if (pArpResponse == NULL)
				{
					*Status = NDIS_STATUS_RESOURCES;
					break;
				}

				ETH_COPY_NETWORK_ADDRESS(pArpResponse->Destination, pArpPacket->Source);
				ETH_COPY_NETWORK_ADDRESS(pArpResponse->Source, MAC);
				pArpResponse->FrameType = NETWORK_BYTE_ORDER_SHORT(0x0806);
				pArpResponse->hwAddressType = NETWORK_BYTE_ORDER_SHORT(0x0001);
				pArpResponse->protoAddressType = NETWORK_BYTE_ORDER_SHORT(0x0800);
				pArpResponse->hwAddressLength = 0x06;
				pArpResponse->protoAddressLength = 0x04;
				pArpResponse->Opcode = ARP_REPLY;
				ETH_COPY_NETWORK_ADDRESS(pArpResponse->hwSource, MAC);
				pArpResponse->ipSource = pArpPacket->ipDestination;
				ETH_COPY_NETWORK_ADDRESS(pArpResponse->hwDestination, pArpPacket->Source);
				pArpResponse->ipDestination = pArpPacket->ipSource;

				Mdl = NdisAllocateMdl(pVNIC->MiniportAdapterHandle, pArpResponse, sizeof(ARP_PACKET));
				if (Mdl == NULL)
				{
					NDIS_FREEMEM(pArpResponse);
					*Status = NDIS_STATUS_RESOURCES;
					break;
				}

				NBL = AllocNBL(pVNIC);
				if (NBL == NULL)
				{
					NdisFreeMdl(Mdl);
					NDIS_FREEMEM(pArpResponse);
					*Status = NDIS_STATUS_RESOURCES;
					break;
				}

				NB = NET_BUFFER_LIST_FIRST_NB(NBL);
				NET_BUFFER_FIRST_MDL(NB) = Mdl;
				NET_BUFFER_DATA_LENGTH(NB) = sizeof(ARP_PACKET);
				NET_BUFFER_DATA_OFFSET(NB) = 0;
				NET_BUFFER_CURRENT_MDL(NB) = Mdl;
				NET_BUFFER_CURRENT_MDL_OFFSET(NB) = 0;

				pReceiveContext = (PRECEIVE_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(NBL);
				pReceiveContext->pReceiveItem = NULL;
				pReceiveContext->pVNIC = pVNIC;

				NET_BUFFER_LIST_NEXT_NBL(NBL) = *NBLReceive;
				*NBLReceive = NBL;
				(*NBLReceiveCount)++;
			}
		}
		else
		{
			DBG_WARNING("Invalid ARP. Ignored.\n");
		}
		*CurrentNetBuffer = NET_BUFFER_NEXT_NB(*CurrentNetBuffer);
	}
}

VOID OnIPPacket(PVNIC pVNIC, PNET_BUFFER_LIST* CurrentNetBufferList, PNET_BUFFER* CurrentNetBuffer, NDIS_STATUS* Status)
{
	UCHAR PacketHeaders[ETH_HEADER_SIZE + IP_HEADER_SIZE];
	PUCHAR pPacket = NULL;

	pPacket = NdisGetDataBuffer(*CurrentNetBuffer, ETH_HEADER_SIZE + IP_HEADER_SIZE + 1, PacketHeaders, 1, 0);

	if (pPacket == NULL)
	{
		*Status = NDIS_STATUS_INVALID_PACKET;
		DBG_ERROR("Invalid packet\n");
		return;
	}

	if (pPacket[23] == 0x04 || // IP-IP packets
	   (pPacket[23] == 0x01 && pPacket[34] == 0x05)) // ICMP Redirect
	{
		DBG_PACKET("IP-IP or ICMP-Redirect packet. Ignored.\n");
	}
	else if (ETH_IS_BROADCAST(pPacket))
	{
		DBG_PACKET("Broadcast\n");
/*					NdisZeroMemory(PacketBuffer, IP_HEADER_SIZE);

		ListLock(&pIpIpAdapter->HostsList, FALSE, &LockState);
		for (Node = pIpIpAdapter->HostsList.First; Node; Node = Node->Next)
		{
			pVirtualHost = (PVIRTUALHOST)Node->Item;
			if ((pVirtualHost->Flags & VIRTUALHOST_FLAG_DIRECT_FORWARDING) == 0 && pVirtualHost->Mask == 0xFFFFFFFF)
			{
				NdisAllocateMemory((PVOID *)&Buffer, PacketLength + 6, 0, HighestAcceptableMax);
				if (Buffer == NULL)
				{
					Status = NDIS_STATUS_RESOURCES;
					break;
				}
				else
				{
					NdisMoveMemory(Buffer, PacketBuffer, PacketLength + 6);
					Buffer[8] = 0x40;
					Buffer[9] = 0x04;
					*(IPADDR *)(Buffer + 12) = pIpIpAdapter->PrimaryIP;
					*(IPADDR *)(Buffer + 16) = pVirtualHost->IP;
					NtStatus = Tunnel_Write(pIpIpAdapter->pTunnelContext, NULL, NULL, Buffer, 0, PacketLength - ETHERNET_HEADER_SIZE + IP_HEADER_SIZE, pVirtualHost->RemoteIP);
					if (NtStatus != STATUS_PENDING)
					{
						Status = NDIS_STATUS_RESOURCES;
						break;
					}
				}
			}
		}
		ListUnlock(&pIpIpAdapter->HostsList, &LockState);

		pIpIpAdapter->Tx++;*/
	}
	else if (ETH_IS_MULTICAST(pPacket))
	{
		DBG_PACKET("Multicast\n");
	}
	else
	{
		PLISTNODE Node;
		LOCK_STATE LockState;
		ARPENTRY ArpEntry;
		PARPENTRY pArpEntry = NULL;
		PVIRTUALHOST pVirtualHost = NULL;
		ULONG NBCount = 0;
		LONG AdvanceDelta = 0;

		ListLock(&pVNIC->ArpEntriesList, FALSE, &LockState);
		for (Node = pVNIC->ArpEntriesList.First; Node && !ETH_CMP_NETWORK_ADDRESSES(((PARPENTRY)Node->Item)->MAC, pPacket); Node = Node->Next);
		if (Node)
		{
			pArpEntry = &ArpEntry;
			NdisMoveMemory(pArpEntry, Node->Item, sizeof(ARPENTRY));
		}
		ListUnlock(&pVNIC->ArpEntriesList, &LockState);

		if (pArpEntry)
		{
			ListLock(&pVNIC->HostsList, FALSE, &LockState);
			for (Node = pVNIC->HostsList.First; Node && ((PVIRTUALHOST)Node->Item)->IP != (pArpEntry->IP & ((PVIRTUALHOST)Node->Item)->Mask); Node = Node->Next);
			if (Node)
			{
				pVirtualHost =  Node->Item;
				for (Node = pVNIC->HostsList.First; Node && ((PVIRTUALHOST)Node->Item)->IP != (pVirtualHost->RemoteIP & ((PVIRTUALHOST)Node->Item)->Mask); Node = Node->Next);
				if (Node)
					pVirtualHost =  Node->Item;
			}
			if (pVirtualHost)
			{
				if ((pVirtualHost->Flags & VIRTUALHOST_FLAG_SIMPLE_FORWARDING) == 0 && (*(ULONG *)&pPacket[ETH_HEADER_SIZE + 12] != pVNIC->PrimaryIP || *(ULONG *)&pPacket[ETH_HEADER_SIZE + 16] != pArpEntry->IP))
				{
					//UCHAR NewHeader[IP_HEADER_SIZE + 12];
					NdisZeroMemory(PacketHeaders, IP_HEADER_SIZE);
					PacketHeaders[0] = 0x45;
					PacketHeaders[8] = 0x40;
					PacketHeaders[9] = 0x04;
					*(ULONG *)&PacketHeaders[12] = pVNIC->PrimaryIP;
					*(ULONG *)&PacketHeaders[16] = pArpEntry->IP;

					AdvanceDelta = -6;
					while (*CurrentNetBuffer != NULL)
					{
/*									pPacket = NdisGetDataBuffer(CurrentNetBuffer, ETH_HEADER_SIZE + IP_HEADER_SIZE, PacketHeaders, 1, 0);
						*(ULONG *)&NewHeader[0] = *(ULONG *)&pPacket[ETH_HEADER_SIZE + 0];
						*(ULONG *)&NewHeader[4] = *(ULONG *)&pPacket[ETH_HEADER_SIZE + 4];
						*(ULONG *)&NewHeader[8] = *(ULONG *)&pPacket[ETH_HEADER_SIZE + 8];
						*(ULONG *)&NewHeader[12] = pVNIC->PrimaryIP;
						*(ULONG *)&NewHeader[16] = pArpEntry->IP;
						NewHeader[0] += 3;
						if (NewHeader[3] >= 256 - 12)
							NewHeader[2]++;
						NewHeader[3] += 12;
						*(ULONG *)&NewHeader[20] = 0x04080CAA;
						*(ULONG *)&NewHeader[24] = *(ULONG *)&pPacket[ETH_HEADER_SIZE + 12];
						*(ULONG *)&NewHeader[28] = *(ULONG *)&pPacket[ETH_HEADER_SIZE + 16];

						NdisAdvanceNetBufferDataStart(CurrentNetBuffer, 2, FALSE, NULL);
						SetData(NET_BUFFER_CURRENT_MDL(CurrentNetBuffer), NET_BUFFER_CURRENT_MDL_OFFSET(CurrentNetBuffer), NewHeader, IP_HEADER_SIZE + 12);*/

						NdisRetreatNetBufferDataStart(*CurrentNetBuffer, 6, 0, AllocateMdl);
						SetData(NET_BUFFER_CURRENT_MDL(*CurrentNetBuffer), NET_BUFFER_CURRENT_MDL_OFFSET(*CurrentNetBuffer), PacketHeaders, IP_HEADER_SIZE);

						*CurrentNetBuffer = NET_BUFFER_NEXT_NB(*CurrentNetBuffer);
						NBCount++;
					}
				}
				else
				{
					AdvanceDelta = ETH_HEADER_SIZE;
					while (*CurrentNetBuffer != NULL)
					{
						NdisAdvanceNetBufferDataStart(*CurrentNetBuffer, ETH_HEADER_SIZE, FALSE, NULL);
						*CurrentNetBuffer = NET_BUFFER_NEXT_NB(*CurrentNetBuffer);
						NBCount++;
					}
				}

				if (pVirtualHost->pTransport != NULL && Transport_Send(pVNIC, pVirtualHost->pTransport, *CurrentNetBufferList, AdvanceDelta, pVirtualHost->RemoteIP, pVirtualHost->RemotePort) == STATUS_SUCCESS)
				{
					NET_BUFFER_LIST_NEXT_NBL(*CurrentNetBufferList) = NULL;
					*CurrentNetBufferList = NULL;
					InterlockedExchangeAdd(&pVNIC->StatsSendsQueued, NBCount);
					DBG_PACKET("%d frames queued\n", NBCount);
				}
				else
				{
					*Status = NDIS_STATUS_RESOURCES;
					InterlockedExchangeAdd(&pVNIC->StatsSendsFailed, NBCount);
				}
			}
			else
			{
				DBG_WARNING("ARP %.2x:%.2x:%.2x:%.2x:%.2x:%.2x, IP host not found. Ignored.\n", pPacket[0], pPacket[1], pPacket[2], pPacket[3], pPacket[4], pPacket[5]);
			}
			ListUnlock(&pVNIC->HostsList, &LockState);
		}
	}
}

VOID IndicateReceive(PVOID WorkItemContext, NDIS_HANDLE NdisIoWorkItemHandle)
{
	PNET_BUFFER_LIST NBLReceive = (PNET_BUFFER_LIST)WorkItemContext;
	ULONG NBLReceiveCount = 0;
	PNET_BUFFER_LIST CurrentNetBufferList = NBLReceive;
	PRECEIVE_CONTEXT pReceiveContext;
	PVNIC pVNIC;

	while (CurrentNetBufferList)
	{
		pReceiveContext = (PRECEIVE_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(CurrentNetBufferList);
		pVNIC = (PVNIC)pReceiveContext->pVNIC;
		NBLReceiveCount++;
		CurrentNetBufferList = NET_BUFFER_LIST_NEXT_NBL(CurrentNetBufferList);
	}

	NdisMIndicateReceiveNetBufferLists(pVNIC->MiniportAdapterHandle, NBLReceive, 0, NBLReceiveCount, /*ReceiveFlags*/0);

	NdisFreeIoWorkItem(NdisIoWorkItemHandle);
}

VOID
MPSendNetBufferLists(
    IN NDIS_HANDLE      MiniportAdapterContext,
    IN PNET_BUFFER_LIST NetBufferLists,
    IN NDIS_PORT_NUMBER PortNumber,
    IN ULONG            SendFlags
    )
/*++

Routine Description:

    Send NET_BUFFER_LISTs to the lower binding

Arguments:
    MiniportAdapterContext          Pointer to our VELAN
    NetBufferLists                  Set of NET_BUFFER_LISTs to send
    SendFlags                       Specify the send flags

Return Value:
    None

--*/
{
	PVNIC                       pVNIC = (PVNIC)MiniportAdapterContext;
    PNET_BUFFER_LIST            CurrentNetBufferList;
    PNET_BUFFER                 CurrentNetBuffer;
    NDIS_STATUS                 Status = NDIS_STATUS_SUCCESS;
    ULONG                       SendCompleteFlags = 0;
	ULONG                       ReceiveFlags = 0;
    PUCHAR                      pEthFrame = NULL;

	PNET_BUFFER_LIST            NBLComplete = NULL;
	PNET_BUFFER_LIST            NBLReceive = NULL;
	ULONG                       NBLReceiveCount = 0;

//	if (!pVNIC->InterfaceIsRunning)
//       return NDIS_STATUS_FAILURE;

    while (NetBufferLists != NULL)
    {
		CurrentNetBufferList = NetBufferLists;
		NetBufferLists = NET_BUFFER_LIST_NEXT_NBL(CurrentNetBufferList);
        CurrentNetBuffer = NET_BUFFER_LIST_FIRST_NB(CurrentNetBufferList);

		Status = NDIS_STATUS_FAILURE;

		while (CurrentNetBuffer != NULL)
		{
			Status = NDIS_STATUS_SUCCESS;

			pEthFrame = NdisGetDataBuffer(CurrentNetBuffer, ETH_HEADER_SIZE, NULL, 1, 0);
			if (pEthFrame == NULL)
			{
				Status = NDIS_STATUS_INVALID_PACKET;
				DBG_ERROR("Invalid packet\n");
				break;
			}

			if (*(USHORT *)(pEthFrame + 12) == NETWORK_BYTE_ORDER_SHORT(0x0806)) // ARP
			{
				OnArpPacket(pVNIC, &CurrentNetBuffer, &NBLReceive, &NBLReceiveCount, &Status);
			}
			else if (*(USHORT *)(pEthFrame + 12) == NETWORK_BYTE_ORDER_SHORT(0x0800)) // IP
			{
				OnIPPacket(pVNIC, &CurrentNetBufferList, &CurrentNetBuffer, &Status);
			}
			else
			{
				DBG_PACKET("Unknown type = %x. Ignored.\n", *(USHORT *)(pEthFrame + 12));
			}

			break;
		}

		if (CurrentNetBufferList != NULL)
		{
			NET_BUFFER_LIST_STATUS(CurrentNetBufferList) = Status;
			NET_BUFFER_LIST_NEXT_NBL(CurrentNetBufferList) = NBLComplete;
			NBLComplete = CurrentNetBufferList;
		}
	}

	if (NBLComplete != NULL)
	{
		if (NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendFlags))
		{
			NDIS_SET_SEND_COMPLETE_FLAG(SendCompleteFlags, NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL);
		}
		NdisMSendNetBufferListsComplete(pVNIC->MiniportAdapterHandle, NBLComplete, SendCompleteFlags);
	}
	if (NBLReceive != NULL)
	{
/*		if (NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendFlags))
		{
			NDIS_SET_RECEIVE_FLAG(ReceiveFlags, NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL);
		}
		NdisMIndicateReceiveNetBufferLists(pVNIC->MiniportAdapterHandle, NBLReceive, 0, NBLReceiveCount, ReceiveFlags);*/
		NDIS_HANDLE NdisIoWorkItemHandle = NdisAllocateIoWorkItem(pVNIC->MiniportAdapterHandle);
		if (NdisIoWorkItemHandle != NULL)
			NdisQueueIoWorkItem(NdisIoWorkItemHandle, IndicateReceive, NBLReceive);
	}
}

VOID 
MPReturnNetBufferLists(
    IN NDIS_HANDLE      MiniportAdapterContext,
    IN PNET_BUFFER_LIST NetBufferLists,
    IN ULONG            ReturnFlags
    )
/*++

Routine Description:
    NDIS Miniport entry point called whenever protocols are done with
    a packet that we had indicated up and they had queued up for returning
    later.

Arguments:
    MiniportAdapterContext          Pointer to VELAN structure
    NetBufferLists                  NetBufferLists being returned
    Dispatch                        TRUE if IRQL == DISPATCH_LEVEL

Return Value:
    None

--*/
{
	PVNIC                   pVNIC = (PVNIC)MiniportAdapterContext;
    PNET_BUFFER_LIST        CurrentNetBufferList = NULL;
    PNET_BUFFER             CurrentNetBuffer;
	PRECEIVE_CONTEXT        pReceiveContext;
	PMDL                    Mdl;
	PVOID                   Buffer;
	ULONG                   Length;
	
    while (NetBufferLists != NULL)
    {
		CurrentNetBufferList = NetBufferLists;
		NetBufferLists = NET_BUFFER_LIST_NEXT_NBL(CurrentNetBufferList);
        NET_BUFFER_LIST_NEXT_NBL(CurrentNetBufferList) = NULL;

        CurrentNetBuffer = NET_BUFFER_LIST_FIRST_NB(CurrentNetBufferList);
		if (NET_BUFFER_NEXT_NB(CurrentNetBuffer) != NULL)
			DBG_WARNING("Invalid NBL\n");

		pReceiveContext = (PRECEIVE_CONTEXT)NET_BUFFER_LIST_CONTEXT_DATA_START(CurrentNetBufferList);
		if (pReceiveContext->pReceiveItem == NULL) // ARP packet
		{
			Mdl = NET_BUFFER_FIRST_MDL(CurrentNetBuffer);
			if (NDIS_MDL_LINKAGE(Mdl) != NULL)
				DBG_WARNING("Invalid NBL\n");

			NdisQueryMdl(Mdl, &Buffer, &Length, NormalPagePriority);
			if (Length != sizeof(ARP_PACKET))
				DBG_WARNING("Invalid NBL\n");

			NdisFreeMdl(Mdl);
			NDIS_FREEMEM(Buffer);
		}
		else
		{
			Transport_ReceiveComplete(pReceiveContext->pReceiveItem);
			InterlockedIncrement64(&pVNIC->StatsReceivesCompleted);
			InterlockedExchangeAdd64(&pVNIC->StatsBytesReceived, NET_BUFFER_DATA_LENGTH(CurrentNetBuffer) - ETH_HEADER_SIZE);
		}

		NET_BUFFER_FIRST_MDL(CurrentNetBuffer) = NULL;
		NET_BUFFER_DATA_LENGTH(CurrentNetBuffer) = 0;
		NET_BUFFER_DATA_OFFSET(CurrentNetBuffer) = 0;
		NET_BUFFER_CURRENT_MDL(CurrentNetBuffer) = NULL;
		NET_BUFFER_CURRENT_MDL_OFFSET(CurrentNetBuffer) = 0;

		ListAdd(&pVNIC->NBLList, CurrentNetBufferList);
	}
}


// Virtual NIC


#pragma NDIS_INIT_FUNCTION(DriverEntry)
#pragma alloc_text(PAGE, MPUnload)

#pragma alloc_text(PAGE, MPInitialize)
#pragma alloc_text(PAGE, MPHalt)

#pragma alloc_text(PAGE, MPPause)
#pragma alloc_text(PAGE, MPRestart)

#pragma alloc_text(PAGE, MpSetOptions)
#pragma alloc_text(PAGE, MPDevicePnPEvent)

//
//  G L O B A L   V A R I A B L E S
//  -----------   -----------------
//

NDIS_OID SupportedOids[] =
{
    OID_GEN_SUPPORTED_LIST,
    OID_GEN_HARDWARE_STATUS,
    OID_GEN_MEDIA_SUPPORTED,
    OID_GEN_MEDIA_IN_USE,
    OID_GEN_MAXIMUM_LOOKAHEAD,
    OID_GEN_MAXIMUM_FRAME_SIZE,
    OID_GEN_LINK_SPEED,
    OID_GEN_TRANSMIT_BUFFER_SPACE,
    OID_GEN_RECEIVE_BUFFER_SPACE,
    OID_GEN_TRANSMIT_BLOCK_SIZE,
    OID_GEN_RECEIVE_BLOCK_SIZE,
    OID_GEN_VENDOR_ID,
    OID_GEN_VENDOR_DESCRIPTION,
    OID_GEN_VENDOR_DRIVER_VERSION,
    OID_GEN_CURRENT_PACKET_FILTER,
    OID_GEN_CURRENT_LOOKAHEAD,
    OID_GEN_MAXIMUM_TOTAL_SIZE,
    OID_GEN_PROTOCOL_OPTIONS,
    OID_GEN_MAC_OPTIONS,
    OID_GEN_MEDIA_CONNECT_STATUS,
    OID_GEN_MAXIMUM_SEND_PACKETS,
    OID_GEN_XMIT_OK,
    OID_GEN_RCV_OK,
	OID_GEN_XMIT_ERROR,
	OID_GEN_RCV_ERROR,
	OID_GEN_RCV_NO_BUFFER,
    OID_GEN_TRANSMIT_QUEUE_LENGTH,
    OID_GEN_STATISTICS,
    OID_802_3_PERMANENT_ADDRESS,
    OID_802_3_CURRENT_ADDRESS,
    OID_802_3_MULTICAST_LIST,
    OID_802_3_MAXIMUM_LIST_SIZE,
    OID_802_3_RCV_ERROR_ALIGNMENT,
    OID_802_3_XMIT_ONE_COLLISION,
    OID_802_3_XMIT_MORE_COLLISIONS,
    OID_802_3_XMIT_DEFERRED,
    OID_802_3_XMIT_MAX_COLLISIONS,
    OID_802_3_RCV_OVERRUN,
    OID_802_3_XMIT_UNDERRUN,
    OID_802_3_XMIT_HEARTBEAT_FAILURE,
    OID_802_3_XMIT_TIMES_CRS_LOST,
    OID_802_3_XMIT_LATE_COLLISIONS,
    OID_PNP_CAPABILITIES,
    OID_PNP_SET_POWER,
    OID_PNP_QUERY_POWER,
    OID_PNP_ADD_WAKE_UP_PATTERN,
    OID_PNP_REMOVE_WAKE_UP_PATTERN,
    OID_PNP_ENABLE_WAKE_UP,
	OID_CUSTOM_VIRTUAL_HOSTS
};

static const NDIS_GUID GuidList[1] =
{
	{
        IPIPNIC_VirtualHostsGuid,
        OID_CUSTOM_VIRTUAL_HOSTS,
        sizeof(UCHAR),
        fNDIS_GUID_TO_OID | fNDIS_GUID_ARRAY
	}
};


//
// Some global NDIS handles:
//
NDIS_HANDLE        MiniportDriverHandle = NULL;     // From NdisMRegisterMiniportDriver


NTSTATUS
DriverEntry(
    IN    PDRIVER_OBJECT        DriverObject,
    IN    PUNICODE_STRING       RegistryPath
    )
/*++

Routine Description:

    First entry point to be called, when this driver is loaded.
    Register with NDIS as an intermediate driver.

Arguments:

    DriverObject - pointer to the system's driver object structure
        for this driver
    
    RegistryPath - system's registry path for this driver
    
Return Value:

    STATUS_SUCCESS if all initialization is successful, STATUS_XXX
    error code if not.

--*/
{
    NDIS_STATUS                     Status;
    NDIS_MINIPORT_DRIVER_CHARACTERISTICS   MChars;
    NDIS_STRING                     Name;

	DBG_INIT("Init\n");

    //
    // Register the miniport with NDIS.
    //
    NdisZeroMemory(&MChars, sizeof(NDIS_MINIPORT_DRIVER_CHARACTERISTICS));

    MChars.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    MChars.Header.Size = sizeof(NDIS_MINIPORT_DRIVER_CHARACTERISTICS);
    MChars.Header.Revision = NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_1;
    
    MChars.MajorNdisVersion = VNIC_MAJOR_NDIS_VERSION;
    MChars.MinorNdisVersion = VNIC_MINOR_NDIS_VERSION;

    MChars.MajorDriverVersion = MAJOR_DRIVER_VERSION;
    MChars.MinorDriverVersion = MINOR_DRIVER_VERSION;

    MChars.SetOptionsHandler = MpSetOptions;
    MChars.InitializeHandlerEx = MPInitialize;
    MChars.UnloadHandler = MPUnload;
    MChars.HaltHandlerEx = MPHalt;

    MChars.OidRequestHandler = MPOidRequest;

    MChars.CancelSendHandler = MPCancelSendNetBufferLists;
    MChars.DevicePnPEventNotifyHandler = MPDevicePnPEvent;
    MChars.ShutdownHandlerEx = MPAdapterShutdown;
    MChars.CancelOidRequestHandler =  MPCancelOidRequest;

    //
    // We will disable the check for hang timeout so we do not
    // need a check for hang handler!
    //
    MChars.CheckForHangHandlerEx = NULL;

    MChars.ReturnNetBufferListsHandler = MPReturnNetBufferLists;
    MChars.SendNetBufferListsHandler = MPSendNetBufferLists;

    MChars.PauseHandler = MPPause;
    MChars.RestartHandler = MPRestart;

    MChars.Flags = 0;

    Status = NdisMRegisterMiniportDriver(DriverObject,
                                         RegistryPath,
                                         NULL,
                                         &MChars,
                                         &MiniportDriverHandle);

    if (Status != NDIS_STATUS_SUCCESS)
	{
		DBG_FAIL(Status);
	}

	// IPIPNIC-specific
	Status = Transport_Register();

    if (Status != NDIS_STATUS_SUCCESS)
    {
	    NdisMDeregisterMiniportDriver(MiniportDriverHandle);
		DBG_FAIL(Status);
	}

    DBG_INIT("Driver registered successfully.\n");

    return Status;
}

NDIS_STATUS
MpSetOptions(
    IN  NDIS_HANDLE             NdisDriverHandle,
    IN  NDIS_HANDLE             DriverContext
    )
/*++

Routine Description:
    This routine registers the optional handlers for the MINIPORT driver
    with NDIS.
    
Arguments:

    NdisDriverHandle           Mux miniport driver handle
    DriverContext              Specifies a handle to a driver-allocated context area where the driver 
                               maintains state and configuration information

Return Value:


--*/
{
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(DriverContext);
    return Status;
}


NDIS_STATUS
MPInitialize(
    IN  NDIS_HANDLE                     MiniportAdapterHandle,
    IN  NDIS_HANDLE                     MiniportDriverContext,
    IN  PNDIS_MINIPORT_INIT_PARAMETERS  MiniportInitParameters
    )
/*++

Routine Description:

    This is the Miniport Initialize routine which gets called as a
    result of our call to NdisIMInitializeDeviceInstanceEx.
    The context parameter which we pass there is the VELan structure
    which we retrieve here.

Arguments:

    MiniportAdapterHandle       NDIS handle for this miniport
    MiniportDriverContext       Handle passed to NDIS when we registered the driver
    MiniportInitParameters      Miniport initialization parameters such
                                as our device context, resources, etc.

Return Value:

    NDIS_STATUS_SUCCESS unless something goes wrong

--*/
{
    PVNIC                           pVNIC;
    UINT                            i;
    NDIS_STATUS                     Status = NDIS_STATUS_FAILURE;
    NDIS_HANDLE                     ConfigurationHandle;
    PVOID                           NetworkAddress;
	PNDIS_CONFIGURATION_PARAMETER   pValue;
	NDIS_STRING                     strVirtualHosts = NDIS_STRING_CONST("VirtualHosts");


    NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES   RegistrationAttributes;
    NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES        GeneralAttributes;
    NDIS_CONFIGURATION_OBJECT                       ConfigObject;
	NDIS_PNP_CAPABILITIES                           PNPCapabilities;
    NET_BUFFER_LIST_POOL_PARAMETERS                 PoolParameters;


    UNREFERENCED_PARAMETER(MiniportDriverContext);

	DBG_INIT("MPInitialize\n");


    do
    {
        pVNIC = NDIS_ALLOCMEM(MiniportAdapterHandle, sizeof(VNIC));
        if (pVNIC == NULL)
        {
            Status = NDIS_STATUS_RESOURCES;
			DBG_FAIL(Status);
            break;
        }

        NdisZeroMemory(pVNIC, sizeof(VNIC));

        pVNIC->MiniportAdapterHandle = MiniportAdapterHandle;
		pVNIC->InterfaceIsRunning = FALSE;
		pVNIC->Lookahead = VNIC_DEFAULT_PACKET_LOOKAHEAD;
		pVNIC->PacketFilter = VNIC_DEFAULT_PACKET_FILTER;
		GenerateMacAddr(pVNIC->PermanentAddress);

		// IPIPNIC-specific
        ListActivate(MiniportAdapterHandle, &pVNIC->ArpEntriesList, 0);
        ListActivate(MiniportAdapterHandle, &pVNIC->HostsList, 0);
        ListActivate(MiniportAdapterHandle, &pVNIC->AddressesList, 0);
        ListActivate(MiniportAdapterHandle, &pVNIC->NBLList, 0);


        //
        // register this miniport with NDIS
        //

        NdisZeroMemory(&RegistrationAttributes, sizeof(NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES));
        NdisZeroMemory(&GeneralAttributes, sizeof(NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES));

        //
        // setting registration attributes
        //
        RegistrationAttributes.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES;
        RegistrationAttributes.Header.Revision = NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_1;
        RegistrationAttributes.Header.Size = sizeof(NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES);

        RegistrationAttributes.MiniportAdapterContext = (NDIS_HANDLE)pVNIC;


        RegistrationAttributes.AttributeFlags = NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND;

        RegistrationAttributes.CheckForHangTimeInSeconds = 0;
        RegistrationAttributes.InterfaceType = NdisInterfaceInternal;

        Status = NdisMSetMiniportAttributes(MiniportAdapterHandle,
                                            (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&RegistrationAttributes);

        

        if (Status != NDIS_STATUS_SUCCESS)
        {
			DBG_FAIL(Status);
            break;
        }
        

        //
        // Access configuration parameters for this miniport.
        //
        ConfigObject.Header.Type = NDIS_OBJECT_TYPE_CONFIGURATION_OBJECT;
        ConfigObject.Header.Revision = NDIS_CONFIGURATION_OBJECT_REVISION_1;
        ConfigObject.Header.Size = sizeof(NDIS_CONFIGURATION_OBJECT);
        ConfigObject.NdisHandle = MiniportAdapterHandle;
        ConfigObject.Flags = 0;

        Status = NdisOpenConfigurationEx(
                    &ConfigObject,
                    &ConfigurationHandle);

        if (Status != NDIS_STATUS_SUCCESS)
        {
			DBG_FAIL(Status);
            break;
        }


        NdisReadNetworkAddress(
            &Status,
            &NetworkAddress,
            &i,
            ConfigurationHandle);

        //
        // If there is a NetworkAddress override, use it 
        //
        if (((Status == NDIS_STATUS_SUCCESS) 
                && (i == ETH_LENGTH_OF_ADDRESS))
                && ((!ETH_IS_MULTICAST(NetworkAddress)) 
                && (ETH_IS_LOCALLY_ADMINISTERED (NetworkAddress))))
        {
            ETH_COPY_NETWORK_ADDRESS(pVNIC->CurrentAddress, NetworkAddress);
        }
        else
        {
            ETH_COPY_NETWORK_ADDRESS(pVNIC->CurrentAddress, pVNIC->PermanentAddress);
        }

		// IPIPNIC-specific
		// Read VirtualHosts

		NdisReadConfiguration(&Status, &pValue, ConfigurationHandle, &strVirtualHosts, NdisParameterBinary);
        
		if (Status == NDIS_STATUS_SUCCESS)
		{
			UpdateHosts(pVNIC, &pVNIC->HostsList, (PUCHAR)pValue->ParameterData.StringData.Buffer, pValue->ParameterData.StringData.Length);
		}
		else
		{
			DBG_INIT("No hosts defined\n");
		}

        //
        // ignore error reading the configuration
        //
        Status = NDIS_STATUS_SUCCESS;

		NdisCloseConfiguration(ConfigurationHandle);

		DBG_INIT("Network address is %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", (UINT)pVNIC->CurrentAddress[0], (UINT)pVNIC->CurrentAddress[1], (UINT)pVNIC->CurrentAddress[2], (UINT)pVNIC->CurrentAddress[3], (UINT)pVNIC->CurrentAddress[4], (UINT)pVNIC->CurrentAddress[5]);


        //
        // set up generic attributes
        //

        GeneralAttributes.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES;
        GeneralAttributes.Header.Revision = NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES_REVISION_1;
        GeneralAttributes.Header.Size = sizeof(NDIS_MINIPORT_ADAPTER_GENERAL_ATTRIBUTES);   

        GeneralAttributes.MediaType = NdisMedium802_3;
        GeneralAttributes.MtuSize = MAX_PACKET_SIZE;
        GeneralAttributes.MaxXmitLinkSpeed = NOMINAL_LINK_SPEED;
        GeneralAttributes.MaxRcvLinkSpeed = NOMINAL_LINK_SPEED;
        GeneralAttributes.XmitLinkSpeed = NOMINAL_LINK_SPEED;
        GeneralAttributes.RcvLinkSpeed = NOMINAL_LINK_SPEED;
        

        //
        // Miniport below has indicated some status indication
        //
        GeneralAttributes.MediaConnectState = MediaConnectStateConnected;
        GeneralAttributes.MediaDuplexState = MediaDuplexStateFull;
        
        
        GeneralAttributes.LookaheadSize = VNIC_DEFAULT_PACKET_LOOKAHEAD;
        GeneralAttributes.MaxMulticastListSize = 0;
        GeneralAttributes.MacAddressLength = ETH_LENGTH_OF_ADDRESS;
        
        GeneralAttributes.PhysicalMediumType = NdisPhysicalMediumUnspecified;
        GeneralAttributes.AccessType = NET_IF_ACCESS_BROADCAST;
        GeneralAttributes.DirectionType = NET_IF_DIRECTION_SENDRECEIVE;
        GeneralAttributes.ConnectionType = NET_IF_CONNECTION_DEDICATED;
        GeneralAttributes.IfType = IF_TYPE_ETHERNET_CSMACD;//IF_TYPE_TUNNEL;
        GeneralAttributes.IfConnectorPresent = FALSE;

        GeneralAttributes.RecvScaleCapabilities = NULL;
        
        GeneralAttributes.MacOptions = NDIS_MAC_OPTION_NO_LOOPBACK | NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA | NDIS_MAC_OPTION_TRANSFERS_NOT_PEND;

        GeneralAttributes.SupportedPacketFilters = VNIC_SUPPORTED_FILTERS;

        GeneralAttributes.SupportedStatistics = NDIS_STATISTICS_XMIT_OK_SUPPORTED |
                                                NDIS_STATISTICS_RCV_OK_SUPPORTED |
                                                NDIS_STATISTICS_TRANSMIT_QUEUE_LENGTH_SUPPORTED |
                                                NDIS_STATISTICS_GEN_STATISTICS_SUPPORTED;

        ETH_COPY_NETWORK_ADDRESS(&GeneralAttributes.CurrentMacAddress, pVNIC->CurrentAddress);

        ETH_COPY_NETWORK_ADDRESS(&GeneralAttributes.PermanentMacAddress, pVNIC->PermanentAddress);

        GeneralAttributes.PowerManagementCapabilities = &PNPCapabilities;
		NdisZeroMemory(&PNPCapabilities, sizeof(PNPCapabilities));

        GeneralAttributes.SupportedOidList = SupportedOids;
        GeneralAttributes.SupportedOidListLength = sizeof(SupportedOids);
                                                        
        Status = NdisMSetMiniportAttributes(MiniportAdapterHandle,
                                            (PNDIS_MINIPORT_ADAPTER_ATTRIBUTES)&GeneralAttributes);

		if (Status != NDIS_STATUS_SUCCESS)
		{
			DBG_FAIL(Status);
			break;
        }

        NdisZeroMemory(&PoolParameters, sizeof(NET_BUFFER_LIST_POOL_PARAMETERS));
        PoolParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        PoolParameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        PoolParameters.Header.Size = sizeof(PoolParameters);
        PoolParameters.ProtocolId = 0;
        PoolParameters.ContextSize = 0;
        PoolParameters.fAllocateNetBuffer = TRUE;
        PoolParameters.PoolTag = MEM_TAG;

        pVNIC->NBLPool = NdisAllocateNetBufferListPool(MiniportAdapterHandle, &PoolParameters);

        if (pVNIC->NBLPool == NULL)
        {
            Status = NDIS_STATUS_RESOURCES;
			DBG_FAIL(Status);
            break;
        }

    } while (FALSE);

    
    if (Status != NDIS_STATUS_SUCCESS && pVNIC != NULL)
    {
		// IPIPNIC-specific
		while (pVNIC->NBLList.Count)
		{
			FreeNBL(ListRemove(&pVNIC->NBLList, LIST_QUEUE));
		}
		if (pVNIC->NBLPool != NULL)
		{
			NdisFreeNetBufferListPool(pVNIC->NBLPool);
			pVNIC->NBLPool = NULL;
		}
        ListDeactivate(&pVNIC->ArpEntriesList, TRUE);
        ListDeactivate(&pVNIC->AddressesList, TRUE);
		UpdateHosts(pVNIC, &pVNIC->HostsList, NULL, 0);

		NDIS_FREEMEM(pVNIC);
    }

	DBG_INIT("MPInitialize complete\n");

    return Status;
}

NDIS_STATUS
MPQueryInformation(
    IN    PVNIC                     pVNIC,
    IN    PNDIS_OID_REQUEST         NdisRequest
    )
/*++

Routine Description:

    This function is called to handle the query request specified by NdisRequest
    All query requests are first handled right here, since this is a virtual
    device (not pass-through).

Arguments:

    MiniportAdapterContext      Pointer to the adapter structure
    NdisRequest                 Specify the query request.

Return Value:

    NDIS_STATUS_SUCCESS         
    NDIS_STATUS_NOT_SUPPORTED
    Return code from the MPForwardOidRequest below.

--*/
{
    NDIS_STATUS                 Status = NDIS_STATUS_SUCCESS;
    NDIS_HARDWARE_STATUS        HardwareStatus = NdisHardwareStatusReady;
    NDIS_MEDIUM                 Medium = NdisMedium802_3;
    UCHAR                       VendorDesc[] = PRODUCT_STRING;
    ULONG                       ulInfo;
    ULONG64                     ulInfo64;
    USHORT                      usInfo;
    PVOID                       pInfo = (PVOID) &ulInfo;
    ULONG                       ulInfoLen = sizeof(ulInfo), NeededLength = 0;
	BOOLEAN                     bStatsOid = FALSE;

    NDIS_OID                    Oid;
    PVOID                       InformationBuffer;
    ULONG                       InformationBufferLength;
    PULONG                      BytesWritten;
    PULONG                      BytesNeeded;
    NDIS_STATISTICS_INFO        StatisticsInfo;
	NDIS_PNP_CAPABILITIES       PNPCapabilities;


    Oid = NdisRequest->DATA.QUERY_INFORMATION.Oid;
    InformationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
    InformationBufferLength = NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength;
    BytesWritten = &(NdisRequest->DATA.QUERY_INFORMATION.BytesWritten);
    BytesNeeded = &(NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded);
    
    // Initialize the result
    *BytesWritten = 0;
    *BytesNeeded = 0;

    switch (Oid)
	{
        case OID_GEN_XMIT_OK:
        case OID_GEN_RCV_OK:
		case OID_GEN_STATISTICS:
		case OID_IP4_OFFLOAD_STATS:
		case OID_IP6_OFFLOAD_STATS:
			bStatsOid = TRUE;
			break;
	}
	if (!bStatsOid)
		DBG_INIT("MPQueryInformation: %x\n", Oid);
	else
		DBG_STAT("MPQueryInformation: %x\n", Oid);

    switch (Oid)
    {
        case OID_GEN_SUPPORTED_LIST:
            pInfo = (PVOID)SupportedOids;
            ulInfoLen = sizeof(SupportedOids);
            break;

        case OID_GEN_SUPPORTED_GUIDS:
            pInfo = (PUCHAR)&GuidList;
            ulInfoLen = sizeof(GuidList);
            break;

        case OID_GEN_HARDWARE_STATUS:
            pInfo = (PVOID) &HardwareStatus;
            ulInfoLen = sizeof(NDIS_HARDWARE_STATUS);
            break;

        case OID_GEN_MEDIA_SUPPORTED:
        case OID_GEN_MEDIA_IN_USE:
            pInfo = (PVOID) &Medium;
            ulInfoLen = sizeof(NDIS_MEDIUM);
            break;

        case OID_GEN_CURRENT_LOOKAHEAD:
            ulInfo = pVNIC->Lookahead;
            break;

		case OID_GEN_MAXIMUM_LOOKAHEAD:
            ulInfo = MAX_PACKET_SIZE;
            break;
            
        case OID_GEN_MAXIMUM_FRAME_SIZE:
            ulInfo = MAX_PACKET_SIZE;

            break;

        case OID_GEN_MAXIMUM_TOTAL_SIZE:
        case OID_GEN_TRANSMIT_BLOCK_SIZE:
        case OID_GEN_RECEIVE_BLOCK_SIZE:
            ulInfo = MAX_PACKET_SIZE + ETH_HEADER_SIZE;
            break;
            
        case OID_GEN_MAC_OPTIONS:
            ulInfo = NDIS_MAC_OPTION_COPY_LOOKAHEAD_DATA | 
                     NDIS_MAC_OPTION_TRANSFERS_NOT_PEND |
                     NDIS_MAC_OPTION_NO_LOOPBACK;

            break;

        case OID_GEN_LINK_SPEED:
            ulInfo = NOMINAL_LINK_SPEED/100;
            break;

        case OID_GEN_TRANSMIT_BUFFER_SPACE:
            ulInfo = MAX_PACKET_SIZE*10;
            break;

        case OID_GEN_RECEIVE_BUFFER_SPACE:
            ulInfo = MAX_PACKET_SIZE*10;
            break;

        case OID_GEN_VENDOR_ID:
            ulInfo = 0xFFFFFF;
            break;

        case OID_GEN_VENDOR_DESCRIPTION:
            pInfo = VendorDesc;
            ulInfoLen = sizeof(VendorDesc);
            break;
            
        case OID_GEN_VENDOR_DRIVER_VERSION:
            ulInfo = (MAJOR_DRIVER_VERSION << 16) + MINOR_DRIVER_VERSION;
            break;

        case OID_802_3_PERMANENT_ADDRESS:
            pInfo = pVNIC->PermanentAddress;
            ulInfoLen = ETH_LENGTH_OF_ADDRESS;
            break;

        case OID_802_3_CURRENT_ADDRESS:
            pInfo = pVNIC->CurrentAddress;
            ulInfoLen = ETH_LENGTH_OF_ADDRESS;
            break;

        case OID_802_3_MAXIMUM_LIST_SIZE:
            ulInfo = 0;
            break;

        case OID_GEN_MAXIMUM_SEND_PACKETS:
            ulInfo = 10;
            break;

        case OID_GEN_MEDIA_CONNECT_STATUS:
            ulInfo = NdisMediaStateConnected;
            break;

        case OID_PNP_QUERY_POWER:
            // simply succeed this.
            ulInfoLen = sizeof(ULONG);
            break;

        case OID_PNP_CAPABILITIES:
			pInfo = (PVOID)&PNPCapabilities;
			ulInfoLen = sizeof(PNPCapabilities);
			NdisZeroMemory(pInfo, ulInfoLen);
            break;

        case OID_GEN_XMIT_OK:
            ulInfo64 = pVNIC->StatsSendsCompleted;
            pInfo = &ulInfo64;
            if (InformationBufferLength >= sizeof(ULONG64) ||
                InformationBufferLength == 0)
            {
                ulInfoLen = sizeof(ULONG64);
            }
            else
            {
                ulInfoLen = sizeof(ULONG);
            }
            NeededLength = sizeof(ulInfo64);

            break;
    
        case OID_GEN_RCV_OK:
            ulInfo64 = pVNIC->StatsReceivesCompleted;
            pInfo = &ulInfo64;
            if (InformationBufferLength >= sizeof(ULONG64) ||
                InformationBufferLength == 0)
            {
                ulInfoLen = sizeof(ULONG64);
            }
            else
            {
                ulInfoLen = sizeof(ULONG);
            }

            NeededLength = sizeof(ulInfo64);
            
            break;
    
        case OID_GEN_TRANSMIT_QUEUE_LENGTH:
            ulInfo = pVNIC->StatsSendsQueued;
            break;
        
        case OID_GEN_STATISTICS:
            ulInfoLen = sizeof (NDIS_STATISTICS_INFO);
            NdisZeroMemory(&StatisticsInfo, sizeof(NDIS_STATISTICS_INFO));

            StatisticsInfo.Header.Revision = NDIS_OBJECT_REVISION_1;
            StatisticsInfo.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
            StatisticsInfo.Header.Size = sizeof(NDIS_STATISTICS_INFO);
            StatisticsInfo.SupportedStatistics = NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_RCV |
                                                 NDIS_STATISTICS_FLAGS_VALID_DIRECTED_FRAMES_XMIT |
                                                 NDIS_STATISTICS_FLAGS_VALID_XMIT_ERROR |
												 NDIS_STATISTICS_FLAGS_VALID_BYTES_RCV |
												 NDIS_STATISTICS_FLAGS_VALID_BYTES_XMIT;

			StatisticsInfo.ifHCInUcastPkts = pVNIC->StatsReceivesCompleted;
			StatisticsInfo.ifHCOutUcastPkts = pVNIC->StatsSendsCompleted;
            StatisticsInfo.ifOutErrors = pVNIC->StatsSendsFailed;
            StatisticsInfo.ifHCInOctets = pVNIC->StatsBytesReceived;
            StatisticsInfo.ifHCOutOctets = pVNIC->StatsBytesSent;


            pInfo = &StatisticsInfo;
            break;

        case OID_802_3_RCV_ERROR_ALIGNMENT:
            ulInfo = 0;
            break;
    
        case OID_802_3_XMIT_ONE_COLLISION:
        	ulInfo = 0;
            break;
    
        case OID_802_3_XMIT_MORE_COLLISIONS:
        	ulInfo = 0;
            break;

        case OID_802_3_XMIT_DEFERRED:
        	ulInfo = 0;
            break;
    
        case OID_802_3_XMIT_MAX_COLLISIONS:
            ulInfo = 0;
            break;
    
        case OID_802_3_RCV_OVERRUN:
            ulInfo = 0;
            break;
    
        case OID_802_3_XMIT_UNDERRUN:
            ulInfo = 0;
            break;
    
        case OID_802_3_XMIT_HEARTBEAT_FAILURE:
            ulInfo = 0;
            break;
    
        case OID_802_3_XMIT_TIMES_CRS_LOST:
            ulInfo = 0;
            break;
    
        case OID_802_3_XMIT_LATE_COLLISIONS:
            ulInfo = 0;
            break;

		case OID_CUSTOM_VIRTUAL_HOSTS:
			ulInfoLen = 0;
			break;

        default:
            Status = NDIS_STATUS_NOT_SUPPORTED;
			if (!bStatsOid)
			    DBG_INIT("MPQueryInformation, OID not supported\n");
			else
			    DBG_STAT("MPQueryInformation, OID not supported\n");
            break;
    }

    if (Status == NDIS_STATUS_SUCCESS)
    {
        if (ulInfoLen <= InformationBufferLength)
        {
            // Copy result into InformationBuffer
            *BytesWritten = ulInfoLen;
            if(ulInfoLen)
            {
                NdisMoveMemory(InformationBuffer, pInfo, ulInfoLen);
                
                if (NeededLength > ulInfoLen)
                {
                    *BytesNeeded = NeededLength;
                }
            }

        }
        else
        {
            // too short
            *BytesNeeded = (NeededLength > ulInfoLen ? NeededLength : ulInfoLen);
            Status = NDIS_STATUS_BUFFER_TOO_SHORT;
        }
    }

    return Status;

}


NDIS_STATUS
MPSetInformation(
    IN    PVNIC                     pVNIC,
    IN    PNDIS_OID_REQUEST         NdisRequest
    )
/*++

Routine Description:

    This is the handler for an set request operation. Relevant
    requests are forwarded down to the lower miniport for handling.

Arguments:

    MiniportAdapterContext      Pointer to the adapter structure
    NdisRequest                 Specify the set request

Return Value:

    NDIS_STATUS_SUCCESS
    NDIS_STATUS_NOT_SUPPORTED
    NDIS_STATUS_INVALID_LENGTH
    Return code from the MPForwardOidRequest below.

--*/
{
    NDIS_STATUS             Status = NDIS_STATUS_SUCCESS;
    ULONG                   PacketFilter;
    NDIS_DEVICE_POWER_STATE NewDeviceState;

    NDIS_OID                Oid;
    PVOID                   InformationBuffer;
    ULONG                   InformationBufferLength;
    PULONG                  BytesRead;
    PULONG                  BytesNeeded;
    
    DBG_INIT("MPSetInformation: %x\n", NdisRequest->DATA.SET_INFORMATION.Oid);
    
    Oid = NdisRequest->DATA.SET_INFORMATION.Oid;
    InformationBuffer = NdisRequest->DATA.SET_INFORMATION.InformationBuffer;
    InformationBufferLength = NdisRequest->DATA.SET_INFORMATION.InformationBufferLength;
    BytesRead = &(NdisRequest->DATA.SET_INFORMATION.BytesRead);
    BytesNeeded = &(NdisRequest->DATA.SET_INFORMATION.BytesNeeded);

    *BytesRead = 0;
    *BytesNeeded = 0;

    switch (Oid)
    {
        //
        // Let the miniport below handle these OIDs:
        //
        case OID_PNP_ADD_WAKE_UP_PATTERN:
        case OID_PNP_REMOVE_WAKE_UP_PATTERN:
        case OID_PNP_ENABLE_WAKE_UP:
            break;

        case OID_PNP_SET_POWER:
            //
            // Store new power state and succeed the request.
            //
            *BytesNeeded = sizeof(NDIS_DEVICE_POWER_STATE);
            if (InformationBufferLength < *BytesNeeded)
            {
                Status = NDIS_STATUS_INVALID_LENGTH;
                break;
            }
           
            NewDeviceState = (*(PNDIS_DEVICE_POWER_STATE)InformationBuffer);

            if (NewDeviceState == NdisDeviceStateD0)
            {
				DBG_INIT("D0\n");
            }
            else
            {
				DBG_INIT("Dx\n");
            }
            break;

        case OID_802_3_MULTICAST_LIST:
			DBG_INIT("Set multicast list: %d\n", InformationBufferLength/6);
            break;

        case OID_GEN_CURRENT_PACKET_FILTER:
            if (InformationBufferLength != sizeof(ULONG))
            {
                Status = NDIS_STATUS_INVALID_LENGTH;
                *BytesNeeded = sizeof(ULONG);
                break;
            }
            pVNIC->PacketFilter = *(ULONG *)InformationBuffer;
			DBG_INIT("New packet filter: %d\n", pVNIC->PacketFilter);
            break;

        case OID_GEN_CURRENT_LOOKAHEAD:
            if (InformationBufferLength < sizeof(ULONG))
            {
                Status = NDIS_STATUS_INVALID_LENGTH;
                *BytesNeeded = sizeof(ULONG);
                break;
            }
			pVNIC->Lookahead = *(ULONG *)InformationBuffer;
            break;

		case OID_GEN_NETWORK_LAYER_ADDRESSES:
			pVNIC->PrimaryIP = UpdateAddresses(&pVNIC->AddressesList, ((PNETWORK_ADDRESS_LIST)InformationBuffer)->Address, ((PNETWORK_ADDRESS_LIST)InformationBuffer)->AddressCount);
            break;
            
		case OID_CUSTOM_VIRTUAL_HOSTS:
			UpdateHosts(pVNIC, &pVNIC->HostsList, InformationBuffer, InformationBufferLength);
			break;

        default:
            Status = NDIS_STATUS_NOT_SUPPORTED;
			DBG_INIT("Set OID ignored\n");
            break;

    }
    
    if (Status == NDIS_STATUS_SUCCESS)
    {
        *BytesRead = InformationBufferLength;
    }

    return Status;
}

NDIS_STATUS
MPMethodRequest(
    IN    PVNIC                   pVNIC,
    IN    PNDIS_OID_REQUEST       NdisRequest
    )
/*++
Routine Description:

    WMI method request handler

Arguments:

    MiniportAdapterContext          Pointer to the adapter structure
    NdisRequest                     Pointer to the request sent down by NDIS

Return Value:

    NDIS_STATUS_SUCCESS
    NDIS_STATUS_NOT_SUPPORTED
   

--*/
{
    NDIS_OID        Oid;
    ULONG           MethodId;
    PVOID           InformationBuffer;
    ULONG           InputBufferLength;
    ULONG           OutputBufferLength;
    ULONG           BytesNeeded;
    NDIS_STATUS     Status = NDIS_STATUS_SUCCESS;

    Oid = NdisRequest->DATA.METHOD_INFORMATION.Oid;
    InformationBuffer = (PVOID)(NdisRequest->DATA.METHOD_INFORMATION.InformationBuffer);
    InputBufferLength = NdisRequest->DATA.METHOD_INFORMATION.InputBufferLength;
    OutputBufferLength = NdisRequest->DATA.METHOD_INFORMATION.OutputBufferLength;
    MethodId = NdisRequest->DATA.METHOD_INFORMATION.MethodId;

    BytesNeeded = 0;

    switch(Oid)
    {
        default:
            Status = NDIS_STATUS_NOT_SUPPORTED;
            break;
    }

    return Status;
}



NDIS_STATUS
MPOidRequest(
    IN    NDIS_HANDLE             MiniportAdapterContext,
    IN    PNDIS_OID_REQUEST       NdisRequest
    )
/*++
Routine Description:

    MiniportRequest dispatch handler

Arguments:

    MiniportAdapterContext      Pointer to the adapter structure
    NdisRequest                 Pointer to NDIS_OID_REQUEST sent down by NDIS.

Return Value:

    NDIS_STATUS_SUCCESS
    NDIS_STATUS_NOT_SUPPORTED
    NDIS_STATUS_XXX

--*/
{
	PVNIC                   pVNIC = (PVNIC)MiniportAdapterContext;
    NDIS_REQUEST_TYPE       RequestType;
    NDIS_STATUS             Status;

    RequestType = NdisRequest->RequestType;

    switch(RequestType)
    {
        case NdisRequestMethod:
            Status = MPMethodRequest(pVNIC, NdisRequest);
            break;

        case NdisRequestSetInformation:
            Status = MPSetInformation(pVNIC, NdisRequest);
            break;

        case NdisRequestQueryInformation:
        case NdisRequestQueryStatistics:
            Status = MPQueryInformation(pVNIC, NdisRequest);
            break;

        default:
            Status = NDIS_STATUS_NOT_SUPPORTED;
            break;
    }

    return Status;
}



VOID
MPHalt(
    IN    NDIS_HANDLE                MiniportAdapterContext,
    IN    NDIS_HALT_ACTION           HaltAction
    )
/*++

Routine Description:

    Halt handler. Add any further clean-up for the VELAN to this
    function.

    We wait for all pending I/O on the VELAN to complete and then
    unlink the VELAN from the adapter.

Arguments:

    MiniportAdapterContext    Pointer to the pVElan
    HaltAction                The reason adapter is being halted 

Return Value:

    None.

--*/
{
	PVNIC             pVNIC = (PVNIC)MiniportAdapterContext;

    UNREFERENCED_PARAMETER(HaltAction);
    

	DBG_INIT("MPHalt\n");
/*
    //
    // Update the packet filter on the underlying adapter if needed.
    //
    if (pVElan->PacketFilter != 0)
    {
        MPSetPacketFilter(pVElan, 0);
    }

    //
    // Wait for any outstanding sends or requests to complete.
    //
    while (pVElan->OutstandingSends)
    {
        DBGPRINT(MUX_INFO, ("MPHalt: VELAN %p has %d outstanding sends\n",
                            pVElan, pVElan->OutstandingSends));
        NdisMSleep(20000);
    }

    //
    // Wait for all outstanding indications to be completed and
    // any pended receive packets to be returned to us.
    //
    while (pVElan->OutstandingReceives)
    {
        DBGPRINT(MUX_INFO, ("MPHalt: VELAN %p has %d outstanding receives\n",
                            pVElan, pVElan->OutstandingReceives));
        NdisMSleep(20000);
    }
*/


	// IPIPNIC-specific
	DBG_INIT("Sends: %d/%d/%d, receives: %d\n", pVNIC->StatsSendsFailed, pVNIC->StatsSendsQueued, pVNIC->StatsSendsCompleted, pVNIC->StatsReceivesCompleted);
	UpdateHosts(pVNIC, &pVNIC->HostsList, NULL, 0);
	while (pVNIC->NBLList.Count)
	{
		FreeNBL(ListRemove(&pVNIC->NBLList, LIST_QUEUE));
	}
	if (pVNIC->NBLPool != NULL)
	{
		NdisFreeNetBufferListPool(pVNIC->NBLPool);
		pVNIC->NBLPool = NULL;
	}
    ListDeactivate(&pVNIC->ArpEntriesList, TRUE);
    ListDeactivate(&pVNIC->AddressesList, TRUE);

	NDIS_FREEMEM(pVNIC);
}

VOID
MPDevicePnPEvent(
    IN NDIS_HANDLE              MiniportAdapterContext,
    IN PNET_DEVICE_PNP_EVENT    NetDevicePnPEvent
    )
/*++

Routine Description:

    This handler is called to notify us of PnP events directed to
    our miniport device object.

Arguments:

    MiniportAdapterContext - pointer to VELAN structure
    DevicePnPEvent - the event
    InformationBuffer - Points to additional event-specific information
    InformationBufferLength - length of above

Return Value:

    None
--*/
{

	UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(NetDevicePnPEvent);

}

VOID
MPAdapterShutdown(
    IN NDIS_HANDLE              MiniportAdapterContext,
    IN NDIS_SHUTDOWN_ACTION     ShutdownAction
    )
/*++

Routine Description:

    This handler is called to notify us of an impending system shutdown.
    Since this is not a hardware driver, there isn't anything specific
    we need to do about this.

Arguments:

    MiniportAdapterContext     pointer to VELAN structure
    ShutdownAction             Specify the reason to shut down the adapter

Return Value:

    None
--*/
{
	PVNIC             pVNIC = (PVNIC)MiniportAdapterContext;

    UNREFERENCED_PARAMETER(pVNIC);
    UNREFERENCED_PARAMETER(ShutdownAction);

    return;
}


VOID
MPUnload(
    IN    PDRIVER_OBJECT        DriverObject
    )
/*++

Routine Description:
    This handler is used to unload the miniport

Arguments:
    DriverObject            Pointer to the system's driver object structure 
                            for this driver.

Return Value:
    None


--*/
{
        
    UNREFERENCED_PARAMETER(DriverObject);

	// IPIPNIC-specific
	Transport_Deregister();

	NdisMDeregisterMiniportDriver(MiniportDriverHandle);

	DBG_INIT("Unload\n");
}

NDIS_STATUS
MPPause(
    IN  NDIS_HANDLE     MiniportAdapterContext,
    IN  PNDIS_MINIPORT_PAUSE_PARAMETERS  MiniportPauseParameters
    )
/*++

Routine Description:
    This handler is used to pause the miniport. During which, no NET_BUFFER_LIST
    will be indicated to the upper binding as well as status indications.

Arguments:
    MiniportAdapterContext      Pointer to our VELAN
    MiniportPauseParameters     Specify the pause parameters

Return Value:
    NDIS_STATUS_SUCCESS

--*/
{
	PVNIC              pVNIC = (PVNIC)MiniportAdapterContext;
    NDIS_STATUS        Status = NDIS_STATUS_SUCCESS;

	DBG_INIT("MPPause\n");
    
    UNREFERENCED_PARAMETER(MiniportPauseParameters);

	pVNIC->InterfaceIsRunning = FALSE;

    return Status;
}


NDIS_STATUS
MPRestart(
    IN  NDIS_HANDLE     MiniportAdapterContext,
    IN  PNDIS_MINIPORT_RESTART_PARAMETERS  MiniportRestartParameters
    )
/*++

Routine Description:
    This handler is used to restart the miniport.  When the miniport is
    back in the restart state, it can indicate NET_BUFFER_LISTs to the
    upper binding

Arguments:
    MiniportAdapterContext      Pointer to our VELAN
    MiniportRestartParameters

Return Value:
    NDIS_STATUS_SUCCESS

--*/
{
	PVNIC                             pVNIC = (PVNIC)MiniportAdapterContext;
    NDIS_STATUS                       Status = NDIS_STATUS_SUCCESS;
    PNDIS_RESTART_ATTRIBUTES          NdisRestartAttributes;
    PNDIS_RESTART_GENERAL_ATTRIBUTES  NdisGeneralAttributes;
    
    UNREFERENCED_PARAMETER(MiniportRestartParameters);

	DBG_INIT("MPRestart\n");

     
    //
    // Here the driver can change its restart attributes 
    //
    NdisRestartAttributes = MiniportRestartParameters->RestartAttributes;

    //
    // If NdisRestartAttributes is not NULL, then miniport can modify generic attributes and add
    // new media specific info attributes at the end. Otherwise, NDIS restarts the miniport because 
    // of other reason, miniport should not try to modify/add attributes
    //
    if (NdisRestartAttributes != NULL)
    {

        ASSERT(NdisRestartAttributes->Oid == OID_GEN_MINIPORT_RESTART_ATTRIBUTES);
    
        NdisGeneralAttributes = (PNDIS_RESTART_GENERAL_ATTRIBUTES)NdisRestartAttributes->Data;
    
        //
        // Check to see if we need to change any attributes, for example, the driver can change the current
        // MAC address here. Or the driver can add media specific info attributes.
        //
    }
   
	pVNIC->InterfaceIsRunning = TRUE;

    return Status;
}


VOID 
MPCancelSendNetBufferLists(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN PVOID       CancelId
    )
/*++

Routine Description:

    The miniport entry point to hanadle cancellation of all send packets that
    match the given CancelId. If we have queued any packets that match this,
    then we should dequeue them and call NdisMSendCompleteNetBufferLists for
    all such packets, with a status of NDIS_STATUS_REQUEST_ABORTED.

    We should also call NdisCancelSendPackets in turn, on each lower binding
    that this adapter corresponds to. This is to let miniports below cancel
    any matching packets.

Arguments:

    MiniportAdapterContext          Pointer to VELAN structure
    CancelID                        ID of NetBufferLists to be cancelled

Return Value:
    None

--*/
{
	PVNIC                   pVNIC = (PVNIC)MiniportAdapterContext;

/*
    DBGPRINT(MUX_LOUD,("==> MPCancelSendNetBufferLists: VElan %p, CancelId %p\n", pVElan, CancelId));
    
    NdisCancelSendNetBufferLists(pVElan->pAdapt->BindingHandle,CancelId);
    
    DBGPRINT(MUX_LOUD,("<== MPCancelSendNetBufferLists: VElan %p, CancelId %p\n", pVElan, CancelId));
*/
}

VOID 
MPCancelOidRequest(
    IN NDIS_HANDLE MiniportAdapterContext,
    IN PVOID       RequestId
    )
/*++

Routine Description:

    The miniport entry point to hanadle cancellation of a request. This function 
    checks to see if the CancelRequest should be terminated at this level
    or passed down to the next driver. 

Arguments:

    MiniportAdapterContext          Pointer to VELAN structure
    RequestId                       RequestId to be cancelled

Return Value:
    None

--*/
{
/*    PVELAN                      pVElan = (PVELAN)MiniportAdapterContext;
    PMUX_NDIS_REQUEST           pMuxNdisRequest = &pVElan->Request;
    BOOLEAN                     fCancelRequest = FALSE;
    
    DBGPRINT(MUX_LOUD, ("==> MPCancelOidRequest: VELAN %p, RequestId %x\n", pVElan, RequestId));
        
    NdisAcquireSpinLock(&pVElan->Lock);
    if (pMuxNdisRequest->OrigRequest != NULL)
    {
        if (pMuxNdisRequest->OrigRequest->RequestId == RequestId)
        {
            pMuxNdisRequest->Cancelled = TRUE;
            fCancelRequest = TRUE;
            pMuxNdisRequest->Refcount++;
        }

    }
    
    NdisReleaseSpinLock(&pVElan->Lock);    

    //
    // If we find the request, just send down the cancel, otherwise return because there is only 
    // one request pending from upper layer on the miniport
    //
    if (fCancelRequest)
    {
        NdisCancelOidRequest(pVElan->pAdapt->BindingHandle, &pMuxNdisRequest->Request);

        PtCompleteForwardedRequest(pVElan->pAdapt, 
                                    pMuxNdisRequest, 
                                    NDIS_STATUS_REQUEST_ABORTED);
    }
   
    DBGPRINT(MUX_LOUD, ("<== MPCancelOidRequest: VELAN %p, RequestId %x\n", pVElan, RequestId));
*/
}
