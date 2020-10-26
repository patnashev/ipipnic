#include "precomp.h"

PLISTROOT ListAlloc(NDIS_HANDLE NdisHandle, ULONG Limit)
{
	return ListActivate(NdisHandle, (PLISTROOT)NDIS_ALLOCMEM(NdisHandle, sizeof(LISTROOT)), Limit);
}

VOID ListFree(PLISTROOT Root, BOOLEAN bFreeMem)
{
	if (Root)
	{
		ListDeactivate(Root, bFreeMem);
		NDIS_FREEMEM((PVOID)Root);
	}
}

PLISTROOT ListActivate(NDIS_HANDLE NdisHandle, PLISTROOT Root, ULONG Limit)
{
	if (Root)
	{
		Root->First = Root->Last = NULL;
		Root->Limit = Limit;
		Root->Count = 0;
		NdisInitializeReadWriteLock(&Root->Lock);
		Root->NdisHandle = NdisHandle;
	}

	return Root;
}

VOID ListDeactivate(PLISTROOT Root, BOOLEAN bFreeMem)
{
	LISTITEM Item;

	if (Root)
	{
		while (Root->Count)
		{
			Item = ListRemove(Root, LIST_QUEUE);
			if (bFreeMem)
				NDIS_FREEMEM(Item);
		}
	}
}

LISTITEM ListAdd(PLISTROOT Root, LISTITEM Item)
{
	LOCK_STATE LockState;
	LISTITEM Return = NULL;
	PLISTNODE Node;

	ListLock(Root, TRUE, &LockState);
	if (Root && (!Root->Limit || Root->Count < Root->Limit))
	{
		Node = (PLISTNODE)NDIS_ALLOCMEM(Root->NdisHandle, sizeof(LISTNODE));
		if (Node)
		{
			if (Root->First)
			{
				Node->Item = Item;
				Node->Previous = Root->Last;
				Root->Last->Next = Node;
				Root->Last = Node;
				Root->Count++;
			}
			else
			{
				Node->Item = Item;
				Node->Next = Node->Previous = NULL;
				Root->First = Root->Last = Node;
				Root->Count = 1;
			}
			Return = Node->Item;
		}
	}
	ListUnlock(Root, &LockState);

	return Return;
}

LISTITEM ListRemove(PLISTROOT Root, LISTMODE Mode)
{
	LOCK_STATE LockState;
	LISTITEM Return = NULL;
	PLISTNODE Node;

	ListLock(Root, TRUE, &LockState);
	if (Root && Root->Count > 0)
	{
		Node = (Mode == LIST_QUEUE ? Root->First : Root->Last);
		if (Node->Next && Mode == LIST_QUEUE)
		{
			Root->First = Node->Next;
			Root->First->Previous = 0;
		}
		else if (Node->Previous && Mode == LIST_STACK)
		{
			Root->Last = Node->Previous;
			Root->Last->Next = 0;
		}
		else
			Root->First = Root->Last = NULL;

		Return = Node->Item;
		NDIS_FREEMEM((PVOID)Node);
		Root->Count--;
	}
	ListUnlock(Root, &LockState);

	return Return;
}

LISTITEM ListExtract(PLISTROOT Root, LISTITEM Item)
{
	LOCK_STATE LockState;
	LISTITEM Return = NULL;
	PLISTNODE Node = NULL;

	ListLock(Root, TRUE, &LockState);
	if (Root)
	{
		for (Node = Root->First; Node && Node->Item != Item; Node = Node->Next);
		if (Node)
		{
			if (Node->Previous)
				Node->Previous->Next = Node->Next;
			if (Node->Next)
				Node->Next->Previous = Node->Previous;
			if (Root->Last == Node)
				Root->Last = Node->Previous;
			if (Root->First == Node)
				Root->First = Node->Next;

			Return = Node->Item;
			NDIS_FREEMEM((PVOID)Node);
			Root->Count--;
		}
	}
	ListUnlock(Root, &LockState);

	return Return;
}

LISTITEM ListPeek(PLISTROOT Root, LISTMODE Mode)
{
	LOCK_STATE LockState;
	LISTITEM Return = NULL;

	ListLock(Root, FALSE, &LockState);
	if (Root && Root->Count > 0)
	{
		if (Root->First && Mode == LIST_QUEUE)
			Return = Root->First->Item;
		else if (Root->Last && Mode == LIST_STACK)
			Return = Root->Last->Item;
	}
	ListUnlock(Root, &LockState);

	return Return;
}

ULONG ListCount(PLISTROOT Root)
{
	LOCK_STATE LockState;
	ULONG Return = 0;

	ListLock(Root, FALSE, &LockState);
	if (Root)
		Return = Root->Count;
	ListUnlock(Root, &LockState);
	return Return;
}


VOID ListLock(PLISTROOT Root, BOOLEAN bWrite, PLOCK_STATE LockState)
{
	if (Root)
		NdisAcquireReadWriteLock(&Root->Lock, bWrite, LockState);
}

VOID ListUnlock(PLISTROOT Root, PLOCK_STATE LockState)
{
	if (Root)
		NdisReleaseReadWriteLock(&Root->Lock, LockState);
}
