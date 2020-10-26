#include "precomp.h"

UCHAR GetByte(PMDL Mdl, ULONG Offset)
{
	PMDL cur = Mdl;
	while (cur && Offset >= MmGetMdlByteCount(cur))
	{
		Offset -= MmGetMdlByteCount(cur);
		cur = cur->Next;
	}
	if (!cur)
		return 0;
	return ((PUCHAR)MmGetSystemAddressForMdlSafe(cur, NormalPagePriority))[Offset];
}

PVOID GetData(PMDL Mdl, ULONG Offset, ULONG Count, PVOID Buffer)
{
	ULONG total = 0;
	PMDL cur = Mdl;
	while (cur && Offset >= MmGetMdlByteCount(cur))
	{
		Offset -= MmGetMdlByteCount(cur);
		cur = cur->Next;
	}
	if (!cur)
		return NULL;
	if (Offset + Count <= MmGetMdlByteCount(cur))
		return (PUCHAR)MmGetSystemAddressForMdlSafe(cur, NormalPagePriority) + Offset;
	while (cur && Count > total)
	{
		ULONG toCopy = MmGetMdlByteCount(cur) - Offset;
		if (toCopy > Count - total)
			toCopy = Count - total;
		RtlMoveMemory((PUCHAR)Buffer + total, (PUCHAR)MmGetSystemAddressForMdlSafe(cur, NormalPagePriority) + Offset, toCopy);
		Offset = 0;
		total += toCopy;
		cur = cur->Next;
	}
	if (!cur)
		return NULL;
	return Buffer;
}

VOID SetData(PMDL Mdl, ULONG Offset, PVOID Buffer, ULONG Count)
{
	ULONG total = 0;
	PMDL cur = Mdl;
	while (cur && Offset >= MmGetMdlByteCount(cur))
	{
		Offset -= MmGetMdlByteCount(cur);
		cur = cur->Next;
	}
	if (!cur)
		return;
	if (Offset + Count <= MmGetMdlByteCount(cur))
	{
		RtlMoveMemory((PUCHAR)MmGetSystemAddressForMdlSafe(cur, NormalPagePriority) + Offset, Buffer, Count);
		return;
	}
	while (cur && Count > total)
	{
		ULONG toCopy = MmGetMdlByteCount(cur) - Offset;
		if (toCopy > Count - total)
			toCopy = Count - total;
		RtlMoveMemory((PUCHAR)MmGetSystemAddressForMdlSafe(cur, NormalPagePriority) + Offset, (PUCHAR)Buffer + total, toCopy);
		Offset = 0;
		total += toCopy;
		cur = cur->Next;
	}
	if (!cur)
		return;
}
