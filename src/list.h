
typedef PVOID LISTITEM;

typedef enum 
{
    LIST_STACK,
    LIST_QUEUE
}
LISTMODE;

typedef struct _LISTNODE
{
	struct _LISTNODE *Next, *Previous;
	LISTITEM Item;
}
LISTNODE, *PLISTNODE;

typedef struct _LISTROOT
{
	ULONG Count, Limit;
	PLISTNODE First, Last;
	NDIS_RW_LOCK Lock;
	NDIS_HANDLE NdisHandle;
}
LISTROOT, *PLISTROOT;

/*****************************************************************************************/

PLISTROOT ListAlloc      (NDIS_HANDLE NdisHandle, ULONG Limit);
VOID      ListFree       (PLISTROOT Root, BOOLEAN bFreeMem);
PLISTROOT ListActivate   (NDIS_HANDLE NdisHandle, PLISTROOT Root, ULONG Limit);
VOID      ListDeactivate (PLISTROOT Root, BOOLEAN bFreeMem);
LISTITEM  ListAdd        (PLISTROOT Root, LISTITEM Item);
LISTITEM  ListExtract    (PLISTROOT Root, LISTITEM Item);
LISTITEM  ListRemove     (PLISTROOT Root, LISTMODE Mode);
LISTITEM  ListPeek       (PLISTROOT Root, LISTMODE Mode);
ULONG     ListCount      (PLISTROOT Root);
VOID      ListLock       (PLISTROOT Root, BOOLEAN bWrite, PLOCK_STATE LockState);
VOID      ListUnlock     (PLISTROOT Root, PLOCK_STATE LockState);

#define QueueNew        ListAlloc
#define QueueDelete     ListFree
#define QueuePush(a,b)  ListAdd (a,b)
#define QueuePop(a)     ListRemove (a, LIST_QUEUE)
#define QueuePeek(a)    ListPeek (a, LIST_QUEUE)
#define QueueCount(a)   ListCount (a)
#define QueueExtract    ListExtract

#define StackNew        ListAlloc
#define StackDelete     ListFree
#define StackPush(a,b)  ListAdd (a, b)
#define StackPop(a)     ListRemove (a, LIST_STACK)
#define StackPeek(a)    ListPeek (a, LIST_STACK)
#define StackCount(a)   ListCount (a)
#define StackExtract    ListExtract

#define Push(a,b)       QueuePush(a,b)
#define Pull(a)         QueuePop(a)
#define Pop(a)          StackPop(a)
#define Peek(a)         QueuePeek(a)
#define Count(a)        QueueCount(a)
#define Extract         ListExtract

