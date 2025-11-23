

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include "btc/clist.h"
#include "btc/net.h"

typedef struct
{  
  int count;          /* Number of items in the list. */  
  int alloc_size;     /* Allocated size in quantity of items */  
  size_t item_size;   /* Size of each item in bytes. */  
  void *items;        /* Pointer to the list */  
} CList_priv_;  



CList *CList_Init(size_t objSize)
{
  CList *lst = (CList *)ps_malloc(sizeof(CList));
  CList_priv_ *p = (CList_priv_ *)ps_malloc(sizeof(CList_priv_));
  if (!lst || !p)
  {
    DBGMSG("CList: ERROR! Can not allocate CList!\n");
    return NULL;
  }
  p->count = 0;
  p->alloc_size = 0;
  p->item_size = objSize;
  p->items = NULL;
  lst->add = &CList_Add_;
  lst->insert = &CList_Insert_;
  lst->replace = &CList_Replace_;
  lst->remove = &CList_Remove_;
  lst->at = &CList_At_;
  lst->realloc = &CList_Realloc_; 
  lst->firstIndex = &CList_FirstIndexBySize_;
  lst->lastIndex = &CList_LastIndex_;
  lst->count = &CList_Count_;
  lst->clear = &CList_Clear_;
  lst->free = &CList_Free_;
  lst->print = &CList_print_;
  lst->priv = p;
  return lst;
}

void CList_Add_(CList *l, void *o)
{
  CList_priv_ *p = (CList_priv_*) l->priv;
  if (p->count == p->alloc_size && 
        CList_Realloc_(l, p->alloc_size * 2) == 0)
    return;
  
  uint8_t *data = (uint8_t*) p->items;
  data = data + p->count * p->item_size;
  memcpy(data, o, p->item_size);
  p->count++;
}

void CList_Insert_(CList *l, void *o, int n)
{
  CList_priv_ *p = (CList_priv_*) l->priv;
  if (n < 0 || n > p->count)
  {
    DBGMSG( "CList: ERROR! Insert position outside range - %d; n - %d.\n", 
                        p->count, n);
    assert(n >= 0 && n <= p->count);
    return;
  }

  if (p->count == p->alloc_size && 
        CList_Realloc_(l, p->alloc_size * 2) == 0)
    return;

  size_t step = p->item_size;
  uint8_t *data = (uint8_t*) p->items + n * step;
  memmove(data + step, data, (p->count - n) * step);
  memcpy(data, o, step);
  p->count++;
}

void CList_Replace_(CList *l, void *o, int n)
{
  CList_priv_ *p = (CList_priv_*) l->priv;
  if (n < 0 || n >= p->count)
  {
    DBGMSG( "CList: ERROR! Replace position outside range - %d; n - %d.\n", 
                        p->count, n);
    assert(n >= 0 && n < p->count);
    return;
  }

  uint8_t *data = (uint8_t*) p->items;
  data = data + n * p->item_size;
  memcpy(data, o, p->item_size);
}

void CList_Remove_(CList *l, int n)
{

  if (CList_Count_(l)==0)  return ;

  CList_priv_ *p = (CList_priv_*) l->priv;
  if (n < 0 || n >= p->count)
  {
    DBGMSG( "CList: ERROR! Remove position outside range - %d; n - %d.\n",
                        p->count, n);
    assert(n >= 0 && n < p->count);
    return;
  }

  size_t step = p->item_size;
  uint8_t *data = (uint8_t*)p->items + n * step;
  memmove(data, data + step, (p->count - n - 1) * step);
  p->count--;

  if (p->alloc_size > 3 * p->count && p->alloc_size >= 4) /* Dont hold much memory */
    CList_Realloc_(l, p->alloc_size / 2);
}

void *CList_At_(CList *l, int n)
{
  CList_priv_ *p = (CList_priv_*) l->priv;
  if (n < 0 || n >= p->count)
  {
   DBGMSG( "CList: ERROR! Get position outside range - %d; n - %d.\n", 
                      p->count, n);
    assert(n >= 0 && n < p->count);
    return NULL;
  }

  uint8_t *data = (uint8_t*) p->items;
  data = data + n * p->item_size;
  return data;
}

int CList_Realloc_(CList *l, int n)
{
  CList_priv_ *p = (CList_priv_*) l->priv;
  if (n < p->count)
  {
    DBGMSG( "CList: ERROR! Can not realloc to '%i' size - count is '%i'\n", n, p->count);
    assert(n >= p->count);
    return 0;
  }

  if (n == 0 && p->alloc_size == 0)
    n = 2;

  void *ptr = ps_realloc(p->items, p->item_size * n);
  if (ptr == NULL)
  {
   DBGMSG( "CList: ERROR! Can not reallocate memory!\n");
    return 0;
  }
  p->items = ptr;
  p->alloc_size = n;
  return 1;
}

int CList_FirstIndexBySize_(CList *l, void *o,int osize)
{ 
  CList_priv_ *p = (CList_priv_*) l->priv;    
  uint8_t *data = (uint8_t*) p->items;
  size_t step = p->item_size;
  size_t i = 0;
  int index = 0;
  for (; i < p->count * step; i += step, index++)
  {
    if (memcmp(data + i, o, (osize==0)?step:osize) == 0)
      return index;
  }
  return -1; 
}




int CList_LastIndex_(CList *l, void *o)
{
  CList_priv_ *p = (CList_priv_*) l->priv;
  uint8_t *data = (uint8_t*) p->items;
  size_t step = p->item_size;
  int i = p->count * step - step;
  int index = p->count - 1;
  for (; i >= 0 ; i -= step, index--)
  {
    if (memcmp(data + i, o, step) == 0)
      return index;
  }
  return -1;
}




int CList_Count_(CList *l)
{
  CList_priv_ *p = (CList_priv_*) l->priv;
  if (!p) return 0;
  return p->count;
}

void CList_Clear_(CList *l)
{
  CList_priv_ *p = (CList_priv_*) l->priv;
  RELEASE_PTR(p->items)
  p->alloc_size = 0;
  p->count = 0;
}




void CList_Free_(CList *l)
{
  CList_priv_ *p = (CList_priv_*) l->priv;
  RELEASE_PTR(p->items)
  RELEASE_PTR(p)
  RELEASE_PTR(l)
}




void CList_print_(CList *l)
{
	CList_priv_ *p = (CList_priv_ *)l->priv;
	DBGMSG("CList:  count = %i  item_size = %zu   "
		   "alloc_size = %i ",p->count, p->item_size, p->alloc_size);

	int n = p->count;
	uint8_t *data = NULL;
	int i = 0;
	for (; i < n; i++)
	{
		data = (uint8_t *)p->items + i * p->item_size;
      DBGMSG("[+]tx->%d",i);
	}
	
}


bool CList_compare_(CList *l,uint8_t *phash,int *index)
{
	CList_priv_ *p = (CList_priv_ *)l->priv;
	*index=-1;
	int n = p->count;
	uint8_t *data = NULL;
	int i = 0;
	for (; i < n; i++)
	{
		data = (uint8_t *)p->items + i * p->item_size;
		if (memcmp(data,phash,SHA256_DIGEST_LENGTH+4)==0){
			*index=i;
			return true;
		}
	}
	return false;
	
}