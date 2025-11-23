
#ifndef CLIST_H
#define CLIST_H

#ifdef __cplusplus
extern "C" {
#endif
#include <Arduino.h>

typedef struct CList
{
  void  (* add)        (struct CList *l, void *o);            /* Add object to the end of a list */
  void  (* insert)     (struct CList *l, void *o, int n);     /* Insert object at position 'n' */
  void  (* replace)    (struct CList *l, void *o, int n);     /* Replace object at position 'n' */
  void  (* remove)     (struct CList *l, int n);              /* Remove object at position 'n' */
  void* (* at)         (struct CList *l, int n);              /* Get object at position 'n' */
  int   (* realloc)    (struct CList *l, int n);              /* Reallocate list to 'size' items */
  int   (* firstIndex) (struct CList *l, void *o,int);        /* Get first index of the object */
  int   (* lastIndex)  (struct CList *l, void *o);            /* Get last index of the object */
  int   (* count)      (struct CList *l);                     /* Get list size */
  void  (* clear)      (struct CList *l);                     /* Clear list */
  void  (* free)       (struct CList *l);                     /* Destroy struct CList and all data */
  void  (* print)      (struct CList *l);  /* Print list data */
  void *priv;          /* NOT FOR USE, private data */
} CList;

void  CList_Add_(CList *l, void *o);
void  CList_Insert_(CList *l, void *o, int n);
void  CList_Replace_(CList *l, void *o, int n);
void  CList_Remove_(CList *l, int n);
void* CList_At_(CList *l, int n);
int   CList_Realloc_(CList *l, int n);
int   CList_FirstIndexBySize_(CList *, void *,int);

int   CList_LastIndex_(CList *l, void *o);
int   CList_Count_(CList *l);
void  CList_Clear_(CList *l);
void  CList_Free_(CList *l);
void  CList_print_(CList *l);
CList *CList_Init(size_t objSize); /* Set list object size in bytes */
bool CList_compare_(CList *l,uint8_t *phash,int *index);

#ifdef __cplusplus
}
#endif

#endif /* CLIST_H */