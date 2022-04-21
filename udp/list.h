#ifndef __LIST_H__
#define __LIST_H__

#define LL_ADD(item, list) do {  \
    item->prev = NULL;           \
    item->next = list;           \
    if (list) list->prev = item; \
    list = item;                 \
} while(0)

#define LL_REMOVE(item, list) do { \
    if (item->prev) item->prev->next = item->next;  \
    if (item->next) item->next->prev = item->prev;  \
    if (list == item) list = item->next; \
    item->prev = item->next = NULL;      \
} while (0)

#endif
