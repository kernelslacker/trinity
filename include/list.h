#pragma once

#include <stddef.h>
#include "types.h"

/*
 * Simple linked-list routines, based on functions of the same name from the Linux kernel.
 *
 * Mirrors the kernel's CONFIG_DEBUG_LIST: validate insertion/deletion
 * invariants, and poison entries after they're removed so subsequent
 * misuse is loud.  Trinity is a fuzzer; spending a few cycles per list
 * op to localise corruption to the caller that broke it is well worth it.
 *
 * Three distinguishable failure modes from the validator:
 *   next/prev == NULL                 -> entry was zeroed (stray write)
 *                                        or never INIT_LIST_HEAD'd
 *   next == POISON1 || prev == POISON2 -> use-after-list_del / double-del
 *   prev->next != entry || next->prev != entry -> the surrounding list
 *                                        links were trampled by a stray
 *                                        write or torn by a missed lock
 */

#define LIST_POISON1 ((struct list_head *) 0xdead000000000100UL)
#define LIST_POISON2 ((struct list_head *) 0xdead000000000122UL)

struct list_head {
        struct list_head *next, *prev;
};

extern void __list_add_valid_or_die(struct list_head *new,
                                    struct list_head *prev,
                                    struct list_head *next,
                                    const char *file,
                                    const char *func,
                                    unsigned int line);

extern void __list_del_entry_valid_or_die(struct list_head *entry,
                                          const char *file,
                                          const char *func,
                                          unsigned int line);

static inline void INIT_LIST_HEAD(struct list_head *list)
{
        list->next = list;
        list->prev = list;
}

static inline bool list_empty(const struct list_head *head)
{
        return head->next == head;
}

static inline void __list_add(struct list_head *new,
                              struct list_head *prev,
                              struct list_head *next)
{
        __list_add_valid_or_die(new, prev, next, __FILE__, __func__, __LINE__);
        next->prev = new;
        new->next = next;
        new->prev = prev;
        prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
        __list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
        __list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
        next->prev = prev;
        prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
        __list_del_entry_valid_or_die(entry, __FILE__, __func__, __LINE__);
        __list_del(entry->prev, entry->next);
        entry->next = LIST_POISON1;
        entry->prev = LIST_POISON2;
}

static inline void __list_del_entry(struct list_head *entry)
{
	__list_del_entry_valid_or_die(entry, __FILE__, __func__, __LINE__);
	__list_del(entry->prev, entry->next);
}

/**
 * list_move - delete from one list and add as another's head
 * @list: the entry to move
 * @head: the head that will precede our entry
 */
static inline void list_move(struct list_head *list, struct list_head *head)
{
	__list_del_entry(list);
	list_add(list, head);
}

#define list_for_each(pos, head) \
         for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * list_for_each_safe - iterate over a list safe against removal of list entry
 * @pos:        the &struct list_head to use as a loop cursor.
 * @n:          another &struct list_head to use as temporary storage
 * @head:       the head for your list.
 */
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

