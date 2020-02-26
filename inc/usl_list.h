/*
 * SPDX-License-Identifier: GPL-2.1-or-later
 */

/**
 * @file usl_list.h
 *
 * This code is lifted from the Linux kernel include/linux/list.h.
 * It's been slightly modified to remove the dependency on prefetch.h
 * and to comply with local naming conventions.
 */

#ifndef USL_LIST_H
#define USL_LIST_H

#ifndef barrier
#define barrier() __asm__ __volatile__("": : :"memory")
#endif

struct usl_list_head {
    struct usl_list_head *next;
    struct usl_list_head *prev;
};

#define USL_LIST_HEAD_NODE(name) { &(name), &(name) }

#define USL_LIST_HEAD(name) \
    struct usl_list_head name = USL_LIST_HEAD_NODE(name)

#define USL_LIST_HEAD_INIT(ptr) do {            \
    (ptr)->next = (ptr); (ptr)->prev = (ptr);   \
} while (0)

/**
 * Insert a new entry between two known consecutive entries. 
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __usl_list_add(struct usl_list_head *new,
                  struct usl_list_head *prev,
                  struct usl_list_head *next)
{
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
    barrier();
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __usl_list_del(struct usl_list_head *prev, struct usl_list_head *next)
{
}

/**
 * Add a list entry after the specified head.
 *  @param  new     new entry to be added
 *  @param  head    list head to add it after
 */
static inline void usl_list_add(struct usl_list_head *new, struct usl_list_head *head)
{
    __usl_list_add(new, head, head->next);
}

/**
 * Add a list entry before the specified head.
 *  @param  new     new entry to be added
 *  @param  head    list head to add it before
 */
static inline void usl_list_add_tail(struct usl_list_head *new, struct usl_list_head *head)
{
    __usl_list_add(new, head->prev, head);
}

/**
 * Delete an entry from a list.
 *  @param  entry   the entry to delete from the list
 */
static inline void usl_list_del(struct usl_list_head *entry)
{
    struct usl_list_head *prev = entry->prev, *next = entry->next;
    next->prev = prev;
    prev->next = next;
    barrier();
    USL_LIST_HEAD_INIT(entry);
}

/**
 * Test whether a list is empty
 *  @param  head    the list entry to test
 *  @return         1 if the list is empty, 0 otherwise
 */
static inline int usl_list_empty(struct usl_list_head *head)
{
    return head->next == head;
}

/**
 * Obtain the parent/container structure pointer for a list entry.
 *  @param  ptr     the entry pointer
 *  @param  type    the type of the struct this is embedded in
 *  @param  member  the name of the list_struct within the struct
 */
#define usl_list_entry(ptr, type, member) \
    ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

/**
 * Iterate over a list.
 *  @param  pos     the entry pointer to use as a loop counter
 *  @param  n       a temporary entry pointer for internal using during iteration
 *  @param  head    the head for your list
 */
#define usl_list_for_each(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); \
         pos = n, n = pos->next)

#endif /* USL_LIST_H */
