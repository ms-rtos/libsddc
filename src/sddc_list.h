/*
 * Copyright (c) 2015-2020 ACOINFO Co., Ltd.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: sddc_list.h Doubly linked list.
 *
 * Author: Jiao.jinxing <jiaojixing@acoinfo.com>
 *
 */

#ifndef SDDC_LIST_H
#define SDDC_LIST_H

#ifdef __cplusplus
extern "C" {
#endif

#define SDDC_CONTAINER_OF(entry, type, member) \
    ((type *)(((unsigned long)(entry)) - (unsigned long)(&((type *)NULL)->member)))

typedef struct sddc_list_head {
    struct sddc_list_head *next; /* next in chain */
    struct sddc_list_head *prev; /* previous in chain */
} sddc_list_head_t;

/*
 * Define an empty list
 */
#define SDDC_LIST_HEAD(name) \
sddc_list_head_t (name) = { &(name), &(name)}

/*
 * Initialize a specified list head to an empty list
 */
#define SDDC_LIST_INIT_HEAD(p) \
    do {                       \
        (p)->next = (p);       \
        (p)->prev = (p);       \
    } while (0)

/*
 * Determine whether a specified list is empty
 */
static inline sddc_bool_t sddc_list_is_empty(const sddc_list_head_t *entry)
{
    return ((entry->next == entry) ? SDDC_TRUE : SDDC_FALSE);
}

/*
 * Determine whether a specified node is the head of list
 */
static inline sddc_bool_t sddc_list_is_head(const sddc_list_head_t *entry, const sddc_list_head_t *list)
{
    return (entry->prev == list) ? SDDC_TRUE : SDDC_FALSE;
}

/*
 * Determine whether a specified node is the tail of list
 */
static inline sddc_bool_t sddc_list_is_tail(const sddc_list_head_t *entry, const sddc_list_head_t *list)
{
    return (entry->next == list) ? SDDC_TRUE : SDDC_FALSE;
}

/*
 * Determine whether a specified node is the only one node in list
 */
static inline sddc_bool_t sddc_list_is_only_one(const sddc_list_head_t *entry, const sddc_list_head_t *list)
{
    return ((entry->prev == list) && (entry->next == list)) ? SDDC_TRUE : SDDC_FALSE;
}

/*
 * Add a specified node to a list
 */
static inline void sddc_list_add(sddc_list_head_t *new_entry, sddc_list_head_t *list)
{
    sddc_list_head_t * const list_next = list->next;

    list->next = new_entry;
    new_entry->prev = list;
    new_entry->next = list_next;
    list_next->prev = new_entry;
}

/*
 * Add a specified node to the tail of a list
 */
static inline void sddc_list_add_tail(sddc_list_head_t *new_entry, sddc_list_head_t *list)
{
    sddc_list_head_t * const list_prev = list->prev;

    list->prev = new_entry;
    new_entry->next = list;
    new_entry->prev = list_prev;
    list_prev->next = new_entry;
}

/*
 * Take a specified node out of its current list, without reinitializing the links.of the entry
 */
static inline void sddc_list_del(sddc_list_head_t * const entry)
{
    sddc_list_head_t * const list_next = entry->next;
    sddc_list_head_t * const list_prev = entry->prev;

    list_next->prev = list_prev;
    list_prev->next = list_next;
}

/*
 * Take a specified node out of its current list, with reinitializing the links.of the entry
 */
static inline void sddc_list_del_init(sddc_list_head_t *entry)
{
    sddc_list_del(entry);
    entry->next = entry;
    entry->prev = entry;
}

/*
 * sddc_list_for_each and sddc_list_for_each_safe iterate over lists.
 * sddc_list_for_each_safe uses temporary storage to make the list delete safe
 */
#define sddc_list_for_each(itervar, list) \
    for (itervar = (list)->next; itervar != (list); itervar = itervar->next)

#define sddc_list_for_each_safe(itervar, save_var, list) \
    for (itervar = (list)->next, save_var = (list)->next->next; \
        itervar != (list); \
        itervar = save_var, save_var = save_var->next)

#ifdef __cplusplus
}
#endif

#endif /* SDDC_LIST_H */
