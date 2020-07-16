/*
 * Copyright (c) 2015-2020 ACOINFO Co., Ltd.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: sddc_msrtos.c SDDC MS-RTOS porting.
 *
 * Author: Jiao.jinxing <jiaojinxing@acoinfo.com>
 *
 */

#ifndef SDDC_MSRTOS_H
#define SDDC_MSRTOS_H

#include <ms_rtos.h>

#define sddc_printf     ms_printf

#define sddc_malloc     ms_malloc
#define sddc_free       ms_free

typedef ms_handle_t     sddc_mutex_t;

static inline int sddc_mutex_create(sddc_mutex_t *mutex)
{
    return ms_mutex_create("sddc_lock", MS_WAIT_TYPE_PRIO, mutex);
}

static inline int sddc_mutex_destroy(sddc_mutex_t mutex)
{
    return ms_mutex_destroy(mutex);
}

static inline int sddc_mutex_lock(sddc_mutex_t mutex)
{
    return ms_mutex_lock(mutex, MS_TIMEOUT_FOREVER);
}

static inline int sddc_mutex_unlock(sddc_mutex_t mutex)
{
    return ms_mutex_unlock(mutex);
}

#endif /* SDDC_MSRTOS_H */
