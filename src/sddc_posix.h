/*
 * Copyright (c) 2015-2020 ACOINFO Co., Ltd.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: sddc_posix.h SDDC POSIX porting.
 *
 * Author: Jiao.jinxing <jiaojinxing@acoinfo.com>
 *
 */

#ifndef SDDC_POSIX_H
#define SDDC_POSIX_H

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#define sddc_printf     printf

#define sddc_malloc     malloc
#define sddc_free       free

typedef pthread_mutex_t sddc_mutex_t;

static inline int sddc_mutex_create(sddc_mutex_t *mutex)
{
    return pthread_mutex_init(mutex, NULL);
}

static inline int sddc_mutex_destroy(sddc_mutex_t *mutex)
{
    return pthread_mutex_destroy(mutex);
}

static inline int sddc_mutex_lock(sddc_mutex_t *mutex)
{
    return pthread_mutex_lock(mutex);
}

static inline int sddc_mutex_unlock(sddc_mutex_t *mutex)
{
    return pthread_mutex_unlock(mutex);
}

#endif /* SDDC_POSIX_H */
