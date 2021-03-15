/*
 * Copyright (c) 2015-2020 ACOINFO Co., Ltd.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: sddc_freertos.h SDDC FreeRTOS porting.
 *
 * Author: Jiao.jinxing <jiaojinxing@acoinfo.com>
 *
 */

#ifndef SDDC_FREERTOS_H
#define SDDC_FREERTOS_H

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"

#define sddc_printf     printf

#define sddc_malloc     malloc
#define sddc_free       free

static inline void sddc_sleep(int sec)
{
    vTaskDelay(sec * configTICK_RATE_HZ);
}

typedef SemaphoreHandle_t   sddc_mutex_t;

static inline int sddc_mutex_create(sddc_mutex_t *mutex)
{
    *mutex = xSemaphoreCreateMutex();
    return 0;
}

static inline int sddc_mutex_destroy(sddc_mutex_t *mutex)
{
    vSemaphoreDelete(*mutex);
    return 0;
}

static inline int sddc_mutex_lock(sddc_mutex_t *mutex)
{
    xSemaphoreTake(*mutex, portMAX_DELAY);
    return 0;
}

static inline int sddc_mutex_unlock(sddc_mutex_t *mutex)
{
    xSemaphoreGive(*mutex);
    return 0;
}

#endif /* SDDC_FREERTOS_H */
