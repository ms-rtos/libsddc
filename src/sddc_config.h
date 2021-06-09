/*
 * Copyright (c) 2015-2020 ACOINFO Co., Ltd.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: sddc_config.h SDDC configuration.
 *
 * Author: Jiao.jinxing <jiaojinxing@acoinfo.com>
 *
 */

#ifndef SDDC_CONFIG_H
#define SDDC_CONFIG_H

#define SDDC_CFG_PORT                   680U
#define SDDC_CFG_RECV_BUF_SIZE          1460U
#define SDDC_CFG_SEND_BUF_SIZE          1460U

#define SDDC_CFG_NET_IMPL               "ms_esp_at_net"

#define SDDC_CFG_MQUEUE_SIZE            6U
#define SDDC_CFG_RETRIES_INTERVAL       500U  /* MS */
#define SDDC_CFG_EDGEROS_ALIVE          40U   /* RETRIES_INTERVAL */
#define SDDC_CFG_CONNECTOR_TIMEOUT      5000U /* MS */

#define SDDC_CFG_DBG_EN                 1U
#define SDDC_CFG_WARN_EN                1U
#define SDDC_CFG_ERR_EN                 1U
#define SDDC_CFG_CRIT_EN                1U
#define SDDC_CFG_INFO_EN                1U

#define SDDC_CFG_SECURITY_EN            1U

/* Define __FREERTOS__ if use FreeRTOS */
#undef __FREERTOS__

#endif /* SDDC_CONFIG_H */
