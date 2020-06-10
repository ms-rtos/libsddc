/*
 * Copyright (c) 2019 MS-RTOS Team.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: sddc_config.h SDDC configuration.
 *
 * Author: Jiao.jinxing <jiaojixing@acoinfo.com>
 *
 */

#ifndef SDDC_CONFIG_H
#define SDDC_CONFIG_H

#define SDDC_PORT                   680U
#define SDDC_RECV_BUF_SIZE          1024U
#define SDDC_SEND_BUF_SIZE          1024U

#define SDDC_NET_IMPL               "ms_esp_at_net"

#define SDDC_COAP_BUF_SIZE          1024U
#define SDDC_COAP_SCRATCH_RAW_SIZE  1024U
#define SDDC_COAP_PORT              5683U
#define SDDC_COAP_THREAD_PRIO       9U
#define SDDC_COAP_THREAD_STK_SIZE   1024U
#define SDDC_COAP_THREAD_TIME_SLICE 0U

#endif /* SDDC_CONFIG_H */
