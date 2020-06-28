/*
 * Copyright (c) 2019 MS-RTOS Team.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: sddc.h SDDC device end server implement.
 *
 * Author: Jiao.jinxing <jiaojixing@acoinfo.com>
 *
 */

#ifndef SDDC_H
#define SDDC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "sddc_config.h"
#include <stdint.h>

typedef uint8_t sddc_bool_t;
#define SDDC_TRUE   1
#define SDDC_FALSE  0

#define SDDC_LOG_EMERG     0U
#define SDDC_LOG_ALERT     1U
#define SDDC_LOG_CRIT      2U
#define SDDC_LOG_ERR       3U
#define SDDC_LOG_WARNING   4U
#define SDDC_LOG_NOTICE    5U
#define SDDC_LOG_INFO      6U
#define SDDC_LOG_DEBUG     7U

/*
 * RTOS needs to provide the following API:
 *
 * void sddc_log(uint8_t level, const char *fmt, ...);
 *
 * int sddc_mutex_create(sddc_mutex_t *mutex);
 * int sddc_mutex_destroy(sddc_mutex_t mutex);
 * int sddc_mutex_lock(sddc_mutex_t mutex);
 * int sddc_mutex_unlock(sddc_mutex_t mutex);
 */

#ifdef __MS_RTOS__
#include "sddc_msrtos.h"
#else
#error "Please porting to you RTOS!"
#endif

/*
 * Report Data(UTF8 JSON format data):
 *  {
 *      "report":{
 *          "name":<String>, "Printer", "Patch panel", "Air conditioning"...
 *          "type":<String>, "monitor", "edger", "device"
 *          "excl":<Boolean> (This Device is App Exclusive)
 *          "desc":<String>, (Device Documents URL)
 *          "model":<String>, (Product Model)
 *          "vendor":<String> (Manufacturer Name)
 *      }
 *      "extension":{
 *          ...
 *      }
 *  }
 *
 * Update and Invite Data(UTF8 JSON format data):
 *  {
 *      "report":{
 *          "name":<String>, "Printer", "Patch panel", "Air conditioning"...
 *          "type":<String>, "monitor", "edger", "device"
 *          "excl":<Boolean> (This Device is App Exclusive)
 *          "desc":<String>, (Device Documents URL)
 *          "model":<String>, (Product Model)
 *          "vendor":<String> (Manufacturer Name)
 *      },
 *      "server":{
 *          "mqtt":[
 *              { "type":"mqtt", "port":<Integer> ... },
 *              { "type":"mqttsn", "port":<Integer> ... },
 *              ...
 *          ],
 *          "coap":[
 *              { "port":<Integer> },
 *              ...
 *          ]
 *      },
 *      "extension":{
 *          ...
 *      }
 *  }
 *
 * Message Data(UTF8 JSON format data):
 *  {
 *      ...
 *  }
 */

/* Header uid length */
#define SDDC_UID_LEN     8

/**
 * @brief Callback function on receive INVITE request.
 *
 * @param[in] addr          Pointer to EdgerOS network address
 * @param[in] invite_data   Pointer to invite data
 * @param[in] len           The length of invite data
 *
 * @return SDDC_TRUE:       process ok, will send a respond
 *         SDDC_FALSE:      process failed
 */
typedef sddc_bool_t (*sddc_on_invite_t)(const struct sockaddr_in *addr, const char *invite_data, size_t len);

/**
 * @brief Callback function after receive INVITE request.
 *
 * @param[in] addr          Pointer to EdgerOS network address
 *
 * @return SDDC_TRUE:       process ok
 *         SDDC_FALSE:      process failed
 */
typedef sddc_bool_t (*sddc_on_invite_end_t)(const struct sockaddr_in *addr);

/**
 * @brief Callback function on receive UPDATE request.
 *
 * @param[in] addr          Pointer to EdgerOS network address
 * @param[in] update_data   Pointer to update data
 * @param[in] len           The length of update data
 *
 * @return SDDC_TRUE:       process ok, will send a respond
 *         SDDC_FALSE:      process failed
 */
typedef sddc_bool_t (*sddc_on_update_t)(const struct sockaddr_in *addr, const char *update_data, size_t len);

/**
 * @brief Callback function on receive MESSAGE request.
 *
 * @param[in] addr          Pointer to EdgerOS network address
 * @param[in] message       Pointer to message data
 * @param[in] len           The length of message data
 *
 * @return SDDC_TRUE:       process ok, will send a respond
 *         SDDC_FALSE:      process failed
 */
typedef sddc_bool_t (*sddc_on_message_t)(const struct sockaddr_in *addr, const char *message, size_t len);

/**
 * @brief Callback function on receive MESSAGE respond.
 *
 * @param[in] addr          Pointer to EdgerOS network address
 * @param[in] seqno         Seq number
 */
typedef void (*sddc_on_message_ack_t)(const struct sockaddr_in *addr, uint16_t seqno);

/**
 * @brief Set callback function of on receive MESSAGE request.
 *
 * @param[in] on_message    callback function
 *
 * @return Error number
 */
int sddc_set_on_message(sddc_on_message_t on_message);

/**
 * @brief Set callback function of on receive MESSAGE ACK.
 *
 * @param[in] on_message    callback function
 *
 * @return Error number
 */
int sddc_set_on_message_ack(sddc_on_message_ack_t on_message);

/**
 * @brief Set callback function of on receive INVITE request.
 *
 * @param[in] on_invite     callback function
 *
 * @return Error number
 */
int sddc_set_on_invite(sddc_on_invite_t on_invite);

/**
 * @brief Set callback function of after receive INVITE request.
 *
 * @param[in] on_invite_end callback function
 *
 * @return Error number
 */
int sddc_set_on_invite_end(sddc_on_invite_end_t on_invite_end);

/**
 * @brief Set callback function on receive UPDATE request.
 *
 * @param[in] on_update     callback function
 *
 * @return Error number
 */
int sddc_set_on_update(sddc_on_update_t on_update);

/**
 * @brief Set report data.
 *
 * @param[in] report_data   Pointer to report data
 *
 * @return Error number
 */
int sddc_set_report_data(const char *report_data);

/**
 * @brief Set report data.
 *
 * @param[in] report_data   Pointer to invite data
 *
 * @return Error number
 */
int sddc_set_invite_data(const char *invite_data);

/**
 * @brief Set device uniquely id.
 *
 * @param[in] mac_addr      Pointer to device mac address
 *
 * @return Error number
 */
int sddc_set_uid(const uint8_t *mac_addr);

/**
 * @brief Enter sddc server loop and run.
 *
 * @param[in] port          Listen port
 *
 * @return Error number
 */
int sddc_server_loop(uint16_t port);

/**
 * @brief Update invite data and send UPDATE request to all EdgerOS which connected.
 *
 * @param[in] invite_data   Pointer to new invite data
 *
 * @return Error number
 */
int sddc_send_update(const char *invite_data);

/**
 * @brief Broadcast message request to all EdgerOS which connected.
 *
 * @param[in] message       Pointer to message data
 * @param[in] ack_req       Does ack request
 * @param[out] seqno        Seq number
 *
 * @return Error number
 */
int sddc_broadcast_message(const char *message, sddc_bool_t ack_req, uint16_t *seqno);

/**
 * @brief Send message request to a specified EdgerOS which connected.
 *
 * @param[in] addr          Pointer to EdgerOS network address
 * @param[in] message       Pointer to message data
 * @param[in] ack_req       Does ack request
 * @param[out] seqno        Seq number
 *
 * @return Error number
 */
int sddc_send_message(const struct sockaddr_in *addr, const char *message, sddc_bool_t ack_req, uint16_t *seqno);

#ifdef __cplusplus
}
#endif

#endif /* SDDC_H */
