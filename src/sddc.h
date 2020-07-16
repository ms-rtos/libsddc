/*
 * Copyright (c) 2015-2020 ACOINFO Co., Ltd.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: sddc.h SDDC implement.
 *
 * Author: Jiao.jinxing <jiaojinxing@acoinfo.com>
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
#define SDDC_TRUE           1U
#define SDDC_FALSE          0U

#if SDDC_CFG_CRIT_EN > 0
#define SDDC_LOG_CRIT(...) do {                             \
    sddc_printf("[%s] %d CRIT: ", __FUNCTION__, __LINE__);  \
    sddc_printf(__VA_ARGS__);                               \
} while (0)
#else
#define SDDC_LOG_CRIT(...)
#endif

#if SDDC_CFG_ERR_EN > 0
#define SDDC_LOG_ERR(...) do {                              \
    sddc_printf("[%s] %d ERR: ", __FUNCTION__, __LINE__);   \
    sddc_printf(__VA_ARGS__);                               \
} while (0)
#else
#define SDDC_LOG_ERR(...)
#endif

#if SDDC_CFG_WARN_EN > 0
#define SDDC_LOG_WARN(...) do {                             \
    sddc_printf("[%s] %d WARN: ", __FUNCTION__, __LINE__);  \
    sddc_printf(__VA_ARGS__);                               \
} while (0)
#else
#define SDDC_LOG_WARN(...)
#endif

#if SDDC_CFG_DBG_EN > 0
#define SDDC_LOG_DBG(...) do {                              \
    sddc_printf(__VA_ARGS__);                               \
} while (0)
#else
#define SDDC_LOG_DBG(...)
#endif

#if SDDC_CFG_INFO_EN > 0
#define SDDC_LOG_INFO(...) do {                             \
    sddc_printf(__VA_ARGS__);                               \
} while (0)
#else
#define SDDC_LOG_INFO(...)
#endif

/*
 * RTOS needs to implement the following API:
 *
 * void sddc_printf(const char *fmt, ...);
 *
 * void *sddc_malloc(size_t size);
 * void  sddc_free(void *ptr);
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

struct sddc_context;
typedef struct sddc_context sddc_t;

/**
 * @brief Callback function on receive INVITE request.
 *
 * @param[in] uid           Pointer to EdgerOS UID
 * @param[in] invite_data   Pointer to invite data
 * @param[in] len           The length of invite data
 *
 * @return SDDC_TRUE:       process ok, will send a respond
 *         SDDC_FALSE:      process failed
 */
typedef sddc_bool_t (*sddc_on_invite_t)(sddc_t *sddc, const uint8_t *uid, const char *invite_data, size_t len);

/**
 * @brief Callback function after send INVITE respond.
 *
 * @param[in] uid           Pointer to EdgerOS UID
 *
 * @return SDDC_TRUE:       process ok
 *         SDDC_FALSE:      process failed
 */
typedef sddc_bool_t (*sddc_on_invite_end_t)(sddc_t *sddc, const uint8_t *uid);

/**
 * @brief Callback function on receive UPDATE request.
 *
 * @param[in] uid           Pointer to EdgerOS UID
 * @param[in] update_data   Pointer to UPDATE data
 * @param[in] len           The length of UPDATE data
 *
 * @return SDDC_TRUE:       process ok, will send a respond
 *         SDDC_FALSE:      process failed
 */
typedef sddc_bool_t (*sddc_on_update_t)(sddc_t *sddc, const uint8_t *uid, const char *update_data, size_t len);

/**
 * @brief Callback function on receive MESSAGE request.
 *
 * @param[in] uid           Pointer to EdgerOS UID
 * @param[in] message       Pointer to message data
 * @param[in] len           The length of message data
 *
 * @return SDDC_TRUE:       process ok, will send a respond
 *         SDDC_FALSE:      process failed
 */
typedef sddc_bool_t (*sddc_on_message_t)(sddc_t *sddc, const uint8_t *uid, const char *message, size_t len);

/**
 * @brief Callback function on receive MESSAGE respond.
 *
 * @param[in] uid           Pointer to EdgerOS UID
 * @param[in] seqno         Seq number
 */
typedef void (*sddc_on_message_ack_t)(sddc_t *sddc, const uint8_t *uid, uint16_t seqno);

/**
 * @brief Callback function on lost MESSAGE respond.
 *
 * @param[in] uid           Pointer to EdgerOS UID
 * @param[in] seqno         Seq number
 */
typedef void (*sddc_on_message_lost_t)(sddc_t *sddc, const uint8_t *uid, uint16_t seqno);

/**
 * @brief Callback function on EdgerOS disconnection.
 *
 * @param[in] uid           Pointer to EdgerOS UID
 */
typedef void (*sddc_on_edgeros_lost_t)(sddc_t *sddc, const uint8_t *uid);

/**
 * @brief Set device uniquely id.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] mac_addr      Pointer to device mac address
 *
 * @return Error number
 */
int sddc_set_uid(sddc_t *sddc, const uint8_t *mac_addr);

/**
 * @brief Set callback function of on receive MESSAGE request.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] on_message    callback function
 *
 * @return Error number
 */
int sddc_set_on_message(sddc_t *sddc, sddc_on_message_t on_message);

/**
 * @brief Set callback function of on receive MESSAGE ACK.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] on_message    callback function
 *
 * @return Error number
 */
int sddc_set_on_message_ack(sddc_t *sddc, sddc_on_message_ack_t on_message_ack);

/**
 * @brief Set callback function of on lost MESSAGE ACK.
 *
 * @param[in] sddc              Pointer to SDDC
 * @param[in] on_message_lost   callback function
 *
 * @return Error number
 */
int sddc_set_on_message_lost(sddc_t *sddc, sddc_on_message_lost_t on_message_lost);

/**
 * @brief Set callback function of on EdgerOS disconnection.
 *
 * @param[in] sddc              Pointer to SDDC
 * @param[in] on_edgeros_lost   callback function
 *
 * @return Error number
 */
int sddc_set_on_edgeros_lost(sddc_t *sddc, sddc_on_edgeros_lost_t on_edgeros_lost);

/**
 * @brief Set callback function of on receive INVITE request.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] on_invite     callback function
 *
 * @return Error number
 */
int sddc_set_on_invite(sddc_t *sddc, sddc_on_invite_t on_invite);

/**
 * @brief Set callback function of after send INVITE respond.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] on_invite_end callback function
 *
 * @return Error number
 */
int sddc_set_on_invite_end(sddc_t *sddc, sddc_on_invite_end_t on_invite_end);

/**
 * @brief Set callback function on receive UPDATE request.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] on_update     callback function
 *
 * @return Error number
 */
int sddc_set_on_update(sddc_t *sddc, sddc_on_update_t on_update);

/**
 * @brief Set REPORT data.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] report_data   Pointer to REPORT data
 * @param[in] len           The length to REPORT data
 *
 * @return Error number
 */
int sddc_set_report_data(sddc_t *sddc, const char *report_data, size_t len);

/**
 * @brief Set INVITE data.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] report_data   Pointer to INVITE data
 * @param[in] len           The length to INVITE data
 *
 * @return Error number
 */
int sddc_set_invite_data(sddc_t *sddc, const char *invite_data, size_t len);

/**
 * @brief Destroy SDDC.
 *
 * @param[in] sddc          Pointer to SDDC
 *
 * @return Error number
 */
int sddc_destroy(sddc_t *sddc);

/**
 * @brief Create SDDC.
 *
 * @param[in] port          UDP port
 *
 * @return Pointer to SDDC
 */
sddc_t *sddc_create(uint16_t port);

/**
 * @brief Run SDDC.
 *
 * @param[in] sddc          Pointer to SDDC
 *
 * @return Error number
 */
int sddc_run(sddc_t *sddc);

/**
 * @brief Send message request to a specified EdgerOS which connected.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] uid           Pointer to EdgerOS UID
 * @param[in] payload       Pointer to message payload data
 * @param[in] payload_len   The length of payload data
 * @param[in] retries       The count of retry send
 * @param[in] urgent        Does urgent request
 * @param[out] seqno        Seq number
 *
 * @return Error number
 */
int sddc_send_message(sddc_t *sddc, const uint8_t *uid,
                      const char *payload, size_t payload_len,
                      uint8_t retries, sddc_bool_t urgent,
                      uint16_t *seqno);

/**
 * @brief Broadcast message request to a specified EdgerOS which connected.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] payload       Pointer to message payload data
 * @param[in] payload_len   The length of payload data
 * @param[in] retries       The count of retry send
 * @param[in] urgent        Does urgent request
 * @param[out] seqno        Seq number array
 *
 * @return Error number
 */
int sddc_broadcast_message(sddc_t *sddc,
                           const char *payload, size_t payload_len,
                           uint8_t retries, sddc_bool_t urgent,
                           uint16_t *seqno);

#ifdef __cplusplus
}
#endif

#endif /* SDDC_H */
