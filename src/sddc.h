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

#define SDDC_VERSION        110U

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

#define sddc_return_value_if_fail(p, value)                     \
    if (!(p)) {                                                 \
        SDDC_LOG_ERR("%s:%d " #p "\n", __FUNCTION__, __LINE__); \
        return (value);                                         \
    }

#define sddc_goto_error_if_fail(p)                              \
    if (!(p)) {                                                 \
        SDDC_LOG_ERR("%s:%d " #p "\n", __FUNCTION__, __LINE__); \
        goto error;                                             \
    }

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
#elif defined(SYLIXOS)
#include "sddc_posix.h"
#elif defined(__FREERTOS__)
#include "sddc_freertos.h"
#else
#error "Please porting to you RTOS!"
#endif

/*
 * SDDC Protocol Header:
 *
 *  0               1               2               3
 *  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | MAGIC |  VER  |  TYPE |U|J|R|A|        SEQ / ACK Number       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Uniquely ID 0 - 3                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Uniquely ID 4 - 7                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  security |C|S|    reserved   |         Data Length           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                |
 *                \- Device Only!
 *
 * MAGIC : Must be: 0x5
 * VER   : Must be: 0x1
 * FLAGS : R: ACK Required, A: ACK, J: Join (Agree to invite and join the network)
 *
 * TYPE                DIRECTION         R  DATA                    DESC
 * 0x00: Discover      B  -> E, E  -> D  -  No data                 Broadcast or Unicast Discover: monitor, edger, device
 * 0x01: Report        B <-  E, E <-  D  -  UTF8 JSON format data   Responding discover or report
 * 0x02: Update        B <-> E, E <-> D  R  UTF8 JSON format data   I changed.
 *
 * 0x03: Invite        B  -> E, E  -> D  R  UTF8 JSON format data   Invite target device
 * 0x03: Invite ACK    B <-  E, E <-  D  -  UTF8 JSON format data   Invite reply (With own server information)
 *
 * 0x04: Ping          B  -> E, E  -> D  R  No data                 Check whether the target device is online
 * 0x04: Ping ACK      B <-  E, E <-  D  -  No data                 Reply Ping request.
 *
 * 0x05: Message       B  -> E, E  -> D  *  UTF8 JSON format data   Send a message to the target
 * 0x05: Message ACK   B <-  E, E <-  D  -  No data                 Reply to sender
 *
 * Report Data:
 *  {
 *      "report":{
 *          "name":<String>, "Printer", "Patch panel", "Air conditioning"...
 *          "type":<String>, "monitor", "edger", "device"
 *          "excl":<Boolean> (This Device is App Exclusive)
 *          "desc":<String>, (Device Documents URL)
 *          "model":<String>, (Product Model)
 *          "vendor":<String> (Manufacturer Name)
 *          "sn":<String>, (Product Serial Numbber optional)
 *      }
 *      "extension":{
 *          ...
 *      }
 *  }
 *
 * Update and Invite Data:
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
 * Message Data:
 *  {
 *      ...
 *  }
 *
 *  TYPE        SECURITY DATA
 *  DISCOVER    NO
 *  REPORT      NO
 *  UPDATE      YES
 *  INVITE      YES
 *  PING        NO
 *  MESSAGE     YES
 */

/* Header uid length */
#define SDDC_UID_LEN     8

struct sddc_context;
typedef struct sddc_context sddc_t;

struct sddc_connector;
typedef struct sddc_connector sddc_connector_t;

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
 * @brief Set device token.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] token         Pointer to token string
 *
 * @return Error number
 */
int sddc_set_token(sddc_t *sddc, const char *token);

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
 * @param[in] invite_data   Pointer to INVITE data
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
                      const void *payload, size_t payload_len,
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
                           const void *payload, size_t payload_len,
                           uint8_t retries, sddc_bool_t urgent,
                           uint16_t *seqno);

/**
 * @brief Create a SDDC connector.
 *
 * @param[in] connector     Pointer to SDDC
 * @param[in] uid           Pointer to EdgerOS UID
 * @param[in] port          EdgerOS TCP server port
 * @param[in] token         Pointer to token string
 * @param[in] get_mode      Get data mode?
 *
 * @return Pointer to SDDC connector.
 */
sddc_connector_t *sddc_connector_create(sddc_t *sddc, const uint8_t *uid, uint16_t port, const char *token, sddc_bool_t get_mode);

/**
 * @brief Destroy SDDC connector.
 *
 * @param[in] connector     Pointer to SDDC connector
 *
 * @return Error number
 */
int sddc_connector_destroy(sddc_connector_t *connector);

/**
 * @brief Get fd of SDDC connector.
 *
 * @param[in] connector     Pointer to SDDC connector
 *
 * @return The fd of SDDC connector if success, -1 if failure.
 */
int sddc_connector_fd(sddc_connector_t *connector);

/**
 * @brief Put data to SDDC connector.
 *
 * @param[in] connector     Pointer to SDDC connector
 * @param[in] data          Pointer to data buffer
 * @param[in] len           The size of data buffer
 * @param[in] finish        Whether to end the transfer
 *
 * @return 0 if success, -1 if failure.
 */
int sddc_connector_put(sddc_connector_t *connector, const void *data, size_t len, sddc_bool_t finish);

/**
 * @brief Get data from SDDC connector.
 *
 * @param[in] connector     Pointer to SDDC connector
 * @param[in] data          Pointer to data buffer pointer
 * @param[out] finish       Whether to end the transfer
 *
 * @return The size of data received.
 */
ssize_t sddc_connector_get(sddc_connector_t *connector, void **data, sddc_bool_t *finish);

#ifdef __cplusplus
}
#endif

#endif /* SDDC_H */
