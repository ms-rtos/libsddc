/*
 * Copyright (c) 2015-2020 ACOINFO Co., Ltd.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: sddc.c SDDC implement.
 *
 * Author: Jiao.jinxing <jiaojinxing@acoinfo.com>
 *
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <stdlib.h>
#include "sddc_config.h"
#include "sddc.h"
#include "sddc_list.h"

#if SDDC_CFG_SECURITY_EN > 0
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/error.h>
#include <mbedtls/cipher.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#endif

/* Header magic and version */
#define SDDC_MAGIC              0x5
#define SDDC_VERSION            0x1

/* Header types */
#define SDDC_TYPE_DISCOVER      0x00
#define SDDC_TYPE_REPORT        0x01
#define SDDC_TYPE_UPDATE        0x02
#define SDDC_TYPE_INVITE        0x03
#define SDDC_TYPE_PING          0x04
#define SDDC_TYPE_MESSAGE       0x05

/* Header type set and get */
#define SDDC_SET_TYPE(h, type)  \
        ((h)->flags_type) &= 0xe0; \
        ((h)->flags_type) |= (type)

#define SDDC_GET_TYPE(h) \
        ((h)->flags_type & 0x1f)

/* Header flags */
#define SDDC_FLAG_NONE          0x00
#define SDDC_FLAG_ACK           0x80
#define SDDC_FLAG_REQ           0x40
#define SDDC_FLAG_JOIN          0x20
#define SDDC_FLAG_URGENT        0x10

/* Header security flags */
#define SDDC_SEC_FLAG_NONE      0x00
#define SDDC_SEC_FLAG_SUPPORT   0x80
#define SDDC_SEC_FLAG_CRYPTO    0x40

/* Buffer to hex char */
#define SDDC_BUF_TO_HEX_CHAR(digit) \
        (char)(((digit) < 10) ? ((digit) + '0') : ((digit) + 'a' - 10))

/* Hex char to buffer */
#define SDDC_HEX_CHAR_TO_BUF(x, c) \
        if (c >= '0' && c <= '9') { \
            x = c - '0'; \
        } else if (c >= 'A' && c <= 'F') { \
            x = 10 + (c - 'A'); \
        } else if (c >= 'a' && c <= 'f') { \
            x = 10 + (c - 'a'); \
        } else { \
            x = 0; \
        }

/* SDDC header */
typedef struct {
    uint8_t             magic_ver;
    uint8_t             flags_type;
    uint16_t            seqno;
    uint8_t             uid[SDDC_UID_LEN];
    uint8_t             security;
    uint8_t             reserved;
    uint16_t            length;
} sddc_header_t;

/* EdgerOS */
typedef struct {
    sddc_list_head_t    node;
    uint8_t             uid[SDDC_UID_LEN];
    struct sockaddr_in  addr;
    sddc_list_head_t    mqueue;
    uint16_t            mqueue_len;
    uint16_t            alive;
} sddc_edgeros_t;

/* Message */
typedef struct {
    sddc_list_head_t    node;
    sddc_edgeros_t     *edgeros;
    uint8_t             retries;
    uint16_t            seqno;
    uint16_t            packet_len;
    uint8_t             packet[1];
} sddc_message_t;

/* SDDC */
struct sddc_context {
    uint8_t                         recv_buf[SDDC_CFG_RECV_BUF_SIZE];
    uint8_t                         send_buf[SDDC_CFG_SEND_BUF_SIZE];
    uint8_t                         uid[SDDC_UID_LEN];
    const char *                    token;
    const char *                    report_data;
    size_t                          report_data_len;
    const char *                    invite_data;
    size_t                          invite_data_len;
    sddc_on_invite_t                on_invite;
    sddc_on_invite_end_t            on_invite_end;
    sddc_on_update_t                on_update;
    sddc_on_message_t               on_message;
    sddc_on_message_ack_t           on_message_ack;
    sddc_on_message_lost_t          on_message_lost;
    sddc_on_edgeros_lost_t          on_edgeros_lost;
    sddc_list_head_t                edgeros_list;
    int                             fd;
    sddc_mutex_t                    lockid;
    uint16_t                        seqno;
    uint16_t                        port;

#if SDDC_CFG_SECURITY_EN > 0
    uint8_t                         decypt_buf[SDDC_CFG_RECV_BUF_SIZE - sizeof(sddc_header_t) + 16];
    mbedtls_cipher_context_t        encypt_cipher_ctx;
    mbedtls_cipher_context_t        decypt_cipher_ctx;
    sddc_bool_t                     security_en;
    const mbedtls_cipher_info_t    *cipher_info;
    uint8_t                         key[16];
    uint8_t                         iv[16];
#endif
};

#define SDDC_PACKET_PAYLOAD(packet)     ((char *)(packet) + sizeof(sddc_header_t))

#define return_value_if_fail(p, value)                          \
    if (!(p)) {                                                 \
        SDDC_LOG_ERR("%s:%d " #p "\n", __FUNCTION__, __LINE__); \
        return (value);                                         \
    }

#define goto_error_if_fail(p)                                   \
    if (!(p)) {                                                 \
        SDDC_LOG_ERR("%s:%d " #p "\n", __FUNCTION__, __LINE__); \
        goto error;                                             \
    }

#if SDDC_CFG_SECURITY_EN > 0

static int __sddc_gen_key(const char *token, uint8_t *key, uint8_t *iv)
{
    mbedtls_md_context_t  md;
    uint8_t               hash[16];
    size_t                token_len = strlen(token);

    mbedtls_md_init(&md);
    mbedtls_md_setup(&md, mbedtls_md_info_from_string("MD5"), 0);

    mbedtls_md_starts(&md);
    mbedtls_md_update(&md, (const uint8_t *)token, token_len);
    mbedtls_md_finish(&md, hash);
    memcpy(key, hash, 16);

    mbedtls_md_starts(&md);
    mbedtls_md_update(&md, hash, 16);
    mbedtls_md_update(&md, (const uint8_t *)token, token_len);
    mbedtls_md_finish(&md, hash);
    memcpy(iv, hash, 16);

    mbedtls_md_free(&md);

    return 0;
}

/**
 * @brief Set device token.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] token         Pointer to token string
 *
 * @return Error number
 */
int sddc_set_token(sddc_t *sddc, const char *token)
{
    return_value_if_fail(sddc && token, -1);

    __sddc_gen_key(token, sddc->key, sddc->iv);

    sddc->cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC);

    sddc->security_en = SDDC_TRUE;

    return 0;
}

static int __sddc_decrypt(sddc_t *sddc, const void *data, size_t len, void *output, size_t *olen)
{
    int ret;
    size_t ulen;
    size_t flen;

    *olen = 0;

    return_value_if_fail(sddc->security_en, -1);

    mbedtls_cipher_init(&sddc->decypt_cipher_ctx);

    mbedtls_cipher_setup(&sddc->decypt_cipher_ctx, sddc->cipher_info);

    mbedtls_cipher_set_iv(&sddc->decypt_cipher_ctx, sddc->iv, sizeof(sddc->iv));

    mbedtls_cipher_setkey(&sddc->decypt_cipher_ctx, sddc->key, sizeof(sddc->key) * 8, MBEDTLS_DECRYPT);

    ret = mbedtls_cipher_update(&sddc->decypt_cipher_ctx, data, len, output, &ulen);
    return_value_if_fail(ret == 0, -1);

    ret = mbedtls_cipher_finish(&sddc->decypt_cipher_ctx, (uint8_t *)output + ulen, &flen);

    return_value_if_fail(ret == 0, -1);

    mbedtls_cipher_free(&sddc->decypt_cipher_ctx);

    *olen = ulen + flen;

    return 0;
}

static int __sddc_encrypt(sddc_t *sddc, const void *data, size_t len, void *output, size_t *olen)
{
    int ret;
    size_t ulen;
    size_t flen;

    *olen = 0;

    return_value_if_fail(sddc->security_en, -1);

    mbedtls_cipher_init(&sddc->encypt_cipher_ctx);

    mbedtls_cipher_setup(&sddc->encypt_cipher_ctx, sddc->cipher_info);

    mbedtls_cipher_set_iv(&sddc->encypt_cipher_ctx, sddc->iv, sizeof(sddc->iv));

    mbedtls_cipher_setkey(&sddc->encypt_cipher_ctx, sddc->key, sizeof(sddc->key) * 8, MBEDTLS_ENCRYPT);

    ret = mbedtls_cipher_update(&sddc->encypt_cipher_ctx, data, len, output, &ulen);
    return_value_if_fail(ret == 0, -1);

    ret = mbedtls_cipher_finish(&sddc->encypt_cipher_ctx, (uint8_t *)output + ulen, &flen);
    return_value_if_fail(ret == 0, -1);

    mbedtls_cipher_free(&sddc->encypt_cipher_ctx);

    *olen = ulen + flen;

    return 0;
}

#endif

/**
 * @brief Set device uniquely id.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] mac_addr      Pointer to device mac address
 *
 * @return Error number
 */
int sddc_set_uid(sddc_t *sddc, const uint8_t *mac_addr)
{
    return_value_if_fail(sddc && mac_addr, -1);

    sddc->uid[0] = mac_addr[0];
    sddc->uid[1] = mac_addr[1];
    sddc->uid[2] = mac_addr[2];
    sddc->uid[3] = 0xfe;
    sddc->uid[4] = 0x80;
    sddc->uid[5] = mac_addr[3];
    sddc->uid[6] = mac_addr[4];
    sddc->uid[7] = mac_addr[5];

    return 0;
}

/**
 * @brief Set callback function of on receive MESSAGE request.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] on_message    callback function
 *
 * @return Error number
 */
int sddc_set_on_message(sddc_t *sddc, sddc_on_message_t on_message)
{
    return_value_if_fail(sddc && on_message, -1);

    sddc->on_message = on_message;

    return 0;
}

/**
 * @brief Set callback function of on receive MESSAGE ACK.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] on_message    callback function
 *
 * @return Error number
 */
int sddc_set_on_message_ack(sddc_t *sddc, sddc_on_message_ack_t on_message_ack)
{
    return_value_if_fail(sddc && on_message_ack, -1);

    sddc->on_message_ack = on_message_ack;

    return 0;
}

/**
 * @brief Set callback function of on lost MESSAGE ACK.
 *
 * @param[in] sddc              Pointer to SDDC
 * @param[in] on_message_lost   callback function
 *
 * @return Error number
 */
int sddc_set_on_message_lost(sddc_t *sddc, sddc_on_message_lost_t on_message_lost)
{
    return_value_if_fail(sddc && on_message_lost, -1);

    sddc->on_message_lost = on_message_lost;

    return 0;
}

/**
 * @brief Set callback function of on EdgerOS disconnection.
 *
 * @param[in] sddc              Pointer to SDDC
 * @param[in] on_edgeros_lost   callback function
 *
 * @return Error number
 */
int sddc_set_on_edgeros_lost(sddc_t *sddc, sddc_on_edgeros_lost_t on_edgeros_lost)
{
    return_value_if_fail(sddc && on_edgeros_lost, -1);

    sddc->on_edgeros_lost = on_edgeros_lost;

    return 0;
}

/**
 * @brief Set callback function of on receive INVITE request.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] on_invite     callback function
 *
 * @return Error number
 */
int sddc_set_on_invite(sddc_t *sddc, sddc_on_invite_t on_invite)
{
    return_value_if_fail(sddc && on_invite, -1);

    sddc->on_invite = on_invite;

    return 0;
}

/**
 * @brief Set callback function of after send INVITE respond.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] on_invite_end callback function
 *
 * @return Error number
 */
int sddc_set_on_invite_end(sddc_t *sddc, sddc_on_invite_end_t on_invite_end)
{
    return_value_if_fail(sddc && on_invite_end, -1);

    sddc->on_invite_end = on_invite_end;

    return 0;
}

/**
 * @brief Set callback function on receive UPDATE request.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] on_update     callback function
 *
 * @return Error number
 */
int sddc_set_on_update(sddc_t *sddc, sddc_on_update_t on_update)
{
    return_value_if_fail(sddc && on_update, -1);

    sddc->on_update = on_update;

    return 0;
}

/**
 * @brief Set REPORT data.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] report_data   Pointer to REPORT data
 * @param[in] len           The length to REPORT data
 *
 * @return Error number
 */
int sddc_set_report_data(sddc_t *sddc, const char *report_data, size_t len)
{
    return_value_if_fail(sddc && report_data && len, -1);

    sddc->report_data     = report_data;
    sddc->report_data_len = len;

    return 0;
}

/**
 * @brief Set INVITE data.
 *
 * @param[in] sddc          Pointer to SDDC
 * @param[in] invite_data   Pointer to INVITE data
 * @param[in] len           The length to INVITE data
 *
 * @return Error number
 */
int sddc_set_invite_data(sddc_t *sddc, const char *invite_data, size_t len)
{
    return_value_if_fail(sddc && invite_data && len, -1);

#if SDDC_CFG_SECURITY_EN > 0
    if (sddc->security_en) {
        sddc->invite_data = sddc_malloc(len + 16);
        return_value_if_fail(sddc->invite_data, -1);

        return __sddc_encrypt(sddc, invite_data, len,
                              (void *)sddc->invite_data, &sddc->invite_data_len);

    } else
#endif
    {
        sddc->invite_data     = invite_data;
        sddc->invite_data_len = len;
    }

    return 0;
}

/**
 * @brief Destroy SDDC.
 *
 * @param[in] sddc          Pointer to SDDC
 *
 * @return Error number
 */
int sddc_destroy(sddc_t *sddc)
{
    return_value_if_fail(sddc, -1);

#if SDDC_CFG_SECURITY_EN > 0
    if (sddc->security_en) {
        sddc_free((void *)sddc->invite_data);
    }
#endif

    close(sddc->fd);
    sddc_mutex_destroy(&sddc->lockid);
    sddc_free(sddc);

    return 0;
}

/**
 * @brief Create SDDC.
 *
 * @param[in] port          UDP port
 *
 * @return Pointer to SDDC
 */
sddc_t *sddc_create(uint16_t port)
{
    sddc_t            *sddc;
    struct sockaddr_in serv_addr;

    return_value_if_fail(port, NULL);

    sddc = sddc_malloc(sizeof(sddc_t));
    if (sddc == NULL) {
        SDDC_LOG_ERR("Failed to allocate memory!\n");
        return NULL;
    }

    bzero(sddc, sizeof(sddc_t));

    sddc->port = port;
    SDDC_LIST_HEAD_INIT(&sddc->edgeros_list);

    if (sddc_mutex_create(&sddc->lockid) != 0) {
        SDDC_LOG_ERR("Failed to create lock!\n");
        sddc_free(sddc);
        return NULL;
    }

    sddc->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sddc->fd < 0) {
        SDDC_LOG_ERR("Failed to create socket!\n");
        sddc_mutex_destroy(&sddc->lockid);
        sddc_free(sddc);
        return NULL;
    }

    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    if (bind(sddc->fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        SDDC_LOG_ERR("Failed to bind port %u!\n", (unsigned)port);
        sddc_destroy(sddc);
        return NULL;
    }

    return sddc;
}

static ssize_t __sddc_build_packet(sddc_t *sddc, uint8_t *packet, uint8_t type, uint8_t flags, uint8_t security_flag,
                                   uint16_t seqno, const void *payload, size_t payload_len)
{
    sddc_header_t *header = (sddc_header_t *)packet;

    bzero(header, sizeof(sddc_header_t));
    header->magic_ver = SDDC_MAGIC | (SDDC_VERSION << 4);
    SDDC_SET_TYPE(header, type);
    header->flags_type |= flags;

#if SDDC_CFG_SECURITY_EN > 0
    if (sddc->security_en) {
        header->security = security_flag | SDDC_SEC_FLAG_SUPPORT;
    }
#endif

    header->seqno  = htons(seqno);
    header->length = htons(payload_len);
    memcpy(header->uid, sddc->uid, sizeof(header->uid));

    if ((payload_len > 0) && ((unsigned long)payload != ((unsigned long)packet + sizeof(sddc_header_t)))) {
        memcpy(packet + sizeof(sddc_header_t), payload, payload_len);
    }

    return sizeof(sddc_header_t) + payload_len;
}

static sddc_edgeros_t *__sddc_edgeros_find(sddc_t *sddc, const uint8_t *uid)
{
    sddc_edgeros_t   *edgeros;
    sddc_list_head_t *itervar;

    sddc_list_for_each(itervar, &sddc->edgeros_list) {
        edgeros = SDDC_CONTAINER_OF(itervar, sddc_edgeros_t, node);
        if (memcmp(edgeros->uid, uid, sizeof(edgeros->uid)) == 0) {
            return edgeros;
        }
    }

    return NULL;
}

static sddc_edgeros_t *__sddc_edgeros_update(sddc_t *sddc, const uint8_t *uid, const struct sockaddr_in *cli_addr)
{
    sddc_edgeros_t *edgeros = __sddc_edgeros_find(sddc, uid);

    if (edgeros != NULL) {
        edgeros->addr  = *cli_addr;
        edgeros->alive = SDDC_CFG_EDGEROS_ALIVE;
    }

    return edgeros;
}

static int __sddc_edgeros_destroy(sddc_edgeros_t *edgeros)
{
    while (edgeros->mqueue_len > 0) {
        sddc_message_t *message = SDDC_CONTAINER_OF(edgeros->mqueue.next, sddc_message_t, node);
        sddc_list_del(&message->node);
        sddc_free(message);
        edgeros->mqueue_len--;
    }

    sddc_list_del(&edgeros->node);

    sddc_free(edgeros);

    return 0;
}

static int __sddc_after_invite_respond(sddc_t *sddc, sddc_edgeros_t *edgeros, const uint8_t *uid, struct sockaddr_in *cli_addr)
{
    if (edgeros == NULL) {
        edgeros = sddc_malloc(sizeof(sddc_edgeros_t));
        if (edgeros != NULL) {
            memcpy(edgeros->uid, uid, sizeof(edgeros->uid));
            edgeros->addr       = *cli_addr;
            edgeros->alive      = SDDC_CFG_EDGEROS_ALIVE;
            edgeros->mqueue_len = 0;
            SDDC_LIST_HEAD_INIT(&edgeros->mqueue);
            sddc_list_add(&edgeros->node, &sddc->edgeros_list);

        } else {
            SDDC_LOG_ERR("Failed to allocate memory!\n");
        }
    }

    return_value_if_fail(edgeros != NULL, -1);

    if (sddc->on_invite_end != NULL) {
        sddc->on_invite_end(sddc, edgeros->uid);
    }

    return 0;
}

/**
 * @brief Run SDDC.
 *
 * @param[in] sddc          Pointer to SDDC
 *
 * @return Error number
 */
int sddc_run(sddc_t *sddc)
{
    return_value_if_fail(sddc, -1);

    while (1) {
        struct timeval tv;
        fd_set         rfds;
        int            ret;

        FD_ZERO(&rfds);

        FD_SET(sddc->fd, &rfds);

        tv.tv_sec  = SDDC_CFG_RETRIES_INTERVAL / 1000;
        tv.tv_usec = (SDDC_CFG_RETRIES_INTERVAL % 1000) * 1000;

        ret = select(sddc->fd + 1, &rfds, NULL, NULL, &tv);
        if (ret > 0) {
            struct sockaddr_in cli_addr;
            socklen_t          addrlen = sizeof(cli_addr);

            int len = recvfrom(sddc->fd, sddc->recv_buf, sizeof(sddc->recv_buf), 0,
                               (struct sockaddr *)&cli_addr, &addrlen);
            if (len >= sizeof(sddc_header_t)) {
                sddc_header_t  *header = (sddc_header_t *)sddc->recv_buf;
                char            ip_str[IP4ADDR_STRLEN_MAX];
                sddc_edgeros_t *edgeros;
                size_t          payload_len;
                void           *payload;
                int             unpack_ret;

                header->seqno  = ntohs(header->seqno);
                header->length = ntohs(header->length);

                inet_ntoa_r(cli_addr.sin_addr, ip_str, sizeof(ip_str));

                sddc_mutex_lock(&sddc->lockid);

                /*
                 * Updated EdgerOS address info
                 */
                edgeros = __sddc_edgeros_update(sddc, header->uid, &cli_addr);

                switch (SDDC_GET_TYPE(header)) {
                case SDDC_TYPE_PING:                                        /* PING                 */
                    if (header->flags_type & SDDC_FLAG_REQ) {               /* PING request         */
                        SDDC_LOG_DBG("Receive ping from: %s.\n", ip_str);

                        /*
                         * Build PING respond
                         */
                        len = __sddc_build_packet(sddc, sddc->send_buf,
                                                  SDDC_TYPE_PING,
                                                  SDDC_FLAG_ACK,
                                                  SDDC_SEC_FLAG_NONE,
                                                  header->seqno,
                                                  NULL, 0);

                        /*
                         * Send PING respond to EdgerOS
                         */
                        sendto(sddc->fd, sddc->send_buf, len, 0,
                               (const struct sockaddr *)&cli_addr, sizeof(cli_addr));
                    } else {
                        SDDC_LOG_DBG("Receive ping respond from: %s.\n", ip_str);
                    }
                    break;

                case SDDC_TYPE_DISCOVER:
                    SDDC_LOG_DBG("Receive discover from: %s.\n", ip_str);

                    if (sddc->report_data != NULL) {
                        /*
                         * Build REPORT
                         */
                        len = __sddc_build_packet(sddc, sddc->send_buf,
                                                  SDDC_TYPE_REPORT,
                                                  SDDC_FLAG_NONE,
                                                  SDDC_SEC_FLAG_NONE,
                                                  sddc->seqno++,
                                                  sddc->report_data, sddc->report_data_len);

                        /*
                         * Send REPORT to EdgerOS
                         */
                        sendto(sddc->fd, sddc->send_buf, len, 0,
                               (const struct sockaddr *)&cli_addr, sizeof(cli_addr));
                    }
                    break;

                case SDDC_TYPE_UPDATE:
                    if (header->flags_type & SDDC_FLAG_REQ) {               /* UPDATE request       */
                        SDDC_LOG_DBG("Receive update request from: %s.\n", ip_str);

                        if ((len - sizeof(sddc_header_t)) >= header->length) {
                            if (sddc->on_update != NULL) {
#if SDDC_CFG_SECURITY_EN > 0
                                if (header->security & SDDC_SEC_FLAG_CRYPTO) {
                                    unpack_ret = __sddc_decrypt(sddc, SDDC_PACKET_PAYLOAD(sddc->recv_buf), header->length,
                                                                sddc->decypt_buf, &payload_len);
                                    payload    = sddc->decypt_buf;
                                } else
#endif
                                {
                                    payload     = SDDC_PACKET_PAYLOAD(sddc->recv_buf);
                                    payload_len = header->length;
                                    unpack_ret  = 0;
                                }

                                if ((unpack_ret == 0) && sddc->on_update(sddc, header->uid, payload, payload_len)) {
                                    /*
                                     * Build update respond
                                     */
                                    len = __sddc_build_packet(sddc, sddc->send_buf,
                                                              SDDC_TYPE_UPDATE,
                                                              SDDC_FLAG_ACK,
                                                              SDDC_SEC_FLAG_NONE,
                                                              header->seqno,
                                                              NULL, 0);

                                    /*
                                     * Send update respond to EdgerOS
                                     */
                                    sendto(sddc->fd, sddc->send_buf, len, 0,
                                           (const struct sockaddr *)&cli_addr, sizeof(cli_addr));
                                }
                            }
                        } else {                                            /* Payload length error */
                            SDDC_LOG_ERR("Payload length error!\n");
                        }
                    } else {                                                /* UPDATE respond       */
                        SDDC_LOG_DBG("Receive update respond from: %s.\n", ip_str);
                    }
                    break;

                case SDDC_TYPE_INVITE:
                    if (header->flags_type & SDDC_FLAG_REQ) {               /* INVITE request       */
                        SDDC_LOG_DBG("Receive invite request from: %s.\n", ip_str);
                        if ((len - sizeof(sddc_header_t)) >= header->length) {
                            if (sddc->on_invite != NULL) {
#if SDDC_CFG_SECURITY_EN > 0
                                if (header->security & SDDC_SEC_FLAG_CRYPTO) {
                                    unpack_ret = __sddc_decrypt(sddc, SDDC_PACKET_PAYLOAD(sddc->recv_buf), header->length,
                                                                sddc->decypt_buf, &payload_len);
                                    payload    = sddc->decypt_buf;
                                } else
#endif
                                {
                                    payload     = SDDC_PACKET_PAYLOAD(sddc->recv_buf);
                                    payload_len = header->length;
                                    unpack_ret  = 0;
                                }

                                if ((unpack_ret == 0) && sddc->on_invite(sddc, header->uid, payload, payload_len)) {
                                    /*
                                     * Build INVITE respond
                                     */
                                    len = __sddc_build_packet(sddc, sddc->send_buf,
                                                              SDDC_TYPE_INVITE,
                                                              SDDC_FLAG_ACK | SDDC_FLAG_JOIN,
#if SDDC_CFG_SECURITY_EN > 0
                                                              sddc->security_en ? SDDC_SEC_FLAG_CRYPTO : SDDC_SEC_FLAG_NONE,
#else
                                                              SDDC_SEC_FLAG_NONE,
#endif
                                                              header->seqno,
                                                              sddc->invite_data, sddc->invite_data_len);

                                    /*
                                     * Send INVITE respond to EdgerOS
                                     */
                                    sendto(sddc->fd, sddc->send_buf, len, 0,
                                           (const struct sockaddr *)&cli_addr, sizeof(cli_addr));

                                    /*
                                     * Call after send INVITE respond
                                     */
                                    __sddc_after_invite_respond(sddc, edgeros, header->uid, &cli_addr);

                                } else {
                                    sddc_sleep(1);

                                    /*
                                     * Build REFUSE respond
                                     */
                                    len = __sddc_build_packet(sddc, sddc->send_buf,
                                                              SDDC_TYPE_INVITE,
                                                              SDDC_FLAG_ACK,
                                                              SDDC_SEC_FLAG_NONE,
                                                              header->seqno,
                                                              NULL, 0);

                                    /*
                                     * Send REFUSE respond to EdgerOS
                                     */
                                    sendto(sddc->fd, sddc->send_buf, len, 0,
                                           (const struct sockaddr *)&cli_addr, sizeof(cli_addr));
                                }
                            }
                        } else {                                            /* Payload length error */
                            SDDC_LOG_ERR("Payload length error!\n");
                        }
                    } else {                                                /* Invite respond       */
                        SDDC_LOG_DBG("Receive invite respond from: %s.\n", ip_str);
                    }
                    break;

                case SDDC_TYPE_MESSAGE:
                    if (edgeros != NULL) {
                        if (header->flags_type & SDDC_FLAG_ACK) {           /* MESSAGE ACK          */
                            SDDC_LOG_DBG("Receive message respond from: %s.\n", ip_str);

                            if (sddc->on_message_ack != NULL) {
                                sddc->on_message_ack(sddc, edgeros->uid, header->seqno);
                            }

                            if (edgeros->mqueue_len > 0) {
                                sddc_list_head_t *itervar;
                                sddc_message_t *message;

                                sddc_list_for_each(itervar, &edgeros->mqueue) {
                                    message = SDDC_CONTAINER_OF(itervar, sddc_message_t, node);
                                    if (message->seqno == header->seqno) {
                                        sddc_list_del(&message->node);
                                        sddc_free(message);
                                        edgeros->mqueue_len--;
                                        break;
                                    }
                                }
                            }

                        } else {                                                /* MESSAGE request      */
                            SDDC_LOG_DBG("Receive message request from: %s.\n", ip_str);

                            if ((len - sizeof(sddc_header_t)) >= header->length) {
                                if (sddc->on_message != NULL) {
#if SDDC_CFG_SECURITY_EN > 0
                                    if (header->security & SDDC_SEC_FLAG_CRYPTO) {
                                        unpack_ret = __sddc_decrypt(sddc, SDDC_PACKET_PAYLOAD(sddc->recv_buf), header->length,
                                                                    sddc->decypt_buf, &payload_len);
                                        payload    = sddc->decypt_buf;
                                    } else
#endif
                                    {
                                        payload     = SDDC_PACKET_PAYLOAD(sddc->recv_buf);
                                        payload_len = header->length;
                                        unpack_ret  = 0;
                                    }

                                    if ((unpack_ret == 0) && sddc->on_message(sddc, edgeros->uid, payload, payload_len)) {
                                        if (header->flags_type & SDDC_FLAG_REQ) {
                                            /*
                                             * Build MESSAGE ACK
                                             */
                                            len = __sddc_build_packet(sddc, sddc->send_buf,
                                                                      SDDC_TYPE_MESSAGE,
                                                                      SDDC_FLAG_ACK,
                                                                      SDDC_SEC_FLAG_NONE,
                                                                      header->seqno,
                                                                      NULL, 0);

                                            /*
                                             * Send MESSAGE ACK to EdgerOS
                                             */
                                            sendto(sddc->fd, sddc->send_buf, len, 0,
                                                   (const struct sockaddr *)&cli_addr, sizeof(cli_addr));
                                        }
                                    }
                                }
                            } else {                                            /* Payload length error */
                                SDDC_LOG_ERR("Payload length error.\n");
                            }
                        }
                    }
                    break;

                case SDDC_TYPE_REPORT:
                    /*
                     * Do nothing
                     */
                    SDDC_LOG_DBG("Receive report from: %s.\n", ip_str);
                    break;

                default:
                    /*
                     * Do nothing
                     */
                    SDDC_LOG_ERR("Receive unrecognizable packet from: %s.\n", ip_str);
                    break;
                }

                sddc_mutex_unlock(&sddc->lockid);
            }

        } else if (ret == 0) {
            sddc_list_head_t *itervar;
            sddc_list_head_t *savevar;
            sddc_edgeros_t   *edgeros;

            sddc_mutex_lock(&sddc->lockid);

            sddc_list_for_each_safe(itervar, savevar, &sddc->edgeros_list) {
                edgeros = SDDC_CONTAINER_OF(itervar, sddc_edgeros_t, node);

                while (edgeros->mqueue_len > 0) {
                    sddc_message_t *message = SDDC_CONTAINER_OF(edgeros->mqueue.next, sddc_message_t, node);
                    sddc_header_t  *header  = (sddc_header_t *)message->packet;

                    if (header->flags_type & SDDC_FLAG_REQ) {
                        if (message->retries > 0) {
                            message->retries--;
                            sendto(sddc->fd, message->packet, message->packet_len, 0,
                                   (const struct sockaddr *)&edgeros->addr, sizeof(edgeros->addr));
                            break;

                        } else {
                            if (sddc->on_message_lost != NULL) {
                                sddc->on_message_lost(sddc, edgeros->uid, message->seqno);
                            }
                        }
                    } else {
                        sendto(sddc->fd, message->packet, message->packet_len, 0,
                               (const struct sockaddr *)&edgeros->addr, sizeof(edgeros->addr));
                    }

                    sddc_list_del(&message->node);
                    sddc_free(message);
                    edgeros->mqueue_len--;
                }

                if (edgeros->alive > 0) {
                    edgeros->alive--;
                } else {
                    if (sddc->on_edgeros_lost != NULL) {
                        sddc->on_edgeros_lost(sddc, edgeros->uid);
                    }
                    __sddc_edgeros_destroy(edgeros);
                }
            }

            sddc_mutex_unlock(&sddc->lockid);

        } else {
            break;
        }
    }

    return -1;
}

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
                      uint16_t *seqno)
{
    sddc_edgeros_t *edgeros;
    uint8_t flag;
    uint8_t security_flag = SDDC_SEC_FLAG_NONE;
    int len;
    int ret = -1;

    return_value_if_fail(sddc && uid && payload && payload_len, -1);

    sddc_mutex_lock(&sddc->lockid);

    edgeros = __sddc_edgeros_find(sddc, uid);
    goto_error_if_fail(edgeros != NULL);

    if (seqno != NULL) {
        *seqno = sddc->seqno;
    }

    retries = 0;
    flag = (retries > 0) ? SDDC_FLAG_REQ : 0;
    if (urgent) {
        flag |= SDDC_FLAG_URGENT;
    }

    if ((retries == 0) && (urgent || (edgeros->mqueue_len == 0))) {
__send_urgent:
#if SDDC_CFG_SECURITY_EN > 0
        if (sddc->security_en) {
            __sddc_encrypt(sddc, payload, payload_len, sddc->send_buf + sizeof(sddc_header_t), &payload_len);
            payload = sddc->send_buf + sizeof(sddc_header_t);
            security_flag |= SDDC_SEC_FLAG_CRYPTO;
        }
#endif

        len = __sddc_build_packet(sddc, sddc->send_buf,
                                  SDDC_TYPE_MESSAGE,
                                  flag,
                                  security_flag,
                                  sddc->seqno++,
                                  payload, payload_len);

        if (sendto(sddc->fd, sddc->send_buf, len, 0,
                   (const struct sockaddr *)&edgeros->addr, sizeof(edgeros->addr)) == len) {
            ret = 0;
        }
    } else {
        sddc_message_t *message = NULL;

        if (edgeros->mqueue_len < SDDC_CFG_MQUEUE_SIZE) {
            message = sddc_malloc(sizeof(sddc_message_t) + sizeof(sddc_header_t) + payload_len
#if SDDC_CFG_SECURITY_EN > 0
                                  + (sddc->security_en ? 16 : 0)
#endif
                                 );

            if (message != NULL) {
                message->edgeros = edgeros;
                message->retries = retries;
                message->seqno   = sddc->seqno;

#if SDDC_CFG_SECURITY_EN > 0
                if (sddc->security_en) {
                    __sddc_encrypt(sddc, payload, payload_len, message->packet + sizeof(sddc_header_t), &payload_len);
                    payload = message->packet + sizeof(sddc_header_t);
                    security_flag |= SDDC_SEC_FLAG_CRYPTO;
                }
#endif

                message->packet_len = __sddc_build_packet(sddc, message->packet,
                                                          SDDC_TYPE_MESSAGE,
                                                          flag,
                                                          security_flag,
                                                          sddc->seqno++,
                                                          payload, payload_len);

                if (urgent) {
                    sddc_list_add(&message->node, &edgeros->mqueue);
                } else {
                    sddc_list_add_tail(&message->node, &edgeros->mqueue);
                }

                edgeros->mqueue_len++;

                ret = 0;
            }
        }

        if (urgent) {
            if (message != NULL) {
                if (message->retries > 0) {
                    message->retries--;
                }
                sendto(sddc->fd, message->packet, message->packet_len, 0,
                       (const struct sockaddr *)&edgeros->addr, sizeof(edgeros->addr));
            } else {
                goto __send_urgent;
            }
        }
    }

error:
    sddc_mutex_unlock(&sddc->lockid);

    return ret;
}

/**
 * @brief Send message request to a specified EdgerOS which connected.
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
                           uint16_t *seqno)
{
    sddc_list_head_t *itervar;
    sddc_edgeros_t   *edgeros;
    int               ret = 0;

    return_value_if_fail(sddc && payload && payload_len, -1);

    sddc_mutex_lock(&sddc->lockid);

    sddc_list_for_each(itervar, &sddc->edgeros_list) {
        edgeros = SDDC_CONTAINER_OF(itervar, sddc_edgeros_t, node);

        if (seqno != NULL) {
            ret |= sddc_send_message(sddc, edgeros->uid,
                                     payload, payload_len,
                                     retries, urgent, seqno);
            seqno++;
        } else {
            ret |= sddc_send_message(sddc, edgeros->uid,
                                     payload, payload_len,
                                     retries, urgent, NULL);
        }
    }

    sddc_mutex_unlock(&sddc->lockid);

    return ret;
}
