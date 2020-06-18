/*
 * Copyright (c) 2019 MS-RTOS Team.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: sddc.c SDDC device end server implement.
 *
 * Author: Jiao.jinxing <jiaojixing@acoinfo.com>
 *
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <stdlib.h>
#include "sddc_config.h"
#include "sddc.h"
#include "sddc_list.h"

/* Header magic and version */
#define SDDC_MAGIC          0x5
#define SDDC_VERSION        0x1

/* Header types */
#define SDDC_TYPE_DISCOVER  0x00
#define SDDC_TYPE_REPORT    0x01
#define SDDC_TYPE_UPDATE    0x02
#define SDDC_TYPE_INVITE    0x03
#define SDDC_TYPE_PING      0x04
#define SDDC_TYPE_MESSAGE   0x05

/* Header type set and get */
#define SDDC_SET_TYPE(h, type)  \
        ((h)->flags_type) &= 0xe0; \
        ((h)->flags_type) |= (type)

#define SDDC_GET_TYPE(h) \
        ((h)->flags_type & 0x1f)

/* Header flags */
#define SDDC_FLAG_ACK  0x80
#define SDDC_FLAG_REQ  0x40
#define SDDC_FLAG_JOIN 0x20

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
struct sddc_header {
    uint8_t magic_ver;
    uint8_t flags_type;
    uint16_t seqno;
    uint8_t uid[SDDC_UID_LEN];
    uint16_t reserved;
    uint16_t length;
};

/* EdgerOS */
typedef struct {
    sddc_list_head_t node;
    uint8_t uid[SDDC_UID_LEN];
    struct sockaddr_in addr;
} sddc_edgeros_t;

static uint8_t               g_sddc_recv_buffer[SDDC_RECV_BUF_SIZE];
static uint8_t               g_sddc_send_buffer[SDDC_SEND_BUF_SIZE];
static uint8_t               g_sddc_uid[SDDC_UID_LEN];
static const char *          g_sddc_report_data;
static const char *          g_sddc_invite_data;
static uint16_t              g_sddc_seqno;
static sddc_on_invite_t      g_sddc_on_invite;
static sddc_on_invite_end_t  g_sddc_on_invite_end;
static sddc_on_update_t      g_sddc_on_update;
static sddc_on_message_t     g_sddc_on_message;
static sddc_on_message_ack_t g_sddc_on_message_ack;
static int                   g_sddc_fd = -1;
static sddc_mutex_t          g_sddc_lockid;
static SDDC_LIST_HEAD(g_sddc_edgeros_list);

static int sddc_build_packet(uint8_t type, uint8_t flags, uint16_t seqno, const char *data, size_t len)
{
    struct sddc_header *header = (struct sddc_header *)g_sddc_send_buffer;

    bzero(header, sizeof(struct sddc_header));
    header->magic_ver = SDDC_MAGIC | (SDDC_VERSION << 4);
    SDDC_SET_TYPE(header, type);
    header->flags_type |= flags;

    header->seqno  = htons(seqno);
    header->length = htons(len);
    memcpy(header->uid, g_sddc_uid, sizeof(header->uid));

    if (len > 0) {
        memcpy(g_sddc_send_buffer + sizeof(struct sddc_header), data, len);
    }

    return sizeof(struct sddc_header) + len;
}

int sddc_set_on_message(sddc_on_message_t on_message)
{
    g_sddc_on_message = on_message;
    return 0;
}

int sddc_set_on_message_ack(sddc_on_message_ack_t on_message_ack)
{
    g_sddc_on_message_ack = on_message_ack;
    return 0;
}

int sddc_set_on_invite(sddc_on_invite_t on_invite)
{
    g_sddc_on_invite = on_invite;
    return 0;
}

int sddc_set_on_invite_end(sddc_on_invite_end_t on_invite_end)
{
    g_sddc_on_invite_end = on_invite_end;
    return 0;
}

int sddc_set_on_update(sddc_on_update_t on_update)
{
    g_sddc_on_update = on_update;
    return 0;
}

int sddc_set_report_data(const char *report_data)
{
    g_sddc_report_data = report_data;
    return 0;
}

int sddc_set_invite_data(const char *invite_data)
{
    g_sddc_invite_data = invite_data;
    return 0;
}

int sddc_set_uid(const uint8_t *mac_addr)
{
    g_sddc_uid[0] = mac_addr[0];
    g_sddc_uid[1] = mac_addr[1];
    g_sddc_uid[2] = mac_addr[2];
    g_sddc_uid[3] = 0xfe;
    g_sddc_uid[4] = 0x80;
    g_sddc_uid[5] = mac_addr[3];
    g_sddc_uid[6] = mac_addr[4];
    g_sddc_uid[7] = mac_addr[5];

    return 0;
}

int sddc_send_update(const char *invite_data)
{
    sddc_edgeros_t *edgeros;
    sddc_list_head_t *itervar;
    int len;

    sddc_mutex_lock(g_sddc_lockid);

    g_sddc_invite_data = invite_data;

    len = sddc_build_packet(SDDC_TYPE_UPDATE, SDDC_FLAG_REQ, g_sddc_seqno++, g_sddc_invite_data, strlen(g_sddc_invite_data));

    sddc_list_for_each(itervar, &g_sddc_edgeros_list) {
        edgeros = SDDC_CONTAINER_OF(itervar, sddc_edgeros_t, node);
        sendto(g_sddc_fd, g_sddc_send_buffer, len, 0, (const struct sockaddr *)&edgeros->addr, sizeof(edgeros->addr));
    }

    sddc_mutex_unlock(g_sddc_lockid);

    return 0;
}

int sddc_send_message(const struct sockaddr_in *addr, const char *message, sddc_bool_t ack_req, uint16_t *seqno)
{
    int len;

    sddc_mutex_lock(g_sddc_lockid);

    if (seqno != NULL) {
        *seqno = g_sddc_seqno;
    }

    len = sddc_build_packet(SDDC_TYPE_MESSAGE, ack_req ? SDDC_FLAG_REQ : 0, g_sddc_seqno++, message, strlen(message));

    sendto(g_sddc_fd, g_sddc_send_buffer, len, 0, (const struct sockaddr *)addr, sizeof(struct sockaddr_in));

    sddc_mutex_unlock(g_sddc_lockid);

    return 0;
}

int sddc_broadcast_message(const char *message, sddc_bool_t ack_req, uint16_t *seqno)
{
    sddc_edgeros_t *edgeros;
    sddc_list_head_t *itervar;
    int len;

    sddc_mutex_lock(g_sddc_lockid);

    if (seqno != NULL) {
        *seqno = g_sddc_seqno;
    }

    len = sddc_build_packet(SDDC_TYPE_MESSAGE, ack_req ? SDDC_FLAG_REQ : 0, g_sddc_seqno++, message, strlen(message));

    sddc_list_for_each(itervar, &g_sddc_edgeros_list) {
        edgeros = SDDC_CONTAINER_OF(itervar, sddc_edgeros_t, node);

        sendto(g_sddc_fd, g_sddc_send_buffer, len, 0, (const struct sockaddr *)&edgeros->addr, sizeof(edgeros->addr));
    }

    sddc_mutex_unlock(g_sddc_lockid);

    return 0;
}

int sddc_server_loop(uint16_t port)
{
    struct sockaddr_in serv_addr, cli_addr;
    char ip_str[IP4ADDR_STRLEN_MAX];

    if (sddc_mutex_create(&g_sddc_lockid) != 0) {
        sddc_log(SDDC_LOG_ERR, "Failed to create lock!\n");
        return -ENOMEM;
    }

    g_sddc_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_sddc_fd < 0) {
        sddc_log(SDDC_LOG_ERR, "Failed to create socket!\n");
        sddc_mutex_destroy(g_sddc_lockid);
        return -errno;
    }

    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    if (bind(g_sddc_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        int err = -errno;
        close(g_sddc_fd);
        sddc_mutex_destroy(g_sddc_lockid);
        sddc_log(SDDC_LOG_ERR, "Failed to bind port %u!\n", (unsigned)port);
        return err;
    }

    while (1) {
        socklen_t addrlen = sizeof(cli_addr);
        int len;

        len = recvfrom(g_sddc_fd, g_sddc_recv_buffer, sizeof(g_sddc_recv_buffer), 0, (struct sockaddr *)&cli_addr, &addrlen);
        if (len >= sizeof(struct sddc_header)) {
            struct sddc_header *packet = (struct sddc_header *)g_sddc_recv_buffer;

            packet->seqno  = ntohs(packet->seqno);
            packet->length = ntohs(packet->length);

            inet_ntoa_r(cli_addr.sin_addr, ip_str, sizeof(ip_str));

            sddc_mutex_lock(g_sddc_lockid);

            switch (SDDC_GET_TYPE(packet)) {
            case SDDC_TYPE_PING:
                if (packet->flags_type & SDDC_FLAG_REQ) {
                    len = sddc_build_packet(SDDC_TYPE_PING, SDDC_FLAG_ACK, packet->seqno, NULL, 0);
                    sendto(g_sddc_fd, g_sddc_send_buffer, len, 0, (const struct sockaddr *)&cli_addr, sizeof(cli_addr));
                } else {
                    sddc_log(SDDC_LOG_DEBUG, "Receive ping respond from: %s.\n", ip_str);
                }
                break;

            case SDDC_TYPE_DISCOVER:
                sddc_log(SDDC_LOG_DEBUG, "Receive discover from: %s.\n", ip_str);
                if (g_sddc_report_data != NULL) {
                    len = sddc_build_packet(SDDC_TYPE_REPORT, 0, g_sddc_seqno++, g_sddc_report_data, strlen(g_sddc_report_data));
                    sendto(g_sddc_fd, g_sddc_send_buffer, len, 0, (const struct sockaddr *)&cli_addr, sizeof(cli_addr));
                }
                break;

            case SDDC_TYPE_REPORT:
                /*
                 * Do nothing
                 */
                sddc_log(SDDC_LOG_DEBUG, "Receive report from: %s.\n", ip_str);
                break;

            case SDDC_TYPE_UPDATE:
                if (packet->flags_type & SDDC_FLAG_REQ) {
                    sddc_log(SDDC_LOG_DEBUG, "Receive update request from: %s.\n", ip_str);
                    if ((len - sizeof(struct sddc_header)) >= packet->length) {
                        if (g_sddc_on_update != NULL) {
                            if (g_sddc_on_update(&cli_addr, (char *)g_sddc_recv_buffer + sizeof(struct sddc_header), packet->length)) {
                                len = sddc_build_packet(SDDC_TYPE_UPDATE, SDDC_FLAG_ACK, packet->seqno, NULL, 0);
                                sendto(g_sddc_fd, g_sddc_send_buffer, len, 0, (const struct sockaddr *)&cli_addr, sizeof(cli_addr));
                            }
                        }
                    } else {
                        sddc_log(SDDC_LOG_ERR, "Payload length error!\n");
                    }
                } else {
                    sddc_log(SDDC_LOG_DEBUG, "Receive update respond from: %s.\n", ip_str);
                }
                break;

            case SDDC_TYPE_INVITE:
                if (packet->flags_type & SDDC_FLAG_REQ) {
                    sddc_log(SDDC_LOG_DEBUG, "Receive invite request from: %s.\n", ip_str);
                    if ((len - sizeof(struct sddc_header)) >= packet->length) {
                        if (g_sddc_on_invite != NULL) {
                            if (g_sddc_on_invite(&cli_addr, (char *)g_sddc_recv_buffer + sizeof(struct sddc_header), packet->length)) {
                                len = sddc_build_packet(SDDC_TYPE_INVITE, SDDC_FLAG_ACK | SDDC_FLAG_JOIN, packet->seqno,
                                                        g_sddc_invite_data, strlen(g_sddc_invite_data));
                                sendto(g_sddc_fd, g_sddc_send_buffer, len, 0, (const struct sockaddr *)&cli_addr, sizeof(cli_addr));

                                {
                                    sddc_edgeros_t *edgeros;
                                    sddc_list_head_t *itervar;
                                    sddc_bool_t found = SDDC_FALSE;

                                    sddc_list_for_each(itervar, &g_sddc_edgeros_list) {
                                        edgeros = SDDC_CONTAINER_OF(itervar, sddc_edgeros_t, node);
                                        if (memcmp(edgeros->uid, packet->uid, sizeof(edgeros->uid)) == 0) {
                                            found = SDDC_TRUE;
                                            break;
                                        }
                                    }

                                    if (!found) {
                                        edgeros = malloc(sizeof(sddc_edgeros_t));
                                    }

                                    if (edgeros) {
                                        edgeros->addr = cli_addr;
                                        memcpy(edgeros->uid, packet->uid, sizeof(edgeros->uid));

                                        if (!found) {
                                            sddc_list_add(&edgeros->node, &g_sddc_edgeros_list);
                                        }
                                    } else {
                                        sddc_log(SDDC_LOG_ERR, "No memory!\n");
                                    }
                                }

                                if (g_sddc_on_invite_end != NULL) {
                                    g_sddc_on_invite_end(&cli_addr);
                                }
                            }
                        }
                    } else {
                        sddc_log(SDDC_LOG_ERR, "Payload length error!\n");
                    }
                } else {
                    sddc_log(SDDC_LOG_DEBUG, "Receive invite respond from: %s.\n", ip_str);
                }
                break;

            case SDDC_TYPE_MESSAGE:
                if (packet->flags_type & SDDC_FLAG_ACK) {
                    sddc_log(SDDC_LOG_DEBUG, "Receive message respond from: %s.\n", ip_str);
                    if (g_sddc_on_message_ack != NULL) {
                        g_sddc_on_message_ack(&cli_addr, packet->seqno);
                    }
                } else {
                    sddc_log(SDDC_LOG_DEBUG, "Receive message request from: %s.\n", ip_str);
                    if ((len - sizeof(struct sddc_header)) >= packet->length) {
                        if (g_sddc_on_message != NULL) {
                            if (g_sddc_on_message(&cli_addr, (char *)g_sddc_recv_buffer + sizeof(struct sddc_header), packet->length)) {
                                if (packet->flags_type & SDDC_FLAG_REQ) {
                                    len = sddc_build_packet(SDDC_TYPE_MESSAGE, SDDC_FLAG_ACK, packet->seqno, NULL, 0);
                                    sendto(g_sddc_fd, g_sddc_send_buffer, len, 0, (const struct sockaddr *)&cli_addr, sizeof(cli_addr));
                                }
                            }
                        }
                    } else {
                        sddc_log(SDDC_LOG_ERR, "Payload length error.\n");
                    }
                }
                break;

            default:
                sddc_log(SDDC_LOG_ERR, "Receive unrecognizable packet from: %s.\n", ip_str);
                break;
            }

            sddc_mutex_unlock(g_sddc_lockid);
        }
    }

    close(g_sddc_fd);
    sddc_mutex_destroy(g_sddc_lockid);

    return 0;
}
