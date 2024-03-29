/*
 * Copyright (c) 2015-2020 ACOINFO Co., Ltd.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: sddc_connector_example.c SDDC connector example.
 *
 * Author: Jiao.jinxing <jiaojinxing@acoinfo.com>
 *
 */

#ifdef __MS_RTOS__
#include <ms_rtos.h>
#elif defined(__linux__) || defined(SYLIXOS)
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>

#if defined(SYLIXOS)
#define SDDC_CFG_NETIF_NAME "en1"
#else
#define SDDC_CFG_NETIF_NAME "eth0"
#endif
#endif
#include "sddc.h"
#include "cJSON.h"

static int led1_fd;
static int led2_fd;
static int led3_fd;

static int key1_fd;
static int key2_fd;
static int key3_fd;

static int sockfd;

static ms_bool_t led_state_bak[3];

static ms_handle_t conn_mqueue_id;
static sddc_connector_t *conn_mqueue_buf[4];

#define __RECV_IMAGE_FILENAME   "/sd0/recv_img.jpg"
#define __SEND_IMAGE_FILENAME   "/sd0/send_img.png"

/*
 * Get picture from connector
 */
static void iot_pi_get_pic(sddc_connector_t *conn)
{
    sddc_bool_t finish;
    void *data;
    ssize_t ret;
    size_t totol_len = 0;

    int fd = ms_io_open(__RECV_IMAGE_FILENAME, O_CREAT | O_RDWR | O_TRUNC, 0666);
    sddc_goto_error_if_fail(fd >= 0);

    while (1) {
        ret = sddc_connector_get(conn, &data, &finish);
        if (ret < 0) {
            sddc_printf("Failed to get!\n");
            break;
        } else {
            sddc_printf("Get %d byte\n", ret);
            totol_len += ret;
            if (ms_io_write(fd, data, ret) != ret) {
                sddc_printf("Failed to write file!\n");
                break;
            }
            if (finish) {
                break;
            }
        }

        ms_io_write(led1_fd, &led_state_bak[0], 1);
        led_state_bak[0] = !led_state_bak[0];
    }

    sddc_printf("Total get %d byte\n", totol_len);
    ms_io_close(fd);

error:
    sddc_connector_destroy(conn);
}

/*
 * Put picture to connector
 */
static void iot_pi_put_pic(sddc_connector_t *conn)
{
    int ret;
    size_t totol_len = 0;
    char buf[1024];
    ssize_t len;
    ms_stat_t st;

    int fd = ms_io_open(__SEND_IMAGE_FILENAME, O_RDONLY, 0666);
    sddc_goto_error_if_fail(fd >= 0);

    ret = ms_io_fstat(fd, &st);
    sddc_goto_error_if_fail(ret == 0);

    while (totol_len < st.st_size) {
        len = ms_io_read(fd, buf, sizeof(buf));
        if (len <= 0) {
            sddc_printf("Failed to read file!\n");
            break;
        }

        ret = sddc_connector_put(conn, buf, len, (totol_len + len) == st.st_size);
        if (ret < 0) {
            sddc_printf("Failed to put!\n");
            break;
        }
        totol_len += len;

        sddc_printf("Put %d byte\n", len);

        ms_io_write(led2_fd, &led_state_bak[1], 1);
        led_state_bak[1] = !led_state_bak[1];
    }

    sddc_printf("Total put %d byte\n", totol_len);

error:
    if (fd >= 0) {
        ms_io_close(fd);
    }
    sddc_connector_destroy(conn);
}

/*
 * Connector service thread
 */
static void iot_pi_connector_thread(ms_ptr_t arg)
{
    sddc_connector_t *conn;
    int ret;

    while (1) {
        ret = ms_mqueue_recv(conn_mqueue_id, &conn, MS_TIMEOUT_FOREVER);
        sddc_return_if_fail(ret == MS_ERR_NONE);

        if (sddc_connector_mode(conn) == 1) {
            iot_pi_get_pic(conn);
        } else {
            iot_pi_put_pic(conn);
        }
    }
}

/*
 * Handle MESSAGE
 */
static sddc_bool_t iot_pi_on_message(sddc_t *sddc, const uint8_t *uid, const char *message, size_t len)
{
    cJSON *root = cJSON_Parse(message);
    cJSON *cmd;
    char *str;

    sddc_return_value_if_fail(root, SDDC_TRUE);

    str = cJSON_Print(root);
    sddc_goto_error_if_fail(str);

    sddc_printf("iot_pi_on_message: %s\n", str);
    cJSON_free(str);

    /*
     * Parse here
     */
    cmd = cJSON_GetObjectItem(root, "cmd");
    if (cJSON_IsString(cmd)) {
        sddc_bool_t get_mode;
        int ret;

        if (strcmp(cmd->valuestring, "recv") == 0) {
            get_mode = SDDC_FALSE;
        } else if (strcmp(cmd->valuestring, "send") == 0) {
            get_mode = SDDC_TRUE;

            cJSON *size = cJSON_GetObjectItem(root, "size");
            if (size && cJSON_IsNumber(size)) {
                sddc_printf("EdgerOS send picture to me, file size %d\n", (int)size->valuedouble);
            }
        } else {
            sddc_printf("Command no support!\n");
            goto error;
        }

        cJSON *connector = cJSON_GetObjectItem(root, "connector");
        sddc_goto_error_if_fail(cJSON_IsObject(connector));

        cJSON *port = cJSON_GetObjectItem(connector, "port");
        sddc_goto_error_if_fail(cJSON_IsNumber(port));

        cJSON *token = cJSON_GetObjectItem(connector, "token");
        sddc_goto_error_if_fail(!token || cJSON_IsString(token));

        sddc_connector_t *conn = sddc_connector_create(sddc, uid, port->valuedouble, token ? token->valuestring : NULL, get_mode);
        sddc_goto_error_if_fail(conn);

        ret = ms_mqueue_trypost(conn_mqueue_id, &conn);
        if (ret != MS_ERR_NONE) {
            sddc_connector_destroy(conn);
            sddc_goto_error_if_fail(ret == MS_ERR_NONE);
        }

    } else {
        sddc_printf("Command no specify!\n");
    }

error:
    cJSON_Delete(root);

    return SDDC_TRUE;
}

/*
 * Handle MESSAGE ACK
 */
static void iot_pi_on_message_ack(sddc_t *sddc, const uint8_t *uid, uint16_t seqno)
{
}

/*
 * Handle MESSAGE lost
 */
static void iot_pi_on_message_lost(sddc_t *sddc, const uint8_t *uid, uint16_t seqno)
{
}

/*
 * Handle EdgerOS lost
 */
static void iot_pi_on_edgeros_lost(sddc_t *sddc, const uint8_t *uid)
{
}

/*
 * Handle UPDATE
 */
static sddc_bool_t iot_pi_on_update(sddc_t *sddc, const uint8_t *uid, const char *udpate_data, size_t len)
{
    cJSON *root = cJSON_Parse(udpate_data);
    char *str;

    sddc_return_value_if_fail(root, SDDC_FALSE);

    /*
     * Parse here
     */

    str = cJSON_Print(root);
    sddc_goto_error_if_fail(str);

    sddc_printf("iot_pi_on_update: %s\n", str);
    cJSON_free(str);

    cJSON_Delete(root);

    return SDDC_TRUE;

error:
    cJSON_Delete(root);

    return SDDC_FALSE;
}

/*
 * Handle INVITE
 */
static sddc_bool_t iot_pi_on_invite(sddc_t *sddc, const uint8_t *uid, const char *invite_data, size_t len)
{
    cJSON *root = cJSON_Parse(invite_data);
    char *str;

    sddc_return_value_if_fail(root, SDDC_FALSE);

    /*
     * Parse here
     */

    str = cJSON_Print(root);
    sddc_goto_error_if_fail(str);

    sddc_printf("iot_pi_on_invite: %s\n", str);
    cJSON_free(str);

    cJSON_Delete(root);

    return SDDC_TRUE;

error:
    cJSON_Delete(root);

    return SDDC_FALSE;
}

/*
 * Handle the end of INVITE
 */
static sddc_bool_t iot_pi_on_invite_end(sddc_t *sddc, const uint8_t *uid)
{
    return SDDC_TRUE;
}

/*
 * Create REPORT data
 */
static char *iot_pi_report_data_create(void)
{
    cJSON *root;
    cJSON *report;
    char *str;

    root = cJSON_CreateObject();
    sddc_return_value_if_fail(root, NULL);

    report = cJSON_CreateObject();
    sddc_return_value_if_fail(report, NULL);

    cJSON_AddItemToObject(root, "report", report);
    cJSON_AddStringToObject(report, "name",   "IoT Camera");
    cJSON_AddStringToObject(report, "type",   "device");
    cJSON_AddBoolToObject(report,   "excl",   SDDC_FALSE);
    cJSON_AddStringToObject(report, "desc",   "翼辉 IoT Camera");
    cJSON_AddStringToObject(report, "model",  "1");
    cJSON_AddStringToObject(report, "vendor", "ACOINFO");
    cJSON_AddStringToObject(report, "sn",     "123456");

    /*
     * Add extension here
     */

    str = cJSON_Print(root);
    sddc_return_value_if_fail(str, NULL);

    sddc_printf("REPORT DATA: %s\n", str);

    cJSON_Delete(root);

    return str;
}

/*
 * Create INVITE data
 */
static char *iot_pi_invite_data_create(void)
{
    cJSON *root;
    cJSON *report;
    char *str;

    root = cJSON_CreateObject();
    sddc_return_value_if_fail(root, NULL);

    report = cJSON_CreateObject();
    sddc_return_value_if_fail(report, NULL);

    cJSON_AddItemToObject(root, "report", report);
    cJSON_AddStringToObject(report, "name",   "IoT Camera");
    cJSON_AddStringToObject(report, "type",   "device");
    cJSON_AddBoolToObject(report,   "excl",   SDDC_FALSE);
    cJSON_AddStringToObject(report, "desc",   "翼辉 IoT Camera");
    cJSON_AddStringToObject(report, "model",  "1");
    cJSON_AddStringToObject(report, "vendor", "ACOINFO");

    /*
     * Add extension here
     */
    /*
     * See sddc.h Update and Invite Data example
     *
    cJSON *server = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "server", server);

    cJSON *vsoa = cJSON_CreateArray();
    cJSON_AddItemToObject(server, "vsoa", vsoa);

    cJSON *vsoa_xxx_server = cJSON_CreateObject();
    cJSON_AddStringToObject(vsoa_xxx_server, "desc", "vsoa xxx server");
    cJSON_AddNumberToObject(vsoa_xxx_server, "port",  1234);

    cJSON_AddItemToArray(vsoa, vsoa_xxx_server);
    */

    str = cJSON_Print(root);
    sddc_return_value_if_fail(str, NULL);

    sddc_printf("INVITE DATA: %s\n", str);

    cJSON_Delete(root);

    return str;
}

/*
 * IoT Pi key scan thread
 */
static void iot_pi_key_thread(ms_ptr_t arg)
{
    fd_set  rfds;
    sddc_t *sddc = arg;
    ms_uint8_t key1_press = 0;
    ms_uint64_t key1_press_begin = 0;
    ms_bool_t smart_config = MS_FALSE;
    struct timeval tv;
    struct ifreq ifreq;
    int ret;

    while (1) {
        if (ioctl(sockfd, SIOCGIFADDR, &ifreq) == 0) {
            smart_config = MS_FALSE;
        }

        if (smart_config) {
            FD_ZERO(&rfds);
            FD_SET(key1_fd, &rfds);

            tv.tv_sec  = 1;
            tv.tv_usec = 0;

            ret = select(key1_fd + 1, &rfds, MS_NULL, MS_NULL, &tv);
            if (ret > 0) {
                key1_press++;
                if (key1_press == 1) {
                    key1_press_begin = ms_time_get_ms();

                } else if (key1_press == 3) {
                    key1_press = 0;

                    if ((ms_time_get_ms() - key1_press_begin) < 800) {
                        sddc_printf("Stop smart configure...\n");
                        smart_config = MS_FALSE;
                        ifreq.ifr_flags = 0;
                        ioctl(sockfd, SIOCSIFPFLAGS, &ifreq);
                        continue;
                    }
                }
            } else if (ret == 0) {
                ms_io_write(led1_fd, &led_state_bak[0], 1);
                led_state_bak[0] = !led_state_bak[0];

                ms_io_write(led2_fd, &led_state_bak[1], 1);
                led_state_bak[1] = !led_state_bak[1];

                ms_io_write(led3_fd, &led_state_bak[2], 1);
                led_state_bak[2] = !led_state_bak[2];
            }
        } else {
            FD_ZERO(&rfds);
            FD_SET(key1_fd, &rfds);
            FD_SET(key2_fd, &rfds);
            FD_SET(key3_fd, &rfds);

            ret = select(key3_fd + 1, &rfds, MS_NULL, MS_NULL, MS_NULL);
            if (ret > 0) {
                if (FD_ISSET(key1_fd, &rfds)) {
                    key1_press++;
                    if (key1_press == 1) {
                        key1_press_begin = ms_time_get_ms();

                    } else if (key1_press == 3) {
                        key1_press = 0;

                        if ((ms_time_get_ms() - key1_press_begin) < 800) {
                            sddc_printf("Start smart configure...\n");
                            smart_config = MS_TRUE;

                            led_state_bak[0] = 0;
                            ms_io_write(led1_fd, &led_state_bak[0], 1);
                            led_state_bak[0] = !led_state_bak[0];

                            led_state_bak[1] = 0;
                            ms_io_write(led2_fd, &led_state_bak[1], 1);
                            led_state_bak[1] = !led_state_bak[1];

                            led_state_bak[2] = 0;
                            ms_io_write(led3_fd, &led_state_bak[2], 1);
                            led_state_bak[2] = !led_state_bak[2];

                            ifreq.ifr_flags = 1;
                            ioctl(sockfd, SIOCSIFPFLAGS, &ifreq);
                            continue;
                        }
                    }
                }

                if (FD_ISSET(key2_fd, &rfds)) {
                    cJSON *root;
                    char *str;
                    ms_stat_t st;
                    int ret;

                    root = cJSON_CreateObject();
                    sddc_return_if_fail(root);

                    cJSON_AddStringToObject(root, "cmd", "recv");

                    ret = ms_io_stat(__SEND_IMAGE_FILENAME, &st);
                    sddc_goto_error_if_fail(ret == 0);
                    cJSON_AddNumberToObject(root, "size", st.st_size);

                    sddc_printf("Send picture to EdgerOS, file size %ld\n", st.st_size);

                    str = cJSON_Print(root);
                    sddc_goto_error_if_fail(str);

                    sddc_broadcast_message(sddc, str, strlen(str), 1, MS_FALSE, MS_NULL);
                    cJSON_free(str);

error:
                    cJSON_Delete(root);

                    key1_press = 0;
                }

                if (FD_ISSET(key3_fd, &rfds)) {
                    key1_press = 0;
                }
            }
        }
    }
}

/*
 * Initialize IoT Pi led
 */
static int iot_pi_led_init(void)
{
    ms_gpio_param_t param;

    /*
     * Open leds
     */
    led1_fd = ms_io_open("/dev/led1", O_WRONLY, 0666);
    sddc_return_value_if_fail(led1_fd >= 0, -1);

    led2_fd = ms_io_open("/dev/led2", O_WRONLY, 0666);
    sddc_return_value_if_fail(led2_fd >= 0, -1);

    led3_fd = ms_io_open("/dev/led3", O_WRONLY, 0666);
    sddc_return_value_if_fail(led3_fd >= 0, -1);

    /*
     * Set gpio output mode
     */
    param.mode  = MS_GPIO_MODE_OUTPUT_PP;
    param.pull  = MS_GPIO_PULL_UP;
    param.speed = MS_GPIO_SPEED_HIGH;
    ms_io_ioctl(led1_fd, MS_GPIO_CMD_SET_PARAM, &param);
    ms_io_ioctl(led2_fd, MS_GPIO_CMD_SET_PARAM, &param);
    ms_io_ioctl(led3_fd, MS_GPIO_CMD_SET_PARAM, &param);

    /*
     * Read led state
     */
    ms_io_read(led1_fd, &led_state_bak[0], 1);
    ms_io_read(led2_fd, &led_state_bak[1], 1);
    ms_io_read(led3_fd, &led_state_bak[2], 1);

    led_state_bak[0] = !led_state_bak[0];
    led_state_bak[1] = !led_state_bak[1];
    led_state_bak[2] = !led_state_bak[2];

    return 0;
}

/*
 * Initialize IoT Pi key
 */
static int iot_pi_key_init(void)
{
    ms_gpio_param_t param;

    /*
     * Open keys
     */
    key1_fd = ms_io_open("/dev/key1", O_WRONLY, 0666);
    sddc_return_value_if_fail(key1_fd >= 0, -1);

    key2_fd = ms_io_open("/dev/key2", O_WRONLY, 0666);
    sddc_return_value_if_fail(key2_fd >= 0, -1);

    key3_fd = ms_io_open("/dev/key3", O_WRONLY, 0666);
    sddc_return_value_if_fail(key3_fd >= 0, -1);

    /*
     * Set gpio irq mode
     */
    param.mode  = MS_GPIO_MODE_IRQ_FALLING;
    param.pull  = MS_GPIO_PULL_UP;
    param.speed = MS_GPIO_SPEED_HIGH;
    ms_io_ioctl(key1_fd, MS_GPIO_CMD_SET_PARAM, &param);
    ms_io_ioctl(key2_fd, MS_GPIO_CMD_SET_PARAM, &param);
    ms_io_ioctl(key3_fd, MS_GPIO_CMD_SET_PARAM, &param);

    return 0;
}

int main(int argc, char *argv[])
{
    struct ifreq ifreq;
    struct sockaddr_in *psockaddrin = (struct sockaddr_in *)&(ifreq.ifr_addr);
    sddc_t *sddc;
    char *data;
    int ret;

    /*
     * Initialize IoT Pi led
     */
    ret = iot_pi_led_init();
    sddc_return_value_if_fail(ret == 0, -1);

    /*
     * Initialize IoT Pi key
     */
    ret = iot_pi_key_init();
    sddc_return_value_if_fail(ret == 0, -1);

    /*
     * Set network implement
     */
#if defined(__MS_RTOS__) && defined(SDDC_CFG_NET_IMPL)
    ret = ms_net_set_impl(SDDC_CFG_NET_IMPL);
    sddc_return_value_if_fail(ret == MS_ERR_NONE, -1);
#endif

    /*
     * Create SDDC
     */
    sddc = sddc_create(SDDC_CFG_PORT);
    sddc_return_value_if_fail(sddc, -1);

    /*
     * Set call backs
     */
    sddc_set_on_message(sddc, iot_pi_on_message);
    sddc_set_on_message_ack(sddc, iot_pi_on_message_ack);
    sddc_set_on_message_lost(sddc, iot_pi_on_message_lost);
    sddc_set_on_invite(sddc, iot_pi_on_invite);
    sddc_set_on_invite_end(sddc, iot_pi_on_invite_end);
    sddc_set_on_update(sddc, iot_pi_on_update);
    sddc_set_on_edgeros_lost(sddc, iot_pi_on_edgeros_lost);

    /*
     * Set token
     */
#if SDDC_CFG_SECURITY_EN > 0
    ret = sddc_set_token(sddc, "1234567890");
    sddc_return_value_if_fail(ret == 0, -1);
#endif

    /*
     * Set report data
     */
    data = iot_pi_report_data_create();
    sddc_return_value_if_fail(data, -1);
    sddc_set_report_data(sddc, data, strlen(data));

    /*
     * Set invite data
     */
    data = iot_pi_invite_data_create();
    sddc_return_value_if_fail(data, -1);
    sddc_set_invite_data(sddc, data, strlen(data));

    /*
     * Get mac address
     */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    sddc_return_value_if_fail(sockfd >= 0, -1);

#if defined(SDDC_CFG_NETIF_NAME)
    strcpy(ifreq.ifr_name, SDDC_CFG_NETIF_NAME); 
#endif

    ioctl(sockfd, SIOCGIFHWADDR, &ifreq);

    sddc_printf("MAC addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
              (ms_uint8_t)ifreq.ifr_hwaddr.sa_data[0],
              (ms_uint8_t)ifreq.ifr_hwaddr.sa_data[1],
              (ms_uint8_t)ifreq.ifr_hwaddr.sa_data[2],
              (ms_uint8_t)ifreq.ifr_hwaddr.sa_data[3],
              (ms_uint8_t)ifreq.ifr_hwaddr.sa_data[4],
              (ms_uint8_t)ifreq.ifr_hwaddr.sa_data[5]);

    /*
     * Set uid
     */
    sddc_set_uid(sddc, (const ms_uint8_t *)ifreq.ifr_hwaddr.sa_data);

    /*
     * Get and print ip address
     */
    if (ioctl(sockfd, SIOCGIFADDR, &ifreq) == 0) {
        char ip[sizeof("255.255.255.255")];

        inet_ntoa_r(psockaddrin->sin_addr, ip, sizeof(ip));

        sddc_printf("IP addr: %s\n", ip);
    } else {
        sddc_printf("Failed to get IP address, Wi-Fi AP not online!\n");
    }

    /*
     * Create keys scan thread
     */
    ret = ms_thread_create("t_key",
                           iot_pi_key_thread,
                           sddc,
                           2048U,
                           30U,
                           70U,
                           MS_THREAD_OPT_USER | MS_THREAD_OPT_REENT_EN,
                           MS_NULL);
    sddc_return_value_if_fail(ret == MS_ERR_NONE, -1);

    /*
     * Create connector message queue
     */
    ret = ms_mqueue_create("conn_mq", conn_mqueue_buf, MS_ARRAY_SIZE(conn_mqueue_buf), sizeof(sddc_connector_t *),
                           MS_WAIT_TYPE_FIFO, &conn_mqueue_id);
    sddc_return_value_if_fail(ret == MS_ERR_NONE, -1);

    /*
     * Create connector service threads
     */
    ret = ms_thread_create("t_conn1",
                           iot_pi_connector_thread,
                           sddc,
                           4096U,
                           20U,
                           70U,
                           MS_THREAD_OPT_USER | MS_THREAD_OPT_REENT_EN,
                           MS_NULL);
    sddc_return_value_if_fail(ret == MS_ERR_NONE, -1);

    ret = ms_thread_create("t_conn2",
                           iot_pi_connector_thread,
                           sddc,
                           4096U,
                           20U,
                           70U,
                           MS_THREAD_OPT_USER | MS_THREAD_OPT_REENT_EN,
                           MS_NULL);
    sddc_return_value_if_fail(ret == MS_ERR_NONE, -1);

    /*
     * SDDC run
     */
    while (1) {
        sddc_printf("SDDC running...\n");

        sddc_run(sddc);

        sddc_printf("SDDC quit!\n");
    }

    /*
     * Destroy SDDC
     */
    sddc_destroy(sddc);

    return 0;
}
