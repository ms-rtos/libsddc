/*
 * Copyright (c) 2015-2020 ACOINFO Co., Ltd.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: sddc_demo.c SDDC demo.
 *
 * Author: Jiao.jinxing <jiaojinxing@acoinfo.com>
 *
 */

#include <ms_rtos.h>
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

/*
 * Report IoT Pi led state
 */
static void iot_pi_led_state_report(sddc_t *sddc, const uint8_t *uid, ms_bool_t *led_state)
{
    cJSON *root;
    char *str;

    root = cJSON_CreateObject();

    if (led_state != MS_NULL) {
        cJSON_AddBoolToObject(root, "led1", led_state[0]);
        cJSON_AddBoolToObject(root, "led2", led_state[1]);
        cJSON_AddBoolToObject(root, "led3", led_state[2]);

    } else {
        cJSON_AddBoolToObject(root, "led1", led_state_bak[0]);
        cJSON_AddBoolToObject(root, "led2", led_state_bak[1]);
        cJSON_AddBoolToObject(root, "led3", led_state_bak[2]);
    }

    str = cJSON_Print(root);

    sddc_send_message(sddc, uid, str, strlen(str), 1, MS_FALSE, MS_NULL);

    cJSON_free(str);

    cJSON_Delete(root);
}

/*
 * Handle MESSAGE
 */
static ms_bool_t iot_pi_on_message(sddc_t *sddc, const uint8_t *uid, const char *message, ms_size_t len)
{
    cJSON *root = cJSON_Parse(message);
    cJSON *led;
    ms_bool_t led_state[3];

    memcpy(led_state, led_state_bak, sizeof(led_state_bak));

    char *str = cJSON_Print(root);
    ms_printf("iot_pi_on_message: %s\n", str);
    cJSON_free(str);

    led = cJSON_GetObjectItem(root, "led1");
    if (cJSON_IsBool(led)) {
        if (cJSON_IsTrue(led)) {
            ms_uint8_t on = 0;
            ms_io_write(led1_fd, &on, 1);
            led_state[0] = 1;
        } else {
            ms_uint8_t off = 1;
            ms_io_write(led1_fd, &off, 1);
            led_state[0] = 0;
        }
    }

    led = cJSON_GetObjectItem(root, "led2");
    if (cJSON_IsBool(led)) {
        if (cJSON_IsTrue(led)) {
            ms_uint8_t on = 0;
            ms_io_write(led2_fd, &on, 1);
            led_state[1] = 1;
        } else {
            ms_uint8_t off = 1;
            ms_io_write(led2_fd, &off, 1);
            led_state[1] = 0;
        }
    }

    led = cJSON_GetObjectItem(root, "led3");
    if (cJSON_IsBool(led)) {
        if (cJSON_IsTrue(led)) {
            ms_uint8_t on = 0;
            ms_io_write(led3_fd, &on, 1);
            led_state[2] = 1;
        } else {
            ms_uint8_t off = 1;
            ms_io_write(led3_fd, &off, 1);
            led_state[2] = 0;
        }
    }

    cJSON_Delete(root);

    iot_pi_led_state_report(sddc, uid, led_state);
    memcpy(led_state_bak, led_state, sizeof(led_state_bak));

    return MS_TRUE;
}

/*
 * Handle MESSAGE ACK
 */
static void iot_pi_on_message_ack(sddc_t *sddc, const uint8_t *uid, ms_uint16_t seqno)
{

}

/*
 * Handle MESSAGE lost
 */
static void iot_pi_on_message_lost(sddc_t *sddc, const uint8_t *uid, ms_uint16_t seqno)
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
static ms_bool_t iot_pi_on_update(sddc_t *sddc, const uint8_t *uid, const char *update_data, ms_size_t len)
{
    cJSON *root = cJSON_Parse(update_data);

    if (root) {
        /*
         * Parse here
         */

        char *str = cJSON_Print(root);

        ms_printf("iot_pi_sddc_on_update: %s\n", str);

        cJSON_free(str);

        cJSON_Delete(root);

        return MS_TRUE;
    } else {
        return MS_FALSE;
    }
}

/*
 * Handle INVITE
 */
static ms_bool_t iot_pi_on_invite(sddc_t *sddc, const uint8_t *uid, const char *invite_data, ms_size_t len)
{
    cJSON *root = cJSON_Parse(invite_data);

    if (root) {
        /*
         * Parse here
         */

        char *str = cJSON_Print(root);

        ms_printf("iot_pi_on_invite: %s\n", str);

        cJSON_free(str);

        cJSON_Delete(root);

        return MS_TRUE;
    } else {
        return MS_FALSE;
    }
}

/*
 * handle the end of INVITE
 */
static ms_bool_t iot_pi_on_invite_end(sddc_t *sddc, const uint8_t *uid)
{
    iot_pi_led_state_report(sddc, uid, MS_NULL);

    return MS_TRUE;
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
    cJSON_AddItemToObject(root, "report", report = cJSON_CreateObject());
        cJSON_AddStringToObject(report, "name",   "IoT Pi");
        cJSON_AddStringToObject(report, "type",   "device");
        cJSON_AddBoolToObject(report,   "excl",   MS_FALSE);
        cJSON_AddStringToObject(report, "desc",   "翼辉 IoT Pi");
        cJSON_AddStringToObject(report, "model",  "1");
        cJSON_AddStringToObject(report, "vendor", "ACOINFO");

    /*
     * Add extension here
     */

    str = cJSON_Print(root);
    ms_printf("REPORT DATA: %s\n", str);

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
    cJSON_AddItemToObject(root, "report", report = cJSON_CreateObject());
        cJSON_AddStringToObject(report, "name",   "IoT Pi");
        cJSON_AddStringToObject(report, "type",   "device");
        cJSON_AddBoolToObject(report,   "excl",   MS_FALSE);
        cJSON_AddStringToObject(report, "desc",   "翼辉 IoT Pi");
        cJSON_AddStringToObject(report, "model",  "1");
        cJSON_AddStringToObject(report, "vendor", "ACOINFO");

    /*
     * Add extension here
     */

    str = cJSON_Print(root);
    ms_printf("INVITE DATA: %s\n", str);

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

    while (1) {
        FD_ZERO(&rfds);
        FD_SET(key1_fd, &rfds);
        FD_SET(key2_fd, &rfds);
        FD_SET(key3_fd, &rfds);

        if (select(key3_fd + 1, &rfds, MS_NULL, MS_NULL, MS_NULL) > 0) {
            cJSON *root;
            char *str;

            root = cJSON_CreateObject();

            if (FD_ISSET(key1_fd, &rfds)) {
                key1_press++;
                if (key1_press == 1) {
                    key1_press_begin = ms_time_get_ms();

                } else if (key1_press == 3) {
                    key1_press = 0;

                    if ((ms_time_get_ms() - key1_press_begin) < 800) {
                        static struct ifreq ifreq;

                        ifreq.ifr_flags = !ifreq.ifr_flags;

                        if (ifreq.ifr_flags) {
                            ms_printf("Start smart configure...\n");
                        } else {
                            ms_printf("Stop smart configure...\n");
                        }
                        ioctl(sockfd, SIOCSIFPFLAGS, &ifreq);
                        continue;
                    }
                }

                cJSON_AddBoolToObject(root, "key1", MS_TRUE);

                ms_io_write(led1_fd, &led_state_bak[0], 1);
                led_state_bak[0] = !led_state_bak[0];
                cJSON_AddBoolToObject(root, "led1", led_state_bak[0]);
            }

            if (FD_ISSET(key2_fd, &rfds)) {
                cJSON_AddBoolToObject(root, "key2", MS_TRUE);

                ms_io_write(led2_fd, &led_state_bak[1], 1);
                led_state_bak[1] = !led_state_bak[1];
                cJSON_AddBoolToObject(root, "led2", led_state_bak[1]);

                key1_press = 0;
            }

            if (FD_ISSET(key3_fd, &rfds)) {
                cJSON_AddBoolToObject(root, "key3", MS_TRUE);

                ms_io_write(led3_fd, &led_state_bak[2], 1);
                led_state_bak[2] = !led_state_bak[2];
                cJSON_AddBoolToObject(root, "led3", led_state_bak[2]);

                key1_press = 0;
            }

            str = cJSON_Print(root);

            sddc_broadcast_message(sddc, str, strlen(str), 1, MS_FALSE, MS_NULL);

            cJSON_free(str);

            cJSON_Delete(root);
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
    if (led1_fd < 0) {
        ms_printf("Failed to open /dev/led1\n");
        return -1;
    }
    led2_fd = ms_io_open("/dev/led2", O_WRONLY, 0666);
    if (led2_fd < 0) {
        ms_printf("Failed to open /dev/led2\n");
        return -1;
    }
    led3_fd = ms_io_open("/dev/led3", O_WRONLY, 0666);
    if (led3_fd < 0) {
        ms_printf("Failed to open /dev/led3\n");
        return -1;
    }

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
    if (key1_fd < 0) {
        ms_printf("Failed to open /dev/key1\n");
        return -1;
    }
    key2_fd = ms_io_open("/dev/key2", O_WRONLY, 0666);
    if (key2_fd < 0) {
        ms_printf("Failed to open /dev/key2\n");
        return -1;
    }
    key3_fd = ms_io_open("/dev/key3", O_WRONLY, 0666);
    if (key3_fd < 0) {
        ms_printf("Failed to open /dev/key3\n");
        return -1;
    }

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

    /*
     * Initialize IoT Pi led
     */
    if (iot_pi_led_init() < 0) {
        return -1;
    }

    /*
     * Initialize IoT Pi key
     */
    if (iot_pi_key_init() < 0) {
        return -1;
    }

#ifdef SDDC_CFG_NET_IMPL
    ms_net_set_impl(SDDC_CFG_NET_IMPL);
#endif

    /*
     * Create SDDC
     */
    sddc = sddc_create(SDDC_CFG_PORT);

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
    sddc_set_token(sddc, "1234567890");
#endif

    /*
     * Set report data
     */
    data = iot_pi_report_data_create();
    sddc_set_report_data(sddc, data, strlen(data));

    /*
     * Set invite data
     */
    data = iot_pi_invite_data_create();
    sddc_set_invite_data(sddc, data, strlen(data));

    /*
     * Get mac address
     */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    ioctl(sockfd, SIOCGIFHWADDR, &ifreq);

    ms_printf("MAC addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
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

        ms_printf("IP addr: %s\n", ip);
    } else {
        ms_printf("Failed to get IP address, Wi-Fi AP not online!\n");
    }

    /*
     * Create keys scan thread
     */
    ms_thread_create("t_key",
                     iot_pi_key_thread,
                     sddc,
                     2048U,
                     30U,
                     70U,
                     MS_THREAD_OPT_USER | MS_THREAD_OPT_REENT_EN,
                     MS_NULL);

    /*
     * SDDC run
     */
    while (1) {
        ms_printf("SDDC running...\n");

        sddc_run(sddc);

        ms_printf("SDDC quit!\n");
    }

    /*
     * Destroy SDDC
     */
    sddc_destroy(sddc);

    return 0;
}
