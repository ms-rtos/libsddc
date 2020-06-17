/*
 * Copyright (c) 2019 MS-RTOS Team.
 * All rights reserved.
 *
 * Detailed license information can be found in the LICENSE file.
 *
 * File: sddc_message_example.c SDDC message server example.
 *
 * Author: Jiao.jinxing <jiaojixing@acoinfo.com>
 *
 */

#include <ms_rtos.h>
#include "sddc.h"
#include "cJSON.h"

static ms_bool_t iot_pi_on_message(const struct sockaddr_in *addr, const char *message, ms_size_t len)
{
    cJSON *root = cJSON_Parse(message);

    /*
     * Parse here
     */

    char *str = cJSON_Print(root);
    ms_printf("iot_pi_on_message: %s\n", str);
    cJSON_free(str);
    cJSON_Delete(root);

    return MS_TRUE;
}

static void iot_pi_on_message_ack(const struct sockaddr_in *addr, ms_uint16_t seqno)
{

}

static ms_bool_t iot_pi_on_update(const struct sockaddr_in *addr, const char *udpate_data, ms_size_t len)
{
    cJSON *root = cJSON_Parse(udpate_data);

    /*
     * Parse here
     */

    char *str = cJSON_Print(root);
    ms_printf("iot_pi_on_update: %s\n", str);
    cJSON_free(str);
    cJSON_Delete(root);

    return MS_TRUE;
}

static ms_bool_t iot_pi_on_invite(const struct sockaddr_in *addr, const char *invite_data, ms_size_t len)
{
    cJSON *root = cJSON_Parse(invite_data);

    /*
     * Parse here
     */

    char *str = cJSON_Print(root);
    ms_printf("iot_pi_on_invite: %s\n", str);
    cJSON_free(str);
    cJSON_Delete(root);

    return MS_TRUE;
}

static ms_bool_t iot_pi_sddc_on_invite_end(const struct sockaddr_in *addr)
{
    return MS_TRUE;
}

static char *iot_pi_create_report_data(void)
{
    cJSON *root;
    cJSON *report;
    char *str;

    root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "report", report = cJSON_CreateObject());
        cJSON_AddStringToObject(report, "name",   "IoT Pi");
        cJSON_AddStringToObject(report, "type",   "device");
        cJSON_AddBoolToObject(report,   "excl",   MS_FALSE);
        cJSON_AddStringToObject(report, "desc",   "https://www.edgeros.com/iotpi");
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

static char *iot_pi_create_invite_data(void)
{
    cJSON *root;
    cJSON *report;
    char *str;

    root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "report", report = cJSON_CreateObject());
        cJSON_AddStringToObject(report, "name",   "IoT Pi");
        cJSON_AddStringToObject(report, "type",   "device");
        cJSON_AddBoolToObject(report,   "excl",   MS_FALSE);
        cJSON_AddStringToObject(report, "desc",   "https://www.edgeros.com/iotpi");
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

int main(int argc, char *argv[])
{
    struct ifreq ifreq;
    int sockfd;
    char ip[sizeof("255.255.255.255")];
    struct sockaddr_in *psockaddrin = (struct sockaddr_in *)&(ifreq.ifr_addr);

#ifdef SDDC_NET_IMPL
    ms_net_impl_set(SDDC_NET_IMPL);
#endif

    /*
     * Set call backs
     */
    sddc_set_on_message(iot_pi_on_message);
    sddc_set_on_message_ack(iot_pi_on_message_ack);
    sddc_set_on_invite(iot_pi_on_invite);
    sddc_set_on_invite_end(iot_pi_sddc_on_invite_end);
    sddc_set_on_update(iot_pi_on_update);

    /*
     * Set report data
     */
    sddc_set_report_data(iot_pi_create_report_data());

    /*
     * Set invite data
     */
    sddc_set_invite_data(iot_pi_create_invite_data());

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
    sddc_set_uid((const ms_uint8_t *)ifreq.ifr_hwaddr.sa_data);

    /*
     * Get ip address
     */
    ioctl(sockfd, SIOCGIFADDR, &ifreq);

    inet_ntoa_r(psockaddrin->sin_addr, ip, sizeof(ip));

    ms_printf("IP addr: %s\n", ip);

    close(sockfd);

    /*
     * SDDC server loop
     */
    return sddc_server_loop(SDDC_PORT);
}
