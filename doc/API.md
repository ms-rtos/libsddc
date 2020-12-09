

# libsddc 应用编程接口

本文档介绍 libsddc 的应用编程接口。

---
## libsddc API
下表展示了 libsddc 相关的 API：

API|功能
---|:--:
sddc_create| 创建 SDDC
sddc_set_uid| 设置唯一 ID
sddc_set_token| 设置加解密 token
sddc_set_invite_data| 设置 INVITE 数据
sddc_set_report_data| 设置 REPORT 数据
sddc_set_on_invite| 设置收到 INVITE 处理函数
sddc_set_on_invite_end| 设置 INVITE 完毕后处理函数
sddc_set_on_update| 设置收到 UPDATE 处理函数
sddc_set_on_edgeros_lost| 设置 EdgerOS 断开链接处理函数
sddc_set_on_message_lost| 设置消息 lost 处理函数
sddc_set_on_message| 设置收到 MESSAGE 处理函数
sddc_set_on_message_ack| 设置收到 MESSAGE ACK 处理函数
sddc_run| 运行 SDDC 
sddc_send_message| 向指定的 EdgerOS 发送 MESSAGE
sddc_broadcast_message| 向所有链接的 EdgerOS 发送 MESSAGE

---
### sddc_create()
* **描述**
创建 SDDC

* **函数原型**
```c
sddc_t *sddc_create(uint16_t port);
```
* **参数**

输入/输出|参数|描述
---|:--:|:--:
[in] | `port` | UDP 端口

* **返回值**
SDDC 对象指针

* **注意事项**
无

* **示例**
无

---
### sddc_set_uid()
* **描述**
设置 SDDC 的唯一 ID

* **函数原型**
```c
int sddc_set_uid(sddc_t *sddc, const uint8_t *mac_addr);
```
* **参数**

输入/输出|参数|描述
---|:--:|:--:
[in] | `sddc` | SDDC 对象指针
[in] | `mac_addr` | MAC 地址(6 个 BYTE 的数组)

* **返回值**
成功返回 0, 失败返回 -1

* **注意事项**
无

* **示例**
无

---
### sddc_set_token()
* **描述**
设置 SDDC 的加解密 token

* **函数原型**
```c
int sddc_set_token(sddc_t *sddc, const char *token);
```
* **参数**

输入/输出|参数|描述
---|:--:|:--:
[in] | `sddc` | SDDC 对象指针
[in] | `token` | 加解密 token

* **返回值**
成功返回 0, 失败返回 -1

* **注意事项**
无

* **示例**
无


---
### sddc_set_invite_data()
* **描述**
设置 SDDC 的 INVITE 数据

* **函数原型**
```c
int sddc_set_invite_data(sddc_t *sddc, const char *invite_data, size_t len);
```
* **参数**

输入/输出|参数|描述
---|:--:|:--:
[in] | `sddc` | SDDC 对象指针
[in] | `invite_data` | INVITE 数据(JSON 格式)
[in] | `len` | INVITE 数据长度

* **返回值**
成功返回 0, 失败返回 -1

* **注意事项**
无

* **示例**

---
### sddc_set_report_data()
* **描述**
设置 SDDC 的 REPORT 数据

* **函数原型**
```c
int sddc_set_report_data(sddc_t *sddc, const char *report_data, size_t len);
```
* **参数**

输入/输出|参数|描述
---|:--:|:--:
[in] | `sddc` | SDDC 对象指针
[in] | `report_data` | REPORT 数据(JSON 格式)
[in] | `len` | REPORT 数据长度

* **返回值**
成功返回 0, 失败返回 -1

* **注意事项**
无

* **示例**
无

---
### sddc_set_on_invite()
* **描述**
设置 SDDC 收到 INVITE 处理函数

* **函数原型**
```c
int sddc_set_on_invite(sddc_t *sddc, sddc_on_invite_t on_invite);
```
* **参数**

输入/输出|参数|描述
---|:--:|:--:
[in] | `sddc` | SDDC 对象指针
[in] | `on_invite` | INVITE 处理函数

其中 `on_invite` 的类型如下：
```c
typedef sddc_bool_t (*sddc_on_invite_t)(sddc_t *sddc, const uint8_t *uid, const char *invite_data, size_t len);
```

SDDC 回调 `on_invite` 函数时会传入 EdgerOS 的 UID、INVITE 数据和长度。
`on_invite` 函数返回一个 `sddc_bool_t` 布尔类型，返回 `SDDC_TRUE` 意味端设备接受 EdgerOS 的邀请，`SDDC_FALSE` 意味端设备拒绝 EdgerOS 的邀请。


* **返回值**
成功返回 0, 失败返回 -1

* **注意事项**
无

* **示例**
无
---
### sddc_set_on_invite_end()
* **描述**
设置 SDDC 的 INVITE 完毕后处理函数

* **函数原型**
```c
int sddc_set_on_invite_end(sddc_t *sddc, sddc_on_invite_end_t on_invite_end);
```
* **参数**

输入/输出|参数|描述
---|:--:|:--:
[in] | `sddc` | SDDC 对象指针
[in] | `on_invite_end` | INVITE 完毕后处理函数

其中 `on_invite_end` 的类型如下：
```c
typedef sddc_bool_t (*sddc_on_invite_end_t)(sddc_t *sddc, const uint8_t *uid);
```

SDDC 回调 `on_invite_end` 函数时会传入 EdgerOS 的 UID。
`on_invite_end` 函数一般用于向 EdgerOS 报告端设备的当前状态信息。

* **返回值**
成功返回 0, 失败返回 -1

* **注意事项**
无

* **示例**
无

---
### sddc_set_on_update()
* **描述**
设置 SDDC 收到 UPDATE 处理函数

* **函数原型**
```c
int sddc_set_on_update(sddc_t *sddc, sddc_on_update_t on_update);
```
* **参数**

输入/输出|参数|描述
---|:--:|:--:
[in] | `sddc` | SDDC 对象指针
[in] | `on_update` | 收到 UPDATE 处理函数

其中 `on_update` 的类型如下：
```c
typedef sddc_bool_t (*sddc_on_update_t)(sddc_t *sddc, const uint8_t *uid, const char *update_data, size_t len);
```

SDDC 回调 `on_update` 函数时会传入 EdgerOS 的 UID、UPDATE 数据和长度。

`on_update` 函数返回一个 `sddc_bool_t` 布尔类型，返回 `SDDC_TRUE` 将会给 EdgerOS 发送回应，否则不发送回应。

* **返回值**
成功返回 0, 失败返回 -1

* **注意事项**
无

* **示例**
无


---
### sddc_set_on_edgeros_lost()
* **描述**
设置 EdgerOS 断开链接处理函数

* **函数原型**
```c
int sddc_set_on_edgeros_lost(sddc_t *sddc, sddc_on_edgeros_lost_t on_edgeros_lost);
```
* **参数**

输入/输出|参数|描述
---|:--:|:--:
[in] | `sddc` | SDDC 对象指针
[in] | `on_edgeros_lost` | EdgerOS 断开链接处理函数

其中 `on_edgeros_lost` 的类型如下：
```c
typedef void (*sddc_on_edgeros_lost_t)(sddc_t *sddc, const uint8_t *uid);
```

SDDC 回调 `on_edgeros_lost` 函数时会传入 EdgerOS 的 UID。

* **返回值**
成功返回 0, 失败返回 -1

* **注意事项**
无

* **示例**
无


---
### sddc_set_on_message_lost()
* **描述**
设置 SDDC 的消息 lost 处理函数

* **函数原型**
```c
int sddc_set_on_message_lost(sddc_t *sddc, sddc_on_message_lost_t on_message_lost);
```
* **参数**

输入/输出|参数|描述
---|:--:|:--:
[in] | `sddc` | SDDC 对象指针
[in] | `on_message_lost` | 消息 lost 处理函数

其中 `on_message_lost` 的类型如下：
```c
typedef void (*sddc_on_message_lost_t)(sddc_t *sddc, const uint8_t *uid, uint16_t seqno);
```

SDDC 回调 `on_message_lost` 函数时会传入 EdgerOS 的 UID 和 lost 掉的消息序列号。

* **返回值**
成功返回 0, 失败返回 -1

* **注意事项**
无

* **示例**
无

---
### sddc_set_on_message()
* **描述**
设置 SDDC 收到 MESSAGE 处理函数

* **函数原型**
```c
int sddc_set_on_message(sddc_t *sddc, sddc_on_message_t on_message);
```
* **参数**

输入/输出|参数|描述
---|:--:|:--:
[in] | `sddc` | SDDC 对象指针
[in] | `on_message` | 收到 MESSAGE 处理函数

其中 `on_message` 的类型如下：
```c
typedef sddc_bool_t (*sddc_on_message_t)(sddc_t *sddc, const uint8_t *uid, const char *message, size_t len);
```

SDDC 回调 `on_message` 函数时会传入 EdgerOS 的 UID 和消息数据及长度。如果收到的是一个需要 ACK 的消息，并且 `on_message` 函数返回 `SDDC_TRUE`，SDDC 将会给 EdgerOS 发送 ACK，否则不发送 ACK。

* **返回值**
成功返回 0, 失败返回 -1

* **注意事项**
无

* **示例**
无

---
### sddc_set_on_message_ack()
* **描述**
设置 SDDC 收到 MESSAGE ACK 处理函数

* **函数原型**
```c
int sddc_set_on_message_ack(sddc_t *sddc, sddc_on_message_ack_t on_message_ack);
```
* **参数**

输入/输出|参数|描述
---|:--:|:--:
[in] | `sddc` | SDDC 对象指针
[in] | `on_message_ack` | 收到 MESSAGE ACK 处理函数

其中 `on_message_ack` 的类型如下：
```c
typedef void (*sddc_on_message_ack_t)(sddc_t *sddc, const uint8_t *uid, uint16_t seqno);
```

SDDC 回调 `on_message_ack` 函数时会传入 EdgerOS 的 UID 和消息的序列号。

* **返回值**
成功返回 0, 失败返回 -1

* **注意事项**
无

* **示例**
无


---
### sddc_run()
* **描述**
运行 SDDC 

* **函数原型**
```c
int sddc_run(sddc_t *sddc);
```
* **参数**

输入/输出|参数|描述
---|:--:|:--:
[in] | `sddc` | SDDC 对象指针

* **返回值**
成功返回 0, 失败返回 -1

* **注意事项**
无

* **示例**
无


---
### sddc_send_message()
* **描述**
发送 MESSAGE

* **函数原型**
```c
int sddc_send_message(sddc_t *sddc, const uint8_t *uid,
                      const void *payload, size_t payload_len,
                      uint8_t retries, sddc_bool_t urgent,
                      uint16_t *seqno);
```
* **参数**

输入/输出|参数|描述
---|:--:|:--:
[in] | `sddc` | SDDC 对象指针
[in] | `uid` | EdgerOS 的唯一 ID
[in] | `payload` | 消息数据
[in] | `payload_len` | 消息数据长度
[in] | `retries` | 消息重发次数
[in] | `urgent` | 是否发送紧急消息
[out] | `seqno` | 消息序列号

* **返回值**
成功返回 0, 失败返回 -1

* **注意事项**
无

* **示例**
无


---
### sddc_broadcast_message()
* **描述**
向所有链接的 EdgerOS 发送 MESSAGE

* **函数原型**
```c
int sddc_broadcast_message(sddc_t *sddc,
                           const void *payload, size_t payload_len,
                           uint8_t retries, sddc_bool_t urgent,
                           uint16_t *seqno);
```
* **参数**

输入/输出|参数|描述
---|:--:|:--:
[in] | `sddc` | SDDC 对象指针
[in] | `uid` | EdgerOS 的唯一 ID
[in] | `payload` | 消息数据
[in] | `payload_len` | 消息数据长度
[in] | `retries` | 消息重发次数
[in] | `urgent` | 是否发送紧急消息
[out] | `seqno` | 消息序列号数组

* **返回值**
成功返回 0, 失败返回 -1

* **注意事项**
无

* **示例**
无

---
## libsddc 示例

```c
#include <ms_rtos.h>
#include "sddc.h"
#include "cJSON.h"

/*
 * handle MESSAGE
 */
static sddc_bool_t iot_pi_on_message(sddc_t *sddc, const uint8_t *uid, const char *message, size_t len)
{
    cJSON *root = cJSON_Parse(message);

    /*
     * Parse here
     */

    char *str = cJSON_Print(root);
    ms_printf("iot_pi_on_message: %s\n", str);
    cJSON_free(str);
    cJSON_Delete(root);

    return SDDC_TRUE;
}

/*
 * handle MESSAGE ACK
 */
static void iot_pi_on_message_ack(sddc_t *sddc, const uint8_t *uid, uint16_t seqno)
{

}

/*
 * handle MESSAGE lost
 */
static void iot_pi_on_message_lost(sddc_t *sddc, const uint8_t *uid, uint16_t seqno)
{

}

/*
 * handle EdgerOS lost
 */
static void iot_pi_on_edgeros_lost(sddc_t *sddc, const uint8_t *uid)
{

}

/*
 * handle UPDATE
 */
static sddc_bool_t iot_pi_on_update(sddc_t *sddc, const uint8_t *uid, const char *udpate_data, size_t len)
{
    cJSON *root = cJSON_Parse(udpate_data);

    if (root) {
        /*
         * Parse here
         */

        char *str = cJSON_Print(root);

        ms_printf("iot_pi_on_update: %s\n", str);

        cJSON_free(str);

        cJSON_Delete(root);

        return SDDC_TRUE;
    } else {
        return SDDC_FALSE;
    }
}

/*
 * handle INVITE
 */
static sddc_bool_t iot_pi_on_invite(sddc_t *sddc, const uint8_t *uid, const char *invite_data, size_t len)
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

        return SDDC_TRUE;
    } else {
        return SDDC_FALSE;
    }
}

/*
 * handle the end of INVITE
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
    struct sockaddr_in *psockaddrin = (struct sockaddr_in *)&(ifreq.ifr_addr);
    sddc_t *sddc;
    char *data;

    /*
     * Set network implement 
     */
#ifdef SDDC_CFG_NET_IMPL
    ms_net_impl_set(SDDC_CFG_NET_IMPL);
#endif

    /*
     * Create sddc
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
        ms_printf("Failed to get IP address, WiFi AP not online!\n");
    }

    close(sockfd);

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
```