# libsddc 移植手册

## libsddc 配置

```c
#define SDDC_CFG_PORT              680U            // EdgerOS 端口
#define SDDC_CFG_RECV_BUF_SIZE     1460U           // 接收缓冲区大小
#define SDDC_CFG_SEND_BUF_SIZE     1460U           // 发送缓冲区大小

#define SDDC_CFG_NET_IMPL          "ms_esp_at_net" // MS-RTOS 网络实现名字

#define SDDC_CFG_MQUEUE_SIZE       6U              // 消息队列大小
#define SDDC_CFG_RETRIES_INTERVAL  500U            // 消息重传时间间隔，单位：毫秒
#define SDDC_CFG_EDGEROS_ALIVE     40U             // EdgerOS 保活时间，单位：消息重传时间间隔
#define SDDC_CFG_CONNECTOR_TIMEOUT 5000U           // 数据连接器接收超时时间，单位：毫秒

#define SDDC_CFG_DBG_EN            1U              // 是否使能调试信息
#define SDDC_CFG_WARN_EN           1U              // 是否使能警告信息
#define SDDC_CFG_ERR_EN            1U              // 是否使能出错信息
#define SDDC_CFG_CRIT_EN           1U              // 是否使能临界信息
#define SDDC_CFG_INFO_EN           1U              // 是否使能打印信息

#define SDDC_CFG_SECURITY_EN       1U              // 是否使能数据加密通信

#undef __FREERTOS__                                // 使用 FreeRTOS 时定义
```

## libsddc 移植

libsddc 通过 [MbedTLS](https://github.com/ARMmbed/mbedtls)  支持数据加密通信，如果您的 IoT 设备需要使用数据加密通信，当您需要移植 libsddc 到当前 libsddc 并不支持的操作系统平台时（如 uC/OS 等），则需要先行移植 MbedTLS 到您的操作系统平台上，目前 libsddc 依赖 `BSD/socket` 的部分接口和 C 库的部分接口：

```c
/*
 * libsddc 依赖的 C 库的部分接口
 */
         memcmp
         memcpy
         bzero
         strlen

/*
 * libsddc 依赖的 BSD/socket 的部分接口
 */
         socket
         close
         bind
         sendto
         recvfrom
         select
         inet_ntoa_r
         htonl
         htons
```

libsddc 将与操作系统相关的接口和类型进行了抽象，当您需要移植 libsddc 到当前 libsddc 并不支持的操作系统平台时（如 uC/OS 等），还需要实现如下的接口和类型，以 MS-RTOS 移植为例进行说明：

```c
/*
 * 信息输出接口
 */
#define sddc_printf     ms_printf

/*
 * 内存分配接口
 */
#define sddc_malloc     ms_malloc
#define sddc_free       ms_free

/*
 * 休眠接口
 */
#define sddc_sleep      ms_thread_sleep_s

/*
 * 互斥量类型
 */
typedef ms_handle_t     sddc_mutex_t;

/*
 * 创建可嵌套加锁的互斥量
 */
static inline int sddc_mutex_create(sddc_mutex_t *mutex)
{
    return ms_mutex_create("sddc_lock", MS_WAIT_TYPE_PRIO, mutex);
}

/*
 * 销毁互斥量
 */
static inline int sddc_mutex_destroy(sddc_mutex_t *mutex)
{
    return ms_mutex_destroy(*mutex);
}

/*
 * 加锁
 */
static inline int sddc_mutex_lock(sddc_mutex_t *mutex)
{
    return ms_mutex_lock(*mutex, MS_TIMEOUT_FOREVER);
}

/*
 * 解锁
 */
static inline int sddc_mutex_unlock(sddc_mutex_t *mutex)
{
    return ms_mutex_unlock(*mutex);
}

```