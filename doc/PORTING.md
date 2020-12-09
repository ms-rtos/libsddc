# libsddc 移植手册

## libsddc 配置

```c
#define SDDC_CFG_PORT                   680U              /* SDDC UDP 端口 */
#define SDDC_CFG_RECV_BUF_SIZE          1024U             /* SDDC 接收缓冲区大小 */
#define SDDC_CFG_SEND_BUF_SIZE          1024U             /* SDDC 发送缓冲区大小 */

#define SDDC_CFG_NET_IMPL               "ms_esp_at_net"   /* MS-RTOS 网络实现名称 */

#define SDDC_CFG_MQUEUE_SIZE            6U                /* 发送消息队列大小 */
#define SDDC_CFG_RETRIES_INTERVAL       500U              /* 消息重发间隔，时间单位: MS */
#define SDDC_CFG_EDGEROS_ALIVE          40U               /* EdgerOS 保活时间，时间单位: SDDC_CFG_RETRIES_INTERVAL */

#define SDDC_CFG_DBG_EN                 1                 /* 使能调试信息 */
#define SDDC_CFG_WARN_EN                1                 /* 使能警告信息 */
#define SDDC_CFG_ERR_EN                 1                 /* 使能错误信息 */
#define SDDC_CFG_CRIT_EN                1                 /* 使能临界信息 */
#define SDDC_CFG_INFO_EN                1                 /* 使能普通信息 */

#define SDDC_CFG_SECURITY_EN            1                 /* 使能加密数据通信(依赖 mbedtls) */
```

## libsddc 移植

libsddc 依赖 mbedtls 实现加密数据通信，如果您的 IoT 设备需要使用加密数据通信，当您需要移植 libsddc 到当前 libsddc 并不支持的操作系统平台时（如 FreeRTOS、uC/OS 等），则需要先行移植 mbedtls 到您的操作系统平台上，目前 libsddc 依赖 BSD/socket 的部分接口和 C 库的部分接口：

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

libsddc 将与操作系统相关的接口和类型进行了抽象，当您需要移植 libsddc 到当前 libsddc 并不支持的操作系统平台时（如 FreeRTOS、uC/OS 等），还需要实现如下的接口和类型，以 MS-RTOS 移植为例进行说明：

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
 * 创建互斥量
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