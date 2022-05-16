
# SDDC

SDDC（Smart Device Discovery & Control，智能设备发现与控制）是 EdgerOS 专门为 Wi-Fi 和以太网通信技术的物联网设备定义的发现与控制通信协议。使用 SDDC 协议开发的物联网设备能被 EdgerOS 自动管理，因此推荐 Wi-Fi 和以太网通信技术的物联网设备使用 SDDC 协议与 EdgerOS 通信。

SDDC 协议实现了以下功能：

- EdgerOS 发现设备
- EdgerOS 邀请设备加入
- 设备加入和退出 EdgerOS
- EdgerOS 维持设备 Online 状态
- EdgerOS 与设备间的双向数据通信，数据可加密，支持带有消息重传和确认的可靠通信方式

[SDDC 协议介绍](https://www.edgeros.com/ms-rtos/guide/sddc_introduction.html)

## libsddc

为了方便开发者在 MCU 上使用 SDDC 协议，翼辉信息开发了 SDDC 协议的 C 语言版参考实现 libsddc，目前 libsddc 支持 MS-RTOS （翼辉开发的一款微型安全物联网操作系统，将在后面的章节介绍）和 FreeRTOS （一个著名的开源免费的小型实时操作系统）及所有符合 POSIX 标准的嵌入式操作系统（如知名的国产大型实时操作系统 SylixOS 和鸿蒙 HarmonyOS）。

## 应用编程接口

[libsddc API](https://www.edgeros.com/ms-rtos/api/libsddc.html)

## 移植手册

[移植手册](doc/PORTING.md)

## 版本
 
- v1.2.0  加入 TIMESTAMP 请求功能

- v1.1.0  加入数据连接器功能

- v1.0.0  首个稳定版本

## 开源协议

Apache-2.0 

## 开发教程

https://www.edgeros.com/ms-rtos/guide/iotpi_sddc_develop.html

https://www.edgeros.com/ms-rtos/guide/esp8266_sddc_develop.html

https://www.edgeros.com/ms-rtos/guide/esp32_sddc_develop.html
