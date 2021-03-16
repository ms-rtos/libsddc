
# libsddc

IoT 端设备和传感器设备能过 WiFi、LoRa、ZigBee 等无线通信技术连接到 EdgerOS。

针对 WiFi 设备，入网时 EdgerOS 提供 SmartConfig 技术支持，可以免密加入 WiFi 网络，同时 EdgerOS 推荐使用 SDDC（Smart Device Discovery & Control Protocol）协议，SDDC 协议是 EdgerOS 定义的一套智能设备发现和控制协议，SDDC 实现了以下功能：

- EdgerOS 发现设备
- EdgerOS 邀请设备加网
- 设备加入和退出 EdgerOS
- EdgerOS 维持设备 Online 状态
- EdgerOS 与设备间的双向数据通信，数据可加密，支持带有消息重传和确认的可靠通信方式

`libsddc` 是 SDDC 协议的 C 语言版参考实现，目前支持 MS-RTOS （翼辉开发的物联网微型安全操作系统）和 FreeRTOS 及所有符合 POSIX 标准的嵌入式操作系统（如知名的国产大型实时操作系统 SylixOS 和鸿蒙 HarmonyOS）。

## 应用编程接口
[libsddc API](doc/API.md)

## IoT Pi SDDC 协议
[IoT Pi SDDC 协议](doc/IOTPI.md)

## 移植手册
[移植手册](doc/PORTING.md)

## 版本
v1.0.0

## 开源协议
Apache-2.0 

## ESP8266/ESP32 wifi 模块使用 `libsddc`
- 请使用 `https://github.com/ms-rtos/ESP8266_RTOS_SDK`。