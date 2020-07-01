
# SDDC

EdgerOS smart device discovery & control protocol.

## IoT Pi SDDC 协议

IoT Pi 实现了 EdgerOS 的 SDDC 协议，允许多个 EdgerOS 同时连接，一个 EdgerOS 连接到 IoT Pi 后，即可控制 IoT Pi，也会收到 IoT Pi 主动上报的状态信息（如按键按下、LED 亮灭）。

EdgerOS 连接 IoT Pi 后，IoT Pi 会主动上报当前的 LED 状态信息：

```js
{
    led1: false, // led1 灭
    led2: true,  // led2 亮
    led3: false, // led3 灭
};
```

如果 IoT Pi 的 LED 状态被一个 EdgerOS 修改了，则其它 EdgerOS 将收到 IoT Pi 主动上报的 LED 状态信息：

```js
{
    led1: false, // led1 灭
    led2: true,  // led2 亮
    led3: false, // led3 灭
};
```

当 IoT Pi 的按键被按下时，IoT Pi 会将按键对应的 LED 亮灭状态反转，同时会主动上报一个 KEY 状态信息给所有连接的 EdgerOS：

假设 key2 按键按下，将收到：
```js
{
    key2: true, // key2 按下了一次
};
```

假设三个按键按下，将收到： 
```js
{
    key1: true, // key1 按下了一次
    key2: true, // key2 按下了一次
    key3: true, // key3 按下了一次
};
```

没有按下的按键，事件不会上报。

EdgerOS 控制 IoT Pi 示例:

```js
    let s = {
        led1: false, // led1 灭
        led2: true,  // led2 亮
        led3: false, // led3 灭
    };
    sddc.send(devid, s);
```
