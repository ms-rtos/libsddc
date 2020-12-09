
# IoT Pi SDDC 协议

IoT Pi 运行 example 下的 demo 程序，即可实现与 EdgerOS 连接，我们专门开发了一个 IoT Pi 的 EdgerOS App，可以通过该 App 远程控制 IoT Pi。

EdgerOS 连接 IoT Pi 后，IoT Pi 会主动上报当前的 LED 状态信息（JSON 格式 MESSAGE）：

```js
{
    led1: false, // led1 灭
    led2: true,  // led2 亮
    led3: false, // led3 灭
};
```

如果 IoT Pi 的 LED 状态被一个 EdgerOS 修改了，则其它 EdgerOS 将收到 IoT Pi 主动上报的 LED 状态信息（JSON 格式 MESSAGE）：

```js
{
    led1: false, // led1 灭
    led2: true,  // led2 亮
    led3: false, // led3 灭
};
```

当 IoT Pi 的按键被按下时，IoT Pi 会将按键对应的 LED 亮灭状态反转，同时会主动上报一个 KEY 状态信息给所有连接的 EdgerOS（JSON 格式 MESSAGE）：

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

EdgerOS 的 IoT Pi App 通过 MESSAGE 控制 IoT Pi 示例:

```js
    let s = {
        led1: false, // led1 灭
        led2: true,  // led2 亮
        led3: false, // led3 灭
    };
    sddc.send(devid, s);
```
