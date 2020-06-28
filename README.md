
# SDDC

EdgerOS smart device discovery & control protocol.

## IoT Pi SDDC Э��

IoT Pi ʵ���� EdgerOS �� SDDC Э�飬������ EdgerOS ͬʱ���ӣ�һ�� EdgerOS ���ӵ� IoT Pi �󣬼��ɿ��� IoT Pi��Ҳ���յ� IoT Pi �����ϱ���״̬��Ϣ���簴�����¡�LED ���𣩡�

EdgerOS ���� IoT Pi ��IoT Pi �������ϱ���ǰ�� LED ״̬��Ϣ��

```js
{
    led1: false, // led1 ��
    led2: true,  // led2 ��
    led3: false, // led3 ��
};
```

��� IoT Pi �� LED ״̬��һ�� EdgerOS �޸��ˣ������� EdgerOS ���յ� IoT Pi �����ϱ��� LED ״̬��Ϣ��

```js
{
    led1: false, // led1 ��
    led2: true,  // led2 ��
    led3: false, // led3 ��
};
```

�� IoT Pi �İ���������ʱ��IoT Pi �Ὣ������Ӧ�� LED ����״̬��ת��ͬʱ�������ϱ�һ�� KEY ״̬��Ϣ���������ӵ� EdgerOS��

���� key2 �������£����յ���
```js
{
    key2: true, // key2 ������һ��
};
```

���������������£����յ��� 
```js
{
    key1: true, // key1 ������һ��
    key2: true, // key2 ������һ��
    key3: true, // key3 ������һ��
};
```

û�а��µİ������¼������ϱ���

EdgerOS ���� IoT Pi ʾ��:

```js
    let s = {
        led1: false, // led1 ��
        led2: true,  // led2 ��
        led3: false, // led3 ��
    };
    sddc.send(devid, s);
```
