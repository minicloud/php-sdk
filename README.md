php-sdk
=======

迷你云的2.1 SDK(PHP版本)

直接运行php-sdk.php即可
相比1.5版SDK有下面变化

1、由相对路径修改为绝对路径
用户：ceshid，系统ID：7
1.5版本是：$miniSDK->listFile("/");
2.1版本是：$miniSDK->listFile("/7/");

其它接口以此类推

2、去掉了文件外链接口


迷你云2.2 将推出完整的SDK，预计发布时间2015年9月

