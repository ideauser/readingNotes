[TOC]

### 待解决问题
* 怎样定制一个事务记录


### IDS系统
* ##### snort/suricata
	* 规则很适合于从网络流量中发现一些字节信息，规则也是基于此来编写的
* ##### bro的特点：
	* 适合于基于协议层的解析，它与支持大多常见的网络协议，可实现脚本编程
	* bro支持动态协议检测（DPD），能识别流量中非标准端口的协议
	* 默认情况下，BRO在流量中检测到已知协议时，会将本次事务细节记录在一个文件中(可定制，怎样定制？)
	* 允许用户向BRO注册事件处理程序，接管事件处理
	* 处理程序允许用户做任何事，且数量没有限制，即同一事可以有多个处理程序

