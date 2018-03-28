[TOC]

### bro的脚本参考
* security onion的/opt/bro/share/bro目录下存放了示例
* [官方在线文档](https://www.bro.org/documentation/index.html)

### 利用bro提取传输中的文件
* 类似tcpxtract,但这类工具通常会将文件分割，需要合并修正
* bro能自动识别协议，并能提取完整的文件

### bro loging
一旦Bro被部署在环境中并监控实时流量，它将以其默认配置开始生成可读的ASCII日志。 由Bro的日志框架[(Logging Framework)](https://www.bro.org/sphinx/frameworks/file-analysis.html#file-analysis-framework)生成的每个日志文件都有组织的，大多数是面向连接的数据。 由于标准日志文件是简单的ASCII数据，因此一旦熟悉了每个文件中可以找到的数据类型，就可以从命令行终端使用它们中包含的数据。 在下面，我们通过日志的一般结构来研究一些标准的工作方式。  

一般而言，Bro的所有日志文件都是由相应的脚本生成的，这些脚本定义了它们各自的结构。但是，由于每个日志文件都流经日志框架，因此它们共享一组结构相似性。这里没有涉及Bro的脚本方面，鸟瞰如何生成日志文件的过程如下。该脚本的作者定义了数据的种类，例如始发IP地址或连接的持续时间，这些数据将组成日志文件的字段（即列）。然后，作者决定哪些网络活动应该生成单个日志文件条目（即，一行）。例如，这可能是一个连接已经完成或一个发起者发出一个HTTP GET请求。在操作过程中观察到这些行为时，数据将传递到日志框架，该日志框架将条目添加到适当的日志文件中。  

由于日志条目的字段可以由用户进一步定制，日志框架使用标题块来确保它仍然是自描述的。可以通过运行Unix实用程序头并输出文件的第一行来查看此标头条目：  

```
# cat conn.log
#separator \x09
#set_separator    ,
#empty_field      (empty)
#unset_field      -
#path     conn
#open     2018-03-27-22-27-54
#fields   ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       proto   service duration        orig_bytes      resp_bytes      conn_state      local_orig      local_resp      missed_bytes    history orig_pkts       orig_ip_bytes   resp_pkts       resp_ip_bytes   tunnel_parents
#types    time    string  addr    port    addr    port    enum    string  interval        count   count   string  bool    bool    count   string  count   count   count   count   set[string]
1300475167.096535 CHhAvVGS1DHFjwGM9       141.142.220.202 5353    224.0.0.251     5353    udp     dns     -       -       -       S0      -       -       0       D       1       73      0       0       (empty)
1300475167.097012 ClEkJM2Vm5giqnMf4h      fe80::217:f2ff:fed7:cf65        5353    ff02::fb        5353    udp     dns     -       -       -       S0      -       -       0       D       1       199     0       0       (empty)
1300475167.099816 C4J4Th3PJpwUYZZ6gc      141.142.220.50  5353    224.0.0.251     5353    udp     dns     -       -       -       S0      -       -       0       D       1       179     0       0       (empty)
1300475168.853899 CmES5u32sYpV7JYN        141.142.220.118 43927   141.142.2.2     53      udp     dns     0.000435        38      89      SF      -       -       0       Dd      1       66      1       117     (empty)
1300475168.854378 CP5puj4I8PtEU4qzYg      141.142.220.118 37676   141.142.2.2     53      udp     dns     0.000420        52      99      SF      -       -       0       Dd      1       80      1       127     (empty)
1300475168.854837 C37jN32gN3y3AZzyf6      141.142.220.118 40526   141.142.2.2     53      udp     dns     0.000392        38      183     SF      -       -       0       Dd      1       66      1       211     (empty)
1300475168.857956 C0LAHyvtKSQHyJxIl       141.142.220.118 32902   141.142.2.2     53      udp     dns     0.000317        38      89      SF      -       -       0       Dd      1       66      1       117     (empty)
[...]
```

如您所见，标题由以＃开头的行组成，并包含诸如分隔符用于各种类型数据的信息，空字段的外观以及未设置字段的外观等信息。在此示例中
* 使用默认的TAB分隔符作为字段之间的分隔符（\ x09是十六进制中的制表符）
* 逗号作为设置数据的分隔符
* 字符串（empty）作为空字段的指示符
* 而 - 字符作为未设置字段的指示符。
* 创建文件时的时间戳包含在#open下。
* 然后头文件分别详细分析文件中列出的字段以及这些字段的数据类型，分别在#fields和#types中。这两个条目通常是两个最重要的兴趣点，因为它们不仅详细描述了字段名称，还详细描述了所使用的数据类型。当使用像sed，awk或grep这样的工具浏览不同的日志文件时，可以使用字段定义来保存用户的一些精力。

字段名称也是使用Bro自带的[bro-cut](https://www.bro.org/sphinx/logs/index.html#bro-cut)工具的关键资源，请参见下文。


542/5000
标题旁边是主要内容。 在这个例子中，我们看到7个连接与它们的关键属性，如发起者和响应者IP地址（注意Bro如何透明地处理IPv4和IPv6），传输层端口，应用层服务（ - service 字段填充为Bro 确定要使用的特定协议，与连接端口无关），有效负载大小等。 有关所有字段的说明，请参阅Conn :: Info。

除了conn.log之外，Bro还会默认生成更多日志，其中包括：