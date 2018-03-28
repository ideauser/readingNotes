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


标题旁边是主要内容。 在这个例子中，我们看到7个连接与它们的关键属性，如发起者和响应者IP地址（注意Bro如何透明地处理IPv4和IPv6），传输层端口，应用层服务（ - service 字段填充为Bro 确定要使用的特定协议，与连接端口无关,即使端口改变也能正大确识别），有效负载大小等。 有关所有字段的说明，请参阅[Conn :: Info](https://www.bro.org/sphinx/scripts/base/protocols/conn/main.bro.html#type-Conn::Info)。建议详细了解一下这些字段说明

除了conn.log之外，Bro默认还会生成更多日志，其中包括：

```
dpd.log
非标准端口上遇到的协议摘要。
dns.log
所有DNS活动。
ftp.log
FTP会话级活动的日志。
files.log
通过网络传输的文件摘要。 这些信息来自不同的协议，包括HTTP，FTP和SMTP。
http.log
所有HTTP请求及其回复的摘要。
known_certs.log
正在使用的SSL证书。
smtp.log
SMTP活动的摘要。
ssl.log
SSL会话记录，包括正在使用的证书。
weird.log
意外协议级活动的日志。 每当Bro的协议分析遇到一个不期望的情况（例如，RFC违规）时，就会将其记录在该文件中。 请注意，在实践中，真实世界的网络倾向于表现出大量通常不值得追随的“残缺”。
```



正如您所看到的，某些日志文件是特定于某个特定协议的，而其他日志文件汇总了不同类型活动的信息。 有关日志文件的完整列表及其目的的说明，请参阅[日志文件](https://www.bro.org/sphinx/logs/index.html)。

### 使用 bro-cut
bro-cut工具可用于替代其他工具来构建终端命令，该命令可保持灵活性和准确性，而与日志文件本身的可能更改无关。 它通过解析每个文件中的头文件并允许用户引用可用的特定列数据（与需要用户引用其位置引用的字段的awk等工具形成对比）来实现此目的。 例如，以下命令仅从conn.log中提取给定的列：

```
# cat conn.log | bro-cut id.orig_h id.orig_p id.resp_h duration
141.142.220.202   5353    224.0.0.251     -
fe80::217:f2ff:fed7:cf65  5353    ff02::fb        -
141.142.220.50    5353    224.0.0.251     -
141.142.220.118   43927   141.142.2.2     0.000435
141.142.220.118   37676   141.142.2.2     0.000420
141.142.220.118   40526   141.142.2.2     0.000392
141.142.220.118   32902   141.142.2.2     0.000317
141.142.220.118   59816   141.142.2.2     0.000343
141.142.220.118   59714   141.142.2.2     0.000375
141.142.220.118   58206   141.142.2.2     0.000339
[...]
```

相应的awk命令将如下所示：

```
# awk '/^[^#]/ {print $3, $4, $5, $6, $9}' conn.log
141.142.220.202 5353 224.0.0.251 5353 -
fe80::217:f2ff:fed7:cf65 5353 ff02::fb 5353 -
141.142.220.50 5353 224.0.0.251 5353 -
141.142.220.118 43927 141.142.2.2 53 0.000435
141.142.220.118 37676 141.142.2.2 53 0.000420
141.142.220.118 40526 141.142.2.2 53 0.000392
141.142.220.118 32902 141.142.2.2 53 0.000317
141.142.220.118 59816 141.142.2.2 53 0.000343
141.142.220.118 59714 141.142.2.2 53 0.000375
141.142.220.118 58206 141.142.2.2 53 0.000339
[...]
```

尽管输出是相似的，但使用bro-cut而不是awk的好处在于，虽然awk灵活而强大，但bro-cut专门用于与Bro的日志文件配合使用。 首先，bro-cut输出仅包含日志文件条目，而awk解决方案需要手动跳过标题。 其次，由于bro-cut使用字段描述符来标识和提取数据，因此可以灵活地独立于日志文件的格式和内容。 Bro配置向环境要求的各种日志文件中添加额外字段并不罕见。 在这种情况下，awk命令中的字段必须被修改以补偿新的位置，而bro-cut输出不会改变。
> 注意:给bro-cut的字段名称顺序决定了输出顺序，这意味着您也可以使用bro-cut来重新排序字段。 当管道进入（例如排序）时，这会很有帮助

正如您可能已经注意到的，bro-cut命令通过cat命令和|使用输出重定向操作。 尽管awk等工具允许您将日志文件指定为命令行选项，但bro-cut仅通过重定向来输入，例如| 和<。 有几种方法可以将日志文件数据导入Bro-cut，每种方式都取决于您正在处理的日志文件的类型。 然而，使用它的一个警告是所有的标题行必须存在。
> 注意:bro-cut提供了一个选项-c将相应的格式标题包含到输出中，从而允许链接多个bro-cut实例或执行评估标题信息的进一步后处理。

在其默认设置中，Bro会每小时轮换日志文件，将当前日志文件移动到格式为YYYY-MM-DD的目录中，gzip使用文件格式压缩文件，该文件格式包括日志文件类型和时间范围文件。 在处理压缩的日志文件的情况下，您只需调整您的命令行工具以使用互补的z*版本的命令，如cat（zcat）或grep（zgrep）。

### 使用时间戳
bro-cut接受标志-d将日志文件中的纪元时间值转换为可读格式。 以下命令包含从http.log文件中提取的人类可读时间戳，唯一标识符，HTTP主机和HTTP URI：

```
# bro-cut -d ts uid host uri < http.log
2011-03-18T19:06:08+0000  CUM0KZ3MLUfNB0cl11      bits.wikimedia.org      /skins-1.5/monobook/main.css
2011-03-18T19:06:08+0000  CwjjYJ2WqgTbAqiHl6      upload.wikimedia.org    /wikipedia/commons/6/63/Wikipedia-logo.png
2011-03-18T19:06:08+0000  C3eiCBGOLw3VtHfOj       upload.wikimedia.org    /wikipedia/commons/thumb/b/bb/Wikipedia_wordmark.svg/174px-Wikipedia_wordmark.svg.png
2011-03-18T19:06:08+0000  Ck51lg1bScffFj34Ri      upload.wikimedia.org    /wikipedia/commons/b/bd/Bookshelf-40x201_6.png
2011-03-18T19:06:08+0000  CtxTCR2Yer0FR1tIBg      upload.wikimedia.org    /wikipedia/commons/thumb/8/8a/Wikinews-logo.png/35px-Wikinews-logo.png
[...]
```

通常情况下，来自多个来源的日志文件以UTC时间存储以允许轻松关联。 将时间戳记从日志文件转换为UTC可以使用-u选项来完成：

```
# bro-cut -u ts uid host uri < http.log
2011-03-18T19:06:08+0000  CUM0KZ3MLUfNB0cl11      bits.wikimedia.org      /skins-1.5/monobook/main.css
2011-03-18T19:06:08+0000  CwjjYJ2WqgTbAqiHl6      upload.wikimedia.org    /wikipedia/commons/6/63/Wikipedia-logo.png
2011-03-18T19:06:08+0000  C3eiCBGOLw3VtHfOj       upload.wikimedia.org    /wikipedia/commons/thumb/b/bb/Wikipedia_wordmark.svg/174px-Wikipedia_wordmark.svg.png
2011-03-18T19:06:08+0000  Ck51lg1bScffFj34Ri      upload.wikimedia.org    /wikipedia/commons/b/bd/Bookshelf-40x201_6.png
2011-03-18T19:06:08+0000  CtxTCR2Yer0FR1tIBg      upload.wikimedia.org    /wikipedia/commons/thumb/8/8a/Wikinews-logo.png/35px-Wikinews-logo.png
[...]
```

使用-d或-u时的默认时间格式是strftime格式字符串％Y-％m-％dT％H：％M：％S％z这会导致包含年份，月份，日期的字符串 按小时，分钟，秒和时区偏移。 使用标准的strftime语法，可以通过使用-D和-U标志来更改默认格式。 例如，要格式化美式典型“Middle Endian”中的时间戳，可以使用格式字符串：％d-％m-％YT％H：％M：％S％z

```
# bro-cut -D %d-%m-%YT%H:%M:%S%z ts uid host uri < http.log
18-03-2011T19:06:08+0000  CUM0KZ3MLUfNB0cl11      bits.wikimedia.org      /skins-1.5/monobook/main.css
18-03-2011T19:06:08+0000  CwjjYJ2WqgTbAqiHl6      upload.wikimedia.org    /wikipedia/commons/6/63/Wikipedia-logo.png
18-03-2011T19:06:08+0000  C3eiCBGOLw3VtHfOj       upload.wikimedia.org    /wikipedia/commons/thumb/b/bb/Wikipedia_wordmark.svg/174px-Wikipedia_wordmark.svg.png
18-03-2011T19:06:08+0000  Ck51lg1bScffFj34Ri      upload.wikimedia.org    /wikipedia/commons/b/bd/Bookshelf-40x201_6.png
18-03-2011T19:06:08+0000  CtxTCR2Yer0FR1tIBg      upload.wikimedia.org    /wikipedia/commons/thumb/8/8a/Wikinews-logo.png/35px-Wikinews-logo.png
[...]
```
有关格式字符串的更多选项，请参阅man strfime。


### 使用UIDs
尽管Bro可以进行基于签名的分析，但其主要关注点在于行为检测，将日志审查的实践从“反动审查”改变为更类似于狩猎之旅的过程。 审查的常见进展包括跨多个日志文件关联会话。 由于连接由Bro处理，所以为每个会话分配唯一的标识符。 此唯一标识符通常包含在与该连接关联的任何日志文件条目中，并可用于交叉引用不同的日志文件。

一个简单的例子是交叉引用在conn.log文件中看到的UID。 在这里，我们通过将cat conn.log的输出重定向到bro-cut以提取UID和resp_bytes，然后通过resp_bytes字段对输出进行排序来查找响应者中具有最大字节数的连接。

```
# cat conn.log | bro-cut uid resp_bytes | sort -nrk2 | head -5
CwjjYJ2WqgTbAqiHl6        734
CtxTCR2Yer0FR1tIBg        734
Ck51lg1bScffFj34Ri        734
CLNN1k2QMum1aexUK7        734
CykQaM33ztNt0csB9a        733
```
*sort -nrk2 //把第2项当数字反向排序*

以第一个响应的UID，我们现在可以将它与http.log文件中的UID进行交叉引用。
```
# cat http.log | bro-cut uid id.resp_h method status_code host uri | grep UM0KZ3MLUfNB0cl11
CUM0KZ3MLUfNB0cl11        208.80.152.118  GET     304     bits.wikimedia.org      /skins-1.5/monobook/main.css
```

正如你所看到的那样，Bro会识别并记录会话内的两个HTTP GET请求。 鉴于HTTP是流协议，它可以在一个流中有多个GET、POST等请求，Bro能够为您提取和跟踪这些信息，从而为您提供网络中HTTP流量的深入和结构化视图。