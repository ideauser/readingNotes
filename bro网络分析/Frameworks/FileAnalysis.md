[TOC]

### File Analysis

过去，为了分析文件内容而编写Bro脚本可能很麻烦，因为事实上内容将以不同的方式通过事件呈现在脚本层上，这取决于文件传输中涉及哪种网络协议。 编写用于通过一种协议分析文件的脚本将不得不被复制和修改以适应其他协议。 文件分析框架（FAF）改为提供文件相关信息的一般表示。 有关通过网络传输文件的协议信息仍然可用，但不再需要指定如何组织其脚本逻辑来处理它。 FAF的目标是专门为类似于Bro为网络连接提供的分析的文件提供分析。

#### File Lifecycle Events文件生命周期事件
文件在生命周期的可能发生的关键事件(event)有如下这几个：
* [1.filen_new](#1)
* [2.file_over_new_connection](#2)
* [3.file_timeout](#3)
* [4.file_gap](#4)
* [5.file_state_remove](#5)
处理这些事件中的任何一个都会提供关于文件的一些信息，例如哪个[网络连接](https://www.bro.org/sphinx/scripts/base/init-bare.bro.html#type-connection)和协议正在传输文件，目前传输了多少个字节，以及它的MIME类型。

```
#file_analysis_01.bro

event connection_state_remove(c: connection)
    {
    print "connection_state_remove";
    print c$uid;
    print c$id;
    for ( s in c$service )
        print s;
    }

event file_state_remove(f: fa_file)
    {
    print "file_state_remove";
    print f$id;
    for ( cid in f$conns )
        {
        print f$conns[cid]$uid;
        print cid;
        }
    print f$source;
    }
```
输出结果
```
connection_state_remove
C88piz3sz2rR6IkHTh
[orig_h=192.168.1.102, orig_p=68/udp, resp_h=192.168.1.1, resp_p=67/udp]
DHCP
connection_state_remove
Cbo2K84HTj3hCuIUp2
[orig_h=192.168.1.103, orig_p=137/udp, resp_h=192.168.1.255, resp_p=137/udp]
DNS
connection_state_remove
CTW2eT37QFgP5s0Yre
[orig_h=192.168.1.102, orig_p=137/udp, resp_h=192.168.1.255, resp_p=137/udp]
DNS
connection_state_remove
CNZFT12ZZf63EoUpX1
[orig_h=192.168.1.103, orig_p=138/udp, resp_h=192.168.1.255, resp_p=138/udp]
connection_state_remove
[...]
```

这还没有执行任何有趣的分析，但确实突出了连接和文件分析之间的相似性。 连接由通常的5元组或方便的UID字符串标识，而文件仅由与连接UID具有相同格式的字符串标识。 所以有独特的方法来识别文件和连接，并且文件保存对传输它的连接（或连接）的引用(f$conn)。
#### Adding Analysis

有内置文件分析器可以附加到文件。 一旦连接，当Bro从正在进行的网络连接中提取文件时，他们就开始接收文件的内容。 他们对文件内容所做的事情取决于特定的文件分析器实现，但他们通常会通过事件报告关于文件的更多信息（例如Files :: ANALYZER_MD5会在计算完成后通过file_hash报告文件的MD5校验和） 会有一些副作用（例如Files :: ANALYZER_EXTRACT会将文件内容写入本地文件系统）。

将来可能会有文件分析器根据启发式自动附加到文件，类似于连接的动态协议检测（DPD）框架，但许多文件分析器总是需要明确的附件决定。

以下是如何使用MD5文件分析器计算纯文本文件的MD5的简单示例：