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

* 注意meta?$mime_type 是meta in mime_type的意思吗？

```
file_analysis_02.bro

event file_sniff(f: fa_file, meta: fa_metadata)
    {
	if ( ! meta?$mime_type ) return;
    print "new file", f$id;
    if ( meta$mime_type == "text/plain" )
        Files::add_analyzer(f, Files::ANALYZER_MD5);
    }

event file_hash(f: fa_file, kind: string, hash: string)
    {
    print "file_hash", f$id, kind, hash;
    }
```


### file的一些属性
**完全属性可以参考[这里](https://www.bro.org/sphinx/scripts/base/init-bare.bro.html?highlight=fa_file#type-fa_file)
* bof_buffer string &optional #一个文件的开始内容最多为bof_buffer_size个字节。 这也是用于文件/MIME类型检测的缓冲区。是否可以把bof_buffer_size调大点以容纳整个文件内容，这样便可以对内容进行检索呢 
* bof_buffer_size count &default = [default_file_bof_buffer_size](https://www.bro.org/sphinx/scripts/base/init-bare.bro.html?highlight=fa_file#id-default_file_bof_buffer_size) &optional 保存在bof_buffer字段中以供稍后检查的文件开始处的字节数。
```
            if ("www.w3.org" in f$bof_buffer)
    {
          print "find www.w3.org";
          print f$bof_buffer_size,"file_content:", f$bof_buffer;
    }
```

```
event file_sniff(f: fa_file, meta: fa_metadata)
    {
        if ( ! meta?$mime_type ) return;
#    print "new file", f$id;

 if ( meta$mime_type == "text/plain"  && "slide.ent.sina.com.cn" in f$bof_buffer)
 {
       print  "file content",f$bof_buffer_size,f$bof_buffer;
    }

}

```

```
event file_sniff(f: fa_file, meta: fa_metadata)
    {
        if ( ! meta?$mime_type ) return;
#    print "new file", f$id;


 if ( meta$mime_type == "text/plain"  && "slide.ent.sina.com.cn" in f$bof_buffer)
 {
#       print  "file content",f$bof_buffer_size,f$bof_buffer;
        print f$http;
    }

}

```
```
seconi:~/pcap$ bro -C -r  test.pcapng htmlana.bro 
[ts=1522203300.395897, uid=CPsMjd1gkVGyEwgAt4, id=[orig_h=192.168.10.250, orig_p=30911/tcp, resp_h=58.63.238.228, resp_p=80/tcp], trans_depth=1, method=GET, host=cre.mix.sina.com.cn, uri=/api/v3/get?cre=sinapc&mod=picg&statics=1&merge=3&type=1&length=20&cateid=t_s&fields=url,stitle,title,thumb&callback=homePicGuessLoaded__&rnd=1522203298880, referrer=http://www.sina.com.cn/, version=1.1, user_agent=Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36, request_body_len=0, response_body_len=0, status_code=200, status_msg=OK, info_code=<uninitialized>, info_msg=<uninitialized>, tags={

}, username=<uninitialized>, password=<uninitialized>, capture_password=F, proxied=<uninitialized>, range_request=F, orig_fuids=<uninitialized>, orig_filenames=<uninitialized>, orig_mime_types=<uninitialized>, resp_fuids=[Fz37vD1LW3luQX87ej], resp_filenames=<uninitialized>, resp_mime_types=[text/plain], current_entity=[filename=<uninitialized>], orig_mime_depth=1, resp_mime_depth=1]
```

```
event file_sniff(f: fa_file, meta: fa_metadata)
    {
        if ( ! meta?$mime_type ) return;
#    print "new file", f$id;


 if ( meta$mime_type == "text/plain"  && /slide.ent.sina.com.cn/ in f$bof_buffer)
 {
#       print  "file content",f$bof_buffer_size,f$bof_buffer;
        print f$http$uri;
    }

}

@seconi:~/pcap$ bro -C -r  test.pcapng htmlana.bro 
/api/v3/get?cre=sinapc&mod=picg&statics=1&merge=3&type=1&length=20&cateid=t_s&fields=url,stitle,title,thumb&callback=homePicGuessLoaded__&rnd=1522203298880
```