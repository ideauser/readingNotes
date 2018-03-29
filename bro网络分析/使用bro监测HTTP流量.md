[TOC]

Bro可用于将来自网络的整个HTTP流量记录到http.log文件。 这个文件可以用于分析和审计目的。

在下面的部分中我们简要介绍http.log文件的结构，然后我们向您展示如何使用Bro进行基本的HTTP流量监控和分析任务。 其中一些想法和技术可以稍后应用于以类似的方式监视不同的协议。

### HTTP日志介绍

http.log文件包含通过Bro监控网络发送的所有HTTP请求和响应的摘要。 以下是http.log的前几列

```
# ts          uid          orig_h        orig_p  resp_h         resp_p
1311627961.8  HSH4uV8KVJg  192.168.1.100 52303   192.150.187.43 80
```
此日志中的每一行都以时间戳，唯一连接标识符（UID）和连接4元组（始发者主机/端口和响应者主机/端口）开始。 UID可以用来识别在其生命周期中与给定连接4元组关联的所有记录的活动（可能跨越多个日志文件）。
> uid: string &log(连接的唯一标识符。)A unique identifier of the connection.

其余列详细说明正在发生的活动。 例如，下面一行中的列（为了简洁起见缩写）显示了对Bro网站根目录的请求：
例如，网络管理员和安全工程师可以使用此日志中的信息来了解网络上的HTTP活动，解决网络问题或搜索异常活动。 我们必须强调，没有单一的正确方法来进行分析。 这将取决于执行分析的人的专业知识和任务的具体细节。
有关如何在Bro中处理HTTP协议的更多信息，请参阅Bro的[HTTP脚本参考](https://www.bro.org/sphinx/scripts/base/protocols/http/main.bro.html)。
```
# method   host         uri  referrer  user_agent
GET        bro.org  /    -         <...>Chrome/12.0.742.122<...>
```

### 检测代理服务器
代理服务器是网络上配置为代表第三个系统请求服务的设备; 最常见的例子之一是Web代理服务器。 没有Internet访问的客户端连接到代理并请求网页，代理将请求发送到接收响应的Web服务器，并将其传递给原始客户端。

代理被设想为帮助管理网络并提供更好的封装。 代理本身不是安全威胁，但配置错误或未经授权的代理可以允许网络内部或外部的其他人访问任何网站，甚至可以使用网络资源匿名进行恶意活动。

##### 代理服务器流量看起来是怎样的？
通常，当客户端开始与代理服务器交谈时，流量由两部分组成：（i）GET请求和（ii）HTTP /回复：
```
Request: GET http://www.bro.org/ HTTP/1.1
Reply:   HTTP/1.0 200 OK
```

这与客户端和普通Web服务器之间的流量不同，因为GET请求不应在字符串中包含“http”。 所以我们可以用它来识别代理服务器。

我们可以在Bro中编写基本脚本来处理http_reply事件并检测GET http：//请求的回复。

```
http_proxy_01.bro

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	if ( /^[hH][tT][tT][pP]:/ in c$http$uri && c$http$status_code == 200 )
		print fmt("A local server is acting as an open proxy: %s", c$id$resp_h);
	}


====执行结果如下
# bro -r http/proxy.pcap http_proxy_01.bro
A local server is acting as an open proxy: 192.168.56.101
```

基本上，脚本在包含“http：”（不区分大小写）的请求的答复中检查“200 OK”状态代码。 实际上，HTTP协议定义了几个200以外的成功状态码，所以我们将扩展我们的基本脚本以考虑附加代码。

```
http_proxy_02.bro


module HTTP;

export {

	global success_status_codes: set[count] = {
		200,
		201,
		202,
		203,
		204,
		205,
		206,
		207,
		208,
		226,
		304
	};
}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	if ( /^[hH][tT][tT][pP]:/ in c$http$uri &&
	     c$http$status_code in HTTP::success_status_codes )
		print fmt("A local server is acting as an open proxy: %s", c$id$resp_h);
	}


======
# bro -r http/proxy.pcap http_proxy_02.bro
A local server is acting as an open proxy: 192.168.56.101
```

接下来，我们将确保响应代理是我们本地网络的一部分。
```
http_proxy_03.bro


@load base/utils/site

redef Site::local_nets += { 192.168.0.0/16 };

module HTTP;

export {

	global success_status_codes: set[count] = {
		200,
		201,
		202,
		203,
		204,
		205,
		206,
		207,
		208,
		226,
		304
	};
}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	if ( Site::is_local_addr(c$id$resp_h) &&
	     /^[hH][tT][tT][pP]:/ in c$http$uri &&
	     c$http$status_code in HTTP::success_status_codes )
		print fmt("A local server is acting as an open proxy: %s", c$id$resp_h);
	}
```

> 注意:[Site :: local_nets](https://www.bro.org/sphinx/scripts/base/utils/site.bro.html#id-Site::local_nets)的重新定义只能在这个脚本中完成，以使其成为一个独立的示例。 它通常在其他地方重新定义。

最后，我们的目标应该是在检测到代理时生成警报，而不是在控制台输出上打印消息。 为此，我们将相应地标记流量并定义新的Open_Proxy通知类型以警告所有标记的通信。 <u>一旦通知被激发，相册的消息在一天内不会再激发？</u>（ Once a notification has been fired, we will further suppress it for one day）。 以下是完整的脚本。

```
http_proxy_04.bro

@load base/utils/site
@load base/frameworks/notice

redef Site::local_nets += { 192.168.0.0/16 };

module HTTP;

export {

	redef enum Notice::Type += {
		Open_Proxy
	};

	global success_status_codes: set[count] = {
		200,
		201,
		202,
		203,
		204,
		205,
		206,
		207,
		208,
		226,
		304
	};
}

event http_reply(c: connection, version: string, code: count, reason: string)
	{
	if ( Site::is_local_addr(c$id$resp_h) &&
	     /^[hH][tT][tT][pP]:/ in c$http$uri &&
	     c$http$status_code in HTTP::success_status_codes )
		NOTICE([$note=HTTP::Open_Proxy,
		        $msg=fmt("A local server is acting as an open proxy: %s",
		                 c$id$resp_h),
		        $conn=c,
		        $identifier=cat(c$id$resp_h),
		        $suppress_for=1day]);
	}


========
# bro -r http/proxy.pcap http_proxy_04.bro

#separator \x09
#set_separator    ,
#empty_field      (empty)
#unset_field      -
#path     notice
#open     2018-03-27-22-27-50
#fields   ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       fuid    file_mime_type  file_desc       proto   note    msg     sub     src     dst     p       n       peer_descr      actions suppress_for    dropped remote_location.country_code    remote_location.region  remote_location.city    remote_location.latitude        remote_location.longitude
#types    time    string  addr    port    addr    port    string  string  string  enum    enum    string  string  addr    addr    port    count   string  set[enum]       interval        bool    string  string  string  double  double
1389654450.449603 CHhAvVGS1DHFjwGM9       192.168.56.1    52679   192.168.56.101  80      -       -       -       tcp     HTTP::Open_Proxy        A local server is acting as an open proxy: 192.168.56.101       -       192.168.56.1    192.168.56.101  80      -       bro     Notice::ACTION_LOG      86400.000000    F       -       -       -       -       -
#close    2018-03-27-22-27-50
```

请注意，此脚本仅将发现代理行为记录到notice.log，但如果需要额外的电子邮件（并且启用了电子邮件功能），那么只需重新定义[Notice :: emailed_types](https://www.bro.org/sphinx/scripts/base/frameworks/notice/main.bro.html#id-Notice::emailed_types)即可为其添加Open_proxy通知类型。


### 检查文件

文件通常在客户端和服务器之间的常规HTTP会话中传输。 大多数情况下这些文件是无害的，只是图像和其他多媒体内容，但也有类型的文件，特别是可执行文件，可能会损坏您的系统。 我们可以指示Bro使用[File Analysis Faramework/文件分析框架](https://www.bro.org/sphinx/frameworks/file-analysis.html#file-analysis-framework)（在Bro 2.2一起引入的）创建它看到的某些类型的所有文件的副本：

```
file_extraction.bro


global mime_to_ext: table[string] of string = {
	["application/x-dosexec"] = "exe",
	["text/plain"] = "txt",
	["image/jpeg"] = "jpg",
	["image/png"] = "png",
	["text/html"] = "html",
};

event file_sniff(f: fa_file, meta: fa_metadata)
	{
	if ( f$source != "HTTP" )
		return;

	if ( ! meta?$mime_type )
		return;

	if ( meta$mime_type !in mime_to_ext )
		return;

	local fname = fmt("%s-%s.%s", f$source, f$id, mime_to_ext[meta$mime_type]);
	print fmt("Extracting file %s", fname);
	Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
	}
```
```
# bro -r http/bro.org.pcap file_extraction.bro
Extracting file HTTP-FiIpIB2hRQSDBOSJRg.html
Extracting file HTTP-FMG4bMmVV64eOsCb.txt
Extracting file HTTP-FnaT2a3UDd093opCB9.txt
Extracting file HTTP-FfQGqj4Fhh3pH7nVQj.txt
Extracting file HTTP-FsvATF146kf1Emc21j.txt
[...]
```


这里，mime_to_ext表有两个目的。 它定义了要提取的MIME类型以及提取文件的文件后缀。 提取的文件被写入新的extract_files子目录。 还要注意，可以删除[file_sniff](https://www.bro.org/sphinx/scripts/base/bif/event.bif.bro.html#id-file_sniff) / [file_new](https://www.bro.org/sphinx/scripts/base/bif/event.bif.bro.html#id-file_new)事件处理程序中的第一个条件，以使此行为对于HTTP以外的其他协议具有通用性。
