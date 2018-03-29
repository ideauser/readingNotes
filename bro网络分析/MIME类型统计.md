[TOC]

文件通过常规网络上的HTTP不断传输。 这些文件属于由多用途Internet邮件扩展（MIME）标识的特定类别（例如，exe可执行文件，text文本，image图像）。 虽然MIME最初是为了识别电子邮件中非文本附件的类型而开发的，但它也被网络浏览器用于识别传输文件的类型并相应地显示它们。

在本教程中，我们将演示如何使用Sumstats框架来收集基于[MIME类型](https://en.wikipedia.org/wiki/MIME)的统计信息; 具体来说就是每个类型发生的总次数，以字节为单位的大小以及通过HTTP传输文件的唯一主机的数量。 有关提取和创建这些文件的本地副本的说明，请访问[这个教程](https://github.com/ideauser/readingNotes/blob/master/bro%E7%BD%91%E7%BB%9C%E5%88%86%E6%9E%90/%E4%BD%BF%E7%94%A8bro%E7%9B%91%E6%B5%8BHTTP%E6%B5%81%E9%87%8F.md)。

### 使用Sumstats统计MIME
在使用[Summary Statistics](https://www.bro.org/sphinx/frameworks/sumstats.html#sumstats-framework)框架时，您需要定义三个不同的部分：
1. 观察，记下事件源并将其录入框架。
2. reducers,收集和测量观测数据的地方。 
3. Sumstats，实现统计功能的地方。

我们首先定义我们的观察结果以及记录以存储所有统计值和观察间隔。 我们正在对[HTTP :: log_http](https://www.bro.org/sphinx/scripts/base/protocols/http/main.bro.html#id-HTTP::log_http)事件进行观察，并对MIME类型，文件大小（“response_body_len”）和发起者主机（“orig_h”）感兴趣。 我们使用MIME类型作为我们的关键，并为其他两个值创建观察者。

```
mimestats.bro

module MimeMetrics;

export {

	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp when the log line was finished and written.
		ts:         time   &log;
		## Time interval that the log line covers.
		ts_delta:   interval &log;
		## The mime type
		mtype:        string &log;
		## The number of unique local hosts that fetched this mime type
		uniq_hosts: count  &log;
		## The number of hits to the mime type
		hits:       count  &log;
		## The total number of bytes received by this mime type
		bytes:      count  &log;
	};

	## The frequency of logging the stats collected by this script.
	const break_interval = 5mins &redef;
}
event HTTP::log_http(rec: HTTP::Info)
	{
	if ( Site::is_local_addr(rec$id$orig_h) && rec?$resp_mime_types )
		{
		local mime_type = rec$resp_mime_types[0];
		SumStats::observe("mime.bytes", [$str=mime_type],
		                  [$num=rec$response_body_len]);
		SumStats::observe("mime.hits",  [$str=mime_type],
		                  [$str=cat(rec$id$orig_h)]);
		}
	}
```
接下来，我们创建reducers。 第一个将累积文件大小，第二个将确保我们只存储一次主机ID。 以下是来自[bro_init](https://www.bro.org/sphinx/scripts/base/bif/event.bif.bro.html#id-bro_init)处理程序的部分代码。

```
mimestats.bro

	local r1: SumStats::Reducer = [$stream="mime.bytes",
	                               $apply=set(SumStats::SUM)];
	local r2: SumStats::Reducer = [$stream="mime.hits", 
	                               $apply=set(SumStats::UNIQUE)];
```

在我们的最后一步中，我们创建SumStats来检查观察间隔。 一旦到期，我们用所有相关数据填充记录（定义如上），并将其写入日志。

```
mimestats.bro

	SumStats::create([$name="mime-metrics",
	                  $epoch=break_interval,
	                  $reducers=set(r1, r2),
	                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	                        {
	                        local l: Info;
	                        l$ts         = network_time();
	                        l$ts_delta   = break_interval;
	                        l$mtype      = key$str;
	                        l$bytes      = double_to_count(floor(result["mime.bytes"]$sum));
	                        l$hits       = result["mime.hits"]$num;
	                        l$uniq_hosts = result["mime.hits"]$unique;
	                        Log::write(MimeMetrics::LOG, l);
	                        }]);
```

把这三部分放在一起后，我们最终得到了我们脚本的最终代码。

```
mimestats.bro

@load base/utils/site
@load base/frameworks/sumstats

redef Site::local_nets += { 10.0.0.0/8 };

module MimeMetrics;

export {

	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp when the log line was finished and written.
		ts:         time   &log;
		## Time interval that the log line covers.
		ts_delta:   interval &log;
		## The mime type
		mtype:        string &log;
		## The number of unique local hosts that fetched this mime type
		uniq_hosts: count  &log;
		## The number of hits to the mime type
		hits:       count  &log;
		## The total number of bytes received by this mime type
		bytes:      count  &log;
	};

	## The frequency of logging the stats collected by this script.
	const break_interval = 5mins &redef;
}

event bro_init() &priority=3
	{
	Log::create_stream(MimeMetrics::LOG, [$columns=Info, $path="mime_metrics"]);
	local r1: SumStats::Reducer = [$stream="mime.bytes",
	                               $apply=set(SumStats::SUM)];
	local r2: SumStats::Reducer = [$stream="mime.hits", 
	                               $apply=set(SumStats::UNIQUE)];
	SumStats::create([$name="mime-metrics",
	                  $epoch=break_interval,
	                  $reducers=set(r1, r2),
	                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	                        {
	                        local l: Info;
	                        l$ts         = network_time();
	                        l$ts_delta   = break_interval;
	                        l$mtype      = key$str;
	                        l$bytes      = double_to_count(floor(result["mime.bytes"]$sum));
	                        l$hits       = result["mime.hits"]$num;
	                        l$uniq_hosts = result["mime.hits"]$unique;
	                        Log::write(MimeMetrics::LOG, l);
	                        }]);
	}

event HTTP::log_http(rec: HTTP::Info)
	{
	if ( Site::is_local_addr(rec$id$orig_h) && rec?$resp_mime_types )
		{
		local mime_type = rec$resp_mime_types[0];
		SumStats::observe("mime.bytes", [$str=mime_type],
		                  [$num=rec$response_body_len]);
		SumStats::observe("mime.hits",  [$str=mime_type],
		                  [$str=cat(rec$id$orig_h)]);
		}
	}
```
```
#separator \x09
#set_separator    ,
#empty_field      (empty)
#unset_field      -
#path     mime_metrics
#open     2018-03-29-00-07-55
#fields   ts      ts_delta        mtype   uniq_hosts      hits    bytes
#types    time    interval        string  count   count   count
1389719059.311698 300.000000      image/png       1       9       82176
1389719059.311698 300.000000      image/gif       1       1       172
1389719059.311698 300.000000      image/x-icon    1       2       2300
1389719059.311698 300.000000      text/html       1       2       42231
1389719059.311698 300.000000      text/plain      1       15      128001
1389719059.311698 300.000000      image/jpeg      1       1       186859
1389719059.311698 300.000000      application/pgp-signature       1       1       836
#close    2018-03-29-00-07-55
```

> 注意 [Site :: local_nets](https://www.bro.org/sphinx/scripts/base/utils/site.bro.html#id-Site::local_nets)的重新定义只能在这个脚本中完成，以使其成为一个独立的示例。 它通常在其他地方重新定义。