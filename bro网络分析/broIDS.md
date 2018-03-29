
[TOC]

入侵检测系统（IDS）允许您检测由于过去或当前（主动）攻击而在网络上发生的可疑活动。 由于其编程功能，Bro可以轻松配置为像传统IDS一样运行，并以众所周知的模式检测常见攻击，或者您可以创建自己的脚本来检测特定情况下的特定情况。

在下面的章节中，我们举几个Bro作为IDS的常用用例

### 检测FTP暴力攻击并通知
为了本练习的目的，我们将FTP暴力破解定义为从单个地址发生的被拒绝的用户名和密码太多。 我们首先定义尝试次数，监控时间间隔（以分钟为单位）和新通知类型的阈值。
```
detect-bruteforcing.bro

module FTP;

export {
	redef enum Notice::Type += {
		## Indicates a host bruteforcing FTP logins by watching for too
		## many rejected usernames or failed passwords.
		Bruteforcing
	};

	## How many rejected usernames or passwords are required before being
	## considered to be bruteforcing.
	const bruteforce_threshold: double = 20 &redef;

	## The time period in which the threshold needs to be crossed before
	## being reset.
	const bruteforce_measurement_interval = 15mins &redef;
}
```

使用ftp_reply事件，我们检查来自[500](https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes)系列的“USER”和“PASS”命令的错误代码，表示被拒绝的用户名或密码。 为此，我们可以使用[FTP :: parse_ftp_reply_code](https://www.bro.org/sphinx/scripts/base/protocols/ftp/main.bro.html#id-FTP::parse_ftp_reply_code)函数来分解回复代码并检查第一个数字是否为“5”。 如果属实，我们将使用[Summary Statistics](https://www.bro.org/sphinx/frameworks/sumstats.html#sumstats-framework)摘要统计框架来跟踪失败尝试次数。

```
detect-bruteforcing.bro

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
	{
	local cmd = c$ftp$cmdarg$cmd;
	if ( cmd == "USER" || cmd == "PASS" )
		{
		if ( FTP::parse_ftp_reply_code(code)$x == 5 )
			SumStats::observe("ftp.failed_auth", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
		}
	}
```
接下来，我们使用SumStats框架在测量间隔期间失败尝试次数超过指定阈值时发出攻击通知。
```
event bro_init()
	{
	local r1: SumStats::Reducer = [$stream="ftp.failed_auth", $apply=set(SumStats::UNIQUE), $unique_max=double_to_count(bruteforce_threshold+2)];
	SumStats::create([$name="ftp-detect-bruteforcing",
	                  $epoch=bruteforce_measurement_interval,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["ftp.failed_auth"]$num+0.0;
	                  	},
	                  $threshold=bruteforce_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["ftp.failed_auth"];
	                  	local dur = duration_to_mins_secs(r$end-r$begin);
	                  	local plural = r$unique>1 ? "s" : "";
	                  	local message = fmt("%s had %d failed logins on %d FTP server%s in %s", key$host, r$num, r$unique, plural, dur);
	                  	NOTICE([$note=FTP::Bruteforcing,
	                  	        $src=key$host,
	                  	        $msg=message,
	                  	        $identifier=cat(key$host)]);
	                  	}]);
	}
```

以下是我们脚本的最终代码。
```
detect-bruteforcing.bro

##! FTP brute-forcing detector, triggering when too many rejected usernames or
##! failed passwords have occurred from a single address.

@load base/protocols/ftp
@load base/frameworks/sumstats

@load base/utils/time

module FTP;

export {
	redef enum Notice::Type += {
		## Indicates a host bruteforcing FTP logins by watching for too
		## many rejected usernames or failed passwords.
		Bruteforcing
	};

	## How many rejected usernames or passwords are required before being
	## considered to be bruteforcing.
	const bruteforce_threshold: double = 20 &redef;

	## The time period in which the threshold needs to be crossed before
	## being reset.
	const bruteforce_measurement_interval = 15mins &redef;
}


event bro_init()
	{
	local r1: SumStats::Reducer = [$stream="ftp.failed_auth", $apply=set(SumStats::UNIQUE), $unique_max=double_to_count(bruteforce_threshold+2)];
	SumStats::create([$name="ftp-detect-bruteforcing",
	                  $epoch=bruteforce_measurement_interval,
	                  $reducers=set(r1),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["ftp.failed_auth"]$num+0.0;
	                  	},
	                  $threshold=bruteforce_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["ftp.failed_auth"];
	                  	local dur = duration_to_mins_secs(r$end-r$begin);
	                  	local plural = r$unique>1 ? "s" : "";
	                  	local message = fmt("%s had %d failed logins on %d FTP server%s in %s", key$host, r$num, r$unique, plural, dur);
	                  	NOTICE([$note=FTP::Bruteforcing,
	                  	        $src=key$host,
	                  	        $msg=message,
	                  	        $identifier=cat(key$host)]);
	                  	}]);
	}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
	{
	local cmd = c$ftp$cmdarg$cmd;
	if ( cmd == "USER" || cmd == "PASS" )
		{
		if ( FTP::parse_ftp_reply_code(code)$x == 5 )
			SumStats::observe("ftp.failed_auth", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
		}
	}
```

```
#separator \x09
#set_separator    ,
#empty_field      (empty)
#unset_field      -
#path     notice
#open     2018-03-29-00-07-20
#fields   ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       fuid    file_mime_type  file_desc       proto   note    msg     sub     src     dst     p       n       peer_descr      actions suppress_for    dropped remote_location.country_code    remote_location.region  remote_location.city    remote_location.latitude        remote_location.longitude
#types    time    string  addr    port    addr    port    string  string  string  enum    enum    string  string  addr    addr    port    count   string  set[enum]       interval        bool    string  string  string  double  double
1389721084.522861 -       -       -       -       -       -       -       -       -       FTP::Bruteforcing       192.168.56.1 had 20 failed logins on 1 FTP server in 0m37s      -       192.168.56.1    -       -       -       bro     Notice::ACTION_LOG      3600.000000     F       -       -       -       -       -
#close    2018-03-29-00-07-20
```
作为最后一点，上面的[detect-bruteforcing.bro](https://www.bro.org/sphinx/scripts/policy/protocols/ftp/detect-bruteforcing.bro.html)脚本随Bro一起提供。 通过在启动过程中加载此脚本来使用此功能。对于security onion,则位于这个目录：
```
seconi:~/pcap/filecap1$ ls /opt/bro/share/bro/policy/protocols/ftp/
detect.bro  detect-bruteforcing.bro  software.bro
```

### 其它攻击
* 检测SQL注入攻击
* 根据恶意软件的hash值来检测文件

在您的网络上传输的文件可能完全无害或包含病毒和其他威胁。 针对此威胁的一种可能行动是计算文件的哈希值并将其与已知恶意软件哈希列表进行比较。 Bro通过提供一个[detect-MHR.bro](https://www.bro.org/sphinx/scripts/policy/frameworks/files/detect-MHR.bro.html)脚本来简化这一任务，该脚本创建并比较由[Team Cymru](https://www.team-cymru.com/)维护的恶意软件哈希注册表的散列值。 通过在启动过程中加载此脚本来使用此功能。
