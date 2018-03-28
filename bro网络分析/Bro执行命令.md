[TOC]

### Bro执行命令

1. bro命令选项

```
@seconi:~$ bro -h
bro version 2.5.2
usage: bro [options] [file ...]
    <file>                         | policy file, or read stdin
    -a|--parse-only                | exit immediately after parsing scripts
    -b|--bare-mode                 | don't load scripts from the base/ directory
    -d|--debug-policy              | activate policy file debugging
    -e|--exec <bro code>           | augment loaded policies by given code
    -f|--filter <filter>           | tcpdump filter
    -g|--dump-config               | dump current config into .state dir
    -h|--help|-?                   | command line help
    -i|--iface <interface>         | read from given interface
    -p|--prefix <prefix>           | add given prefix to policy file resolution
    -r|--readfile <readfile>       | read from given tcpdump file
    -s|--rulefile <rulefile>       | read rules from given file
    -t|--tracefile <tracefile>     | activate execution tracing
    -v|--version                   | print version and exit
    -w|--writefile <writefile>     | write to given tcpdump file
    -x|--print-state <file.bst>    | print contents of state file
    -C|--no-checksums              | ignore checksums
    -F|--force-dns                 | force DNS
    -G|--load-seeds <file>         | load seeds from given file
    -H|--save-seeds <file>         | save seeds to given file
    -I|--print-id <ID name>        | print out given ID
    -N|--print-plugins             | print available plugins and exit (-NN for verbose)
    -P|--prime-dns                 | prime DNS
    -Q|--time                      | print execution time summary to stderr
    -R|--replay <events.bst>       | replay events
    -S|--debug-rules               | enable rule debugging
    -T|--re-level <level>          | set 'RE_level' for rules
    -U|--status-file <file>        | Record process status in file
    -W|--watchdog                  | activate watchdog timer
    -X|--broxygen <cfgfile>        | generate documentation based on config file
    --pseudo-realtime[=<speedup>]  | enable pseudo-realtime for performance evaluation (default 1)
    $BROPATH                       | file search path (.:/opt/bro/share/bro:/opt/bro/share/bro/policy:/opt/bro/share/bro/site)
    $BRO_PLUGIN_PATH               | plugin search path (/opt/bro/lib/bro/plugins)
    $BRO_PLUGIN_ACTIVATE           | plugins to always activate ()
    $BRO_PREFIXES                  | prefix list ()
    $BRO_DNS_FAKE                  | disable DNS lookups (off)
    $BRO_SEED_FILE                 | file to load seeds from (not set)
    $BRO_LOG_SUFFIX                | ASCII log file extension (.log)
    $BRO_PROFILER_FILE             | Output file for script execution statistics (not set)
    $BRO_DISABLE_BROXYGEN          | Disable Broxygen documentation support (not set)


```

##### 处理pcap文件
处理日志文件后，生成的几个文件之间通过uid关联起来
```
bro -C -r file.pcap  //bro默认是开启对包进行较验和(checksum)功能的，-C关闭这个功能
                     //执行完这个命令后，会在当前目录下生成多个以协议区分的日志文件*.log
@seconi:~/pcap$ bro -C -r test.pcapng 
@seconi:~/pcap$ ls
conn.log  dns.log  files.log  http.log  packet_filter.log  ssl.log  test.pcapng  weird.log  x509.log



```
### bro分析pcap的后产生的日志文件
* 默认情况下，bro记录一切事件
* 可以使用额外的字段扩展标准的Bro日志文件，这取决于在Bro实例中所使用的脚本
* **conn.log**:记录从pcap文件提取出来的网络连接
	* orig_h: 表示的是originator host,即包的发起者，相当于source源
	* resp_?: 表示的是resposedes,即响应者,destination,目标

```
@seconi:~/pcap$ cat conn.log |more
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
#open	2018-03-28-10-20-36
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state    local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
#types	time	string	addr	port	addr	port	enum	string	interval	count	count	string	bool	bool	count	string	count	count	count count	set[string]
1522203268.241492	C39BYt4YE4z5K6z3mi	192.168.10.250	30719	64.233.189.102	443	tcp	-	0.000003	0	0	S0	-	-     96	0	0	(empty)
1522203268.489502	CCBlmo3Xrp4QVblOnh	192.168.10.250	30720	64.233.189.102	443	tcp	-	0.000005	0	0	S0	-	-     96	0	0	(empty)
1522203266.076098	C5Rn4z3WZyTg77leyd	192.168.11.151	52855	224.0.0.252	5355	udp	dns	0.099244	44	0	S0	-	-     100	0	0	(empty)
1522203266.229842	CkvY1n40Ph2MW2HHW3	169.254.79.146	53	169.254.255.255	53	udp	dns	-	-	-	S0	-	-	0     144	0	0	(empty)
1522203266.702057	CA0sTh4j6c6ojl0ke	192.168.11.196	137	192.168.11.255	137	udp	dns	-	-	-	S0	-	-	0     78	0	0	(empty)
1522203275.659088	CtrYw02LFa2ewH7ODj	192.168.10.250	30755	174.36.228.136	443	tcp	-	3.005029	0	0	S0	-	-     208	0	0	(empty)
1522203275.906296	CFPhSx2uEb86HUFzul	192.168.10.250	30756	174.36.228.136	443	tcp	-	3.000824	0	0	S0	-	-     208	0	0	(empty)

```

* **dns.log**:记录从pcap文件里提取DNS查询条目

```
@seconi:~/pcap$ cat dns.log |more
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dns
#open	2018-03-28-10-20-36
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_n
ame	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	rejected
#types	time	string	addr	port	addr	port	enum	count	interval	string	count	string	count	string	count	string	bool	bool	bool  bool	count	vector[string]	vector[interval]	bool

1522203273.667468	CDIr6G1KlGnskbn0lg	192.168.10.250	56298	192.168.8.253	53	udp	25755	0.027077	count.2881.com	1	C_INTERNET    NOERROR	F	F	T	T	0	112.124.34.135	730.000000	F
1522203273.667470	CvBBWx12TEIl1grOyf	192.168.10.250	54721	192.168.8.253	53	udp	35	0.027186	count.knowsky.com	1	C_INTER
NET	1	A	0	NOERROR	F	F	T	T	0	112.124.34.135	306.000000	F
1522203274.323996	C0klHQ3SXVLdDekdPl	192.168.10.250	50314	192.168.8.253	53	udp	20293	0.000813	hm.baidu.com	1	C_INTERNET    NOERROR	F	F	T	T	0	hm.e.shifen.com,220.181.7.190	907.000000,34.000000	F

```

* **files.log** :记录了所有文件的传输，包括通过HTTP、FTP传输的HTMP、images、video、rar、exe等文件

```
@seconi:~/pcap$ cat files.log |more
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	files
#open	2018-03-28-10-20-36
#fields	ts	fuid	tx_hosts	rx_hosts	conn_uids	source	depth	analyzers	mime_type	filename	duration	local_orig    is_orig	seen_bytes	total_bytes	missing_bytes	overflow_bytes	timedout	parent_fuid	md5	sha1	sha256	extracted	extracted_cutoff      extracted_size
#types	time	string	set[addr]	set[addr]	set[string]	string	count	set[string]	string	string	interval	bool	bool	count	count count	count	bool	string	string	string	string	string	bool	count
1522203274.406374	F5nZOq2qHYeLSVCMag	220.181.7.190	192.168.10.250	Cg8g2i3QZqL4EpvEuh	HTTP	0	(empty)	image/gif	-	0.000000      43	43	0	0	F	-	-	-	-	-	-	-
1522203274.483567	FPMKKB3kK5Cn7eUBRk	112.124.34.135	192.168.10.250	CrSPwx3Ic1x3VMFEZb	HTTP	0	(empty)	application/javascript	-	0.00000
0	-	F	513	513	0	0	F	-	-	-	-	-	-	-
1522203283.452429	Fcv09ROLvJPGsg2Z2	14.215.177.38	192.168.10.250	C07jir3L6pOhH3VX1e	HTTP	0	(empty)	text/html	-	0.000000      225	225	0	0	F	-	-	-	-	-	-	-
1522203283.476558	FjAl5727AT6JQiBYUj	14.215.177.38	192.168.10.250	C5WTRh161VW4U6Zn37	SSL	0	SHA1,X509,MD5	application/pkix-cert	-     0.000000	-	F	2433	-	0	0	F	-	3dddab209d0368a7eea0b49aae87b583	b4ad16eebadaccecd1cbd4f61fee1865775833ab	-     -
1522203283.476558	FkAuDN3KUZE4VGlv5i	14.215.177.38	192.168.10.250	C5WTRh161VW4U6Zn37	SSL	0	SHA1,X509,MD5	application/pkix-cert	

```

* **http.log**:

```
@seconi:~/pcap$ cat http.log |more
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	http
#open	2018-03-28-10-20-36
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent    request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	tags	username	password	proxied	orig_fu
ids	orig_filenames	orig_mime_types	resp_fuids	resp_filenames	resp_mime_types
#types	time	string	addr	port	addr	port	count	string	string	string	string	string	string	count	count	count	string	count	string	set[enu
m]	string	string	set[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]
1522203274.361958	Cg8g2i3QZqL4EpvEuh	192.168.10.250	30748	220.181.7.190	80	1	GET	hm.baidu.com	/hm.gif?cc=0&ck=1&cl=24-bit&ds=1440x900
&vl=0&ep=782083066,6819&et=3&ja=0&ln=zh-cn&lo=0&rnd=735603868&si=4b0c844bc745979ebe00fede9ce45e18&su	http://count.knowsky.com/js.asp	1.1	Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36	0	43    200	OK	-	-	(empty)	-	-	-	-	-	-	F5nZOq2qHYeLSVCMag	-	image/gif
1522203274.346190	CrSPwx3Ic1x3VMFEZb	192.168.10.250	30742	112.124.34.135	80	1	GET	count.2881.com	/count/count.asp?id=56906&sx=1&ys=43  	1.1	Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36	0	513   200	OK	-	-	(empty)	-	-	-	-	-	-	FPMKKB3kK5Cn7eUBRk	-	application/javascript
1522203274.513836	CSJwvB2Z1lAGdgXuD3	192.168.10.250	30744	112.124.34.135	80	1	GET	count.knowsky.com	/img/43/2.gif	
0769.com/	1.1	Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36	0	0	304   Not Modified	-	-	(empty)	-	-	-	-	-	-	-	-	-
1522203274.514125	CIAY6V1rmunu56Wemj	192.168.10.250	30747	112.124.34.135	80	1	GET	count.knowsky.com	/img/43/0.gif		1.1	Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.186 Safari/537.36	0	0	304   Notlsls Modified	-	-	(empty)	-	-	-	-	-	-	-	-	-

```

* **verid.log** :记录任何协议异常的事件

#### 日志字段截断
* **bro-cut** : 日志字段过多，有时会干扰分析，可以使用bro-cut过滤自己关心的部分

```
bro-cut -h

bro-cut [options] [<columns>]

Extracts the given columns from an ASCII Bro log on standard input.
If no columns are given, all are selected. By default, bro-cut does
not include format header blocks into the output.

Example: cat conn.log | bro-cut -d ts id.orig_h id.orig_p

    -c       Include the first format header block into the output.
    -C       Include all format header blocks into the output.
    -d       Convert time values into human-readable format.
    -D <fmt> Like -d, but specify format for time (see strftime(3) for syntax).
    -F <ofs> Sets a different output field separator.
    -n       Print all fields *except* those specified.
    -u       Like -d, but print timestamps in UTC instead of local time.
    -U <fmt> Like -D, but print timestamps in UTC instead of local time.

For time conversion option -d or -u, the format string can be specified by
setting an environment variable BRO_CUT_TIMEFMT.


```

* bro-cut的具体例子

```
@seconi:~/pcap$ cat http.log |bro-cut ts uid method host
1522203274.361958	Cg8g2i3QZqL4EpvEuh	GET	hm.baidu.com
1522203274.346190	CrSPwx3Ic1x3VMFEZb	GET	count.2881.com
1522203274.539820	CSJwvB2Z1lAGdgXuD3	GET	count.knowsky.com
1522203274.536801	CoOd8W2t2HscZk9wGd	GET	count.knowsky.com
1522203274.621029	Cg8g2i3QZqL4EpvEuh	GET	hm.baidu.com
1522203275.233433	Cg8g2i3QZqL4EpvEuh	GET	hm.baidu.com
1522203275.454159	COpd2t4Uqlfl0l0222	GET	crl.microsoft.com
1522203283.445798	C07jir3L6pOhH3VX1e	GET	www.baidu.com
1522203283.707515	Cg8g2i3QZqL4EpvEuh	GET	hm.baidu.com
1522203296.568391	CQDdtmRaFnbg7jqN3	GET	www.sina.com

加上-u 选项，使用UTC时间,加-d显示本地时间 
seconi:~/pcap$ cat http.log |bro-cut -u ts uid method host
2018-03-28T02:14:34+0000	Cg8g2i3QZqL4EpvEuh	GET	hm.baidu.com
2018-03-28T02:14:34+0000	CrSPwx3Ic1x3VMFEZb	GET	count.2881.com
2018-03-28T02:14:34+0000	CSJwvB2Z1lAGdgXuD3	GET	count.knowsky.com
2018-03-28T02:14:34+0000	CIAY6V1rmunu56Wemj	GET	count.knowsky.com
2018-03-28T02:14:34+0000	C0tlaC2c6CL8vZePI3	GET	count.knowsky.com


@seconi:~/pcap$ cat http.log |bro-cut -dc ts uid method host
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	http
#open	2018-03-28-10-20-36
#fields	ts	uid	method	host
#types	string	string	string	string
2018-03-28T10:14:34+0800	Cg8g2i3QZqL4EpvEuh	GET	hm.baidu.com
2018-03-28T10:14:34+0800	CrSPwx3Ic1x3VMFEZb	GET	count.2881.com
2018-03-28T10:14:34+0800	CSJwvB2Z1lAGdgXuD3	GET	count.knowsky.com

```