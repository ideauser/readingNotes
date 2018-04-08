[TOC]

### 日志框架
[原文](https://www.bro.org/sphinx/frameworks/logging.html)
Bro带有一个灵活的基于键值的日志记录接口，可以对记录的内容以及记录方式进行细化控制。 本文档介绍了如何定制和扩展日志记录。

#### Terminology术语
Bro的日志接口是围绕三个主要抽象构建的：
* streams:一个日志流对应于单个日志。它定义了一组字段，这组字段构成日志及类型。 比如用于记录连接摘要的conn流(conn.log)，以及用于记录HTTP活动的http流(http.log)。
* Filters:每个流都附有一组过滤器，以确定哪些信息被写到日志文件里。 默认情况下，每个流都有一个默认筛选器，它将所有内容直接记录到磁盘。 但是，可以添加额外的筛选器以仅记录日志记录的子集，写入不同的输出或设置自定义循环重写日志文件的间隔。 如果所有过滤器都从流中删除，则该流的输出被禁用。即如果想停止输出这个日志，只需删除它的过滤器就行了。
* Writers:每个过滤器都有一个writer。writer为被记录的信息定义实际的输出格式。 默认编写器是ASCII编写器，它生成制表符分隔的ASCII文件。 还有其他writer可用，例如二进制输出或直接将日志写到数据库。

有多种不同的方式可以自定义Bro的日志记录，本文档介绍了所有这些方法。
* 您可以创建新的日志流
* 可以使用新字段扩展现有日志
* 可以将过滤器应用于现有日志流
* 可以通过设置日志记录器选项来自定义输出格式 

#### streams
为了将数据记录到新的日志流中，需要完成以下所有操作：
* 必须定义一个record类型，它由所有将被记录的字段组成（按照惯例，该记录类型的名称通常是“Info”）。
* 必须定义一个日志流ID（类型名为“Log::ID”的enum枚举），以唯一地标识新日志流。
* 日志流必须使用Log::create_stream函数创建。
当要记录的数据变为可用时，必须调用Log::write函数
在下面的例子中，我们创建一个新的模块“Foo”，它创建一个新的日志流。

```
module Foo;

export {
    # Create an ID for our new stream. By convention, this is
    # called "LOG".定义一个日志流ID
    redef enum Log::ID += { LOG };

    # Define the record type that will contain the data to log.
    type Info: record {
        ts: time        &log;#字段要带有log属性
        id: conn_id     &log;
        service: string &log &optional;
        missed_bytes: count &log &default=0;
    };
}

# Optionally, we can add a new field to the connection record（通过redef） so that
# the data we are logging (our "Info" record) will be easily
# accessible in a variety of event handlers.
#我们可以使用redef来给"connection"增加一些可选字段，这样可以方便其他的各种事件处理handler获取这些字段信息
redef record connection += {
    # By convention, the name of this new field is the lowercase name
    # of the module.
    foo: Info &optional;
};

# This event is handled at a priority higher than zero so that if
# users modify this stream in another script, they can do so at the
# default priority of zero.
event bro_init() &priority=5
    {
    # Create the stream. This adds a default filter automatically.
    Log::create_stream(Foo::LOG, [$columns=Info, $path="foo"]);
    }
```

在上面的“Info”记录的定义中，请注意每个字段都有[＆log](https://www.bro.org/sphinx/script-reference/attributes.html#attr-&log)属性。 没有这个属性，一个字段不会出现在日志输出中。 另请注意，一个字段具有[＆optional](https://www.bro.org/sphinx/script-reference/attributes.html#attr-&optional)属性。 这表示在写入日志记录之前，该字段可能未被赋值。 最后，带有[＆default](https://www.bro.org/sphinx/script-reference/attributes.html#attr-&default)属性的字段会自动为其分配默认值。

此时，唯一缺少的是调用Log::write函数将数据发送到日志框架。 实际发生的事件处理程序将取决于数据的可用位置。 在这个例子中，connection_established事件提供了我们的数据，并且我们还将一个正在记录的数据的副本存储到连接记录中：

```
event connection_established(c: connection)
    {
    local rec: Foo::Info = [$ts=network_time(), $id=c$id];

    # Store a copy of the data in the connection record so other
    # event handlers can access it.
    c$foo = rec;

    Log::write(Foo::LOG, rec);
    }

```
输出
```
[root@tmp]# head  foo.log 
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	foo
#open	2018-04-08-08-34-43
#fields	ts	id.orig_h	id.orig_p	id.resp_h	id.resp_p	service	missed_bytes
#types	time	addr	port	addr	port	string	count
1523147683.000451	163.142.111.212	54798	192.168.9.63	80	-	0
1523147683.011671	182.92.82.243	60250	192.168.9.88	80	-	0

```
如果您使用此脚本运行Bro，则会创建一个新的日志文件foo.log。虽然我们只在上面的“Info”记录中只指定了四个字段，但日志输出实际上将包含七个字段，因为其中一个字段（名为“id”的字段）本身就是一种record类型。由于[conn_id](https://www.bro.org/sphinx/scripts/base/init-bare.bro.html#type-conn_id)记录具有四个字段，因此这些字段中的每一个都是日志输出中的单独列。请注意，在日志输出中命名这些字段的方式与我们在Bro脚本中引用同一字段的方式（每个美元符号被一段时间替换）略有不同。例如，要访问Bro脚本中的conn_id的第一个字段，我们将使用记号id$orig_h，但该字段在日志输出中名为id.orig_h。

在开发将数据添加到[connection](https://www.bro.org/sphinx/scripts/base/init-bare.bro.html#type-connection)记录的脚本时，必须注意何时存储数据和存储多长时间。正常情况下，保存到连接记录的数据将保留在连接期间，从实际的角度来看，在连接结束之前需要删除该数据并不罕见。



#### Add Fields to a Log
通过扩展定义其内容的记录类型，并在每个日志记录写入之前为新字段设置一个值，可以将其他字段添加到日志。
假设我们想要添加一个布尔字段is_private到Conn::Info，它指示发起者IP地址是否为RFC 1918空间的一部分：
```
# Add a field to the connection log record.
redef record Conn::Info += {
    ## Indicate if the originator of the connection is part of the
    ## "private" address space defined in RFC1918.
    is_private: bool &default=F &log;
};
```

如本例所示，在扩展日志流的“Info”记录时，每个新字段必须始终使用＆default或＆optional来声明。 此外，您需要添加＆log属性，否则该字段不会出现在日志文件中。

现在我们需要设置该字段。 虽然细节取决于要扩展的日志，但总体而言，选择合适的事件来设置附加字段很重要，因为我们需要**确保在写入日志记录之前设置字段**。 有时候，正确的选择是写入日志记录的相同事件，但具有更高的优先级（以确保设置附加字段的事件处理程序在写入日志记录的事件处理程序之前执行）。

在这个例子中，由于连接的摘要是在其状态从内存中删除时生成的，所以我们可以在那个时候添加另一个处理程序来正确设置我们的字段：

```
event connection_state_remove(c: connection)
    {
    if ( c$id$orig_h in Site::private_address_space )
        c$conn$is_private = T;
    }
```