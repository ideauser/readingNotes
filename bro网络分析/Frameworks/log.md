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