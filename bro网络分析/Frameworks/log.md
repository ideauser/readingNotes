[TOC]

### 日志框架
[原文](https://www.bro.org/sphinx/frameworks/logging.html)
Bro带有一个灵活的基于键值的日志记录接口，可以对记录的内容以及记录方式进行细化控制。 本文档介绍了如何定制和扩展日志记录。

#### Terminology术语
Bro的日志接口是围绕三个主要抽象构建的：
* streams:一个日志流对应于单个日志。它定义了一组字段，这组字段构成日志及类型。 比如用于记录连接摘要的conn流，以及用于记录HTTP活动的http流。
* Filters 