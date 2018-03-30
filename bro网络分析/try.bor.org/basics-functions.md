[TOC]

### 函数

介绍一种编程语言经常遇到相互依赖于不同的知识片段。作为基本部分，我们现在介绍功能。为了向您展示一个工作示例，我们需要使用稍后解释的一些元素。

该示例函数接受一个字符串参数和另一个可选的字符串参数它返回一个字符串。该功能是同时声明和实施的。该函数然后在bro_init事件中调用。

我们在这里看到什么？

输入参数在逗号分隔列表中的括号内指定。返回值在冒号后面。该函数中的所有参数都是'string'类型。在下一课中，我们将在Bro中看到更多关于类型的内容。

这个例子中的第二个参数是可选的。这是因为[属性](https://www.bro.org/sphinx/script-reference/attributes.html)＆默认。在这里的例子中，如果缺少第二个参数，默认值就是'*'。[点这查看bro支持的属性](https://www.bro.org/sphinx/script-reference/attributes.html)

这里看到的另一个元素是在这种情况下连接字符串的'+' - 运算符。

最后，当使用该函数时，结果值将被简单地打印到STDOUT。

关于函数和事件之间关系的另一个侧面说明：事件也是一种函数，并且都只能在全局范围内定义声明;一个函数不能嵌套定义其它函数。

```
#!/usr/bin/env bro
function emphasize(s: string,p:string &default = "*"):string
{
        return p + s + p;
}
event bro_init()
{
        #Function colls
        print emphasize("yes");
        print emphasize("no","-");
}

```
结果
```
$ ./testfunc.bro 
*yes*
-no-

```

* bro语言的定义变量有点像go,类型置后,但变量名与类型间多了一个“：”
* 函数参数支持默认值，格式参考例子
* 返回类型也是置后，前面也带一个“：”
* 字符串支持“+”、“+="操作