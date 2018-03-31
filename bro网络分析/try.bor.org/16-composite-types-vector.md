[TOC]

### vector


vector矢量是以索引0开始的值的集合。 与set相比，这允许存储相同的值。

第6行显示了长度运算符的一个示例。 该行在列表的末尾添加一个新元素。

```
event bro_init() 
	{ 
	local x: vector of string = { "one", "two", "three" };
	print x; # [one, two, three]
	print x[1]; # two
	x[|x|] = "one";#"|x|"求x的长度
	print x; # [one, two, three, one]

	for ( i in x ) 
		{
		print i;  # Iterates over indices.
		}
	}

```
结果输出
```
[one, two, three]
two
[one, two, three, one]
0
1
2
3
```