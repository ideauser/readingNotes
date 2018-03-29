[TOC]

### 常用类型
* **connection**
* **string**
* **count**：数值？
* **set[类型]** ？类似数据还是集合
* table[类型]？
* time 日期时间
* interval 间隔
### 变量修饰
* global 全局？

```
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


global mime_to_ext: table[string] of string = {
	["application/x-dosexec"] = "exe",
	["text/plain"] = "txt",
	["image/jpeg"] = "jpg",
	["image/png"] = "png",
	["text/html"] = "html",
};
```



### 操作符
* +=