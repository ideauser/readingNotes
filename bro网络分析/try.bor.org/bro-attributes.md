[TOC]

### Attributes
* 属性是个什么东东？
#### bro支持的属性
[官方文档](https://www.bro.org/sphinx/script-reference/attributes.html)


|Name|Description| 
|-|-|
|&redef|Redefine a global constant or extend a type. |
|&priority|Specify priority for event handler or hook. |
|&log|Mark a record field as to be written to a log. |
|&optional|Allow a record field value to be missing. |
|&default|Specify a default value. |
|&add_func|Specify a function to call for each “redef +=”. |
|&delete_func|Same as “&add_func”, except for “redef -=”. |
|&expire_func|Specify a function to call when container element expires. |
|&read_expire|Specify a read timeout interval. |
|&write_expire|Specify a write timeout interval. |
|&create_expire|Specify a creation timeout interval. |
|&synchronized|Synchronize a variable across nodes. |
|&persistent|Make a variable persistent (written to disk). |
|&rotate_interval|Rotate a file after specified interval. |
|&rotate_size|Rotate a file after specified file size. |
|&encrypt|Encrypt a file when writing to disk. |
|&raw_output|Open file in raw mode (chars. are not escaped). |
|&mergeable|Prefer set union for synchronized state. |
|&error_handler|Used internally for reporter framework events. |
|&type_column|Used by input framework for “port” type. |
|&deprecated|Marks an identifier as deprecated. |
