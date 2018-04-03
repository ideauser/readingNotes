bro是utf8编码的，可以直接识别编码为utf8的汉字(但好像print不了汉字)，如果要识别gbk编码字符串，则需要对字符串仅需gbk编码，然后使用16进制来表示字符串
比如“东”的gbk编码为：B6AB，则表示为：\xB6\xAB,"莞"为：DDB8，则表示为：\xDD\xB8,那么，"东莞"则表示为：\xB6\xAB\xDD\xB8，如果要对bro抓取编码为gbk的网页关键词“东莞”识别，那么可以这样表达， 
```
"\xB6\xAB\xDD\xB8\xBB\xC6\xD3\xC0" in f$bof_buffer   #检测文件中是否含有“东莞”

/\xB6\xAB\xDD\xB8\xBB\xC6\xD3\xC0/ in f$bof_buffer   #这是正则表示
```
[这里](https://bianma.supfree.net/)可以查询汉字的gbk编码的16进制表示。
```
      1 #!/opt/bro/bin/bro
      2 redef default_file_bof_buffer_size=500024;#将sniff文件缓存设为500024字节
      3 global flog=open("catpurekeywords.log");
      4 event file_sniff(f: fa_file,meta: fa_metadata)
      5 {
      6     if(f$source !="HTTP") return;
      7     if( !meta?$mime_type) return;
      8     if(meta$mime_type == "text/html" && f$http?$host && f$http$host== "xxx.xxx.com" && "\xB6\xAB\xDD\xB8\xBB\xC6\xD3\xC0"in f$bof_buffer)
      9         print flog,f$http$host,f$http$uri;
     10 
     11 }

```
```
      1 #!/opt/bro/bin/bro
      2 redef default_file_bof_buffer_size=500024;
      3 global flog=open("catpurekeywords.log");
      4 global keywords :table[string] of string = {["东莞"]="\xB6\xAB\xDD\xB8",
      5 ["xxx"]="xxxxxxx",
      6 };
      7 event file_sniff(f: fa_file,meta: fa_metadata)
      8 {
      9     if(f$source !="HTTP") return;
     10     if( !meta?$mime_type) return;
     11     if(meta$mime_type == "text/html" && f$http?$host && f$http$host== "xxx.com")
     12     {
     13         for(key in keywords)
     14         {
     15             if(keywords[key] in f$bof_buffer)
     16             print key,"in file ",f$http$uri;
     17         }
     18     }
     19 
     20 }
```
改成拼音table,一个关键词应该做两个编码，一个是utf8，一个是gbk
```
      1 #!/opt/bro/bin/bro
      2 redef default_file_bof_buffer_size=500024;
      3 global flog=open("catpurekeywords.log");
      4 global keywords :table[string] of string = {["dongguan"]="\xB6\xAB\xDD\xB8",
      5 ["xxxx"]="xxxxxxx",
      6 };
      7 event file_sniff(f: fa_file,meta: fa_metadata)
      8 {
      9     if(f$source !="HTTP") return;
     10     if( !meta?$mime_type) return; #如果没有meta没有mime_type的值，则返回
     11     if(meta$mime_type == "text/html" && f$http?$host && f$http$host== "xxx.com")
     12     {
     13         for(key in keywords)
     14         {
     15             if(keywords[key] in f$bof_buffer)
     16             print fmt("%s in file %s", key,f$http$uri);
     17         }
     18     }
     19 
     20 }
```