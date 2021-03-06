---
layout: post
title: 颜のない月的汉化逆向分析
---

此项目已经托管到我的[github](https://github.com/chungou1996/NSMoonCN)上，以GPL开源，感谢汉公等逆向前辈。  

# 文件结构
  从Crass的源代码基础上，可以看到pak文件实际是  
1.pak_header magic GsPack4 abc  
2.pak_data  
3.pak_index  
  这三个块所组成的打包文件，其中pak_header记录了pak_data和pak_index在pak文件中的偏移和长度。  
pak_index和下面的scw_data为LZSS加密，此算法在标准算法上有所改动，根据网上的一些资料和自己研究，花了两个晚上时间解决了加密算法，在C#上，由于byte在位运算后变为32位，会导致算法异常，将byte&0xff取低8位即可。  
  pak_index记录了文件在pak_data中的偏移和长度。  
  在剧本主要的SCR.PAK中，主要存放的是magic为Scw4.x的文件。  
  scw文件主要为  
1.scw_header  
2.scw_data  
  其中scw_header主要存放scw_data的长度以及，各个块的位置，scw_data为LZSS加密，同时还做了异或，因此解包之前需要对scw_data进行异或还原，再LZSS解密。  
  其中scw_data主要存放了6个块，分别是  
1.脚本表  
2.字符串表  
3.方法表  
4.脚本  
5.字符串  
6.方法  
  其中脚本暂时不明白意义，为游戏实际执行的剧本，方法经观察，实际反映了脚本的数个块的长度，猜测应该是将一部分脚本认为是某个方法，然后在脚本中使用。这里只关心字符串表和字符串即可。  
  至此游戏资源的解包全部结束。  
# 可执行文件  
  需要将游戏的编码改成gb2312，使用ollydbg调试程序，根据对程序的导入表观察，猜测程序使用了Createfontindirect创建字体后，使用TextOut对文本输出。因此在Createfontindirect下断点，游戏两次调用了这个方法，第一次断点时观察TextOut的入栈参数，可知第一次调用是为了输出倒三角，第二次调用才是输出文本。这里修改参数指向的LOGFONT结构体，将lfCharSet从0x80改为0x86，继续程序后，发现游戏变成乱码，证明方法正确。  
  然而倒入gb2312文本时仍然不正常。观察堆栈可以发现，在TextOut的参数压入栈的时候，已经只有一个字节了，也就因为未知的原因，游戏将中文字符认为是单字节了，这里继续向上跟踪堆栈压入的返回地址，在地址0x414824处可以发现关键代码cmp ax,0x80和下面的3个cmp，这里的意思是检查字符的边界是否在指定的区域内，否则就认为是单字符，这里将几个cmp修改为gb2312的编码范围，然后重开游戏，正常显示中文了。  
  但是刚才对于LOGFONT的改动，由于是内存数据，必须找到LOGFONT是在何时压入的lfCharSet代码0x80，这里向堆栈上跟踪了几个方法没有找到，于是转变思路，LOGFONT里有字体的名称，而字体的名称在data段，因此在程序中必然有，重新载入程序，搜索字体的开头，找到了字体，然后在该内存区域下内存断点，成功断下，向上寻找堆栈后，终于在地址0x44565f处找到关键代码mov指令将80压入栈，这里修改为86，保存到程序，正常了。  
  但是倒三角由于也是使用这个字体，被解释成了中文字符乱码，但是猜测倒三角是硬编码的，因此直接使用16进制编辑器在主程序里寻找倒三角的编码，运气不错的是只有一处，直接将它改成gb2312的倒三角编码，保存运行。  
![nsmoon]({{ site.baseurl }}/images/nsmoon.jpg)