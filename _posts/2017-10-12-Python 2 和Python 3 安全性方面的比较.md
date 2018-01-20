---

layout: post

title: 'Python 2 和Python 3 安全性方面的比较'

date: '2017-10-12'

header-img: "img/home-bg.jpg"

tags:
     - python  
author: 'De4dCr0w'

---

<!-- more -->

###  异常处理机制

Python 3是默认开启异常链的，当异常发生的时候，会完整地显示回溯路径和异常细节。而Python 2 默认下是不显示的。

### 输入函数

Python 2 提供了eval（）函数，但这并不是一个安全的函数，因为它会将字符串当做有效的表达式来求值并返回计算结果  
例如，输入以下字符串，就会执行显示当前目录文件的命令：
```
__import__('os').system('dir')
```
Python 2 提供的input函数和eval函数类似，也是不安全的，所以Python 2应该尽量不使用这两个函数，而用raw_input来代替

而在Python 3中的input函数就是Python 2中的raw_input，是安全的。

但是如果在Python 2环境中运行Python 3，那么input就会存在问题。

总结如下：

| 函数      |    Python 2 | Python 3  |
| :-------- | --------:| :--: |
| eval()    | 不安全 |  不安全   |
| input()    |  不安全 |  和Python 2的raw_input类似 |
| raw_input()    |    暂时安全 | 已经移除 |

### 整数除法

在Python 2 中整数除法总是返回结果的整数部分，就是地板除。而在Python 3中用**//**实现地板除，而**/**是真除法，会保留小数部分。那么不安全的地方有可能发生在Python 3程序在Python 2 环境里运行的时候，这得放在具体的环境中去分析。

### 默认编码

Python 2 默认使用ASCII编码，而ASCII编码只能表示256个字符。而Python 3默认使用的是Unicode编码，支持超过128000个字符。  
这种差异可能导致网络钓鱼。所以在Python 2和3环境切换时要注意该问题，尽量都转成Unicode码。


### 总结
Python 2 官方支持到2020年，所以可以计划使用Python 3了。

参考链接：https://snyk.io/blog/python-2-vs-3-security-differences/ 