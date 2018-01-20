---

layout: post

title: 'system_call到iret过程分析'

date: '2017-03-20'

header-img: "img/home-bg.jpg"

tags:
     - linux   
author: 'De4dCr0w'

---

<!-- more -->

>版权声明：本文为博主原创文章，未经博主允许不得转载。
>
>罗军 + 原创作品转载请注明出处 + 《Linux内核分析》MOOC课程http://mooc.study.163.com/course/USTC-1000029000  

### 基础知识 ###

#### 中断的分类 ####

（1）中断有两种，一种是由CPU外部硬件产生的，另一种是由CPU本身执行程序的过程中产生的；外部中断即我们所说的中断（interrupt），外部中断是异步的，由硬件产生，我们无法预测它什么时候发生；  
（2）x86软件产生的中断是由“INT n”同步产生的，由程序产生，只要CPU执行了一条INT指令，就知道在开始执行下一条指令前就会进入中断服务程序，我们又称此类中断为“陷阱”；int 80为系统调用的陷阱号；  
（3）异常，是被动的，如页面异常，除数为0的异常；  
因此系统调用是中断中的陷阱的一种，系统调用只发生在用户空间，必然会发生用户栈和内核栈的切换。

#### 中断的过程 ####

　　在linux内核启动过程中，start_kernel中trap_init()函数初始化了中断门，通过set_system_intr_gate->set_gate进行设置，通过write_idt_entry将中断信息写进中断描述符表IDT，中断描述符表（Interrupt Descriptor Table，IDT）是一个系统表，它与每一个中断或异常向量相联系，每一个向量在表中存放的是相应的中断或异常处理程序的入口地址，当处于实模式下时，IDT 被初始化并由 BIOS 程序所使用。然而，一旦 Linux 开始接管，IDT 就被移到另一个区域，并进行第二次初始化。  
　　　当中断发生时，通过中断描述符表IDT获取中断服务程序入口地址，调用相应的中断服务程序，而int 0x80的中断服务程序就是system_call  

![](http://i.imgur.com/7BjTT3j.png)

### 实验过程 ###

#### 修改test.c文件 ####

将fork和fork-asm函数添加到test.c文件中，如下图：

![](http://i.imgur.com/OZ8j2K1.png)

运行效果如下：

![](http://i.imgur.com/T7jNaCz.png)

### system_call代码分析 ###

> system_call代码

	ENTRY(system_call)
		RING0_INT_FRAME			# can't unwind into user space anyway
		ASM_CLAC
		pushl_cfi %eax			# save orig_eax
		SAVE_ALL
		GET_THREAD_INFO(%ebp)
						# system call tracing in operation / emulation
		testl $_TIF_WORK_SYSCALL_ENTRY,TI_flags(%ebp)
		jnz syscall_trace_entry
		cmpl $(NR_syscalls), %eax
		jae syscall_badsys
	syscall_call:
		call *sys_call_table(,%eax,4)
	syscall_after_call:
		movl %eax,PT_EAX(%esp)		# store the return value
	syscall_exit:
		LOCKDEP_SYS_EXIT
		DISABLE_INTERRUPTS(CLBR_ANY)	# make sure we don't miss an interrupt
						# setting need_resched or sigpending
						# between sampling and the iret
		TRACE_IRQS_OFF
		movl TI_flags(%ebp), %ecx
		testl $_TIF_ALLWORK_MASK, %ecx	# current->work
		jne syscall_exit_work

下面我们看看SAVE_ALL执行了哪些操作，对fork系统调用一文中我们对linux-0.11内核版本的进行分析，了解到system_call会保存用户态堆栈的相关寄存器，下面就是对应的保存操作

>SAVE_ALL代码  

	.macro SAVE_ALL
		cld
		PUSH_GS
		pushl_cfi %fs
		/*CFI_REL_OFFSET fs, 0;*/
		pushl_cfi %es
		/*CFI_REL_OFFSET es, 0;*/
		pushl_cfi %ds
		/*CFI_REL_OFFSET ds, 0;*/
		pushl_cfi %eax
		CFI_REL_OFFSET eax, 0
		pushl_cfi %ebp
		CFI_REL_OFFSET ebp, 0
		pushl_cfi %edi
		CFI_REL_OFFSET edi, 0
		pushl_cfi %esi
		CFI_REL_OFFSET esi, 0
		pushl_cfi %edx
		CFI_REL_OFFSET edx, 0
		pushl_cfi %ecx
		CFI_REL_OFFSET ecx, 0
		pushl_cfi %ebx
		CFI_REL_OFFSET ebx, 0
		movl $(__USER_DS), %edx
		movl %edx, %ds                                                  
		movl %edx, %es
		movl $(__KERNEL_PERCPU), %edx
		movl %edx, %fs
		SET_KERNEL_GS %edx
	.endm

　　我们通过syscall_call进行系统调用（这部分已经在fork系统调用一文中阐述过了）后，在syscall_after_call中进行返回，返回的结果保存在eax寄存器中。然后顺序执行到syscall_exit，这部分首先关闭中断，保证不被其它中断和信号打扰。然后判断是否响应其它中断或信号，如果所有标志都没设置，就直接restore_all,恢复原来进程的执行，如果有的话就进入syscall_exit_work。然后判断是否还有任务，如果有就跳转到work_pending。

>work_pending代码

	work_pending:
		testb $_TIF_NEED_RESCHED, %cl
		jz work_notifysig
	work_resched:
		call schedule
		LOCKDEP_SYS_EXIT
		DISABLE_INTERRUPTS(CLBR_ANY)	# make sure we don't miss an interrupt
	        ...
		jz restore_all

　　在work_pending中先判断NEED_RESCHED位，如果置位了就执行work_resched段代码，被动调度当前进程，调度完还会继续判断是否还有任务，是否还有调度进程，这里是一个循环处理，直到判断没置位，就继续处理当前进程未处理的信号，最后会跳转到resume_userspace，恢复到用户态。

>resume_userspace

	ENTRY(resume_userspace)
		LOCKDEP_SYS_EXIT
	 	DISABLE_INTERRUPTS(CLBR_ANY)	# make sure we don't miss an interrupt
						# setting need_resched or sigpending
						# between sampling and the iret
		TRACE_IRQS_OFF
		movl TI_flags(%ebp), %ecx
		andl $_TIF_WORK_MASK, %ecx	# is there any work to be done on
						# int/exception return?
		jne work_pending
		jmp restore_all
	END(ret_from_exception)

　　在系统调用或中断，异常返回到用户态之前内核都会检查是否有信号在当前进程中挂起，然后转而去处理这些信号。
  
具体的从system_call开始到iret结束之间的整个过程如下图：  

![](http://i.imgur.com/CbLYL2q.png)

参考资料：  
[http://www.2cto.com/os/201404/292864.html](http://www.2cto.com/os/201404/292864.html)  
[http://blog.csdn.net/yaozhenguo2006/article/details/7313956](http://blog.csdn.net/yaozhenguo2006/article/details/7313956)  
[理解系统调用的原理（二）](http://burningcodes.net/%e7%90%86%e8%a7%a3%e7%b3%bb%e7%bb%9f%e8%b0%83%e7%94%a8%e7%9a%84%e5%8e%9f%e7%90%86%ef%bc%88%e4%ba%8c%ef%bc%89/)