---
layout: post
tags: xv6 
category: OS
---
[TOC]
# Memory Management

{% highlight c linenos %}
static inline void*
page2kva(struct PageInfo *pp)
{
	return KADDR(page2pa(pp));
}
static inline physaddr_t
page2pa(struct PageInfo *pp)
{
	return (pp - pages) << PGSHIFT;
}
#define KADDR(pa) _kaddr(__FILE__, __LINE__, pa)

static inline void*
_kaddr(const char *file, int line, physaddr_t pa)
{
	if (PGNUM(pa) >= npages)
		_panic(file, line, "KADDR called with invalid pa %08lx", pa);
	return (void *)(pa + KERNBASE);
}
{% endhighlight %}

{% highlight ruby %}
def foo
  puts 'foo'
end
{% endhighlight %}

内存管理有两个部分。

首先是关于内核的物理内存分配器，分配了实际的物理内存后，内核才能分配内存并在之后释放它。任务是维护记录着空闲页表和已分配页表的数据结构，以及多少进程在共享分配的页面。需要编写分配和释放页面的流程。

其次是虚拟内存管理。根据要求来修改JOS设置页表的方式。

`git checkout -b lab2 origin/lab2`

1. 基于origin/lab2建立本地的lab2分支
2. 改变lab下的内容来更新lab2分支的文件

新增/改动文件说明

| 文件名            |                                                              |
| ----------------- | ------------------------------------------------------------ |
| `inc/memlayout.h` | ⭐通过改动`pmap.c`，`pmap.h`以及`inc/memlayout.h`应该实现的虚拟地址空间的内存分布。 |
| `kern/pmap.c`     | 读取设备硬件来确定物理内存空间有多少。                       |
| `kern/pmap.h`     | ⭐可以也参考`inc/mmu.h`                                       |
| `kern/kclock.h`   | 管理PC的后备电池和CMOS RAM硬件，BIOS在其中记录PC的物理内存。 |
| `kern/kclock.c`   |                                                              |

## Part 1：Physical Page Management

JOS以页面为单位管理PC的物理内存，因此MMU可以通过映射来保护分配的内存。

编写一个物理页面分配器。使用以`struct PageInfo`为元素的链表来管理空闲页面。该链表不像xv6一样就存储在空闲页面中，而是要另外写。每个链表元素都对应着一个空闲的物理页面。



## Part 2：Virtual Memory

了解x86保护模式下的分段和页转换机制。



### Virtual，Linear and Physical Addresses

{% raw %}

           Selector  +--------------+         +-----------+
          ---------->|              |         |           |
                     | Segmentation |         |  Paging   |
Software             |              |-------->|           |---------->  RAM
            Offset   |  Mechanism   |         | Mechanism |
          ---------->|              |         |           |
                     +--------------+         +-----------+
            Virtual                   Linear                Physical

{% endraw %}
C指针实际时虚拟地址的offset部分。在`boot/boot.S`中，通过加载GDT并设置所有的`base`和`limit`分别为`0`和`0xffffffff`来禁用了段转换功能。因此selector域没有任何的功能，并且线性地址永远等于虚拟地址。

JOS内核有时需要读取或修改物理地址的内存。例如，将映射添加到页表可能需要分配物理内存以存储页目录，然后初始化该内存。但是，内核无法绕过虚拟地址转换，因此无法直接加载并存储到物理地址。 

JOS将物理地址0开始的所有物理内存重映射到虚拟地址`0xf0000000`处的的原因之一是帮助内核仅知道物理地址时读写内存。能够将物理地址转换为内核可以实际读写的虚拟地址，内核必须在物理地址上添加`0xf0000000`才能在重映射区域中找到其对应的虚拟地址。应该使用`KADDR(pa)`进行添加。

JOS内核有时有时还需要能够根据虚拟地址找到物理地址。 `boot_alloc()`分配的内核全局变量和内存位于加载内核的区域中，从`0xf0000000`开始，该区域正是我们映射所有物理内存的区域。因此，要将该区域中的虚拟地址转换为物理地址，内核可以简单地减去`0xf0000000`。应该使用`PADDR(va)`进行减法。



### Reference counting

在`struct PageInfo`中维护一个`pp_ref`来记录对每个物理页面的引用次数。当计数为0时，物理页面就可以被释放。总的来说，该计数值应该等于物理页面在所有页表中在UTOP之下出现的次数。同时，该值还可以被用来记录对页目录的引用指针次数以及页目录对页表的引用次数。

使用`page_alloc()`时，其返回的页面的引用次数一直是0.因此`pp_ref`应该及时进行递增。



### Page Table Management

插入和移除页表中的映射。

在需要时创建页表。



## Part 3：Kernel Address Space

JOS将处理器的32位线性地址空间分成两个部分。用户部分占用低地址，内核部分通常占用高地址。该分界线在`memlayout.h`中，为内核虚拟地址空间预留了大约256MB的内容。这也是为什么要给内核一个相对较高的链接地址的原因：否则，内核的虚拟地址空间将没有足够的空间同时映射到其下方的用户环境中。



### Permissions and Fault Isolation


由于内核和用户内存都存在于每个环境的地址空间中，因此我们将不得不使用x86页表中的权限位来允许用户代码仅访问地址空间的用户部分。否则，用户代码中的错误可能会覆盖内核数据，从而导致崩溃或更微妙的故障。用户代码也可能能够窃取其他环境的私有数据。请注意，可写权限位（PTE_W）同时影响用户代码和内核代码！

用户环境将不具有对ULIM之上的任何内存的许可，而内核将能够读写此内存。对于地址范围[UTOP，ULIM），内核和用户环境都具有相同的权限：它们可以读取但不能写入该地址范围。此地址范围用于将某些内核数据结构只读给用户环境。最后，UTOP下的地址空间供用户环境使用；用户环境将设置访问该内存的权限。

### Initializing the Kernel Address Space

建立UTOP之上的地址空间即内核部分。



### Address Space Layout Alternatives


在JOS中使用的地址空间布局不是唯一的一种。操作系统可能会将内核映射到低线性地址，而将线性地址空间的上部留给用户进程。但是，x86内核通常不采用这种方法，因为x86的向后兼容模式之一（称为虚拟8086模式）在处理器中“硬接线”以使用线性地址空间的底部，因此如果将内核映射到那里将不可以使用。

甚至有可能（尽管要困难得多）设计内核，以便不必自己保留处理器的线性或虚拟地址空间的任何固定部分，而是有效地允许用户级进程不受限制地使用整个4GB虚拟地址空间-同时仍然完全保护内核免受这些进程的侵害，并保护彼此之间的不同进程！

---

Exercise 1

首先分析一下各个函数的目的和其简单流程



mem_init

1. 探测可用物理内存，输出到屏幕，并初始化npages（空闲物理页面总数），npages_basemem（空闲基本内存页面数）

2. 建立最初始的内核页表，使用boot_alloc分配内存。boot_alloc使用的是从bss开始的虚拟内存。类似于在代码中的kpgdir；

	<img src="C:\Users\60392\AppData\Roaming\Typora\typora-user-images\image-20200218194935556.png" alt="image-20200218194935556" style="zoom:50%;" />

	看到，bss的链接地址是0xf0113300，在经过了ROUNPUP对齐之后，分配到的kern_pgdir的地址应该是0xf0114000

	<img src="C:\Users\60392\AppData\Roaming\Typora\typora-user-images\image-20200218195059971.png" alt="image-20200218195059971" style="zoom:50%;" />

3. 先将页表全部字节置零，再建立映射[UVPT]->[kern_pgdir的物理地址（虚拟地址-KERNBASE）]

  PDX[UVPT]得到了前十位(将其右移22位)，这是作为页表目录的索引的

  UVPT=111011110100(0x00000)

  PDX[UVPT] = 1110111101

  这意味着，页表目录的UVPT项对应的页表是他自己，第N页的页表项为UVPT[N]

  <img src="C:\Users\60392\AppData\Roaming\Typora\typora-user-images\image-20200218195428459.png" alt="image-20200218195428459" style="zoom:50%;" />

4. 建立pages数据结构管理所有的物理页面即npages个物理页面，之前kern_pgdir占用一个页面，那么pages的地址应该从一个页面后开始，是`0xf0115000`

5. 进行页面初始化，将pages数据结构中已经使用的去除，没有使用的建立好page_free_list。

补全页面分配和释放的操作，对页面用memset进行置位时，要注意，memset应该传入物理页面对应的的虚拟地址，因此使用page2kva。

{% highlight c%}
static inline void*
page2kva(struct PageInfo *pp)
{
	return KADDR(page2pa(pp));
}
static inline physaddr_t
page2pa(struct PageInfo *pp)
{
	return (pp - pages) << PGSHIFT;
}
#define KADDR(pa) _kaddr(__FILE__, __LINE__, pa)

static inline void*
_kaddr(const char *file, int line, physaddr_t pa)
{
	if (PGNUM(pa) >= npages)
		_panic(file, line, "KADDR called with invalid pa %08lx", pa);
	return (void *)(pa + KERNBASE);
}
{% endhighlight %}


pages的地址是结构体数组struct PageInfo的起始地址，其中的编号对应着相应的物理页面。

![lab2_0](C:\Users\60392\Desktop\202002\lab2_0.png)

看page2pa，通过结构体指针减去结构体起始地址pages，得到的是下标i，即&pages[i] - &pages[0] = i。

而后再左移PGSHIFT(log2(PGSIZE))位，得到其对应物理页面的真实物理地址，再通过KADDR将其上移，就得到了虚拟地址。



pgdir_walk

页表的结构到底是怎样的

页表目录共有一页4096字节，一项4字节即32位，对于一个虚拟地址，其前10位是页表目录的表项，正好对应页表目录的1024项。在取得页表目录表项之后，该项的内容是指向页表的地址。

使用PTE_ADDR(页表目录项内容)来获得该内容对应的页面的实际物理地址，因此还需要KADDR来转换成虚拟地址。

![lab2_1](C:\Users\60392\Desktop\202002\lab2_1.png)



6. 接下来设置虚拟地址
	1. 将pages结构体数组映射到UPAGES，设置用户只读
	2. 将bootstack指向的物理地址映射为内核栈
	3. 将KERNBASE以上的全部映射，限制是npages





`boot_alloc()`

在UTOP之上建立内存映射，只在JOS建立虚拟内存系统时使用，page_alloc才是真正的物理内存分配器。

- n>0，分配足够的连续物理页面来存放n个字节的内容，不初始化内存，返回分配的内核的虚拟地址。
- n==0，不进行分配工作，返回下一个空闲页面的地址。
- 没有内存可分配，boot_alloc应该panic
- 该函数只在初始化的时候调用，此时，page_free_list列表还没有建立



`mem_init()`

建立一个两层的页表。

`kern_pgdir`是根的虚拟地址。

该函数只是建立在UTOP之上的内核部分的地址空间。

从UTOP到ULIM的区域是用户可读但不可写的，ULIM之上用户没有读写权限

```
void
mem_init(void)
{
	uint32_t cr0;
	size_t n;
/* 检查机器内存 */
	i386_detect_memory();
	//panic("mem_init: This function is not finished\n");

/* 
 * 建立最开始的内核页表目录 ，使用boot_alloc进行分配
 */   
	kern_pgdir = (pde_t *) boot_alloc(PGSIZE);
	memset(kern_pgdir, 0, PGSIZE);

/*
 * 递归地将页表目录作为页表插入自身，以在地址UVPT处形成虚拟页表地址。
 * PADDR将虚拟内核地址（在KERNBASE之上的地址）转换成相应的物理地址。
 * 在内核页表中，插入用户页表的物理地址。
 */
	kern_pgdir[PDX(UVPT)] = PADDR(kern_pgdir) | PTE_U | PTE_P;
/*
 * 分配npages个struct PageInfo的数组，存放在pages中。
 * kernel使用该数据来跟踪记录物理页面的使用情况：对每个物理页面都应该有一个相应的结构体保存信息。
 * npages时内存中的物理页面的个数
 * 使用memset来初始化为0
 */
	// Your code goes here:

/*
 * 分配了初始化的内核数据结构，建立空闲物理页面表
 * 之后的内存管理都会通过page_开头的函数进行
 * 可以使用boot_map_regin或page_insert来进行内存映射
 */
	page_init();

	check_page_free_list(1);
	check_page_alloc();
	check_page();

    // 虚拟内存建立完毕
	// 将用户只读的pages映射到线性地址UPAGES
	// Permissions:
	//    - the new image at UPAGES -- kernel R, user R
	//      (ie. perm = PTE_U | PTE_P)
	//    - pages itself -- kernel RW, user NONE
	// Your code goes here:

/*
 * 使用bootstack指向的内核栈的物理地址空间
 * 内核栈从KSTACKTOP向下生长，将其分为两个部分：
 * 1. [KSTACKTOP-KSTKSIZE, KSTACKTOP)由物理内存备份，即从KSTACKTOP向下生长的栈
 * 2. [KSTACKTOP-PTSIZE, KSTACKTOP-KSTKSIZE)不备份
 * 可以在溢出时及时报错
*/
	//     Permissions: kernel RW, user NONE
	// Your code goes here:

/*
 * 将KERNBASE的所有物理地址进行映射，
 * 虚拟地址[KERNBASE, 2^32)映射到物理地址[0, 2^32 - KERNBASE)
*/
	// Permissions: kernel RW, user NONE
	// Your code goes here:

	// Check that the initial page directory has been set up correctly.
	check_kern_pgdir();
/*
 * 从最小的页表目录入口转到完整的页表目录
 * 指令指针正在KERNBASE 和 KERNBASE+4MB之间的某个位置，该位置被两个页表都同样地映射了
 * 如果机器在这时重启，那就可能设置错误了。
*/
	lcr3(PADDR(kern_pgdir));

	check_page_free_list(0);

	// entry.S set the really important flags in cr0 (including enabling
	// paging).  Here we configure the rest of the flags that we care about.
	cr0 = rcr0();
	cr0 |= CR0_PE|CR0_PG|CR0_AM|CR0_WP|CR0_NE|CR0_MP;
	cr0 &= ~(CR0_TS|CR0_EM);
	lcr0(cr0);

	// Some more checks, only possible after kern_pgdir is installed.
	check_page_installed_pgdir();
}
```



# Code Analysis

创建地址空间

对于物理地址的分配，在文件kmalloc中

```c
// Allocate one 4096−byte page of physical memory.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
char*
kalloc(void)
{
	struct run *r;

	if(kmem.use_lock)
		acquire(&kmem.lock);
	r = kmem.freelist;
	if(r)
		kmem.freelist = r−>next;
	if(kmem.use_lock)
		release(&kmem.lock);
	return (char*)r;
}
```





```c
/*
 * main首先调用kvmalloc，将内核页表设置好，并将内核页表加载到cr3中
 */
// Set up kernel part of a page table.
void
kvmalloc(void)
{
	kpgdir = setupkvm();
	switchkvm();
}
// 程序返回的都是虚拟地址
// setupkvm完成内核部分的地址映射，映射关系在kmap结构体中
// V2P/P2V都只是简单地将地址减去/加上KERNBASE
static struct kmap {
void *virt;
uint phys_start;
uint phys_end;
int perm;
} kmap[] = {
    // I/O space
    // KERNBASE -> 0~EXTMEM
	{ (void*)KERNBASE, 0, EXTMEM, PTE_W}, 
    // kern text+rodata KERNLINK是链接器的链接地址
    // KERNLINK -> KERNLINK物理地址 ~ data的物理地址
	{ (void*)KERNLINK, V2P(KERNLINK), V2P(data), 0}, 
    // kern data+memory
    // data -> data物理地址 ~ PHYSTOP
	{ (void*)data, V2P(data), PHYSTOP, PTE_W}, 
	{ (void*)DEVSPACE, DEVSPACE, 0, PTE_W}, // more devices
};
pde_t*
setupkvm(void)
{
	pde_t *pgdir;
	struct kmap *k;
	
	if((pgdir = (pde_t*)kalloc()) == 0)
		return 0;
	memset(pgdir, 0, PGSIZE);
	if (P2V(PHYSTOP) > (void*)DEVSPACE)
		panic("PHYSTOP too high");
	for(k = kmap; k < &kmap[NELEM(kmap)]; k++)
		if(mappages(pgdir, k−>virt, k−>phys_end − k−>phys_start,
		(uint)k−>phys_start, k−>perm) < 0) {
            freevm(pgdir);
			return 0;
		}
		return pgdir;
}
void
switchkvm(void)
{
	lcr3(V2P(kpgdir)); // switch to the kernel page table
}
```

