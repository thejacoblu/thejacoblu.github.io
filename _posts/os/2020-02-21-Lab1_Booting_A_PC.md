---
layout: post
tags: xv6 
category: OS
---
# Lab1：Booting A PC

## Part 1：PC Bootstrap

- X86汇编语言
- PC自举过程
- QEMU的使用以及与GDB的结合调试



QEMU自带的监视器只能提供有限的debug支持，但QEMU可以作为GDB远程的目标调试机。

在lab目录下执行了`make`之后，`obj/kern/kernel.img`已经存放了用于模拟PC的虚拟光盘，这个光盘镜像文件包含了boot loader(`obj.boot/boot`)和kernel(`obj/kernel`)的内容。

使用`make qemu`指令，会弹出QEMU窗口，其内容和shell的内容同步；退出时只需关闭即可。使用`make qemu-nox`指令，就可以在jnbshell上运行，退出时`Ctrl+a x`即可。



### PC的物理地址空间

<img src="C:\Users\60392\Desktop\lab1_0.png" alt="lab1_0" style="zoom:67%;" />

初代PC基于16位的intel8088处理器，只能寻址1MB的物理空间，只能配置16KB，32KB，664KB的RAM。

从`0x000A0000`到`0x000FFFFF`的内存空间是由硬件保存以进行特殊使用的。比如视频播放缓存以及固件信息。

其中最重要的是基本IO系统(Basic Input/Output System)即BIOS，占据了64KB的空间。早期的BIOS烧写在只读存储器上，但现在BIOS被存放在可更新的flash中。BIOS负责将系统初始化，激活视频卡，检查内存分配等。处理完毕之后，将操作系统加载到内存，并将控制权交给内核。

当80286/80236突破了1MB的障碍后，物理地址空间分别扩展到了16MB/4GB。

Low memory仍然被保存，以便向前兼容现存的软件。因此现代的PC会从`0x000A0000`到`0x00100000`存在一个空洞。

### ROM BIOS

打开两个终端，进入到lab目录下，一个执行`make qemu-nox-gdb`或`make qemu-gdb`，qemu会启动但会在处理器执行第一条指令时停下，等待远程的debug连接。在另一个终端执行`make gdb`。

```bash
jacob@ubuntu:~/6828_lab/lab1$ make gdb
gdb -n -x .gdbinit
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.5) 7.11.1
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word".
+ target remote localhost:26000
warning: A handler for the OS ABI "GNU/Linux" is not built into this configuration
of GDB.  Attempting to continue with the default i8086 settings.

The target architecture is assumed to be i8086
[f000:fff0]    0xffff0:	ljmp   $0xf000,$0xe05b
0x0000fff0 in ?? ()
+ symbol-file obj/kern/kernel
(gdb) 
```

- PC从物理地址`0x000ffff0`执行命令
- [CS:IP]分别为[f000:fff0]
	- CS是代码段寄存器，IP为指令指针寄存器，指示了CPU当前要读取指令的地址。
	- 任意时刻8086CPU会将CS:IP指向的指令作为下一条需要取出的指令
	- https://www.jianshu.com/p/d1721bd48c88
- jmp指令跳转到[f000:e05b]执行

PC机中的BIOS通过硬件机制连线到物理地址`0x000f0000-0x000fffff`，确保BIOS总是在通电后首先获得对机器的控制。

QEMU将BIOS放在处理器的模拟的物理地址空间上。处理器重启时，处理器就将CSIP设置为上面的值，使得指令从[CS:IP]开始执行。

而[CS:IP]转化成物理地址的公式如下
$$
physical=16*segment+offset
$$
那么，$16*0xf000+0xfff0=0xffff0$，在0x100000的16字节前的位置。

BIOS启动时，建立中断描述符表，初始化多个设备。发现可启动的硬件胡，从硬盘读取boot loader，并将控制权交给它。



## Part 2：The Boot Loader

PC的硬盘的空间都以512字节为单位分块，称作扇区。扇区是硬盘的最小数据传输单位。

如果硬盘是可自举的，第一个扇区就称作boot sector，存放了boot loader的代码。如果BIOS发现了可自举的硬盘，那么就将512字节的扇区内容加载到`0x7c00-0x7dff`的位置，然后使用`jmp`指令跳转到`0x0007c00`执行。

现代的BIOS从CD-ROM加载。使用2048字节大小的扇区。

本课程中的boot代码在`boot/main.c`以及`boot/boot.S`中，执行以下步骤：

1. 首先，boot loader将处理器从实地址模式(real mode)转化成32位的保护模式。只有在该模式下软件可以访问1MB以上的物理地址空间。地址转换的方式和上面提到的不同
2. 其次，boot loader直接访问设备寄存器将kernel从硬盘中读出。

`obj/boot/boot.asm`和`obj/kern/kernel.asm`包含了编译后的指令。

- 处理器何时开始执行32位的代码？
- 什么导致了从16位到32位模式的转换？
- boot loader执行到哪条指令为止？kernel从哪条指令开始？
- boot loader如何决定读取多少扇区以完整加载kernel？该信息从哪里找到？

### Loading the kernel

理解`boot/main.c`

ELF(Executable and Linkable) binary

当编译C文件时，.c文件转换成了包含汇编语言指令的二进制表示的.o文件。链接器再将编译好的.o文件组合成一个二进制文件，该文件就以ELF形式表示。

ELF文件可以视为一个含有加载信息、程序区块信息、加载数据信息的头文件。

ELF文件以固定长度的ELF头开始，接着是可变长的程序头部，列出了将要加载的程序块，我们需要知道的程序区有

- `.text`：可执行指令
- `.rodata`：只读数据
- `.data`：程序初始化了的数据

当链接器计算程序的内存布局时，会为没有初始化的全局变量保留空间。保存在紧跟`.data`的`.bss`存储区。在C程序中，未被初始化的全局变量都会是0，因此没有必要在`.bss`中保存内容。链接器只需要记录`.bss`块的地址和大小。加载器或程序自己负责置零操作。

```bash
jacob@ubuntu:~/6828_lab/lab1$ objdump -h ./obj/kern/kernel

./obj/kern/kernel:     file format elf32-i386

Sections:
Idx Name          Size      VMA       LMA       File off  Algn
  0 .text         00001871  f0100000  00100000  00001000  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  1 .rodata       00000714  f0101880  00101880  00002880  2**5
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  2 .stab         000038d1  f0101f94  00101f94  00002f94  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  3 .stabstr      000018bb  f0105865  00105865  00006865  2**0
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  4 .data         0000a300  f0108000  00108000  00009000  2**12
                  CONTENTS, ALLOC, LOAD, DATA
  5 .bss          00000648  f0112300  00112300  00013300  2**5
                  CONTENTS, ALLOC, LOAD, DATA
  6 .comment      00000035  00000000  00000000  00013948  2**0
                  CONTENTS, READONLY
```

LMA（load address）是该块被加载到内存时的物理地址。

VMA（link address）是该块开始执行时的虚拟内存地址。

```shell
jacob@ubuntu:~/6828_lab/lab1$ objdump -h ./obj/boot/boot.out

./obj/boot/boot.out:     file format elf32-i386

Sections:
Idx Name          Size      VMA       LMA       File off  Algn
  0 .text         00000186  00007c00  00007c00  00000074  2**2
                  CONTENTS, ALLOC, LOAD, CODE
  1 .eh_frame     000000a8  00007d88  00007d88  000001fc  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  2 .stab         00000720  00000000  00000000  000002a4  2**2
                  CONTENTS, READONLY, DEBUGGING
  3 .stabstr      0000088f  00000000  00000000  000009c4  2**0
                  CONTENTS, READONLY, DEBUGGING
  4 .comment      00000035  00000000  00000000  00001253  2**0
                  CONTENTS, READONLY

```

对于boot loader而言，VMA和LMA是相同的。boot loader使用ELF头来决定如何加载块，程序头指定ELF对象的哪些部分要加载到内存中的以及每个部分的目标地址。

ELF头部中的e_entry，存放的是程序开始点，即程序text块的内存地址。

```shell
jacob@ubuntu:~/6828_lab/lab1$ objdump -f ./obj/kern/kernel

./obj/kern/kernel:     file format elf32-i386
architecture: i386, flags 0x00000112:
EXEC_P, HAS_SYMS, D_PAGED
start address 0x0010000c
```



## Part 3：The Kernel

kernel的VMA和LMA是不一致的。操作系统内核经常会在虚拟内存高地址链接运行，以留出低地址给用户程序使用。

很多机器在`0xf0100000`没有物理内存，因此使用内存管理硬件的映射机制，将虚拟地址`0xf0100000`（VMA）映射为真实的物理地址`0x00100000`（LMA）

在`kern/entry.s`设置`CR0_OG`之前，虚拟内存地址直接被视为物理地址。设置之后，虚拟内存地址需要映射为物理地址。

`kern/entrypgdir.c`实现映射，将虚拟内存地址`0xf0000000 - 0xf0400000`映射到`0x00000000 - 0x00400000`，以及`0x00000000 - 0x00400000`映射到`0x00000000 - 0x00400000`。

不在范围内的地址会导致硬件报异常错误。QEMU在输出机器信息后退出。

### 控制台格式化输出

`kern/printf.c`，`lib/printfmt.c`， `kern/console.c`



### The Stack

- kernel在哪里初始化栈
- 栈在内存中的位置
- 内核如何为栈分配空间
- 栈指针指向分配空间的高地址还是低地址 

x86栈指针为`esp`寄存器，指向栈正在使用的最低地址。栈向低地址（向下）生长，向栈加入值时，先将栈指针递减，然后向其写入值。

在32位模式下，栈只能保存32位的值，esp可以被4整除。多种x86指令是硬连线的，可以直接使用栈指针。

基地址指针`ebp`通过程序操作来和栈指针相关联。在进入C函数时，将调用者的基地址指针压入栈保存，然后将esp的内容放入ebp，此后就可以通过栈来实现回溯。

基于这个机制，当某个函数产生assert错误或者panic之后，可以通过栈来追踪产生错误的原因。

查看`kern/monitor.c`，`inc/x86.h`

`eip`时函数的返回指令指针，保存函数返回时的指令地址

> 指针和整数相加，指针移动的实际是整数个该指针指向的类型的大小。

为了知道导致kernel出错的函数是什么，在`kern/kdebug.c`中有具体实现。

---

# Book guidance

## Modern x86 registers

|                |                                                              |                                                              |
| -------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 32位通用寄存器 | `%eax`, `%ebx`, `%ecx`, `%edx`<br />`%edi`, `%esi`, `%ebp`, `%esp` | 'e' for extended，是对16位的`%ax`, `%bx`...的扩展。<br />用`%al`, `%ah`来表示`%ax`的低八位和高八位，依此类推<br />`edi` 常用作指针，和`esi`很相似，只是后者常常作为源，前者作为目的指针<br />在进入函数时，`%ebp`保存了`%esp`当前的值 |
| 程序计数器(PC) | `%eip`                                                       |                                                              |
| 特殊寄存器     | `%cr0`, `%cr1`, `%cr2`, `%cr3`                               | 控制寄存器                                                   |
|                | `%dr0`, `%dr1`, `%dr2`, `%dr3`                               | 调试寄存器，x86弃用                                          |
|                | `%cs`, `%ds`, `%es`, `%fs`, `%gs`, `%ss`                     | 段寄存器                                                     |
|                | `%gdtr`, `%ldtr`                                             | 全局/局部描述符表寄存器                                      |

通常使用EBP来备份ESP，因此如果函数中的代码更改了ESP，则恢复ESP只需要执行`mov %ebp %esp `。此外，由于函数中的代码通常保持EBP不变，因此可以使用它。访问传递的参数或局部变量，而无需调整偏移量。

对于stack frame用法，EBP在任何函数开始时都被压入堆栈，因此被压入堆栈的EBP值就是调用当前函数的地址。这使得代码或以便调试器在将EBP压入堆栈的所有实例中“回溯”，并且堆栈上EBP值的每个实例都可以视为堆栈帧的基本指针。

请注意，某些编译器具有“忽略帧指针”选项，在这种情况下，EBP并不用于保存ESP或用作堆栈帧指针。相反，编译器会跟踪ESP，并且所有局部偏移量都是相对于当前ESP值的偏移量。

## I/O

处理器需要和设备进行通信。x86处理器提供了从设备I/O端口读写数据的in和out指令。

设备的端口使得可以通过软件方式配置设备，检查设备状态并驱动设备工作。例如，软件可以使用I/O端口读写来使得硬盘与硬件交互，实现扇区的读写操作。

许多电脑架构没有单独的硬件操作指令，而是将设备赋予固定的内存地址，通过对地址的读写实现设备的交互。现代的x86架构就使用这种内存映射的I/O架构。



## Address Translation

Xv6预设x86指令集以虚拟地址(virtual address)寻址，但实际x86指令集以逻辑地址(logical address)寻址。

逻辑地址以`segment:offset`的形式组成。段硬件通过转换生成线性地址(linear address)。如果分页硬件激活，就将线性地址转换成物理地址(physical address)，否则就直接将线性地址作为物理地址来使用。

虚拟地址是程序使用的地址，Xv6的虚拟地址就是x86的逻辑地址。同时Xv6设置段硬件来将逻辑地址直接作为线性地址使用，因此这两者是相同的，即虚拟地址(xv6叫法)=逻辑地址(x86叫法)=线性地址(通过段硬件转换)。

因此最重要的地址映射是分页硬件激活之后的线性地址向物理地址的转换。

# Code Analysis

<img src="C:\Users\60392\Desktop\lab1_1.png" alt="lab1_1" style="zoom:67%;" />

`boot/boot.S`

```assembly
#include <inc/mmu.h>

# Start the CPU: switch to 32-bit protected mode, jump into C.
# The BIOS loads this code from the first sector of the hard disk into
# memory at physical address 0x7c00 and starts executing in real mode
# with %cs=0 %ip=7c00.

.set PROT_MODE_CSEG, 0x8         # kernel code segment selector
.set PROT_MODE_DSEG, 0x10        # kernel data segment selector
.set CR0_PE_ON,      0x1         # protected mode enable flag

.globl start
start:
  .code16                     # Assemble for 16-bit mode
  cli                         # Disable interrupts
# ------------------------------------------------------------------------------------- #
# 首先调用cli，禁用处理器中断。
# 处理器中断是硬件用于调用操作系统的中断处理例程的方式。BIOS就是一个小型的操作系统，并可能设置了自己的中断
# 处理例程。但在boot loader运行的过程中，仍然打开硬件中断的处理是不安全的。
# ------------------------------------------------------------------------------------- #
  cld                         # String operations increment
# ------------------------------------------------------------------------------------- #
# BIOS不保证段寄存器的内容，因此需要进行设置
# ------------------------------------------------------------------------------------- #
  # Set up the important data segment registers (DS, ES, SS).
  xorw    %ax,%ax             # Segment number zero
  movw    %ax,%ds             # -> Data Segment
  movw    %ax,%es             # -> Extra Segment
  movw    %ax,%ss             # -> Stack Segment
# ------------------------------------------------------------------------------------- #
# 处理器处于实地址模式 real mode
# 实地址模式有八个16位的通用寄存器，但处理器使用20位的地址寻址。
# 段寄存器cs，ds，es，ss提供额外的位用于生成20位地址。方法是将源地址左移四位并加上段寄存器的内容。
# cs		指令
# ds		数据读写
# ss		栈读写
# segment:offset可能会生成21位的地址,早期的8088会丢弃21位。而现代的可以进行更多位数的寻址。
# 因此为了前向兼容，使用0x64和0x60的IO端口来控制第21位的寻址
# ------------------------------------------------------------------------------------- #
  # Enable A20:
  #   For backwards compatibility with the earliest PCs, physical
  #   address line 20 is tied low, so that addresses higher than
  #   1MB wrap around to zero by default.  This code undoes this.
seta20.1:
  inb     $0x64,%al               # Wait for not busy
  testb   $0x2,%al
  jnz     seta20.1

  movb    $0xd1,%al               # 0xd1 -> port 0x64
  outb    %al,$0x64

seta20.2:
  inb     $0x64,%al               # Wait for not busy
  testb   $0x2,%al
  jnz     seta20.2

  movb    $0xdf,%al               # 0xdf -> port 0x60
  outb    %al,$0x60

# ------------------------------------------------------------------------------------- #
# 实地址模式的16位寻址有限，因此要打开32位寻址的保护模式。
# 保护模式中，段寄存器是到段描述符表的索引。每个表定义了一个基地址base，最大虚拟地址limit和段的权限
# 在x86中，不是用段，而是使用分页机制。boot loader将段描述符表gdt设置为所有的段都有base=0.limit=4GB
# gdt表有一个空入口，一个执行代码的入口，一个数据的入口。
# 用lgdt加载了gdt之后，再将cr0设置为CRO_PE
# ------------------------------------------------------------------------------------- #

  # Switch from real to protected mode, using a bootstrap GDT
  # and segment translation that makes virtual addresses 
  # identical to their physical addresses, so that the 
  # effective memory map does not change during the switch.
  lgdt    gdtdesc
  movl    %cr0, %eax
  orl     $CR0_PE_ON, %eax
  movl    %eax, %cr0
# ------------------------------------------------------------------------------------- #
# 使能了保护模式后还没有立即改变处理器的寻址，只有当新的值加载到段寄存器时，处理器才会读GDT表来改变模式
# 不能直接改变%cs，因此执行ljmp，会设置cs来指向gdt的代码入口，而该描述符指明了32位模式
# 从此正式开启32位模式
# ------------------------------------------------------------------------------------- #
  # Jump to next instruction, but in 32-bit code segment.
  # Switches processor into 32-bit mode.
  ljmp    $PROT_MODE_CSEG, $protcseg

  .code32                     # Assemble for 32-bit mode
# ------------------------------------------------------------------------------------- #
# 正式开启32位模式
# 将数据寄存器初始化
# 设置栈，栈顶为$start，即0x7c00，栈向下增长到0x0000
# 最后，调用bootmain，如果出错，陷入死循环。
# ------------------------------------------------------------------------------------- #
protcseg:
  # Set up the protected-mode data segment registers
  movw    $PROT_MODE_DSEG, %ax    # Our data segment selector
  movw    %ax, %ds                # -> DS: Data Segment
  movw    %ax, %es                # -> ES: Extra Segment
  movw    %ax, %fs                # -> FS
  movw    %ax, %gs                # -> GS
  movw    %ax, %ss                # -> SS: Stack Segment
  
  # Set up the stack pointer and call into C.
  movl    $start, %esp
  call bootmain

  # If bootmain returns (it shouldn't), loop.
spin:
  jmp spin

# Bootstrap GDT
.p2align 2                                # force 4 byte alignment
gdt:
  SEG_NULL				# null seg
  SEG(STA_X|STA_R, 0x0, 0xffffffff)	# code seg
  SEG(STA_W, 0x0, 0xffffffff)	        # data seg

gdtdesc:
  .word   0x17                            # sizeof(gdt) - 1
  .long   gdt                             # address gdt
```



`boot/main.c`

```c
#include <inc/x86.h>
#include <inc/elf.h>

/**********************************************************************
 * This a dirt simple boot loader, whose sole job is to boot
 * an ELF kernel image from the first IDE hard disk.
 *
 * DISK LAYOUT
 *  * This program(boot.S and main.c) is the bootloader.  It should
 *    be stored in the first sector of the disk.
 *
 *  * The 2nd sector onward holds the kernel image.
 *
 *  * The kernel image must be in ELF format.
 *
 * BOOT UP STEPS
 *  * when the CPU boots it loads the BIOS into memory and executes it
 *
 *  * the BIOS intializes devices, sets of the interrupt routines, and
 *    reads the first sector of the boot device(e.g., hard-drive)
 *    into memory and jumps to it.
 *
 *  * Assuming this boot loader is stored in the first sector of the
 *    hard-drive, this code takes over...
 *
 *  * control starts in boot.S -- which sets up protected mode,
 *    and a stack so C code then run, then calls bootmain()
 *
 *  * bootmain() in this file takes over, reads in the kernel and jumps to it.
 **********************************************************************/

#define SECTSIZE	512
#define ELFHDR		((struct Elf *) 0x10000) // scratch space

void readsect(void*, uint32_t);
void readseg(uint32_t, uint32_t, uint32_t);

void
bootmain(void)
{
	struct Proghdr *ph, *eph;

	// read 1st page off disk
/*
	首先从disk的0开始读取一个页面4096，即8个扇区的内容，到ELFHDR位置(0x10000)
*/
	readseg((uint32_t) ELFHDR, SECTSIZE*8, 0);

	// is this a valid ELF?
	if (ELFHDR->e_magic != ELF_MAGIC)
		goto bad;

	// load each program segment (ignores ph flags)
	ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
	eph = ph + ELFHDR->e_phnum;
	for (; ph < eph; ph++)
		// p_pa is the load address of this segment (as well
		// as the physical address)
		readseg(ph->p_pa, ph->p_memsz, ph->p_offset);

	// call the entry point from the ELF header
	// note: does not return!
	((void (*)(void)) (ELFHDR->e_entry))();

bad:
	outw(0x8A00, 0x8A00);
	outw(0x8A00, 0x8E00);
	while (1)
		/* do nothing */;
}

// Read 'count' bytes at 'offset' from kernel into physical address 'pa'.
// Might copy more than asked
void
readseg(uint32_t pa, uint32_t count, uint32_t offset)
{
	uint32_t end_pa;

	end_pa = pa + count;

	// round down to sector boundary
	pa &= ~(SECTSIZE - 1);

	// translate from bytes to sectors, and kernel starts at sector 1 0开始的是bootloader
	offset = (offset / SECTSIZE) + 1;

	// If this is too slow, we could read lots of sectors at a time.
	// We'd write more to memory than asked, but it doesn't matter --
	// we load in increasing order.
	while (pa < end_pa) {
		// Since we haven't enabled paging yet and we're using
		// an identity segment mapping (see boot.S), we can
		// use physical addresses directly.  This won't be the
		// case once JOS enables the MMU.
		readsect((uint8_t*) pa, offset);
		pa += SECTSIZE;
		offset++;
	}
}

void
waitdisk(void)
{
	// wait for disk reaady
	while ((inb(0x1F7) & 0xC0) != 0x40)
		/* do nothing */;
}

void
readsect(void *dst, uint32_t offset)
{
	// wait for disk to be ready
	waitdisk();

	outb(0x1F2, 1);		// count = 1
	outb(0x1F3, offset);
	outb(0x1F4, offset >> 8);
	outb(0x1F5, offset >> 16);
	outb(0x1F6, (offset >> 24) | 0xE0);
	outb(0x1F7, 0x20);	// cmd 0x20 - read sectors

	// wait for disk to be ready
	waitdisk();

	// read a sector
	insl(0x1F0, dst, SECTSIZE/4);
}

```



# Exercise

gdb 常用指令

`c`/`continue`

一直执行到下一个断点

`si`/`stepi`

执行一条机器指令

`b function_name`/`b file:line`

在函数名或者文件的某一行设置断点

`b *addr`

在ELP头设置断点

`x/Nx addr`
从虚拟地址addr开始显示N个字的十六进制转储，如果省略N，则默认为1。

`x/Ni addr`
显示从addr开始的N条汇编指令。使用$ eip作为addr将在当前指令指针处显示指令。





## Exercise 3

### 过程

在`0x7c00`设置断点，这里是boot扇区加载的物理地址。

<img src="C:\Users\60392\AppData\Roaming\Typora\typora-user-images\image-20200213141034242.png" alt="image-20200213141034242" style="zoom: 50%;" />

可以看到，将boot loader的起始地址分配给了栈指针。因此，栈的起始位置在0x7c00，并且向下生长

<img src="C:\Users\60392\AppData\Roaming\Typora\typora-user-images\image-20200213142501974.png" alt="image-20200213142501974" style="zoom:50%;" />



在bootmain()函数的地址设置断点（不知道为什么`b bootmain`不工作。没有办法根据函数名来设置断点）

<img src="C:\Users\60392\AppData\Roaming\Typora\typora-user-images\image-20200213144231856.png" alt="image-20200213144231856" style="zoom:50%;" />

在`0x7d1a`处调用`readseg`，将参数压入栈后调用函数，跳转到`0x7cdc`

在boot.asm中，

```assembly
00007cdc <readseg>:

void
readseg(uint32_t pa, uint32_t count, uint32_t offset)
{
    7cdc:	55                   	push   %ebp
    7cdd:	89 e5                	mov    %esp,%ebp
    7cdf:	57                   	push   %edi
    7ce0:	56                   	push   %esi

	// round down to sector boundary
	pa &= ~(SECTSIZE - 1);

	// translate from bytes to sectors, and kernel starts at sector 1
	offset = (offset / SECTSIZE) + 1;
    7ce1:	8b 7d 10             	mov    0x10(%ebp),%edi

void
readseg(uint32_t pa, uint32_t count, uint32_t offset)
{
    7ce4:	53                   	push   %ebx
	uint32_t end_pa;

	end_pa = pa + count;
    7ce5:	8b 75 0c             	mov    0xc(%ebp),%esi
void
readseg(uint32_t pa, uint32_t count, uint32_t offset)
{
    7ce8:	8b 5d 08             	mov    0x8(%ebp),%ebx

	// round down to sector boundary
	pa &= ~(SECTSIZE - 1);

	// translate from bytes to sectors, and kernel starts at sector 1
	offset = (offset / SECTSIZE) + 1;
    7ceb:	c1 ef 09             	shr    $0x9,%edi
void
readseg(uint32_t pa, uint32_t count, uint32_t offset)
{
	uint32_t end_pa;

	end_pa = pa + count;
    7cee:	01 de                	add    %ebx,%esi

	// round down to sector boundary
	pa &= ~(SECTSIZE - 1);

	// translate from bytes to sectors, and kernel starts at sector 1
	offset = (offset / SECTSIZE) + 1;
    7cf0:	47                   	inc    %edi
	uint32_t end_pa;

	end_pa = pa + count;

	// round down to sector boundary
	pa &= ~(SECTSIZE - 1);
    7cf1:	81 e3 00 fe ff ff    	and    $0xfffffe00,%ebx
	offset = (offset / SECTSIZE) + 1;
##############################################################
	while (pa < end_pa) {
    7cf7:	39 f3                	cmp    %esi,%ebx
    7cf9:	73 12                	jae    7d0d <readseg+0x31>

		readsect((uint8_t*) pa, offset);
    7cfb:	57                   	push   %edi
    7cfc:	53                   	push   %ebx
		pa += SECTSIZE;
		offset++;
    7cfd:	47                   	inc    %edi

		pa += SECTSIZE;
    7cfe:	81 c3 00 02 00 00    	add    $0x200,%ebx
	while (pa < end_pa) {
# 在这里可以看到，没有直接调用函数体，而是先进行了循环体里不影响函数调用的其他操作，再进行了函数的调用，跳转到0x7c7c执行。
		readsect((uint8_t*) pa, offset);
    7d04:	e8 73 ff ff ff       	call   7c7c <readsect>
		pa += SECTSIZE;
		offset++;
    7d09:	58                   	pop    %eax
    7d0a:	5a                   	pop    %edx
    7d0b:	eb ea                	jmp    7cf7 <readseg+0x1b>
	}
}
    7d0d:	8d 65 f4             	lea    -0xc(%ebp),%esp
    7d10:	5b                   	pop    %ebx
    7d11:	5e                   	pop    %esi
    7d12:	5f                   	pop    %edi
    7d13:	5d                   	pop    %ebp
    7d14:	c3                   	ret    
    
    
##################################################
00007c6a <waitdisk>:
	}
}

void
waitdisk(void)
{
    7c6a:	55                   	push   %ebp

static inline uint8_t
inb(int port)
{
	uint8_t data;
	asm volatile("inb %w1,%0" : "=a" (data) : "d" (port));
    7c6b:	ba f7 01 00 00       	mov    $0x1f7,%edx
    7c70:	89 e5                	mov    %esp,%ebp
    7c72:	ec                   	in     (%dx),%al
	// wait for disk reaady
	while ((inb(0x1F7) & 0xC0) != 0x40)
    7c73:	83 e0 c0             	and    $0xffffffc0,%eax
    7c76:	3c 40                	cmp    $0x40,%al
    7c78:	75 f8                	jne    7c72 <waitdisk+0x8>
		/* do nothing */;
}
    7c7a:	5d                   	pop    %ebp
    7c7b:	c3                   	ret  

# readsect部分
00007c7c <readsect>:

void
readsect(void *dst, uint32_t offset)
{
    7c7c:	55                   	push   %ebp
    7c7d:	89 e5                	mov    %esp,%ebp
    7c7f:	57                   	push   %edi
    7c80:	8b 4d 0c             	mov    0xc(%ebp),%ecx
	// wait for disk to be ready
	waitdisk();
    7c83:	e8 e2 ff ff ff       	call   7c6a <waitdisk>
}

static inline void
outb(int port, uint8_t data)
{
	asm volatile("outb %0,%w1" : : "a" (data), "d" (port));
    7c88:	ba f2 01 00 00       	mov    $0x1f2,%edx
    7c8d:	b0 01                	mov    $0x1,%al
    7c8f:	ee                   	out    %al,(%dx)
    7c90:	ba f3 01 00 00       	mov    $0x1f3,%edx
    7c95:	88 c8                	mov    %cl,%al
    7c97:	ee                   	out    %al,(%dx)
    7c98:	89 c8                	mov    %ecx,%eax
    7c9a:	ba f4 01 00 00       	mov    $0x1f4,%edx
    7c9f:	c1 e8 08             	shr    $0x8,%eax
    7ca2:	ee                   	out    %al,(%dx)
    7ca3:	89 c8                	mov    %ecx,%eax
    7ca5:	ba f5 01 00 00       	mov    $0x1f5,%edx
    7caa:	c1 e8 10             	shr    $0x10,%eax
    7cad:	ee                   	out    %al,(%dx)
    7cae:	89 c8                	mov    %ecx,%eax
    7cb0:	ba f6 01 00 00       	mov    $0x1f6,%edx
    7cb5:	c1 e8 18             	shr    $0x18,%eax
    7cb8:	83 c8 e0             	or     $0xffffffe0,%eax
    7cbb:	ee                   	out    %al,(%dx)
    7cbc:	ba f7 01 00 00       	mov    $0x1f7,%edx
    7cc1:	b0 20                	mov    $0x20,%al
    7cc3:	ee                   	out    %al,(%dx)
	outb(0x1F5, offset >> 16);
	outb(0x1F6, (offset >> 24) | 0xE0);
	outb(0x1F7, 0x20);	// cmd 0x20 - read sectors

	// wait for disk to be ready
	waitdisk();
    7cc4:	e8 a1 ff ff ff       	call   7c6a <waitdisk>
}

static inline void
insl(int port, void *addr, int cnt)
{
	asm volatile("cld\n\trepne\n\tinsl"
    7cc9:	8b 7d 08             	mov    0x8(%ebp),%edi
    7ccc:	b9 80 00 00 00       	mov    $0x80,%ecx
    7cd1:	ba f0 01 00 00       	mov    $0x1f0,%edx
    7cd6:	fc                   	cld    
    7cd7:	f2 6d                	repnz insl (%dx),%es:(%edi)

	// read a sector
	insl(0x1F0, dst, SECTSIZE/4);
}
    7cd9:	5f                   	pop    %edi
    7cda:	5d                   	pop    %ebp
    7cdb:	c3                   	ret  
```

<img src="C:\Users\60392\AppData\Roaming\Typora\typora-user-images\image-20200213153124859.png" alt="image-20200213153124859" style="zoom:50%;" />

发现在7cd7处的repnz指令会不断地执行，在第一次到达该指令时，调用info registers查看，并单步执行一次后再次查看：

<img src="C:\Users\60392\AppData\Roaming\Typora\typora-user-images\image-20200213153231764.png" alt="image-20200213153231764" style="zoom:50%;" /><img src="C:\Users\60392\AppData\Roaming\Typora\typora-user-images\image-20200213153322008.png" alt="image-20200213153322008" style="zoom:52%;" />

在执行128次后，到达7cd9，再通过ret指令回到7d09，即readseg中的while循环体中。

<img src="C:\Users\60392\AppData\Roaming\Typora\typora-user-images\image-20200213154119595.png" alt="image-20200213154119595" style="zoom:50%;" />

由`cmp %esi, %ebx`知道，要比较esi和ebx寄存器的内容。ebx一个循环增加了512，而esi是4096。因此还要继续循环。可以推断一次是读取了一个扇区512字节，而目标是读取4096字节。这也和bootmain中的8*SECTSIZE相符合。读取结束之后，回到bootmain。在7d51处开始for循环

```assembly
00007d15 <bootmain>:
void readsect(void*, uint32_t);
void readseg(uint32_t, uint32_t, uint32_t);

void
bootmain(void)
{
    7d15:	55                   	push   %ebp
    7d16:	89 e5                	mov    %esp,%ebp
    7d18:	56                   	push   %esi
    7d19:	53                   	push   %ebx
	struct Proghdr *ph, *eph;

	// read 1st page off disk
	readseg((uint32_t) ELFHDR, SECTSIZE*8, 0);
    7d1a:	6a 00                	push   $0x0
    7d1c:	68 00 10 00 00       	push   $0x1000
    7d21:	68 00 00 01 00       	push   $0x10000
    7d26:	e8 b1 ff ff ff       	call   7cdc <readseg>

	// is this a valid ELF?
	if (ELFHDR->e_magic != ELF_MAGIC)
    7d2b:	83 c4 0c             	add    $0xc,%esp
    7d2e:	81 3d 00 00 01 00 7f 	cmpl   $0x464c457f,0x10000
    7d35:	45 4c 46 
    7d38:	75 37                	jne    7d71 <bootmain+0x5c>
		goto bad;

	// load each program segment (ignores ph flags)
	ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
    7d3a:	a1 1c 00 01 00       	mov    0x1001c,%eax
	eph = ph + ELFHDR->e_phnum;
    7d3f:	0f b7 35 2c 00 01 00 	movzwl 0x1002c,%esi
	// is this a valid ELF?
	if (ELFHDR->e_magic != ELF_MAGIC)
		goto bad;

	// load each program segment (ignores ph flags)
	ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
    7d46:	8d 98 00 00 01 00    	lea    0x10000(%eax),%ebx
	eph = ph + ELFHDR->e_phnum;
    7d4c:	c1 e6 05             	shl    $0x5,%esi
    7d4f:	01 de                	add    %ebx,%esi
	for (; ph < eph; ph++)
    7d51:	39 f3                	cmp    %esi,%ebx
    7d53:	73 16                	jae    7d6b <bootmain+0x56>
		readseg(ph->p_pa, ph->p_memsz, ph->p_offset);
    7d55:	ff 73 04             	pushl  0x4(%ebx)
    7d58:	ff 73 14             	pushl  0x14(%ebx)
		goto bad;

	// load each program segment (ignores ph flags)
	ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
	eph = ph + ELFHDR->e_phnum;
	for (; ph < eph; ph++)
    7d5b:	83 c3 20             	add    $0x20,%ebx

		readseg(ph->p_pa, ph->p_memsz, ph->p_offset);
    7d5e:	ff 73 ec             	pushl  -0x14(%ebx)
    7d61:	e8 76 ff ff ff       	call   7cdc <readseg>
		goto bad;

	// load each program segment (ignores ph flags)
	ph = (struct Proghdr *) ((uint8_t *) ELFHDR + ELFHDR->e_phoff);
	eph = ph + ELFHDR->e_phnum;
	for (; ph < eph; ph++)
    7d66:	83 c4 0c             	add    $0xc,%esp
    7d69:	eb e6                	jmp    7d51 <bootmain+0x3c>
		// as the physical address)
		readseg(ph->p_pa, ph->p_memsz, ph->p_offset);

	// call the entry point from the ELF header
	// note: does not return!
	((void (*)(void)) (ELFHDR->e_entry))();
    7d6b:	ff 15 18 00 01 00    	call   *0x10018
}

static inline void
outw(int port, uint16_t data)
{
	asm volatile("outw %0,%w1" : : "a" (data), "d" (port));
    7d71:	ba 00 8a 00 00       	mov    $0x8a00,%edx
    7d76:	b8 00 8a ff ff       	mov    $0xffff8a00,%eax
    7d7b:	66 ef                	out    %ax,(%dx)
    7d7d:	b8 00 8e ff ff       	mov    $0xffff8e00,%eax
    7d82:	66 ef                	out    %ax,(%dx)
    7d84:	eb fe                	jmp    7d84 <bootmain+0x6f>
```

<img src="C:\Users\60392\AppData\Roaming\Typora\typora-user-images\image-20200213155345898.png" alt="image-20200213155345898" style="zoom:50%;" />

最后在7d6b处调用entry的入口代码。

<img src="C:\Users\60392\AppData\Roaming\Typora\typora-user-images\image-20200213160223950.png" alt="image-20200213160223950" style="zoom:50%;" />

通过对比源程序和汇编程序，发现机器代码和源程序的执行顺序是有可能不一样的。经过编译器的优化，在不影响结果的前提下改变指令的执行顺序，达到提高效率的目的。

### 回答

1. 处理器在加载了gdt表并设置了CR0_PE_ON位之后进入32位模式。但改变flag位并没有立即改变原来的16位实地址模式，只有当新的值加载到段寄存器时，处理器才会读GDT表来改变模式。

	由于不能直接改变%cs，因此执行ljmp，设置cs来指向gdt的代码入口，而gdt中该表项描述符指明了32位模式，从此正式开启32位保护模式。

2. boot loader最后执行的指令是加载entry()的入口代码

	```asm
	// call the entry point from the ELF header
		// note: does not return!
		((void (*)(void)) (ELFHDR->e_entry))();
	    7d6b:	ff 15 18 00 01 00    	call   *0x10018
	```

	此后进入entry.S，内核开始运行

	```assembly
	.globl entry
	entry:
		movw	$0x1234,0x472			# warm boot
	f0100000:	02 b0 ad 1b 00 00    	add    0x1bad(%eax),%dh
	f0100006:	00 00                	add    %al,(%eax)
	f0100008:	fe 4f 52             	decb   0x52(%edi)
	f010000b:	e4                   	.byte 0xe4
	```

3. boot loader如何决定应该读多少扇区以加载整个内核？

	在bootmain中一开始就调用了readseg来加载整个内核

	```c
	#define ELFHDR		((struct Elf *) 0x10000) // scratch space
	void
	bootmain(void)
	{
		struct Proghdr *ph, *eph;
	
		// read 1st page off disk
		readseg((uint32_t) ELFHDR, SECTSIZE*8, 0);
	    
	void
	readseg(uint32_t pa, uint32_t count, uint32_t offset)
	{
		...
		// translate from bytes to sectors, and kernel starts at sector 1
		offset = (offset / SECTSIZE) + 1;
		...
		while (pa < end_pa) {
	
			readsect((uint8_t*) pa, offset);
			pa += SECTSIZE;
			offset++;
		}
	}
	```

	该函数指明了从偏移0开始读取8个扇区的内容到ELFHDR指向的地址`0x10000`。在readseg对offset的处理可以看到，内核是作为第一个扇区的。那么boot loader实际就在第零个扇区。

### 问题

1. 指令缺失（仍然是编译器优化吗?）

<img src="C:\Users\60392\AppData\Roaming\Typora\typora-user-images\image-20200214095123236.png" alt="image-20200214095123236" style="zoom:50%;" />

2. asm文件中是表示32位的以e开头，而gdb显示的指令是16位的

<img src="C:\Users\60392\AppData\Roaming\Typora\typora-user-images\image-20200214095528915.png" alt="image-20200214095528915" style="zoom:50%;" />

## Exercise 5

找到第一个会因为改动了boot sector的加载地址`0x7c00`而crush的指令。

### 过程

1. 在`boot/Makefrag`中将`-Ttext 0x7c00`改为`-Text 0x7d00`。
2. `make clean`之后再进行`make`。

### 回答

<img src="C:\Users\60392\AppData\Roaming\Typora\typora-user-images\image-20200214101900602.png" alt="image-20200214101900602" style="zoom:50%;" />

在0x7c2d的ljmp处出现了SIGTRAP的错误。

是在进入32位保护模式时产生了错误。吧地址改为0x7b00也会产生同样的错误。

make clean后改回7c00，正常运行。

7c00是传给链接器的链接地址。

> 由于链接器计算内存地址是根据 boot/Makefrag 中的设置。然而由于 BIOS 会把 boot loader 固定加载在 0x7c00，于是导致了错误。

## Exercise 8

<img src="C:\Users\60392\AppData\Roaming\Typora\typora-user-images\image-20200214140931610.png" alt="image-20200214140931610" style="zoom:50%;" />

分析输入输出代码。

#### `console.c`

<img src="C:\Users\60392\Desktop\lab1_2.png" alt="lab1_2" style="zoom: 67%;" />

`cputchar`直接调用了`cons_putc`，同样，`getchar`直接调用了`cons_getc`。

`cons_putc`顺序调用了图中的三个函数，分别对应电脑串口，平行端口，文本模式CGA/VGA显示输出。

`cons_getc`轮询串口和键盘输入，监测是否有输入字符，因此即使是中断禁用的情况函数也可以工作。

`kbd_intr`和`serial_intr`分别将 `kbd_proc_data`和`serial_proc_data`函数指针作为参数传进`cons_intr`。后者调用这两个函数，将字符存进缓冲区。



#### `printfmt.c`

printf风格的输出格式化例程。

内核进程和用户进程都使用该代码。

#### `printf.c`

基于printfmt()和内核控制台的cputchar()来实现控制台输出。

![lab1_3](C:\Users\60392\Desktop\lab1_3.png)

printfmt和vprintfmt之间存在互相调用的情况。

其中的直线上的矩形框，代表函数作为参数传向箭头所指的函数中。虚线相连，表示有一者使用一者。

### 回答

- `console.c`为`printf.c`提供了cputchar输出函数，负责将字符输出到控制台。`printf.c`将其封装在`putch`函数中，增加了一个增加输出字符的一个计数功能。

	```c
	static void
	putch(int ch, int *cnt)
	{
		cputchar(ch);
		*cnt++;
	}
	```

- 解释代码含义

  ```c
  static void
  cga_putc(int c)
  {
  	...
  
  	// What is the purpose of this?
  	if (crt_pos >= CRT_SIZE) {
  		int i;
  		// 把从第1~n行的内容复制到0~(n-1)行，第n行未变化
  		memmove(crt_buf, crt_buf + CRT_COLS, (CRT_SIZE - CRT_COLS) * sizeof(uint16_t));
          // 将第n行覆盖为默认属性下的空格
  		for (i = CRT_SIZE - CRT_COLS; i < CRT_SIZE; i++)
  			crt_buf[i] = 0x0700 | ' ';
          // 清空了最后一行，同步crt_pos
  		crt_pos -= CRT_COLS;
  	}
  	...
  }
  ```

  如果输出的字符导致游标溢出屏幕之外，需要换行，换行是需要准备的是，将当前行已经上面的信息进行循环上移，再将光标进行移动到屏幕最左端进行输入操作。

- 执行以下代码, 
	
	```c
	int x = 1, y = 3, z = 4;
	cprintf("x %d, y %x, z %d\n", x, y, z);
```
	
	该在哪里执行代码？在`kern/monitor.c`中的`mon_backtrace`函数，可以编写自己的代码。之后重新编译进入调试，`b kern/monitor.c:61`设置断点并运行到断点处
	
	```shell
	=> 0xf0100774 <mon_backtrace+6>:	push   $0x4
	
	Breakpoint 1, mon_backtrace (argc=0, argv=0x0, tf=0x0) at kern/monitor.c:62
	62		cprintf("x %d, y %x, z %d\n", x, y, z);
	(gdb) si
	=> 0xf0100776 <mon_backtrace+8>:	push   $0x3
	0xf0100776	62		cprintf("x %d, y %x, z %d\n", x, y, z);
	(gdb) 
	=> 0xf0100778 <mon_backtrace+10>:	push   $0x1
	0xf0100778	62		cprintf("x %d, y %x, z %d\n", x, y, z);
	(gdb) 
	=> 0xf010077a <mon_backtrace+12>:	push   $0xf0101bce
	0xf010077a	62		cprintf("x %d, y %x, z %d\n", x, y, z);
	(gdb) 
	=> 0xf010077f <mon_backtrace+17>:	call   0xf010090b <cprintf>
	0xf010077f	62		cprintf("x %d, y %x, z %d\n", x, y, z);
	# ---------------------------------------------------------------------------------- #
	# 到这为止，各个参数被压入栈保存，包括0xf0101bce的内容，即第一个字符串的地址。准备调用cprintf
	# ---------------------------------------------------------------------------------- #
	(gdb) 
	=> 0xf010090b <cprintf>:	push   %ebp
	cprintf (fmt=0xf0101bce "x %d, y %x, z %d\n") at kern/printf.c:27
	27	{
	(gdb) 
	=> 0xf010090c <cprintf+1>:	mov    %esp,%ebp
	0xf010090c	27	{
	(gdb) 
	=> 0xf010090e <cprintf+3>:	sub    $0x10,%esp
	# ---------------------------------------------------------------------------------- #
	# 保存ebp内容，即调用函数的起始地址。再将esp保存到ebp中。
	# 递减esp，为局部变量预留空间。
	# ---------------------------------------------------------------------------------- #
	0xf010090e	27	{
	(gdb) 
	=> 0xf0100911 <cprintf+6>:	lea    0xc(%ebp),%eax
	31		va_start(ap, fmt);
	(gdb) 
	=> 0xf0100914 <cprintf+9>:	push   %eax
	32		cnt = vcprintf(fmt, ap);
	(gdb) 
	=> 0xf0100915 <cprintf+10>:	pushl  0x8(%ebp)
	0xf0100915	32		cnt = vcprintf(fmt, ap);
	# ---------------------------------------------------------------------------------- #
	# 由于之前已经将sep保存到ebp中了，之后就可以通过相对位移来取得参数的值。
	# ebp+c是ap的值，ebp+8是fmt的值。（？）
	# ---------------------------------------------------------------------------------- #
	(gdb) 
	=> 0xf0100918 <cprintf+13>:	call   0xf01008e5 <vcprintf>
	0xf0100918	32		cnt = vcprintf(fmt, ap);
	(gdb) 
	=> 0xf01008e5 <vcprintf>:	push   %ebp
	vcprintf (fmt=0xf0101bce "x %d, y %x, z %d\n", ap=0xf010ff04 "\001")
	# ---------------------------------------------------------------------------------- #
	# fmt就是格式化输入函数中“”的字符串地址，即cprintf 函数的第一个参数，即指向字符串"x %d, y %x, z 
	# %d\n"的指针0xf0101bce。ap指向存放第二个参数的地址，而非第二个参数
	# ---------------------------------------------------------------------------------- #
	```
	
	
	- fmt，ap都指向哪里：见上面
	- `cons_putc`：调用关系cprintf -> vcprintf -> vprintfmt -> putch -> cputchar -> cons_putc
	- `va_arg`：每次调用 va_arg 都会使得 ap 的位置指向变参表的下一个变量位置。
	
- ```c
	cprintf("x=%d y=%d", 3);
	```

	- 由于第二个参数尚未指定，输出 3 以后无法确定 ap 的值应该变化多少，更无法根据 ap 的值获取参数。
		 va_arg 取当前栈地址，并将指针移动到下个“参数”所在位置--简单的栈内移动，没有任何标志或者条件能够让你确定可变参函数的参数个数，也不能判断当前栈指针的合法性。

## Exercise 9

确定内核初始化堆栈的位置，以及堆栈在内存中的确切位置。内核如何为其堆栈保留空间？堆栈指针被初始化为指向这个保留区域的哪一端？

`entry.S`

```asm
	# Clear the frame pointer register (EBP)
	# so that once we get into debugging C code,
	# stack backtraces will be terminated properly.
	movl	$0x0,%ebp			# nuke frame pointer

	# Set the stack pointer
	movl	$(bootstacktop),%esp

	# now to C code
	call	i386_init
	
.data
###################################################################
# boot stack
###################################################################
	.p2align	PGSHIFT		# force page alignment
	.globl		bootstack
bootstack:
	.space		KSTKSIZE
	.globl		bootstacktop   
bootstacktop:
```

栈指针赋值为bootstacktop所指向的地址

`inc/memlayout.h`

```c
// All physical memory mapped at this address
#define	KERNBASE	0xF0000000

// Kernel stack.
#define KSTACKTOP	KERNBASE
#define KSTKSIZE	(8*PGSIZE)   		// size of a kernel stack
#define KSTKGAP		(8*PGSIZE)   		// size of a kernel stack guard
```

`inc/mmu.h`

```c
#define PGSIZE		4096		// bytes mapped by a page
#define PGSHIFT		12		// log2(PGSIZE)
```



可以看到，栈的大小为8个页面的大小，即8x4096字节

```shell
(gdb) b kern/entry.S:74
Breakpoint 1 at 0xf010002f: file kern/entry.S, line 74.
(gdb) c
Continuing.
The target architecture is assumed to be i386
=> 0xf010002f <relocated>:	mov    $0x0,%ebp

Breakpoint 1, relocated () at kern/entry.S:74
74		movl	$0x0,%ebp			# nuke frame pointer
(gdb) si
=> 0xf0100034 <relocated+5>:	mov    $0xf0110000,%esp
relocated () at kern/entry.S:77
77		movl	$(bootstacktop),%esp
(gdb) 
=> 0xf0100039 <relocated+10>:	call   0xf0100094 <i386_init>
80		call	i386_init
(gdb) info registers 
eax            0xf010002f	-267386833
ecx            0x0	0
edx            0x9d	157
ebx            0x10094	65684
esp            0xf0110000	0xf0110000 <entry_pgdir>
ebp            0x0	0x0
esi            0x10094	65684
edi            0x0	0
eip            0xf0100039	0xf0100039 <relocated+10>
eflags         0x86	[ PF SF ]
cs             0x8	8
ss             0x10	16
ds             0x10	16
es             0x10	16
fs             0x10	16
gs             0x10	16
(gdb) 
```

设置断点并保存寄存器的值，发现栈顶端在0xf0110000，

结合栈大小，可以得出栈位于 `0xf0110000` 到 `0xf0108000`。

## Exercise 10

在`obj/kern/kernel.asm`找到test_backtrace函数的地址，设置断点之后查看其被调用之后发生了什么，多少32位的字在调用该函数的时候被推到了栈上。

```shell
(gdb) b *0xf0100076
Breakpoint 1 at 0xf0100076: file kern/init.c, line 18.
(gdb) c
Continuing.
The target architecture is assumed to be i386
=> 0xf0100076 <test_backtrace+54>:  call   0xf010076e <mon_backtrace>
Breakpoint 1, 0xf0100076 in test_backtrace (x=0) at kern/init.c:18
18          mon_backtrace(0, 0, 0);
(gdb) x/52x $esp
0xf010ff20: 0x00000000  0x00000000  0x00000000  0x00000000
0xf010ff30: 0xf01008ef  0x00000001  0xf010ff58  0xf0100068
0xf010ff40: 0x00000000  0x00000001  0xf010ff78  0x00000000
0xf010ff50: 0xf01008ef  0x00000002  0xf010ff78  0xf0100068
0xf010ff60: 0x00000001  0x00000002  0xf010ff98  0x00000000
0xf010ff70: 0xf01008ef  0x00000003  0xf010ff98  0xf0100068
0xf010ff80: 0x00000002  0x00000003  0xf010ffb8  0x00000000
0xf010ff90: 0xf01008ef  0x00000004  0xf010ffb8  0xf0100068
0xf010ffa0: 0x00000003  0x00000004  0x00000000  0x00000000
0xf010ffb0: 0x00000000  0x00000005  0xf010ffd8  0xf0100068
0xf010ffc0: 0x00000004  0x00000005  0x00000000  0x00010094
0xf010ffd0: 0x00010094  0x00010094  0xf010fff8  0xf01000d4
0xf010ffe0: 0x00000005  0x00001aac  0x00000644  0x00000000
0xf010fff0: 0x00000000  0x00000000  0x00000000  0xf010003e
```

因为栈向下生长，从后往前看即为执行顺序。
 在调用函数时，对栈需要进行以下操作：

1. 将参数由右向左压入栈
2. 将返回地址 (eip中的内容) 入栈，在 call 指令执行
3. 将上一个函数的 ebp 入栈
4. 将 ebx 入栈，保护寄存器状态
5. 在栈上开辟一个空间存储局部变量

可以看出，第二列出现的`0x00000005` 到 `0x00000000`都是参数。
 在参数前一个存储的是返回地址，`0xf0100068`出现了多次，是 test_backtrace 递归过程中的返回地址。而 `0xf01000d4`出现仅一次，是 i386_init 函数中的返回地址。可以通过查看 obj/kern/kernel.asm 证明。

## Exercise 11

实现backtrace函数，拥有以下格式

```
Stack backtrace:
  ebp f0109e58  eip f0100a62  args 00000001 f0109e80 f0109e98 f0100ed2 00000031
  ebp f0109ed8  eip f01000d6  args 00000000 00000000 f0100058 f0109f28 00000061
  ...
```

- ebp：函数使用的基地址指针。即刚刚进入函数时函数会压入堆栈的ebp内容，即上一个函数的返回位置。
- eip：函数的返回指令指针。即函数在返回时跳转到的指令的地址。
- args：函数传入的前五个参数，即在调用函数之前被压入栈的内容
- 第一行反映当前正在执行的函数，第二行时调用了第一行的函数的函数的内容，以此类推。通过查看entry.S可以知道，ebp一开始的值位0，因此可以设置判断条件来终止。