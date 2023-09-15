/*
 *  linux/mm/memory.c
 *
 *  (C) 1991  Linus Torvalds
 */

/*
 * demand-loading started 01.12.91 - seems it is high on the list of
 * things wanted, and it should be easy to implement. - Linus
 */

/*
 * Ok, demand-loading was easy, shared pages a little bit tricker. Shared
 * pages started 02.12.91, seems to work. - Linus.
 *
 * Tested sharing by executing about 30 /bin/sh: under the old kernel it
 * would have taken more than the 6M I have free, but it worked well as
 * far as I could see.
 *
 * Also corrected some "invalidate()"s - I wasn't doing enough of them.
 */

#include <signal.h>

#include <asm/system.h>

#include <linux/sched.h>
#include <linux/head.h>
#include <linux/kernel.h>

void do_exit(long code);

static inline void oom(void)
{
	printk("out of memory\n\r");
	do_exit(SIGSEGV);
}

#define invalidate() \
__asm__("movl %%eax,%%cr3"::"a" (0))

/* these are not to be changed without changing head.s etc */
#define LOW_MEM 0x100000
#define PAGING_MEMORY (15*1024*1024)
#define PAGING_PAGES (PAGING_MEMORY>>12)
#define MAP_NR(addr) (((addr)-LOW_MEM)>>12)
#define USED 100

#define CODE_SPACE(addr) ((((addr)+4095)&~4095) < \
current->start_code + current->end_code)

static long HIGH_MEMORY = 0;

#define copy_page(from,to) \
__asm__("cld ; rep ; movsl"::"S" (from),"D" (to),"c" (1024))

static unsigned char mem_map [ PAGING_PAGES ] = {0,};

/*
 * Get physical address of first (actually last :-) free page, and mark it
 * used. If no free pages left, return 0.
 * process steps 
 * 0. mem map = memory map 
 * 1. find where are free pages
 * 2. set it's mem map to 1 , and make it empty ,and return it .
 */
unsigned long get_free_page(void)
{
register unsigned long __res asm("ax");

__asm__("std ; repne ; scasb\n\t"
	"jne 1f\n\t"
	"movb $1,1(%%edi)\n\t"
	"sall $12,%%ecx\n\t"
	"addl %2,%%ecx\n\t"
	"movl %%ecx,%%edx\n\t"
	"movl $1024,%%ecx\n\t"
	"leal 4092(%%edx),%%edi\n\t"
	"rep ; stosl\n\t"
	" movl %%edx,%%eax\n"
	"1: cld"
	:"=a" (__res)
	:"0" (0),"i" (LOW_MEM),"c" (PAGING_PAGES),
	"D" (mem_map+PAGING_PAGES-1)
	);
return __res;
}

/*
 * Free a page of memory at physical address 'addr'. Used by
 * 'free_page_tables()'
 */
void free_page(unsigned long addr)
{
	if (addr < LOW_MEM) return;
	if (addr >= HIGH_MEMORY)
		panic("trying to free nonexistent page");
	addr -= LOW_MEM;
	addr >>= 12;  // calculate where pages are ?
	if (mem_map[addr]--) return;  // if (a--)  first condite a then  -- ; bug if the mem_map bigger than 1 (e.g == 3 ) ,is it meaningful ?
	mem_map[addr]=0;  // if mem_map[addr] is zero .
	panic("trying to free free page"); //error 
}

/*
 * This function frees a continuos block of page tables, as needed
 * by 'exit()'. As does copy_page_tables(), this handles only 4Mb blocks.
 * 函数功能: 释放一块连续的物理内存 
 * process: 
 * 1. begin addr + size (only aligned to 4M ,so begin address could be 0 4M 8M 12M )
 * 2. confirm dir : need dir location ; 
 *    which page table : need page table location . 
 * 	  if LINEAR ADDRESS , only need it's DIR offset that used to locate page table base address.
 * 3. free each FRAME PAGE that relative to page table entries .
 * from : 线性地址
 * size : 长度(页表个数)
 * 
 * 总结: 从一个入参线性地址from 确定对应的页目录项, 页表 . 根据size大小确定要释放的范围.
 * 从页目录到页表 逐级遍历释放掉PAGE FRAME , 最后释放掉页表
 * 再刷新缓存区
 * 完毕.
 */
int free_page_tables(unsigned long from,unsigned long size)
{
	unsigned long *pg_table;
	unsigned long * dir, nr;

	if (from & 0x3fffff) /* 3fffff = 4M . 计算过程: 3fffff/ffffff = 1/4 ; 0xffffff = 2^24 = 16M  ; 0xffffff * 1/4 = 4M 
						  & 位与; && 逻辑与
						  只有当from 是4M 或4M的倍数的时候,条件才为假 . 学习表达式. if (from & 0xff)
						 表示判断某个数 from 是否在 (0xff+0x1)的边界上,如果条件为否,表示在边界上.是说明不在边界上.
						 linus 编程也太牛了.*/
						 /*
						 The expression from & 0x3fffff checks if the least significant 22 bits of the from variable are non-zero. 
						 If the result is non-zero, the if condition evaluates to true.
						 Therefore, the if statement will be false when from has a value that has all 22 least significant bits set to zero. 
						 In other words, if from is a multiple of 4M (0x400000).
						 */
						
		panic("free_page_tables called with wrong alignment");
	if (!from)  // 判断是否为地址零, 条件否 则是零, 条件是, 则非零 , 死机
		panic("Trying to free up swapper memory space");
	size = (size + 0x3fffff) >> 22;/*
									左移多少位代表什么含义?表示除2^22的大小 . 2^22 = 4M . 除4M . 计算得到多少页表个数. 一个页表能包含的额内存范围是4M 
									所以在 linux 0.11 中 ,主物理内存大小是16M ,所以用4个页表表示足够了.
									*/
	dir = (unsigned long *) ((from>>20) & 0xffc); /* _pg_ dir = 0 ; dir指的是目录项, 计算的应该是从哪个页目录项*/ 
								/*
									回忆一下页目录项的地址: 分别是0x0000 ; 0x0004 ; 0x0008 ;0x0012 
									
									2^20 = 1M ; from 从上面的条件判断只能是4M或4M的倍数. 所以得到的值会是0;4;8;12

									0xffc:The purpose of this operation is to mask the lower bits 
									and ensure that the resulting value is aligned to a 4KB boundary (the size of a page directory entry).
									注意这里的mask.  0xffc = 1111 1111 1100 . 所以这里是为了mask掉最后 2bits.
	
									unsigned long * dir : dir是一个地址. *dir 就是该地址的值.
									例如 在调试debug的时候, 0x0004  -- 0x002027 --0x40a06700
									x 0x0004 : 0x002027 
									x 0x002027 : 0x40a06700
									x (*0x0004): 0x40a06700
									所以 *0x0004能够取到地址0x0004的内容.
									x 0x002027 与 x (*0x0004)是等价的.
								*/
	for ( ; size-->0 ; dir++) {    // 换个写法 : for( ; size>0 ; size-- , dir ++ )
		if (!(1 & *dir))          // *dir 就是某一个page table的基地址, 如果*dir无效 continue   
			continue;
		pg_table = (unsigned long *) (0xfffff000 & *dir); //取pa_table的基地址 mask掉最后三位无关地址的内容
		for (nr=0 ; nr<1024 ; nr++) {  //释放掉page table中的每一个entry 
			if (1 & *pg_table)  // *pa_table 指的是某一个FRAME_PAGE(4K)的地址. 如果这个地址有效call free_page ; 
								//  如果无效(指已经是零,或者无法映射到物理内存FRAME PAGE), 令FRAME_PAGE =0 ()
				free_page(0xfffff000 & *pg_table); // 0xfffff000 & *pg_table : 取地址
			*pg_table = 0;
			pg_table++;
		}
		free_page(0xfffff000 & *dir); // page table 自己的mem map 置为空闲状态
		*dir = 0; // page table 指向 PAGE FRAME 的地址 清零
	}
	invalidate(); //刷新缓存
	return 0;
}

/*
 *  Well, here is one of the most complicated functions in mm. It
 * copies a range of linerar addresses by copying only the pages.
 * Let's hope this is bug-free, 'cause this one I don't want to debug :-)
 *
 * Note! We don't copy just any chunks of memory - addresses have to
 * be divisible by 4Mb (one page-directory entry), as this makes the
 * function easier. It's used only by fork anyway.
 *
 * NOTE 2!! When from==0 we are copying kernel space for the first
 * fork(). Then we DONT want to copy a full page-directory entry, as
 * that would lead to some serious memory waste - we just copy the
 * first 160 pages - 640kB. Even that is more than we need, but it
 * doesn't take any more memory - we don't copy-on-write in the low
 * 1 Mb-range, so the pages can be shared with the kernel. Thus the
 * special case for nr=xxxx.
 * 这里注意: 最后是将from_page_table复制给to_page_table ,并且两者指向的是同一块pageframe,复制的不是page frame .
 */
int copy_page_tables(unsigned long from,unsigned long to,long size)
{
	unsigned long * from_page_table;
	unsigned long * to_page_table;
	unsigned long this_page;
	unsigned long * from_dir, * to_dir;
	unsigned long nr;
	

	if ((from&0x3fffff) || (to&0x3fffff))
		panic("copy_page_tables called with wrong alignment");
	from_dir = (unsigned long *) ((from>>20) & 0xffc); /* _pg_dir = 0 */
	to_dir = (unsigned long *) ((to>>20) & 0xffc);
	size = ((unsigned) (size+0x3fffff)) >> 22;
	for( ; size-->0 ; from_dir++,to_dir++) {
		if (1 & *to_dir)  //end page_tables 
			panic("copy_page_tables: already exist");
		if (!(1 & *from_dir))
			continue;
		from_page_table = (unsigned long *) (0xfffff000 & *from_dir);
		if (!(to_page_table = (unsigned long *) get_free_page()))
			return -1;	/* Out of memory, see freeing */
		*to_dir = ((unsigned long) to_page_table) | 7;
		nr = (from==0)?0xA0:1024;
		for ( ; nr-- > 0 ; from_page_table++,to_page_table++) {
			this_page = *from_page_table;
			if (!(1 & this_page))
				continue;
			this_page &= ~2;   //设置只读 ? // ~2　＝~10  = 01 　// this_page = this_page & ~2 //为什么可以设置成只读?4K page frame的数据格式是如何定义的?
			*to_page_table = this_page;  
			if (this_page > LOW_MEM) { 
				*from_page_table = this_page;
				this_page -= LOW_MEM;
				this_page >>= 12;  //计算页数序号
				mem_map[this_page]++; /*设置共享。mem_map[page] =1 表示被占用；
                                       mem_map[page] >=2 表示被占用且共享 */
			}
		}
	}
	invalidate();
	return 0;
}

/*
 * This function puts a page in memory at the wanted address.
 * It returns the physical address of the page gotten, 0 if
 * out of memory (either when trying to access page-table or
 * page.)
 * 
 * 入参: page(4K)-- > PAGE FRAME
 * 入参: address  linear address
 * put page to  linear address 
 * 
 * 总结:实际上这个函数表达的意思是, 用入参address得到的page基地址 映射到 入参page基地址
 * 	    也就是变更了线性地址中的某个页表所指向的PAGEFRAME 
 * 
 * 
 * 有几个问题 1. page_table 是数组吗？ 如果不是 怎么可以page_table[] 进行操作 ，如果是，unsigned long page_tables 不是定义数组 
 * 			答 : 数组的本质是指针 , 所以指针可以用数组表示,他们可以互相表示.
 * 2. page_table是局部变量 ,这样的映射是否有效,在函数之外?
 * 			答 : 其实实际上操作的是内存中的值, 所以在函数之外是有效的. 对dir;page_table;pageframe操作,这些都是在内存中.
 * 
 */
unsigned long put_page(unsigned long page,unsigned long address) 
{
	unsigned long tmp, *page_table;

/* NOTE !!! This uses the fact that _pg_dir=0 */

	if (page < LOW_MEM || page >= HIGH_MEMORY)  // page variable is page table or page entry ? page pointer ? page 
		printk("Trying to put page %p at %p\n",page,address);
	if (mem_map[(page-LOW_MEM)>>12] != 1) 
		printk("mem_map disagrees with %p at %p\n",page,address);
	page_table = (unsigned long *) ((address>>20) & 0xffc);  // 目录项偏移地址, 前面变量名应该为dir才对
	// (address>>20) & 0xffc: extract DIR(10bits) of LINER ADDRESS 
	//  0xffc = 1111 1111 1100 . 所以这里是为了mask掉最后 2bits.
	if ((*page_table)&1) //指向pagetable的DIR 是否有效
		page_table = (unsigned long *) (0xfffff000 & *page_table); // 接上面  (unsigned long *) (0xfffff000 & *dir) 
																   //  *dir 等价于page_table 
																   //  0xfffff000 & page_table  只保留page table 中的frame page address,也就是指向某个page frame
	else { // 如果无效
		if (!(tmp=get_free_page()))
			return 0;
		*page_table = tmp|7;
		page_table = (unsigned long *) tmp;
	}
	page_table[(address>>12) & 0x3ff] = page | 7;   /* 
													address >> 12  保留DIR|PAGE| ; OFFSET 被移出
													0x3ff = 0011 1111 1111   
													(address>>12) & 0x3ff : 保留10bits , 其他mask , get PAGE(10bits) 
													page_table[(address>>12) & 0x3ff] 等价于 page_table[PAGE] ,
													等价于page_table的基地址+偏移地址PAGE 可以计算得到一个page frame的起始地址
													总结:实际上这个函数表达的意思是, 用入参address得到的page基地址 映射到 入参page基地址
													也就是变更了线性地址中的某个页表所指向的PAGEFRAME 
													*/						
/* no need for invalidate */
	return page;
}

/*
Introduction write_verify(), un_wp_page(),do_wp_page().

write_verify() : why need to verify 
		 	in : linear address 



*/

//un-write protect page 
//
void un_wp_page(unsigned long * table_entry)
{
	unsigned long old_page,new_page;

	old_page = 0xfffff000 & *table_entry;
	//后者判断页面是否处于共享状态；== 1 则表示 未处于共享状态
	if (old_page >= LOW_MEM && mem_map[MAP_NR(old_page)]==1) {
		*table_entry |= 2;// |2 取消写保护  r/w bit . 1 =w ; 0=r 
		invalidate();
		return;
	}
	//page 处于共享状态
	if (!(new_page=get_free_page()))
		oom();
	if (old_page >= LOW_MEM)
		mem_map[MAP_NR(old_page)]--;//表示取消共享，但实际上有改变吗？映射有改变吗?
	*table_entry = new_page | 7; // | 7 表示可读可写 
	invalidate();
	copy_page(old_page,new_page);// 交换，为了不浪费page  
}	

/*
 * This routine handles present pages, when users try to write
 * to a shared page. It is done by copying the page to a new address
 * and decrementing the shared-page counter for the old page.
 *
 * If it's in code space we exit with a segment error.
 */
void do_wp_page(unsigned long error_code,unsigned long address)
{
#if 0
/* we cannot do this yet: the estdio library writes to code space */
/* stupid, stupid. I really want the libc.a from GNU */
	if (CODE_SPACE(address))
		do_exit(SIGSEGV);
#endif
	un_wp_page((unsigned long *)
		(((address>>10) & 0xffc) + (0xfffff000 &
		*((unsigned long *) ((address>>20) &0xffc)))));

}
/*

write_verify() : why need to verify .写页面之前做验证，目的是尝试是否可写
		 	in : linear address 

*/
void write_verify(unsigned long address)
{
	unsigned long page;

	if (!( (page = *((unsigned long *) ((address>>20) & 0xffc)) )&1)) // twice get value :  equal to ** (address >> 22)
		return;
	page &= 0xfffff000; // 
	page += ((address>>10) & 0xffc);  // page = page + address ( DIR | PAGE )
	if ((3 & *(unsigned long *) page) == 1)  /* non-writeable, present */  
											 /* 3(dec) = 11(bin)   
											    3 & 1011 = 3;
												3 & 1001 = 1;
												bit write/read , 0 non-writeable
											The Present bit indicates whether a page table
											entry can be used in address translation. 
											P=1 indicates that the entry can be used.
											 */
		un_wp_page((unsigned long *) page);
	return;
}




/// @brief get free page and map to address 
//  the difference between get_empty_page and get_free_page ?
//  get_free_page : not relative to linear addres 
//  get_empty_page : map free page and linear address. this page called empty page.
/// @param address : if successed , param address map to empty page .
void get_empty_page(unsigned long address)
{
	unsigned long tmp;

	if (!(tmp=get_free_page()) || !put_page(tmp,address)) {
		free_page(tmp);		/* 0 is ok - ignored */
		oom();
	}
}

/*
 * try_to_share() checks the page at address "address" in the task "p",
 * to see if it exists, and if it is clean. If so, share it with the current
 * task.
 *
 * NOTE! This assumes we have checked that p != current, and that they
 * share the same executable.
 */
static int try_to_share(unsigned long address, struct task_struct * p)
{
	unsigned long from;
	unsigned long to;
	unsigned long from_page;
	unsigned long to_page;
	unsigned long phys_addr;

	from_page = to_page = ((address>>20) & 0xffc);
	from_page += ((p->start_code>>20) & 0xffc);
	to_page += ((current->start_code>>20) & 0xffc);
/* is there a page-directory at from? */
	from = *(unsigned long *) from_page;
	if (!(from & 1))
		return 0;
	from &= 0xfffff000;
	from_page = from + ((address>>10) & 0xffc);
	phys_addr = *(unsigned long *) from_page;
/* is the page clean and present? */
	if ((phys_addr & 0x41) != 0x01)
		return 0;
	phys_addr &= 0xfffff000;
	if (phys_addr >= HIGH_MEMORY || phys_addr < LOW_MEM)
		return 0;
	to = *(unsigned long *) to_page;
	if (!(to & 1)) {
		if ((to = get_free_page()))
			*(unsigned long *) to_page = to | 7;
		else
			oom();
	}
	to &= 0xfffff000;
	to_page = to + ((address>>10) & 0xffc);
	if (1 & *(unsigned long *) to_page)
		panic("try_to_share: to_page already exists");
/* share them: write-protect */
	*(unsigned long *) from_page &= ~2;
	*(unsigned long *) to_page = *(unsigned long *) from_page;
	invalidate();
	phys_addr -= LOW_MEM;
	phys_addr >>= 12;
	mem_map[phys_addr]++;
	return 1;
}

/*
 * share_page() tries to find a process that could share a page with
 * the current one. Address is the address of the wanted page relative
 * to the current data space.
 *
 * We first check if it is at all feasible by checking executable->i_count.
 * It should be >1 if there are other tasks sharing this inode.
 */
static int share_page(unsigned long address)
{
	struct task_struct ** p;

	if (!current->executable)
		return 0;
	if (current->executable->i_count < 2)
		return 0;
	for (p = &LAST_TASK ; p > &FIRST_TASK ; --p) {
		if (!*p)
			continue;
		if (current == *p)
			continue;
		if ((*p)->executable != current->executable)
			continue;
		if (try_to_share(address,*p))
			return 1;
	}
	return 0;
}

//
void do_no_page(unsigned long error_code,unsigned long address)
{
	int nr[4];
	unsigned long tmp;
	unsigned long page;
	int block,i;

	address &= 0xfffff000;
	tmp = address - current->start_code; // current process . start_code : the address of process code 
	if (!current->executable || tmp >= current->end_data) {
		get_empty_page(address);
		return;
	}
	if (share_page(tmp))
		return;
	if (!(page = get_free_page()))
		oom();
/* remember that 1 block is used for header */
	block = 1 + tmp/BLOCK_SIZE;
	for (i=0 ; i<4 ; block++,i++)
		nr[i] = bmap(current->executable,block);
	bread_page(page,current->executable->i_dev,nr);
	i = tmp + 4096 - current->end_data;
	tmp = page + 4096;
	while (i-- > 0) {
		tmp--;
		*(char *)tmp = 0;
	}
	if (put_page(share_page,address))
		return;
	free_page(page);
	oom();
}

void mem_init(long start_mem, long end_mem)
{
	int i;
	/*总结初始化流程
	1. S1：15M主内存，每个页都设置为USED ，通过>>12 （4K）来计算页数量。4K 为每页的大小。 按照道理mem_map只是一个内存状态的映射
	2. S2：计算start_mem 所在的页数位置 ；
	3. S3：start 到end 之间的页都设置为零; 
	*/
	HIGH_MEMORY = end_mem;  // LOW_MEMORY HIGH_MEMORY 应该表示的是 内存的低位 和 高位
	for (i=0 ; i<PAGING_PAGES ; i++)  // PAGING_PAGES = 15x1024x1024 / 2^12 = (15x1024x1024) / 4096 (4K)=  3840 (PAGES)
		mem_map[i] = USED;   // unsigned char   0 - 65535 
	i = MAP_NR(start_mem); //#define 当作函数来使用。 MAP_NR(MEM_NUMBER) 根据 start_mem 返回内存页. 
	end_mem -= start_mem;
	end_mem >>= 12;  // >>=  等价于  emd_mem = end_mem >> 12 
	while (end_mem-->0)  // end_mem -- > 0 ?  等价于  (end_mem --) > 0
		mem_map[i++]=0; // 为什么一会儿设置为USED ，又设置成零
}

void calc_mem(void)
{
	int i,j,k,free=0;
	long * pg_tbl;

	for(i=0 ; i<PAGING_PAGES ; i++)
		if (!mem_map[i]) free++;
	printk("%d pages free (of %d)\n\r",free,PAGING_PAGES);
	for(i=2 ; i<1024 ; i++) {
		if (1&pg_dir[i]) {
			pg_tbl=(long *) (0xfffff000 & pg_dir[i]);
			for(j=k=0 ; j<1024 ; j++)
				if (pg_tbl[j]&1)
					k++;
			printk("Pg-dir[%d] uses %d pages\n",i,k);
		}
	}
}
