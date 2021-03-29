#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/export.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include <linux/pgtable.h>
#include <linux/mm_types.h>
#include <linux/highmem.h>


static struct proc_dir_entry *proc_root;
static struct proc_dir_entry * rootit;
static struct cred *cred_back;
static struct task_struct *task;
static unsigned long vaddr;//虚拟地址
static unsigned long paddr;//物理地址i




static int vaddrtopaddr(struct task_struct *p,unsigned long vaddr);
static void get_pgtable_macro(void);
static ssize_t readwrite_phys_write(struct file *file, const char __user *buffer,size_t count, loff_t *data);
ssize_t readwrite_phys_read(struct file *file, char __user *buf, size_t size, loff_t *ppos);
static int readwrite_phys_open(struct inode *inode, struct file *file);
static int proc_fs_attach(void);



static ssize_t readwrite_phys_write(struct file *file, const char __user *buffer,size_t count, loff_t *data)
{
    char *buf,*str;
    struct task_struct *tasklist,*p;
    struct list_head *pos;
    int index,pidflag;   
	unsigned long _pid;
	unsigned long _vaddr;
	char pidstr[20];
    char vaddrstr[50];	
    tasklist=&init_task;
    if (count < 1)
        return -EINVAL;

    buf = kmalloc(count, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    if (copy_from_user(buf, buffer, count)) {
        kfree(buf);
        return -EFAULT;
    }
	
	str=buf;
	pidflag=1;
	index=0;
	while(*str!='\0')
	{
		if(*str=='|')
		{
			pidstr[index]='\0';
			pidflag=0;
			index=0;
			str++;
			continue;
		}
		if(pidflag==1)
		{
			pidstr[index]=*str;
		}
		else
		{
			vaddrstr[index]=*str;
		}
		index++;
		str++;
	}
	vaddrstr[index]='\0';
	_pid=(int) simple_strtoull(pidstr,NULL,10);
	_vaddr=simple_strtoull(vaddrstr,NULL,10);
	printk("pid %ld vaddr %ld\n",_pid,_vaddr);
    list_for_each(pos,&tasklist->tasks){
        p=list_entry(pos,struct task_struct,tasks);
    	if(p->pid==_pid){
        	task = p;
        	printk("pid %d name %sfind address\n",p->pid,p->comm);
			vaddrtopaddr(p,_vaddr);	
			break;
    	}
    }
    kfree(buf);
    return count;
}

static int vaddrtopaddr(struct task_struct *p,unsigned long vaddr)
{
	struct mm_struct *mm=p->mm;
	pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
	unsigned long kks;
    unsigned long paddr = 0;
    unsigned long page_addr = 0;
    unsigned long page_offset = 0;
    
	pgd =pgd_offset(mm,vaddr);
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        return -1;
    }
 
    pud = pud_offset((p4d_t*)pgd, vaddr);
    printk("pud_val = 0x%lx\n", pud_val(*pud));
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        return -1;
    }
 
    pmd = pmd_offset(pud, vaddr);
    if (pmd_none(*pmd)) {
        printk("not mapped in pmd\n");
        return -1;
    }
 
    pte = pte_offset_kernel(pmd, vaddr);
    if (pte_none(*pte)) {
        printk("not mapped in pte\n");
        return -1;
    }
	//页框地址 页的物理地址
	page_addr = pte_val(*pte) & PAGE_MASK;
    page_offset = vaddr & ~PAGE_MASK; //虚拟地址在物理地址中的偏移

	paddr = page_addr | page_offset; //内存的物理地址
	unsigned long _pageaddr=pte_page(*pte); //拿到物理地址对应的内存结构实例 page,这是Linux的物理内存管理结构，每个page结构实例表示一块物理内存

    //kmap要的是page结构的虚拟地址
    unsigned long vptr=kmap(_pageaddr); //将该物理地址映射到内核的虚拟地址空间中，这样才能访问该物理内存。
	if(vptr<=0)
	{
		printk("vptr is null");
	}
	else
	{
		printk("vptr 0x%lx vaddr value 0x%lx\n",vptr,vptr+page_offset);
		unsigned int *vint=(unsigned int*)(vptr+page_offset);
		printk("int val %d\n",*vint);
		*vint=2021;
	}
	kunmap(page_addr);
	return 1; 

}

ssize_t readwrite_phys_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
    return 0;
}

static int readwrite_phys_open(struct inode *inode, struct file *file)
{
    return 0;
}

static const struct proc_ops proc_fops = {
    .proc_open= readwrite_phys_open,
    .proc_read= readwrite_phys_read,
    .proc_write = readwrite_phys_write,
};

static int proc_fs_attach(void)
{
    proc_root = proc_mkdir("readwrite_phys", NULL);
    rootit= proc_create("read_write_phys", 0666, proc_root, &proc_fops);
    if (IS_ERR(rootit)){
        printk("create read_write_phys dir error\n");
        return -1;
    }
    return 0;

}

static void get_pgtable_macro(void)
{
    printk("PAGE_OFFSET = 0x%lx\n", PAGE_OFFSET);
    printk("PGDIR_SHIFT = %d\n", PGDIR_SHIFT);
    printk("PUD_SHIFT = %d\n", PUD_SHIFT);
    printk("PMD_SHIFT = %d\n", PMD_SHIFT);
    printk("PAGE_SHIFT = %d\n", PAGE_SHIFT); 
    printk("PTRS_PER_PGD = %d\n", PTRS_PER_PGD);
    printk("PTRS_PER_PUD = %d\n", PTRS_PER_PUD);
    printk("PTRS_PER_PMD = %d\n", PTRS_PER_PMD);
    printk("PTRS_PER_PTE = %d\n", PTRS_PER_PTE);
	printk("__BITS_PER_LONG = %d\n",__BITS_PER_LONG); 
    printk("PAGE_MASK = 0x%lx\n", PAGE_MASK);
    printk("PTE_PFN_MASK = 0x%lx\n", PTE_PFN_MASK);
    printk("PGD_ALLOWED_BITS = 0x%lx\n",PGD_ALLOWED_BITS);
}

static int __init module1_init(void)
{
    int ret;
    cred_back = kmalloc(sizeof(struct cred), GFP_KERNEL);
    if (IS_ERR(cred_back))
        return PTR_ERR(cred_back);

    ret = proc_fs_attach();
	get_pgtable_macro();
    return 0;
}

static void __exit module1_exit(void)
{
    if(task!=NULL && task->mm!=NULL){
        struct cred *cred = (struct cred *)__task_cred(task);
        memcpy(cred, cred_back, sizeof(struct cred));
    }
    kfree(cred_back);
	remove_proc_entry("read_write_phys", proc_root);
    remove_proc_entry("readwrite_phys", NULL);
}

module_init(module1_init);
module_exit(module1_exit);
MODULE_LICENSE("GPL");
