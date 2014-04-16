#define VIRT_MEM_LOGPAGESIZE    12
#define VIRT_MEM_PAGESHIFT      MEM_LOGPAGESIZE
#define VIRT_MEM_PAGESIZE       (1<<MEM_LOGPAGESIZE)
#define VIRT_MEM_PAGEMASK       (~(MEM_PAGESIZE-1))
#define VIRT_MEM_PAGE_COUNT     1024

struct page_table_entry
{
	int valid_bit;
	uint32_t physical_addr;
	int dirtybit;
	int swap_disk_num;
	int swap_offset;
	int used;
}
	
struct page_table
{
	struct page_table_entry translation[VIRT_MEM_PAGE_COUNT];
}
struct page_table page_table_create()
{
	size=0;
}

uint32_t get_physical(struct page_table * P,uint32_t vaddr)
{
	uint32_t index, tag,paddr;
	int valid_bit;
	tag = vaddr & ~(VIRT_MEM_PAGESIZE - 1);
	offset = vadrr & (VIRT_MEM_PAGESIZE -1);
	index = (vaddr >> VIRT_MEM_LOGPAGESIZE) % MEM_PAGE_COUNT;
	
	valid_bit = (P->translation[index]).valid_bit;
	
	//function page fault should be called if not valid...
	
	phystag = (P->translation[index]).physical_addr; 
	
	paddr = phystag << VIRT_MEM_LOGPAGESIZE + offset;
	return paddr;
}

uint32_t get_logical(struct page_table * P,uint32_t paddr)
{
	int offset = paddr & (VIRT_MEM_LOGPAGESIZE -1);
	for(uint32_t i=0;i<size;i++)
	{
		if(P->translation[i]->physical_addr == paddr)
			return i << VIRT_MEM_LOGPAGESIZE + offset;
	}
}

struct page_table_entry * get_page_table_entry(struct page_table * P,uint32_t vaddr)
{
	uint32_t index, tag,paddr;
	tag = vaddr & ~(VIRT_MEM_PAGESIZE - 1);
	index = (vaddr >> VIRT_MEM_LOGPAGESIZE) % MEM_PAGE_COUNT;
	return &(P->translation[index]);
}

uint32_t make_an_entry(struct page_table * P,uint32_t vaddr,uint32_t paddr)
{
	offset = vadrr & (VIRT_MEM_PAGESIZE -1);
	index = (vaddr >> VIRT_MEM_LOGPAGESIZE) % MEM_PAGE_COUNT;
	
	struct page_table_entry * E;
	E = calloc(1,size(struct page_table_entry));
	E->valid_bit = 1;
	E->dirtybit = 0;
	E->physical_addr = paddr;
	E->swap_disk_num = 1;
	E->swap_offset = offset;
	
	P->translation[index] = 
}
