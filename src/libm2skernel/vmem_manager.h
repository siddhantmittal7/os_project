#ifndef os_project_vmem_manager_h
#define os_project_vmem_manager_h

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
};

typedef struct page_table_entry ptentry_t;
	
struct page_table
{
	ptentry_t translation[VIRT_MEM_PAGE_COUNT];
};

struct page_table page_table_create()
{
	size=0;
}

typedef uint32_t logical_addr_t;
typedef uint32_t physical_addr_t;

typedef struct page_operation_t pageop_t;

#define OPERATION_PAGE_OUT 0
#define OPERATION_PAGE_IN 1

struct page_operation_t {
	int operation;
	logical_addr_t vaddr;
	ptentry_t *pte;
	physical_addr_t paddr;
};

void vmem_load_page(ptentry_t *entry);
void display_state();

#endif
