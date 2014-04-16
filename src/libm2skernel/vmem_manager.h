#ifndef os_project_vmem_manager_h
#define os_project_vmem_manager_h

#define VIRT_MEM_LOGPAGESIZE    12
#define VIRT_MEM_PAGESHIFT      MEM_LOGPAGESIZE
#define VIRT_MEM_PAGESIZE       (1<<MEM_LOGPAGESIZE)
#define VIRT_MEM_PAGEMASK       (~(MEM_PAGESIZE-1))
#define VIRT_MEM_PAGE_COUNT     1024

struct ptentry
{
	int valid_bit;
	uint32_t paddr;
	uint32_t tag;
	int dirtybit;
	int used;
	uint32_t disk_start

	struct ptentry *next;
};

struct page_table
{
	ptentry_t *entries[VIRT_MEM_PAGE_COUNT];
};

// struct page_table page_table_create()
// {
// 	size=0;
// }

typedef struct page_operation_t pageop_t;

#define OPERATION_PAGE_OUT 0
#define OPERATION_PAGE_IN 1

struct page_operation_t {
	int operation;
	uint32_t vaddr;
	ptentry_t *pte;
	uint32_t paddr;
};

void vmem_load_page(ptentry_t *entry);
void display_state();

#endif
