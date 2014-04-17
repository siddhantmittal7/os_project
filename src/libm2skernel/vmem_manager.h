#ifndef os_project_vmem_manager_h
#define os_project_vmem_manager_h

#define VIRT_MEM_LOGPAGESIZE    12
#define VIRT_MEM_PAGESHIFT      MEM_LOGPAGESIZE
#define VIRT_MEM_PAGESIZE       (1<<MEM_LOGPAGESIZE)
#define VIRT_MEM_PAGEMASK       (~(MEM_PAGESIZE-1))
#define VIRT_MEM_PAGE_COUNT     1024

struct mem_t;

struct ptentry
{
	int valid_bit;
	uint32_t paddr;
	uint32_t tag;
	int dirtybit;
	int used;
	uint32_t disk_start;

	struct ptentry *next;
	struct mem_host_mapping_t *host_mapping;  /* If other than null, page is host mapping */
};

struct page_table
{
	struct ptentry *entries[VIRT_MEM_PAGE_COUNT];
};

typedef struct page_operation_t pageop_t;

#define OPERATION_PAGE_OUT 0
#define OPERATION_PAGE_IN 1

struct page_operation_t {
	int operation;
	uint32_t vaddr;
	struct ptentry *pte;
	uint32_t paddr;
};

void vmem_load_page(struct mem_t *mem, struct ptentry *entry);
void display_state(struct mem_t *mem);

#endif
