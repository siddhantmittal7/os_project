#include <stdio.h>
#include "m2skernel.h"

void vmem_add_page(ptentry_t *page);
ptentry_t* run_clock_policy();
void perform_page_in(pageop_t op);
void perform_page_out(pageop_t op);

/*
 * Address Translation
 */

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

ptentry_t * get_page_table_entry(struct page_table * P,uint32_t vaddr)
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
	
	ptentry_t * E;
	E = calloc(1,size(ptentry_t));
	E->valid_bit = 1;
	E->dirtybit = 0;
	E->physical_addr = paddr;
	E->swap_disk_num = 1;
	E->swap_offset = offset;
	
	P->translation[index] = 
}


/*
 * Page Replacement
 */

void vmem_load_page(ptentry_t *entry) {
	printf("Starting page load for vaddr: %d\n", entry->vaddr);

	pageop_t pagein_op;
	pagein_op.operation = OPERATION_PAGE_IN;
	pagein_op.vaddr = entry->vaddr;
	pagein_op.pte = entry;

	// Check for free frames
	if (isa_ctx->mem->free_frames_size > 0) {
		pagein_op.paddr = isa_ctx->mem->free_frames[isa_ctx->mem->free_frames_size - 1];
		vmem_add_page(pagein_op.pte);
		printf("Loading into free_frame: %d\n", pagein_op.paddr);
	}
	else
	{
		ptentry_t *pte = run_clock_policy(entry);
		pagein_op.paddr = pte->paddr;
			
		pageop_t pageout_op;
		pageout_op.operation = OPERATION_PAGE_OUT;
		pageout_op.pte = pte;
		pageout_op.vaddr = pte->vaddr;
		pageout_op.paddr = pte->paddr; // No physical address for pageout
		perform_page_out(pageout_op);
	}
	
	perform_page_in(pagein_op);
}

void* read_swap(uint32_t vaddr) {
	return NULL;
}

void write_swap(uint32_t vaddr, void* data) {
	
}

void perform_page_in(pageop_t op) {
	printf("Page in: %d -> %d\n", op.vaddr, op.paddr);
	void* page = read_swap(op.vaddr);
	// TODO Store page in ctx->mem at position corresponding to paddr
	op.pte->valid_bit = 1;
	op.pte->paddr = op.paddr;
	op.pte->dirty = 0;
	isa_ctx->mem->free_frames_size--;
}

void perform_page_out(pageop_t op) {
	printf("Page out: %d from %d\n", op.vaddr, op.paddr);
	if (op.pte->dirty) {
		void* data;
		// TODO load page data in 'data'
		write_swap(op.vaddr, data);
	}
	op.pte->valid_bit = 0;
	isa_ctx->mem->free_frames[isa_ctx->mem->free_frames_size] = op.paddr;
	isa_ctx->mem->free_frames_size++;
}

/*
 * Page Replacement Policy (One Hand Clock Algorithm)
 */

void vmem_add_page(ptentry_t *page) {
	isa_mem->page_list[isa_mem->valid_pages_size] = page;
	isa_mem->valid_pages_size++;
}

void inc_pointer() {
	clock_pointer++;
	if (clock_pointer == isa_mem->valid_pages_size)
		clock_pointer = 0;
}

void display_state() {
    int i;
    for (i = 0; i < isa_mem->valid_pages_size; i++) {
        if (i == clock_pointer)
            printf("*");
        printf("[%d,%d]\t", isa_mem->valid_pages[i]->vaddr, isa_mem->valid_pages[i]->used);
    }
    printf("\n");
}

ptentry_t* run_clock_policy(ptentry_t* newpage) {
    printf("Starting page replacement, initial state:\n");
    display_state();
    ptentry_t **page_list = isa_mem->valid_pages;
	while (1) {
		if (!page_list[clock_pointer]->used) {
			ptentry_t * page_to_replace = page_list[clock_pointer];
			page_list[clock_pointer] = newpage;
			inc_pointer();
            printf("OUT: %d,  IN: %d\n", page_to_replace->vaddr, newpage->vaddr);
            return page_to_replace;
		} else {
			page_list[clock_pointer]->used = 0;
			inc_pointer();
		}
        display_state();
	}
}
