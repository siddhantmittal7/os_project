struct page_table
{
	uint32_t virtual_addr;
	uint32_t physical_addr;
	unsigned char *data;
}

uint32_t get_physical(struct * page_table,uint32_t vaddr)
{
	return page_table->physical_addr;
}

uint32_t get_logical(struct * page_table,uint32_t paddr)
{
	return page_table->vrtual_addr;
}


