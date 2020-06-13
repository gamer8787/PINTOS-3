/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include <hash.h>
#include <threads/vaddr.h>

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);
/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool		
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable, 
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;
	
	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page *page = NULL ;
		page = malloc(sizeof(struct page));
		enum vm_type t = VM_TYPE(type);
		bool *page_initializer;
		if(t==1){
			page_initializer = anon_initializer;
		}
		else if(t==2){
			page_initializer = file_map_initializer;
		}
		uninit_new (page, upage, init, t, aux, page_initializer);
		page-> writable =  writable;
		page-> type = type;
		page->is_uninit_init=false;
		/* TODO: Insert the page into the spt. */
		return spt_insert_page(spt,page);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	uint64_t pg_num = pg_round_down(va);
	struct page pg;
	pg.va = pg_num;
	struct hash_elem *e = hash_find(&spt->hash_table, &pg.elem);
	if (e != NULL)
	{
		page = hash_entry(e, struct page, elem);
	}
	return page;
}
 
/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	bool succ = false;
	/* TODO: Fill this function. */ 
	if(hash_find(&spt->hash_table,&page->elem) == NULL){
		succ = true;
		hash_insert(&spt->hash_table, &page->elem);
	}
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	uint64_t kva = palloc_get_page (PAL_USER);
	if (kva == NULL)
	{
		PANIC("TO DO swap out");
	}

	frame = malloc(sizeof(struct frame));
	frame->kva = kva;
	frame->page = NULL;

	frame->is_alloc = true;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	check_address(addr);
	page = spt_find_page(spt, pg_round_down (addr));
	if(page ==NULL){
		return false; 
	}

	return vm_do_claim_page (page);
}
/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
} 

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL)
	{
		return false;
	}
	return vm_do_claim_page (page);
}


/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	//spt_insert_page(&thread_current()->spt, page);  
	pml4_set_page (thread_current()->pml4, page->va, frame->kva, page->writable);

	return swap_in (page, frame->kva);
}



/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->hash_table, spt_hash_func, spt_less_func, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	struct hash_iterator i;
	hash_first (&i, &src->hash_table);
	while (hash_next (&i)){	
		struct page *page = hash_entry (hash_cur (&i), struct page, elem);
		enum vm_type type =page->type;
		void *va = page->va;
		bool  writable = page->writable;
		vm_initializer *init =  page->uninit.init;
		void *aux = page->uninit.aux;
		if(!vm_alloc_page_with_initializer (type, va, writable, init, aux)){
			
			return false;
		}
		void *newpage;
		if(page->is_uninit_init){
			newpage = palloc_get_page(PAL_USER);
			if (newpage == NULL) {			
				return false;
			}
			memcpy(newpage, page->frame->kva, PGSIZE);
			writable = page->writable;
			if (!pml4_set_page (thread_current()->pml4, va, newpage, writable)) {
				palloc_free_page(newpage);
				return false;
			}
		}
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	if(hash_empty(&spt->hash_table)){
		return;
	}
	struct hash_iterator i;
	hash_first (&i, &spt->hash_table);
	while (hash_next (&i)){	
		struct page *page = hash_entry (hash_cur (&i), struct page, elem);
		destroy(page);
	}	  
	supplemental_page_table_init(spt);
}

static uint64_t spt_hash_func(const struct hash_elem *e, void*aux)
{
	return hash_int(hash_entry(e, struct page, elem)->va);
}

static bool spt_less_func(const struct hash_elem *a, const struct hash_elem *b, void*aux)
{
	return ( hash_int(hash_entry(a, struct page, elem)->va) < hash_int(hash_entry(b, struct page, elem)->va) );
}
