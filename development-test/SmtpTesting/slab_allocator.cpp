#include "slab_allocator.h"
#include <cstring>
#include <malloc.h>

slab_buffer* slab_buffer_alloc(slaballoc_state* slaballoc){
	void* buffer;
	slab_free_link* link;

	if (slaballoc->free_buffers != NULL){
		link = slaballoc->free_buffers;
		buffer = link->buffer;
		slaballoc->free_buffers = link;
		free(link);
	}
	else{
		buffer = malloc(SLAB_SIZE);
	}

	slab_buffer* ret = (slab_buffer*)malloc(sizeof(slab_buffer));
	ret->buffer = buffer;
	ret->next = NULL;
	ret->used = 0;
	return ret;
}

void slab_buffer_free(slaballoc_state* slaballoc, slab_buffer* buffer){
	slab_free_link* link;
	link = (slab_free_link*)malloc(sizeof(slab_free_link));
	link->buffer = buffer;
	link->next = slaballoc->free_buffers;
	slaballoc->free_buffers = link;
	free(buffer);
}