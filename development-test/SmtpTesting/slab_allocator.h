#include <stdint.h>

#define SLAB_SIZE 8096

struct slab_buffer {
	uint16_t used;
	slab_buffer* next;
	void* buffer;
};

struct slab_free_link {
	void* buffer;
	slab_free_link* next;
};

struct slaballoc_state {
	struct slab_free_link* free_buffers;
};

slab_buffer* slab_buffer_alloc(slaballoc_state* slaballoc);
void slab_buffer_free(slaballoc_state* slaballoc, slab_buffer* buffer);