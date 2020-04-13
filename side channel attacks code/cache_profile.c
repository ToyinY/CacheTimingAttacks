#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/mman.h>
#include <sys/stat.h>

void * target;

static __inline__ void maccess(void *p) {
  asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax");
}

static __inline__ uint64_t timer_start (void) {
        unsigned cycles_low, cycles_high;
        asm volatile ("CPUID\n\t"
                    "RDTSC\n\t"
                    "mov %%edx, %0\n\t"
                    "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
                    "%rax", "%rbx", "%rcx", "%rdx");
        return ((uint64_t)cycles_high << 32) | cycles_low;
}

static __inline__ uint64_t timer_stop (void) {
        unsigned cycles_low, cycles_high;
        asm volatile("RDTSCP\n\t"
                    "mov %%edx, %0\n\t"
                    "mov %%eax, %1\n\t"
                    "CPUID\n\t": "=r" (cycles_high), "=r" (cycles_low):: "%rax",
                    "%rbx", "%rcx", "%rdx");
        return ((uint64_t)cycles_high << 32) | cycles_low;
}

void clflush(volatile void* Tx) {
    asm volatile("lfence;clflush (%0) \n" :: "c" (Tx));
}

uint32_t reload(void *target)
{
    volatile uint32_t time;
    uint64_t t1, t2;
    t1 = timer_start();
    maccess(target);
    t2 = timer_stop();
    return t2 - t1;
}

void *map_offset(const char *file, size_t offset) {
  int fd = open(file, O_RDONLY);
  if (fd < 0)
    return NULL;

  char *mapaddress = mmap(0, sysconf(_SC_PAGE_SIZE), PROT_READ, MAP_PRIVATE, fd, offset & ~(sysconf(_SC_PAGE_SIZE) -1));
  close(fd);
  if (mapaddress == MAP_FAILED)
    return NULL;
  return (void *)(mapaddress+(offset & (sysconf(_SC_PAGE_SIZE) -1)));
}

int main() {
	//init array
	int arr[100];
	memset(arr, 1, sizeof(int)*100);
	unsigned char* addr = (unsigned char*)arr;
	printf("Array initialized.\n");
	/*char* victimBinaryFileName = "librcrypto.so.3";
	size_t offset = (int)strtol("227b20", NULL, 16);	
	target = map_offset(victimBinaryFileName, offset);*/

	int i;
	uint32_t *timing;
	timing = (uint32_t *) malloc(sizeof(uint32_t));
	
	//hits
	FILE *hit_timingFP;
	hit_timingFP = fopen("hit_times.txt", "w");
	for (i = 0; i < 100; i++) {
		timing = reload(&arr[i]);
		fprintf(hit_timingFP, "%lu\n", timing);
	}
	fclose(hit_timingFP);
	printf("Hits timed.\n");
	
	//misses
	FILE *miss_timingFP;
	miss_timingFP = fopen("miss_times.txt", "w");
	for (i = 0; i < 100; i++) {
		clflush(&arr[i]);
		timing = reload(&arr[i]);
		fprintf(miss_timingFP, "%lu\n", timing);
	}
	fclose(miss_timingFP);
	printf("Misses timed.\n");

	return 0;
}
