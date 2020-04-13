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

#define ARM_V8_TIMING_H

#include <stdint.h>

#define ARMV8_PMCR_E            (1 << 0) /* Enable all counters */
#define ARMV8_PMCR_P            (1 << 1) /* Reset all counters */
#define ARMV8_PMCR_C            (1 << 2) /* Cycle counter reset */

#define ARMV8_PMUSERENR_EN      (1 << 0) /* EL0 access enable */
#define ARMV8_PMUSERENR_CR      (1 << 2) /* Cycle counter read enable */
#define ARMV8_PMUSERENR_ER      (1 << 3) /* Event counter read enable */

#define BILLION 1000000000
#define ARMV8_PMCNTENSET_EL0_EN (1 << 31) /* Performance Monitors Count Enable Set register */


#define ARM_V8_TIMING_H

#include <stdint.h>

#define ARMV8_PMCR_E            (1 << 0) /* Enable all counters */
#define ARMV8_PMCR_P            (1 << 1) /* Reset all counters */
#define ARMV8_PMCR_C            (1 << 2) /* Cycle counter reset */

#define ARMV8_PMUSERENR_EN      (1 << 0) /* EL0 access enable */
#define ARMV8_PMUSERENR_CR      (1 << 2) /* Cycle counter read enable */
#define ARMV8_PMUSERENR_ER      (1 << 3) /* Event counter read enable */

#define ARMV8_PMCNTENSET_EL0_EN (1 << 31) /* Performance Monitors Count Enable Set register */


void * target;

static __inline__ void maccess(void *p) {
  volatile uint32_t value;
  asm volatile ("LDR %0, [%1]\n\t"
      : "=r" (value)
      : "r" (p)
      );
}


void flush(volatile void* Tx) {
    	asm volatile ("DC CIVAC, %0" :: "r"(Tx));
	asm volatile ("DSB ISH");
	asm volatile ("ISB");
}


uint32_t reload(void *target)
{
    uint64_t diff;
    struct timespec start, end;
    int i;
    clock_gettime(CLOCK_MONOTONIC, &start); /* mark start time */
    maccess(target);
    clock_gettime(CLOCK_MONOTONIC, &end); /* mark start time */
    diff = end.tv_nsec - start.tv_nsec;
    return(diff);
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
	hit_timingFP = fopen("hit_times_arm.txt", "w");
	for (i = 0; i < 100; i++) {
		timing = reload(&arr[i]);
		fprintf(hit_timingFP, "%lu\n", timing);
	}
	fclose(hit_timingFP);
	printf("Hits timed.\n");
	
	//misses
	FILE *miss_timingFP;
	miss_timingFP = fopen("miss_times_arm.txt", "w");
	for (i = 0; i < 100; i++) {
		flush(&arr[i]);
		timing = reload(&arr[i]);
		fprintf(miss_timingFP, "%lu\n", timing);
	}
	fclose(miss_timingFP);
	printf("Misses timed.\n");

	return 0;
}
