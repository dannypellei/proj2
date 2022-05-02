#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

// Access hardware timestamp counter
#define RDTSC(cycles) __asm__ volatile ("rdtsc" : "=a" (cycles));

// Serialize execution
#define CPUID() asm volatile ("CPUID" : : : "%rax", "%rbx", "%rcx", "%rdx");

// Intrinsic CLFLUSH for FLUSH+RELOAD attack
#define CLFLUSH(address) _mm_clflush(address);

#define SAMPLES 10000 // TODO: CONFIGURE THIS

#define L1_CACHE_SIZE (32*1024)
#define LINE_SIZE 64
#define ASSOCIATIVITY 8
#define L1_NUM_SETS (L1_CACHE_SIZE/(LINE_SIZE*ASSOCIATIVITY))
#define NUM_OFFSET_BITS 6
#define NUM_INDEX_BITS 6
#define NUM_OFF_IND_BITS (NUM_OFFSET_BITS + NUM_INDEX_BITS)
uint64_t startTime;
uint64_t endTime;

uint64_t eviction_counts[L1_NUM_SETS] = {0};
__attribute__ ((aligned (64))) uint64_t trojan_array[32*4096];
__attribute__ ((aligned (64))) uint64_t spy_array[4096];


/* TODO:
 * This function provides an eviction set address, given the
 * base address of a trojan/spy array, the required cache
 * set ID, and way ID.
 *
 * Describe the algorithm used here.
 * 
 * first, gets the tag bits and the index bits from the base address.
 * get the tag bits by shifting the base by 6. gets the index bits by shifting the base by 12 then masking to get only the last 6.
 * once we have the index and tag bits, we can find where to begin
 * we know that our eviction set address is going to have the same index bits as the victim, but the tag bits will differ
 * if the value of the index bits is greater than the required cache set ID 
 * we change our tag bits but keep the same index bits as the victim

wrap around; wanna make sure we go past the current set by a few
 * 
 * so we need that inequality because we have an issue with alignment. when we first index in, we are not sure where we are in the set. so essentially that is a modulus operator where if we ar in the middle, we go past and wrap around to finish copying it.
 * 
 *
 * set that is passed in is just the set that we r dealing with
 * high level description
 *
 * use rlly large structure to construct eviction set address
 * we just have to describe the algorithm of this below


//////////////////Alex's DESCR//////////////////
 *  First 2 lines mask off the tag bits and index bits respectivly of the base addressvalue
 *  This tells us the offset of our starting point, where we will begin our eviction set
 *
 *  We want to change our tag bits to begin the evistion set in the right place, so we can enact our attack there
 *  The last half of the addr will always be (L1_NUM_SETS * LINE_SIZE * way)) bc the index bits should be the 
 * same as the victim but our tgas should be different
 *
 *  until the set increments enough to be greater than the base index, we will add the total num sets to our tag bits
 *  once it is greater, we will just add the set
 *  This will return all the eviction set addresses, but in a wrapped around fashion due to the if condition


 */
uint64_t* get_eviction_set_address(uint64_t *base, int set, int way)
{
    uint64_t tag_bits = (((uint64_t)base) >> NUM_OFF_IND_BITS);//shifts by 6
    int idx_bits = (((uint64_t)base) >> NUM_OFFSET_BITS) & 0x3f; //shifts by 12 and get last 6

    if (idx_bits > set) {
        return (uint64_t *)((((tag_bits << NUM_INDEX_BITS) +
                               (L1_NUM_SETS + set)) << NUM_OFFSET_BITS) +
                            (L1_NUM_SETS * LINE_SIZE * way));
    } else {
        return (uint64_t *)((((tag_bits << NUM_INDEX_BITS) + set) << NUM_OFFSET_BITS) +
                            (L1_NUM_SETS * LINE_SIZE * way));
    }
}

/* This function sets up a trojan/spy eviction set using the
 * function above.  The eviction set is essentially a linked
 * list that spans all ways of the conflicting cache set.
 *
 * i.e., way-0 -> way-1 -> ..... way-7 -> NULL
 *
 * read a byte and encode it; not case sensitive
 * after encoding, trasnmit secret by making cache address by traversing eviction set (constructed already in setup function)
 * we get address then set up linked list 
 * reg linked list but every element is evict set addresst hat allows us to completely occupy all ways of an eviction set
 */
void setup(uint64_t *base, int assoc)
{
    uint64_t i, j;
    uint64_t *eviction_set_addr;

    // Prime the cache set by set (i.e., prime all lines in a set)
    for (i = 0; i < L1_NUM_SETS; i++) {
        eviction_set_addr = get_eviction_set_address(base, i, 0);
        for (j = 1; j < assoc; j++) {
            *eviction_set_addr = (uint64_t)get_eviction_set_address(base, i, j);
            eviction_set_addr = (uint64_t *)*eviction_set_addr;
        }
        *eviction_set_addr = 0;
    }
}

/* TODO:
 *
 * This function implements the trojan that sends a message
 * to the spy over the cache covert channel.  Note that the
 * message forgoes case sensitivity to maximize the covert
 * channel bandwidth.
 *
 * Your job is to use the right eviction set to mount an
 * appropriate PRIME+PROBE or FLUSH+RELOAD covert channel
 * attack.  Remember that in both these attacks, we only need
 * to time the spy and not the trojan.
 *
 * Note that you may need to serialize execution wherever
 * appropriate.
*
*use set num and traaverse eviction set
 */
void trojan(char byte)
{
    int set;
    uint64_t *eviction_set_addr;

    if (byte >= 'a' && byte <= 'z') {
        byte -= 32;
    }
    if (byte == 10 || byte == 13) { // encode a new line
        set = 63;
    } else if (byte >= 32 && byte < 96) {
        set = (byte - 32);
    } else {
        printf("pp trojan: unrecognized character %c\n", byte);
        exit(1);
    }
    //evictset_addr = evictset_addr->next
  //evictionset(set)
  *eviction_set_addr = get_eviction_set_address(trojan_array, set, 0);
  
    eviction_set_addr = (uint64_t *)*eviction_set_addr;//do this until end
    
    /* TODO:
     * Your attack code goes in here.
     * so we are gonna wanna insert watever trojan does into our eviction set address
traverse all the sets once


     */  

}

/* TODO:
 *
 * This function implements the spy that receives a message
 * from the trojan over the cache covert channel.  Evictions
 * are timed using appropriate hardware timestamp counters
 * and recorded in the eviction_counts array.  In particular,
 * only record evictions to the set that incurred the maximum
 * penalty in terms of its access time.
 *
 * Your job is to use the right eviction set to mount an
 * appropriate PRIME+PROBE or FLUSH+RELOAD covert channel
 * attack.  Remember that in both these attacks, we only need
 * to time the spy and not the trojan.
 *
 * Note that you may need to serialize execution wherever
 * appropriate.

trogan is prime and spy is probing; we populate each iteration of fore loop
time probing operations
traversing spy's own eviction set

use RDTSC start and end to time 
use CPUID for seralizing execution (so that out of order processor din't affect it)

populate eviction_counts array and record set with maximum time (initilaize max_set) --> find out which sets you incurred a miss which would be max set. 

speed up test by taking less samples or configure associativity (can reduce number to smaller number)

 */



/*
- look at all the sets one by one
- time these probing operations 
- its also traversing eviction set 
- use RDTSC start and RDSC end to time, use CPUID to keep inorder 
- populate evictions count array (it records the set with the maximum access time). You want to initizlize max set 
- find out for which of these sets you incurred a miss. 
*/
char spy()
{
    int i, max_set;
    uint64_t *eviction_set_addr;
    uint64_t max_time;

    // Probe the cache line by line and take measurements
    for (i = 0; i < L1_NUM_SETS; i++) {
      
        *eviction_set_addr = get_eviction_set_address(spy_array, i, 0);
      RDTSC(startTime);
    if(*eviction_set_addr != NULL){//finished going thro
        eviction_set_addr = (uint64_t *)*eviction_set_addr;
      
    }
    
      RDTSC(endTime);
      if((endTime-startTime) > max_time){
        max_time = (endTime-startTime);
        max_set = i;
      }
      
        /* TODO:
         * Your attack code goes in here. PROBE. TIME THESE OPS for which did we take max am of time. Thats max set
         *
         */  
        
        
    }
    eviction_counts[max_set]++;
}

int main()
{
    FILE *in, *out;
    in = fopen("transmitted-secret.txt", "r");
    out = fopen("received-secret.txt", "w");

    int j, k;
    int max_count, max_set;

    // TODO: CONFIGURE THIS -- currently, 32*assoc to force eviction out of L2
    setup(trojan_array, ASSOCIATIVITY*32);

    setup(spy_array, ASSOCIATIVITY);
    
    for (;;) {
        char msg = fgetc(in);
        if (msg == EOF) {
            break;
        }
        for (k = 0; k < SAMPLES; k++) {
          trojan(msg);
          spy();
        }
        for (j = 0; j < L1_NUM_SETS; j++) {
            if (eviction_counts[j] > max_count) {
                max_count = eviction_counts[j];
                max_set = j;
            }
            eviction_counts[j] = 0;
        }
        if (max_set >= 33 && max_set <= 59) {
            max_set += 32;
        } else if (max_set == 63) {
            max_set = -22;
        }
        fprintf(out, "%c", 32 + max_set);
        max_count = max_set = 0;
    }
    fclose(in);
    fclose(out);
}
