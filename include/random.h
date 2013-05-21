#ifndef _RANDOM_H
#define _RANDOM_H 1

extern unsigned int seed;
unsigned int init_seed(unsigned int seed);
void set_seed(unsigned int pidslot);
void reseed(void);
unsigned int new_seed(void);

unsigned int rand_bool(void);
unsigned int rand_single_32bit(void);
unsigned long rand_single_64bit(void);
unsigned int rand32(void);
unsigned long rand64(void);

#endif	/* _RANDOM_H */
