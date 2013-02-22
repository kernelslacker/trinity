#ifndef _RANDOM_H
#define _RANDOM_H 1

extern unsigned int seed;
unsigned int init_seed(unsigned int seed);
void set_seed(unsigned int pidslot);
void reseed(void);

#endif	/* _RANDOM_H */
