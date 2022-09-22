#ifndef CIPHER_PIPES_H
#define CIPHER_PIDES_H

#include <sys/types.h>

int allocCipherPipeSpace(size_t numNewPipes);
int addCipherPipe(int p);
void delCipherPipe(int p);
int closeCipherPipes();

#endif /* CIPHER_PIPES_H */
