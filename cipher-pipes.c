#include <stdlib.h>
#include <unistd.h>

#include "cipher-pipes.h"

size_t cipherPipesSize = 0;
int * cipherPipes = NULL;

void
repack()
{
	size_t i = 0;
	size_t j = 0;
	for (; i < cipherPipesSize; i++) {
		if (cipherPipes[i] != -1)
			continue;
		if (j < i)
			j = i;
		for (; j < cipherPipesSize; j++) {
			if (cipherPipes[j] == -1)
				continue;
			cipherPipes[i] = cipherPipes[j];
			cipherPipes[j] = -1;
			break;
		}
	}
	if (cipherPipesSize > 0 && cipherPipes[0] == -1) {
		free(cipherPipes);
		cipherPipes = NULL;
		cipherPipesSize = 0;
	}
}

int
allocCipherPipeSpace(size_t numNewPipes)
{
	if ((cipherPipesSize == 0) != (cipherPipes == NULL))
		return 1;

	size_t count = 0;
	for (size_t i = 0; i < cipherPipesSize; i++)
		if (cipherPipes[i] != -1)
			count++;
	if (cipherPipesSize < count + numNewPipes) {
		size_t delta = count + numNewPipes - cipherPipesSize;
		int * newptr = realloc(cipherPipes,
		    (cipherPipesSize + delta) * sizeof(int));
		if (newptr == NULL)
			return 1;
		cipherPipes = newptr;
		for (size_t i = 0; i < delta; i++)
			cipherPipes[cipherPipesSize + i] = -1;
		cipherPipesSize += delta;
	}
	return 0;
}

int
addCipherPipe(int p)
{
	for (size_t i = 0; i < cipherPipesSize; i++)
		if (cipherPipes[i] == -1) {
			cipherPipes[i] = p;
			return 0;
		}
	return 1;
}

void
delCipherPipe(int p)
{
	for (size_t i = 0; i < cipherPipesSize; i++)
		if (cipherPipes[i] == p) {
			cipherPipes[i] = -1;
			repack();
			return;
		}
}

int
closeCipherPipes()
{
	int ret = 0;
	for (size_t i = 0; i < cipherPipesSize; i++)
		if (cipherPipes[i] != -1)
			if (close(cipherPipes[i]) == -1)
				ret = 1;
	return ret;
}
