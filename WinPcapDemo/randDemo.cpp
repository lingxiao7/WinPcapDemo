#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int main() {
		srand((int)time(0));
	while (true) {
		int rnd[6];
		for (int i = 0; i < 6; i++) {
			rnd[i] = 1 + (int)((double)0xFF * rand() / (RAND_MAX + 1.0));
			printf("%d ", rnd[i]);
		}
	}
}