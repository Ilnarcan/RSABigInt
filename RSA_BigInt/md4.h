#ifndef MD4_H
#define MD4_H

#include <string>
using namespace std;

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a, b, c, d, x, s) { \
	(a) += F ((b), (c), (d)) + (x); \
	(a) = ROTATE_LEFT ((a), (s)); \
}
#define GG(a, b, c, d, x, s) { \
	(a) += G ((b), (c), (d)) + (x) + (unsigned int)0x5a827999; \
	(a) = ROTATE_LEFT ((a), (s)); \
}
#define HH(a, b, c, d, x, s) { \
	(a) += H ((b), (c), (d)) + (x) + (unsigned int)0x6ed9eba1; \
	(a) = ROTATE_LEFT ((a), (s)); \
}
class MD4
{
	unsigned int A;
	unsigned int B;
	unsigned int C;
	unsigned int D;
	void init();
public:
	MD4();
	string calculate( string data );
	void encrypt(const char *in, const char *out);
};
#endif 