#include "md4.h"
#include "cryptkey.h"
#include <string>
#include <iostream>

#define KEYLENGTH 80


using namespace std;
void MD4::init()
{
	this->A = 0x67452301;
	this->B = 0xefcdab89;
	this->C = 0x98badcfe;
	this->D = 0x10325476;
}
MD4::MD4()
{
	this->init();
}

void MD4::encrypt(const char *in, const char *out)
{

  string buff;

  ifstream input (in);
  if (!input.good())
    throw rsaErr("unable to open input file");

	FILE* pFile = fopen(out, "wt");

  while (!input.eof())
  {
    buff.clear();

    for (int i = 0; i < (KEYLENGTH-4)/3; i++)
    {
      char bf = input.get();
      if (input.eof())
        break;
      buff += bf;
    }

  }
	
  MD4	md4hash;
  
	string hstr;
	hstr = md4hash.calculate( buff );
	for( int i = 0; i < hstr.length(); i++ )
		  fprintf(pFile, "%x",(unsigned char)hstr[i]);

	cout << '\n' << endl;

	fclose(pFile);

  input.close();
}


string MD4::calculate( string data )
{
	long long int		len = data.length()*8;
	unsigned int		add_on;
	char				*ptr = (char*)&len;
	unsigned int		x[16];
	unsigned int		a,b,c,d;
	unsigned char		z = 128;
	string				ret;

	this->init();

	// дописываем в коннец данных 1
	data.push_back( z );
	// дополняем нулевыми битами до 448 по модулю 512
	add_on = 56 - ( data.length() % 64 );
	data.append( add_on, 0 );
	// дописываем длинну сообщения 
	for( int i = 0; i < 8; i++ )
		data.push_back( ((char*)&len)[ i ] );

	if( data.length() % 64 )
		return ret += "error";   
	for( int i = 0; i < data.length()/64; i++ )
	{
		a = A;
		b = B;
		c = C;
		d = D;
		for( int j = 0; j < 16; j++ )
		{
			x[j] = (unsigned char)data[ i*64 + j*4 ];
			x[j] += (unsigned char)data[ i*64 + j*4 + 1 ] << 8;
			x[j] += (unsigned char)data[ i*64 + j*4 + 2 ] << 16;
			x[j] += (unsigned char)data[ i*64 + j*4 + 3 ] << 24;
		}
		/* FF(a,b,c,d, k, s) =>  a = (a + F(b,c,d) + X[k]) <<< s. */
		FF (a, b, c, d, x[0],  3);	/* 1 */
		FF (d, a, b, c, x[1],  7);	/* 2 */
		FF (c, d, a, b, x[2],  11);	/* 3 */
		FF (b, c, d, a, x[3],  19);	/* 4 */
		FF (a, b, c, d, x[4],  3);	/* 5 */
		FF (d, a, b, c, x[5],  7);	/* 6 */
		FF (c, d, a, b, x[6],  11);	/* 7 */
		FF (b, c, d, a, x[7],  19);	/* 8 */
		FF (a, b, c, d, x[8],  3);	/* 9 */
		FF (d, a, b, c, x[9],  7);	/* 10 */
		FF (c, d, a, b, x[10], 11); /* 11 */
		FF (b, c, d, a, x[11], 19); /* 12 */
		FF (a, b, c, d, x[12], 3);	/* 13 */
		FF (d, a, b, c, x[13], 7);	/* 14 */
		FF (c, d, a, b, x[14], 11); /* 15 */
		FF (b, c, d, a, x[15], 19); /* 16 */
		/* GG(a,b,c,d, k, s) => a = (a + G(b,c,d) + X[k] + 5A827999) <<< s. */
		GG (a, b, c, d, x[0], 3);	/* 17 */
		GG (d, a, b, c, x[4],   5);	/* 18 */
		GG (c, d, a, b, x[8],  9);	/* 19 */
		GG (b, c, d, a, x[12], 13); /* 20 */
		GG (a, b, c, d, x[1],  3);	/* 21 */
		GG (d, a, b, c, x[5],  5);	/* 22 */
		GG (c, d, a, b, x[9],  9);	/* 23 */
		GG (b, c, d, a, x[13], 13); /* 24 */
		GG (a, b, c, d, x[2],  3);	/* 25 */
		GG (d, a, b, c, x[6],  5);	/* 26 */
		GG (c, d, a, b, x[10], 9);	/* 27 */
		GG (b, c, d, a, x[14], 13); /* 28 */
		GG (a, b, c, d, x[3],  3);	/* 29 */
		GG (d, a, b, c, x[7],  5);	/* 30 */
		GG (c, d, a, b, x[11], 9);	/* 31 */
		GG (b, c, d, a, x[15], 13); /* 32 */
		/* HH(a,b,c,d, k, s) => a = (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s. */
		HH (a, b, c, d, x[0],  3);		/* 33 */
		HH (d, a, b, c, x[8],  9);		/* 34 */
		HH (c, d, a, b, x[4],  11);		/* 35 */
		HH (b, c, d, a, x[12], 15);		/* 36 */
		HH (a, b, c, d, x[2],  3);		/* 37 */
		HH (d, a, b, c, x[10], 9);		/* 38 */
		HH (c, d, a, b, x[6],  11);		/* 39 */
		HH (b, c, d, a, x[14], 15);		/* 40 */
		HH (a, b, c, d, x[1],  3);		/* 41 */
		HH (d, a, b, c, x[9],  9);		/* 42 */
		HH (c, d, a, b, x[5],  11);		/* 43 */
		HH (b, c, d, a, x[13], 15);		/* 44 */
		HH (a, b, c, d, x[3],  3);		/* 45 */
		HH (d, a, b, c, x[11], 9);		/* 46 */
		HH (c, d, a, b, x[7],  11);		/* 47 */
		HH (b, c, d, a, x[15], 15);		/* 48 */
		
		A += a;
		B += b;
		C += c;
		D += d;

	}


	ret.push_back( ((char*)&A)[0] );
	ret.push_back( ((char*)&A)[1] );
	ret.push_back( ((char*)&A)[2] );
	ret.push_back( ((char*)&A)[3] );
	ret.push_back( ((char*)&B)[0] );
	ret.push_back( ((char*)&B)[1] );
	ret.push_back( ((char*)&B)[2] );
	ret.push_back( ((char*)&B)[3] );
	ret.push_back( ((char*)&C)[0] );
	ret.push_back( ((char*)&C)[1] );
	ret.push_back( ((char*)&C)[2] );
	ret.push_back( ((char*)&C)[3] );
	ret.push_back( ((char*)&D)[0] );
	ret.push_back( ((char*)&D)[1] );
	ret.push_back( ((char*)&D)[2] );
	ret.push_back( ((char*)&D)[3] );
	
	return ret;
}
