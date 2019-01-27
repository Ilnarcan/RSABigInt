#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <ctime>
#include "md4.h"
#include "rsa.h"

using namespace std;

int main(int argc, char *argv[])
{
  srand(time(0));

  cout << "RSA Encryption/Decryption\n"; 


  try
  {
    //if (argc < 4)
     // throw commandErr();

    if (argv[1][0] == 'e')
    {
      if (argc == 4)
      {
        cryptkey publicKey, privateKey;

        ifstream test (argv[2]);
        if (!test.good())
          throw fileErr(argv[2]);
        test.close();

        cout << "Generating keys...\n";
        rsa::genKeys(publicKey, privateKey);
        publicKey.saveToFile("public_key");
        privateKey.saveToFile("private_key");

        cout << "Encrypting data...\n";
        rsa::encryptTxtFile(argv[2],argv[3], publicKey);
      }
      else

        if(argc == 5)
        {
          cryptkey publicKey;

          if (!publicKey.loadFromFile(argv[4]))
            throw fileErr(argv[4]);

          cout << "Encrypting data...\n";
          rsa::encryptTxtFile(argv[2],argv[3],publicKey);
        }
        else
          throw commandErr();
    }
    else
      if (argv[1][0] == 'g')
      {
        if (argc == 4)
        {
          cryptkey publicKey, privateKey;
          cout << "Generating keys...\n";

          rsa::genKeys(publicKey, privateKey);

          publicKey.saveToFile(argv[2]);
          privateKey.saveToFile(argv[3]);
        }
        else
          throw commandErr();
      }
      else
        if (argv[1][0] == 'd')
        {
          if (argc == 5)
          {
            cryptkey privateKey;

            if (!privateKey.loadFromFile(argv[4]))
              throw fileErr(argv[4]);

            cout << "Decrypting...\n";
            rsa::decryptTxtFile(argv[2],argv[3],privateKey);
          }
          else
            throw commandErr();
        }
	else
		if(argv[1][0] == 'h')
		{

			MD4	md4hash;

			ifstream test (argv[2]);
			if (!test.good())
			  throw fileErr(argv[2]);
			test.close();

			cout << "MD4 hash...\n";

			cout << "Encrypting data...\n";
			md4hash.encrypt(argv[2],argv[3]);

		}

  }
  catch(rsaErr &err)
  {
    cout << "Error (rsa): " << err.what() <<endl;
    return 1;
  }
  catch(mathErr &err)
  {
    cout << "Error (hugeint): " << err.what() <<endl;
    return 1;
  }
  catch(commandErr)
  {
    cout << "Usage:\n";
    cout << " e <in> <out> <public_key_path> - Encrypt data from the file <in> to <out>.\n";
    cout << "    If the key is not specified, it will be automatically\n";
    cout << "    created and saved in the current directory.\n\n";
    cout << " g <pb_key_path> <pr_key_path> - Generate keys.\n\n";
    cout << " d <in> <out> <private_key_path> - Encrypt data from the file <in> to <out>.\n"; 
  }
  catch(fileErr &err)
  {
    cout << "Error: unable to open file " << err.filename() << endl;
    return 1;
  }

  system("pause");

  return 0;
}
