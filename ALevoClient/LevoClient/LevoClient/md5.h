#ifndef md5_INCLUDED
#define md5_INCLUDED

void MD5Init(MD5_CTX *);
void MD5Update(MD5_CTX *, unsigned char *, unsigned int);
void MD5Final(unsigned char[16], MD5_CTX *);
void hmac_md5(unsigned char* text, int text_len, unsigned char* key, int key_len, unsigned char* outPut);

#endif
