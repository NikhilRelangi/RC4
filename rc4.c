#include "rc4.h"


void swap(unsigned char state[], unsigned int i, unsigned int j)
{
unsigned int tmp = state[i];
state[i] = state[j];
state[j] = tmp;
}

bool comparehash(unsigned char a[], unsigned char b[])     //COMPARES OF THE HASH FUNCTION TAKES PLACE AND DECIDES WHETHER SAME OR NOT//
{
int i;
for(i=0;i<16;i++)
{
if(a[i]!=b[i])return false;
}
return true;
}

unsigned int len (unsigned char m[], unsigned int offset)   //IF HASH FUNCTION ARE EQUAL THAN IT WILL CONSIDER THE LENGTH VALUE OF THE OFFSET //
{
unsigned int len = 0, index;
for(index=0; index<64; index++)
{
len = len + (int)m[index];
}
len = len % 256;
if (len == 0)
{
len = offset % 256;
}
return len;
}

void ksa(unsigned char state[], unsigned char key[], unsigned int keylen)  //NOW THE KSA ALGORITHM IS APPLIED //
{
unsigned int i, j = 0;
for (i=0; i<256; i++)
{
state[i] = i;
}
for (i=0; i<256; i++)
{
j = (j + state[i] + key[i % keylen]) % 256;
swap(state, i, j);
}

}

void ksa_star(unsigned char state[], unsigned char m[])            //Applied in hash function //
{
unsigned int i, j = 0;
for (i=0; i<256; i++)
{
j = (j + state[i] + m[i % 64]) % 256;
swap(state, i, j);
}
}

void prga(unsigned char state[], unsigned char output[], unsigned int messagelength, unsigned int *i, unsigned int *j)
{
unsigned int index;
for (index=0; index<messagelength; index++)
{
*i = (*i + 1) % 256;
*j = (*j + state[*i]) % 256;
swap(state, *i, *j);
output[index] = state[(state[*i] + state[*j]) % 256];
}
}

void prga_nopt(unsigned char state[], unsigned int messagelength, unsigned int *i, unsigned int *j)
{
unsigned int index;
for (index=0; index < messagelength; index++)
{
*i = (*i + 1) % 256;
*j = (*j + state[*i]) % 256;
swap(state, *i, *j);
}
}


void prga_star(unsigned char state[], unsigned int len)      //applied in hash function//
{
unsigned int i,j=0;
for (i=0; i < len; i++)
{
j = (j + state[i]) % 256;
swap(state, i, j);
}
}

void iprga(unsigned char state[], unsigned int messagelength, unsigned int *i, unsigned int *j)
{
unsigned int index;
for (index=0; index<messagelength; index++)
{
swap(state, *i, *j);
*j = (*j - state[*i]) % 256;
*i = (*i - 1) % 256;
}
}

