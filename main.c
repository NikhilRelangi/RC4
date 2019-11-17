#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>

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




char arr[8192]={0};
unsigned char key[256];
int tm = 0;
unsigned char **mes;

int tests[] = {0,1,2,3};
                                             //RC4 -BHF HASH FUNCTION//

void hash (unsigned char plaintext[], unsigned char Hvalue[], unsigned int offset)
{
unsigned char state[256], state2[256], op_stream[256];
unsigned int messagelength = 0, index, total_msg = 0, zerolen, x, y;
unsigned char **m;

messagelength = strlen((char*)plaintext);

total_msg = (messagelength + 3) / 252;
if ((messagelength + 3) % 252 != 0)
{
total_msg = total_msg + 1;
}


zerolen = 252 * total_msg - messagelength - 3;

m = (unsigned char **)malloc(total_msg*sizeof(unsigned char*));
for (index=0; index<total_msg; index++)
{
m[index]=(unsigned char *)malloc(252*sizeof(unsigned char));             //PADDING AND DIVIDING PROCESS//
}
if (((252*total_msg)-messagelength) == 254)
{
for(x=0; x<(total_msg-2); x++)
{
for(y=0; y<252; y++)
{
m[x][y] = plaintext[252*x+y];
}
}
for(y=0; y<250; y++)
{
m[total_msg-2][y] = plaintext[64*(total_msg-2)+y];
}
m[total_msg-2][250]= 0x80;
m[total_msg-2][251]= 0x00;
for(y=0; y<250; y++)
{
m[total_msg-1][y] = 0x00;
}
m[total_msg-1][250]=messagelength>>8;
m[total_msg-1][251]=messagelength&~(0xFF<<8);
}
else if (((252*total_msg)-messagelength) == 253)
{
for(x=0; x<(total_msg-2); x++)
{
for(y=0; y<252; y++)
{
m[x][y] = plaintext[252*x+y];
}
}
for(y=0; y<251; y++)
{
m[total_msg-2][y] = plaintext[252*(total_msg-2)+y];
}
m[total_msg-2][251]= 0x80;
for(y=0; y<250; y++)
{
m[total_msg-1][y] = 0x00;
}
m[total_msg-1][250]=messagelength>>8;
m[total_msg-1][251]=messagelength&~(0xFF<<8);
}
else
{
for(x=0; x<(total_msg-1); x++)
{
for(y=0; y<252; y++)
{
m[x][y] = plaintext[64*x+y];
}
}
for(y=0; y<(249-zerolen); y++)
{
m[total_msg-1][y] = plaintext[252*(total_msg-1)+y];
}
m[total_msg-1][251-zerolen] = 0x80;
for(y=(62-zerolen); y<250; y++)
{
m[total_msg-1][y] = 0x00;
}
m[total_msg-1][250]=messagelength>>8;
m[total_msg-1][251]=messagelength&~(0xFF<<8);
}
ksa(state, m[0], 252);                                                    //COMPRESSION OF RC4 BEGINS//
prga_star(state, offset);
prga_star(state, len(m[0], offset));
if (total_msg > 1)
{
for (index=1; index < total_msg; index++)
{
ksa_star(state, m[index]);
prga_star(state, len(m[index], offset));
}
}

ksa(state2, state, 256);
x=0;
y=0;
prga_nopt(state2, 256, &x, &y);
prga(state2, op_stream, 256, &x, &y);
for(index=0; index<256; index++)
{
op_stream[index] = op_stream[index] ^ state[index];
}

for (index=0; index<32; index++)
{
Hvalue[index] = 0;
}
for (index=0; index<256; index++)
{
int bucket = index/8;
int offset = index%8;
unsigned char flag = (op_stream[index]&0x01)<<(7-offset);
Hvalue[bucket] = Hvalue[bucket] + flag;
}

for (index=0; index<16; index++)
{
Hvalue[index] = 0;
}
for (index=0; index<256; index=index+2)
{
int bucket = index/16;
int offset = (index%16)/2;
unsigned char flag = (op_stream[index]&0x01)<<(7-offset);
Hvalue[bucket] = Hvalue[bucket] + flag;
}

for (index=0; index<16; index++)
{
Hvalue[index] = 0;
}
for (index=1; index<256; index=index+2)
{
int bucket = index/16;
int offset = ((index-1)%16)/2;
unsigned char flag = (op_stream[index]&0x01)<<(7-offset);
Hvalue[bucket] = Hvalue[bucket] + flag;
}
}

void sender(unsigned char *input, unsigned char *data)
{
unsigned int messagelength = 0, total_msg = 0, offset = 100, keylen, tmp, index, x, y , i, j;
unsigned char Hinput[252];
unsigned char Hvalue[16];
unsigned char state[256];

unsigned char keystream[268];
messagelength = strlen(input);
keylen = sizeof(key) - 1;
ksa(state,key,keylen);
total_msg = messagelength / 252;
if (messagelength % 252 != 0)
{
total_msg = total_msg + 1;
}
prga_nopt(state, offset, &i, &j);
memcpy(arr, input, messagelength + 1);
for(x=0; x<total_msg; x++)
{
tmp=x;
if(x==(total_msg-1))tmp+=0x8000;
data[data_length*x]=((tmp&0xFF00)>>8);
data[data_length*x+1]=(tmp&0xFF);
for(y=0; y<252; y++)
{
if((252*x+y)<messagelength)
{
data[data_length*x+2+y]= *input++;
}
else if((252*x+y)==messagelength)
{
data[data_length*x+2+y]=0x8;
}
else
{
data[data_length*x+2+y]=0x7F;
}
}
for(index=0; index<254; index++)
{
Hinput[index] = data[data_length*x+index];
}
hash(Hinput, Hvalue, offset);
for(index=0; index<16; index++)
{
data[data_length*x+254+index]=Hvalue[index];
}

printf("\nHash value: ");
for (index=0; index<16; index++)
{
printf("%X ", Hvalue[index]);
}
printf("\n");

prga(state, keystream, 268, &i, &j);
printf("Keystream: ");
for(index=0;index<268;index++)
{
data[data_length*x+2+index] = keystream[index] ^ data[data_length*x+2+index];
printf("%x ", keystream[index]);
}
printf("\n");
}

}
void receiver(unsigned char *data, unsigned char *output)
{
unsigned int messagelength = 0, total_msg = 0, offset = 100, keylen, index, x, y , i, j;
unsigned char Hinput[254];
unsigned char recvhash[16];
unsigned char calhash[16];
unsigned char state[256];

unsigned char keystream[250];

keylen = sizeof(key) - 1;
ksa(state,key,keylen);
prga_nopt(state, offset, &i, &j);

mes = calloc(10, sizeof(char*));
for (i=0; i <= tm; i++)
{
    mes[i] = calloc(253, sizeof(char));
    memcpy(mes[i], (arr + (252 * i)), 252);
}

printf("\n\n\nRECEIVER\n\n\n");
for(x=0; ; x++)
{
prga(state, keystream, 250, &i, &j);
for(index=0;index<250;index++)
{
data[data_length*x+2+index] = keystream[index] ^ data[data_length*x+2+index];
}
for(index=0;index<16;index++)
{
recvhash[index]=data[data_length*x+index+48];
}
for(index=0; index<254; index++)
{
Hinput[index] = data[data_length*x+index];
}
hash(Hinput, calhash, offset);

if (comparehash(calhash,recvhash))
{
for(y=0; y<254; y++)
{
if(data[x*data_length+2+y]!=0x8)*output++=data[x*data_length+2+y];
else break;
}
}
messagelength+=252;
if(data[data_length*x]&0x80)break;
}
*output='\0';
}

void main()
{
    unsigned char plaintext[8000];
    unsigned char *m;
    unsigned int messagelength;
    unsigned int total_msg = 0, index;
    unsigned char *output_str;

    int offset, i, tv;

    printf("Enter plaintext\n");
    fgets(plaintext, 8000, stdin);

    printf("Enter key\n");
    fgets(key, 256, stdin);

    printf("Enter offset\n");
    scanf("%d", &offset);

    offset = offset % 16;

    //printf("offset mod16 = %d\n", offset);
    printf("Enable tests: ");
    scanf("%d", &tv);

    messagelength = strlen((char*)plaintext);
    output_str=(unsigned char *)malloc(messagelength*sizeof(unsigned char));

    total_msg = messagelength / 252;
    tm = total_msg;
    if (messagelength % 252 != 0)
    {
    total_msg = total_msg + 1;
    }
    m = (unsigned char *)malloc(total_msg*272*sizeof(unsigned char)+1);
    sender(plaintext, m);
    receiver(m, output_str);


    printf("\nThe recovered message is :");
    for (i=0; i <= tm; i++)
    {
        if (tv ==1) {
            printf("Data-%d: %s\n\n",tests[i], mes[tests[i]]);
        } else {
            printf("Data-%d: %s\n\n",i, mes[i]);
        }
    }
}

