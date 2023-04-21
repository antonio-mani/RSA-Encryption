/*Antonio Maniscalco
 *CS427 RSA encryption proj
 *Instructor: Dr. Grant Williams
 *04/06/2022
 *To run type 'gcc -o sig rsa.c' then ./sig to run then type input
 *NOTE: In ideone when typing into stdin you have to hit enter to get new line in input
 *      cause I scan to new line initially on line 33
 *Formats:
 * Sign Mode: sign <message> 
 * Verify Mode: verify <mod> <message> <signature>
 */

#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include<string.h>
#include<time.h>
#include<stdint.h>

#define MAXSTR 512

unsigned int elfHash();
int sigSign();
int sigVerify();
uint16_t getRand();
uint32_t encDec();
int primeCheck();
int64_t inverse();

int main(int argc, char *argv[]) {
    char buff[MAXSTR], readBuff[MAXSTR], a[16], mode[16], msg[MAXSTR];;
    fgets(readBuff, MAXSTR, stdin);
    sscanf(readBuff, "%s %[^\n]", mode, msg);

    if(strcmp("sign", mode) == 0) sigSign(msg);
    else {
        uint32_t mod, sig;
        sscanf(msg, "%x %s %x", &mod, buff, &sig);
        sigVerify(mod, buff, sig);
    }    
    return(0);
}

//ELF Hash function code block pulled from: https://www.programmingalgorithms.com/algorithm/elf-hash/c/
unsigned int elfHash(char *str, unsigned int length) {
    unsigned int hash, x, i = 0;
    hash = x = 0;
    for (i = 0; i < length; str++, i++) {
        hash = (hash << 4) + (*str);
        if((x = hash & 0xF0000000L) != 0) hash ^= (x >> 24);
        hash &= ~x;
    }
    return(hash);
}

//takes in mod message and signiture and checks if the message is forged or not
int sigVerify(uint32_t mod, char *message, uint32_t sig) {
    uint32_t hashStr = elfHash(message, strlen(message)), orgMsg = encDec(sig, 65537, mod);
    if(hashStr == orgMsg) printf("Message verified!\n");
    else printf("Message forged!\n");
    return(0);
} 

//takes in message hashes, gets primes, totients, mod and encrypts
int sigSign(char *message) {
    //set seed and assign values
    //p,q are our primes, e is our private key, n is our mod, totient and signedHash(self explanitory)
    unsigned int hashMsg = elfHash(message, strlen(message));
    srand(time(NULL));
    uint16_t p = getRand(), q = getRand();
    int64_t x, e;
    uint32_t n = p*q, totient = ((p-1) * (q-1));;
    inverse(totient, 65537, &x, &e);
    if(e < 0) e = totient + e;
    uint32_t signedHash = encDec(hashMsg, e, n);

    printf("p: %x, q: %x, n: %x, t: %x\n", p, q, n, totient);
    printf("Message hash: %x\n", hashMsg);
    printf("Private key: %llx\n", e);
    printf("Signed hash: %x\n", signedHash);
    printf("Uninverted Message to ensure integrity: %x\n", encDec(signedHash, 65537, n));
    printf("Complete output for verification:\n\t%x %s  %x\n", n, message, signedHash);
    
    return(0);
}


//random number generator uses high range of 0x8000 and 0xFFFF
uint16_t getRand() {
    unsigned int prime = 0, randNum;
    //range is random num mod ceiling-floor+1 + floor.
    //check random nums if prime using miller-rabin until prime flg is set then return the number
    while(!prime) {
        randNum = ((rand() % (65535- 32768 + 1)) + 32768);
        prime = primeCheck(randNum);
    }
    return(randNum);
}

//check prime using Miller-Rabin Primality test
//slightly adjusted from https://www.geeksforgeeks.org/primality-test-set-3-miller-rabin/ implementation
int primeCheck(int p) {
    //base line check
    if(p % 2 == 0) return(0);
    int s = p -1;
    while(s%2 == 0)
        s /= 2;
    //check for prime for 9 interations 
    for(int i = 0; i < 10; i++) {
        //get random num [2, n-2] then perform modular exponentiation on it
        unsigned int a = 2 + rand() % (p - 4), tmp = s;
        unsigned long int mod = encDec(a, tmp, p);
        //squaring mod uptil on of our conditions is not met
        if(mod == 1 || mod == p - 1) return(1);
        while(s != p-1) {
            mod = (mod * mod) % p;
            s *= 2;
            if(mod == 1) return(0);
            if(mod == p-1) return(1);
        }
    return(0);
    }
    return(0);
}

//using extended euclidian alg source: 
/*https://www.techiedelight.com/extended-euclidean-algorithm-implementation
/#:~:text=Programming%20Puzzles-,Extended%20Euclidean%20Algorithm%20%E2%80%93%20C%2C%20C%2B%2B%2C%20Java%2C%20and,gcd(a%2C%20b)%20.*/
//multiplicative inverse is y which we se the value in sigSign function
int64_t inverse(int64_t totient, int64_t pub, int64_t *x, int64_t *y){
    if(totient == 0) {
        *x = 0;
        *y = 1;
        return(pub);
    }
    int64_t _x, _y, gcd = inverse(pub%totient, totient, &_x, &_y);
    *x = _y - (pub/totient) * _x;
    *y = _x;
    if(_y < 0) _y = totient + _y;
    //gcd is irrelevant just returns 1 
    return(gcd);
}

//function for encrypting and decrypting using fast exp by spuaring
uint32_t encDec(uint64_t msg, uint64_t exp, uint32_t n) {
    uint64_t retVal = 1;
    msg = msg % n;
    //each iteration we are shifting the bits of the exp 1(dividing by 2)
    while(exp > 0) {
        //exp is odd if true otherwise it's even
        if((exp & 1)) retVal = (retVal*msg) % n;
        exp = exp >> 1;
        msg = (msg*msg) % n;
    }
    return(retVal);
}

