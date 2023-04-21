# RSA-Encryption

## Description 
Simplified version of RSA encrytion developed in C that is for digital signatures rather than encrypted key-sharing. Program has two modes "sign" and "verify". Input comes from stdin.

### Two Modes
sig sign "message text"
sig verify <modulus_n> "message text" <message_signature>

### Sign Mode
Program will generate two random primes, 'p' and 'q'(16-bits each, chosen from the range 0x8000-0xFFFF), a modulus(32-bits), and a totient(randomly generated with Euler's totient). Then, given the decryption key, which will be 65,537 (public), and the totient, the program will compute an encryption key 'e'. Which is the private key. Program first hashes the message using ELFhash then encrypted with the encryption key 'e', giving the digital signature. Digital signature can be verified by hashing the same text with the same algorithm, and comparing the resulting number to the decryption of signature with the key 65,537.

### Verify Mode
The program will read <modulus> "<message>" <signature> from standard input and will print "message verified!" if the signature matches a hash computed from the message in the given modulus. If it does not, print the message "!!! message is forged !!!"

## Running Program
```
gcc -o sig rsa.c
```
### Sign Mode
```
./rsa
```
When Prompted: 
```
sign <message>
```

### Verify Mode
```
./rsa
```
When Promted:
```
verify <mod> <message> <signature>
```
