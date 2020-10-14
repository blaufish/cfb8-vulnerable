
# Netlogon CFB8 considered harmful. OFB8 also.

## CFB8

Test for ZeroLogon behavior in which CFB-8 goes into an incredibly interesting and exploitable behavior  when IV = 0 and P = 0.

CFB8:

```
S0 = IV
Ci = head8( E( Si-1 ) ) xor Pi
Si = (S << 8 + Ci)
```

If head8() truncation to 8 bits returns zero, Si will be get stuck on zeros.

Some keys will trigger the all-zero S states, some will not (1/256 chance that it will).

(CFB-8 appears to be quite broken and dangerous as the IV-bytes are reused 15 times, i.e. plaintext and IV are reused a lot. 
And 128-bit cipher is reduced to an 8-bit PRF, throwing away some of the benefits of a large block cipher. 
This bug was a Microsoft implementation error, but it seems to demonstrate the underlying weirdness of the CFB8 mode)

## OFB8

OFB8 has a 1/256 chance to turn into a no-operation for a random key if IV=0.

OFB8:
```
S0 = IV
Oi = head8( E( Si-1 ) )
Ci = Oi xor Pi
Si = (S << 8 + Oi)
```


# Example output when finding a key triggering the issue

```
Key = 203D7243BE5818A91BF89F32115AD201
CFB-8: i=0 s=00000000000000000000000000000000 intermediate=AES(s)=00538BF988CD455495BEBC8A7C3DEA97 c=00
CFB-8: i=1 s=00000000000000000000000000000000 intermediate=AES(s)=00538BF988CD455495BEBC8A7C3DEA97 c=00
CFB-8: i=2 s=00000000000000000000000000000000 intermediate=AES(s)=00538BF988CD455495BEBC8A7C3DEA97 c=00
CFB-8: i=3 s=00000000000000000000000000000000 intermediate=AES(s)=00538BF988CD455495BEBC8A7C3DEA97 c=00
CFB-8: i=4 s=00000000000000000000000000000000 intermediate=AES(s)=00538BF988CD455495BEBC8A7C3DEA97 c=00
CFB-8: i=5 s=00000000000000000000000000000000 intermediate=AES(s)=00538BF988CD455495BEBC8A7C3DEA97 c=00
CFB-8: i=6 s=00000000000000000000000000000000 intermediate=AES(s)=00538BF988CD455495BEBC8A7C3DEA97 c=00
CFB-8: i=7 s=00000000000000000000000000000000 intermediate=AES(s)=00538BF988CD455495BEBC8A7C3DEA97 c=00
Netlogon CFB8 considered harmful vulnerability found - after testing 790 keys, with IV=0, P=0 on a random key, C=0 due to S stuck at S=0
```

```
Key = 1A5DCFB1CFC70A938825EF124C34DF5E
OFB-8: i=0 s=00000000000000000000000000000000 intermediate=AES(s)=0075E674CD5B8C10ABF5A83A95F3AC11 c=00
OFB-8: i=1 s=00000000000000000000000000000000 intermediate=AES(s)=0075E674CD5B8C10ABF5A83A95F3AC11 c=00
OFB-8: i=2 s=00000000000000000000000000000000 intermediate=AES(s)=0075E674CD5B8C10ABF5A83A95F3AC11 c=00
OFB-8: i=3 s=00000000000000000000000000000000 intermediate=AES(s)=0075E674CD5B8C10ABF5A83A95F3AC11 c=00
OFB-8: i=4 s=00000000000000000000000000000000 intermediate=AES(s)=0075E674CD5B8C10ABF5A83A95F3AC11 c=00
OFB-8: i=5 s=00000000000000000000000000000000 intermediate=AES(s)=0075E674CD5B8C10ABF5A83A95F3AC11 c=00
OFB-8: i=6 s=00000000000000000000000000000000 intermediate=AES(s)=0075E674CD5B8C10ABF5A83A95F3AC11 c=00
OFB-8: i=7 s=00000000000000000000000000000000 intermediate=AES(s)=0075E674CD5B8C10ABF5A83A95F3AC11 c=00
OFB8 attack also vulnerable to same sample - after testing 166 keys, with IV=0, P=0 on a random key, C=0 due to S stuck at S=0

```

# example of output on keys not vulnerable:

Example of non-vulnerable key:

```
Key = 01B3E2A90EAB80B7101F4DAC987720E2
CFB-8: i=0 s=00000000000000000000000000000000 intermediate=AES(s)=A459A4B512BC800F91DDB4799781E1EA c=a4
CFB-8: i=1 s=000000000000000000000000000000A4 intermediate=AES(s)=78AEA90D0520AB38AE7E94DAC36BB786 c=78
CFB-8: i=2 s=0000000000000000000000000000A478 intermediate=AES(s)=13198B38F3AFB723DA6A065A5398188F c=13
CFB-8: i=3 s=00000000000000000000000000A47813 intermediate=AES(s)=50C8FB6EC74B458721C54ED8CA8DE865 c=50
CFB-8: i=4 s=000000000000000000000000A4781350 intermediate=AES(s)=E85DD6542E4D090676D6B2DFCA207241 c=e8
CFB-8: i=5 s=0000000000000000000000A4781350E8 intermediate=AES(s)=C8CC9F117676E0DF1A624B12C098D42A c=c8
CFB-8: i=6 s=00000000000000000000A4781350E8C8 intermediate=AES(s)=2C9273560CE67E72152BBA38A814B192 c=2c
CFB-8: i=7 s=000000000000000000A4781350E8C82C intermediate=AES(s)=1D917A75388931BF6FE9ED389EE002E2 c=1d
```

It doesn't trigger the issue because the first shift will copy first byte of ciphertext (that is not zero).

```
Key = 27583526CBEB582F9520C74B48A165B8
OFB-8: i=0 s=00000000000000000000000000000000 intermediate=AES(s)=EE8934E785A40F56B53882CF6E8705B3 c=ee
OFB-8: i=1 s=000000000000000000000000000000EE intermediate=AES(s)=AD84A86AAD475A4EE18F2D4168C06AAC c=ad
OFB-8: i=2 s=0000000000000000000000000000EEAD intermediate=AES(s)=38A1613E4B8F4E9B4D60993C39C9E345 c=38
OFB-8: i=3 s=00000000000000000000000000EEAD38 intermediate=AES(s)=FFD86B7A6FB9469AFE6D838BAF3715D4 c=ff
OFB-8: i=4 s=000000000000000000000000EEAD38FF intermediate=AES(s)=FA7C5321243C19ABAE92ADAE4915893F c=fa
OFB-8: i=5 s=0000000000000000000000EEAD38FFFA intermediate=AES(s)=E56B7578A793BE67986F6B587172F74B c=e5
OFB-8: i=6 s=00000000000000000000EEAD38FFFAE5 intermediate=AES(s)=6238B5F723BDBF3BFEE308143A94FE26 c=62
OFB-8: i=7 s=000000000000000000EEAD38FFFAE562 intermediate=AES(s)=D01B9B21E023E003D32515BC99E578B1 c=d0
```

It doesn't trigger the issue because the first shift will copy first byte of output from AES(s) (that is not zero).

# Reflections

* It is funny how the details of OFB and CFB modes are pretty hidden away in text in SP800-38A instead of being properly described in an algorithm.
* It is funny how Wikipedia details CFB-8 but not OFB-8.
* It is funny how Wikipedia images of OFB and CFB are just plain wrong for truncated -8 modes. The feedback illustrated does not descibe how the algorithm works.
* I probably should dig up my old Wikipedia account and update with corrected information.

# References

[NakedSecurity - ZeroLogon Hacking Windows Servers with a bunch of zeros](https://nakedsecurity.sophos.com/2020/09/17/zerologon-hacking-windows-servers-with-a-bunch-of-zeros/)

[Wikipedia: Block cipher mode - CFB8](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)

[NIST SP800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)

[Mark Wooding: New proofs for old modes](https://eprint.iacr.org/2008/121.pdf). Has a description of OFB-8 and other truncated OFB-modes. (Wikipedia was lacking this at the time of testing.)

