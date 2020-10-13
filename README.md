
# Netlogon CFB8 considered harmful

Test for ZeroLogon behavior in which CFB-8 goes into an incredibly interesting and exploitable behavior  when IV = 0 and P = 0.

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

# Example output when finding a key triggering the issue

```
Key = 3B43002743F7ABBA21BCD2CA2A88517D
i=0 s=00000000000000000000000000000000 intermediate=AES(s)=00710FEC9D1D6431C1CA8E58E8BCF654 c=00
i=1 s=00000000000000000000000000000000 intermediate=AES(s)=00710FEC9D1D6431C1CA8E58E8BCF654 c=00
i=2 s=00000000000000000000000000000000 intermediate=AES(s)=00710FEC9D1D6431C1CA8E58E8BCF654 c=00
i=3 s=00000000000000000000000000000000 intermediate=AES(s)=00710FEC9D1D6431C1CA8E58E8BCF654 c=00
i=4 s=00000000000000000000000000000000 intermediate=AES(s)=00710FEC9D1D6431C1CA8E58E8BCF654 c=00
i=5 s=00000000000000000000000000000000 intermediate=AES(s)=00710FEC9D1D6431C1CA8E58E8BCF654 c=00
i=6 s=00000000000000000000000000000000 intermediate=AES(s)=00710FEC9D1D6431C1CA8E58E8BCF654 c=00
i=7 s=00000000000000000000000000000000 intermediate=AES(s)=00710FEC9D1D6431C1CA8E58E8BCF654 c=00
Netlogon CFB8 considered harmful vulnerability found - after testing 32 keys, with IV=0, P=0 on a random key, C=0 due to S stuck at S=0
```

Example of non-vulnerable key:

```
Key = F9A17B5D4C710734BFD59C74BCD5A87C
i=0 s=00000000000000000000000000000000 intermediate=AES(s)=51A1F712988ECB0F53857CE8FB4A8DA6 c=51
i=1 s=00000000000000000000000000000051 intermediate=AES(s)=35A254DEE0977119BDB6CCF42AECFC55 c=35
i=2 s=00000000000000000000000000005135 intermediate=AES(s)=D4299E6C46FA6E8F48AF43FFD7A1550C c=d4
i=3 s=000000000000000000000000005135D4 intermediate=AES(s)=D764388DDBC3E3F30EC4F6FB97454208 c=d7
i=4 s=0000000000000000000000005135D4D7 intermediate=AES(s)=AA07BFF1D02ABDA314D6C0C18E37F3A6 c=aa
i=5 s=00000000000000000000005135D4D7AA intermediate=AES(s)=7E7D2E2B8396A2AE1DD2E9EFCC488872 c=7e
i=6 s=000000000000000000005135D4D7AA7E intermediate=AES(s)=F2DD5399CB62598120A6BA77BCD9D058 c=f2
i=7 s=0000000000000000005135D4D7AA7EF2 intermediate=AES(s)=FB2E3E8F8B098B4619E802FCD169C64C c=fb
```

It doesn't trigger the issue because the first shift will copy first byte of ciphertext (that is not zero).

# References

[NakedSecurity - ZeroLogon Hacking Windows Servers with a bunch of zeros](https://nakedsecurity.sophos.com/2020/09/17/zerologon-hacking-windows-servers-with-a-bunch-of-zeros/)

[Wikipedia: Block cipher mode - CFB8](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
