INTRODUCTION
------------

Handling public key cryptography keys is a hard job. This library provides the ability to 
transform keys between the different storage types. 

Supported file type include:
 - DNS_PUB: fetch the DNSKEY record of a specific dns domain.
 - PEM_PUB, PEM_PRIV, PEM_CERT: handling PEM formatted public and private keys.
 - DNS_PRIV: Read private key format files containing private key information. This type is 
             widely used by DNSSEC software in order to sign zones. 

LIMITATIONS
-----------

Current version of the library supports only RSA cryptography. Further some transformation cases
are not yet supported. 

COMPILATION
-----------

In order to compile the ocaml-crypto-keys library , you are required to have installed the 
following ocaml libraries: cryptokit, ocaml-dns, bitstring, ocaml-getopt. 

Additionally, in order to compile the c code, you need the ssl header files too. (library tested
against libssl 0.9.8). 

The library is fully integrated with the oasis compialtion platform and provide a provide a make
file to automate the compilation mechanism. 

USAGE
-----

the library currently provides a command line front-end that allows access to the basic
functionality of the library. 

the name of the program is crypto-convert and provide the following option: 

-k, --in_key: filename of the input file
-i, --issuer: a comma separated issuer string (sign only)
-s, --cert_subj: a comma separate string to describe the subject of the certificate. (sign only)
-p, --ca_priv: the filename of the file to read the private key to sign a certification (sign only)
-t, --in_type: the type of the input file: PEM_PUB, PEM_PRIV, PEM_CERT, DNS_PUB, DNS_PRIV
-a, --action: the action performed over the key: SIGN, TRANSFORM, VERIFY
-K, --out_key: filename to save the resulting key format.
-T, --out_type: the key type of the output data. 
-D, --duration: how long is the certificate valid for. (sign only)


usage examples:

- generate a pem private key from an private key format file
ldns-keygen -a RSASHA1_NSEC3 -b 1024 alice.signpo.st
crypto-convert -k Kalice.signpo.st.+007+31148.private \
 --i DNS_PRIV -a transform -T PEM_PRIV \
 -K alice.key

 - fetch the public key from the dnssec service and store it in pem format.
crypto-convert -k bob.signpo.st -t DNS_PUB -a transform -T PEM_PUB -K bob.pub

 - sign a certificate for a public key fetch from DNSSEC: 
crypto-convert -k bob.signpo.st -p laptop.alice.key -t DNS_PUB -a sign \
    -T PEM_CERT -K laptop.alice-bob.crt -s "C=UK;O=signpost;CN=bob.signpo.st;"\
    -i  "C=UK;O=signpost;CN=laptop.alice.signpo.st;"

