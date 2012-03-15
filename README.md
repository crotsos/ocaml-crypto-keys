


 ./convert.byte -k test_data/pub.pem -t PEM_PUB -p /auto/homes/cr409/scratch/code/ocaml-crypto-keys/test_data/priv.pem -a sign -K bob.crt -T PEM_CERT

DNSSEC configuration:

1) generate dnssec keys
ldns-keygen -a RSASHA1_NSEC3 -b 1024 alice.signpo.st
ldns-keygen -a RSASHA1_NSEC3 -b 1024 laptop.alice.signpo.st
ldns-keygen -a RSASHA1_NSEC3 -b 1024 bob.signpo.st
ldns-keygen -a RSASHA1_NSEC3 -b 1024 laptop.bob.signpo.st

2) insert keys in signpo.st nsd config and resign the domain:
cat K*bob.signpo.st*.key >> signpo.st
cat K*alice.signpo.st*.key >> signpo.st

 ldns-signzone signpo.st Ksignpo.st.+007+27455 Ksignpo.st.+007+17264
 cp signpo.st.signed /etc/nsd3/
 nsdc restart
 nsdc rebuild
 nsdc reload
 nsdc notify

 root@domU-12-31-39-0A-9E-56:/home/ubuntu/dnssec# dig bob.signpo.st
 DNSKEY +dnssec

 ; <<>> DiG 9.7.3 <<>> bob.signpo.st DNSKEY +dnssec
 ;; global options: +cmd
 ;; Got answer:
 ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 27773
 ;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

 ;; OPT PSEUDOSECTION:
 ; EDNS: version: 0, flags: do; udp: 4096
 ;; QUESTION SECTION:
 ;bob.signpo.st.                 IN      DNSKEY

 ;; ANSWER SECTION:
 bob.signpo.st.          3600    IN      DNSKEY  256 3 7
 AwEAAcAVwjuzHUCfFs7/U1BynkB/kGS37d3bXf8rBdeJul1F9I6nRD4m
 GyNNZOmgUis1QHxIoA5/xnI5Otsd0B3OcToie4UjFynnuibEcreT+Gea
 kxskTbSbPyW4jdxshHeQ562Y1o0DZKOhHpDoD2q3uCJieBWABG5z7hm/ TxSPBYN7
 bob.signpo.st.          3600    IN      RRSIG   DNSKEY 7 3 3600
 20120319143529 20120220143529 17264 signpo.st.
 JIrzIU6VS2CK00itxlu0BNwLcwOrEwYjUU7x/THcw+xn4NJ6smCyYhDe
 Uqgngd747pBgAe8iH1nMy4M+0sw5WeZEqfWJp6SDYQl5EzXOcROlJeLV
 oup/VIV6lpOTWp7s+EEmmSSXjJnPyb9KGLDeedplhEf2VcnRaeS0c3av JEc=
 bob.signpo.st.          3600    IN      RRSIG   DNSKEY 7 3 3600
 20120319143529 20120220143529 27455 signpo.st.
 pS1lEp5oXFE+MGLmYr2vTN7H0O+OZtMLw1zhSbudTg8yt5J0XmYovKr0
 koTcAM9hdG4FinhnSLHbfDybhDGMeHO9mB+2oVG5FeNtily4GZYxlWax
 qzrNrMAxueQJncQ+X8Yr2e3zaTMusupFvGXycgaIXhFLK5py4iNDQkgQ
 ogGlGpoiubUJM8YLQtqJ6gX1oeSSSVXdM0ox+PHzwt6YL7C4ImHGrmyI
 Tww8dIc0JsjsSdsfDNzmVjus1BS1AxVuijnidlcq3MbeRNxLrKajrNLI
 UB2ZW5dvt6fqFtvpR1iaaP3OUvl6elrUtLnVfZFhirNvw0xucU6jhlDR j65DUQ==

 3) Convert keys to pem format

 ../signpost/util/key_convert.pl
 --in_key=Klaptop.alice.signpo.st.+007+31148.private
 --in_type=dns_priv --action=transform --out_type=pem_priv
 --out_key=laptop.alice.key
 ../signpost/util/key_convert.pl
 --in_key=Kalice.signpo.st.+007+31148.private  --in_type=dns_priv
 --action=transform --out_type=pem_priv --out_key=alice.key
  ../signpost/util/key_convert.pl
  --in_key=Kbob.signpo.st.+007+05744.private  --in_type=dns_priv
  --action=transform --out_type=pem_priv --out_key=bob.key
  ../signpost/util/key_convert.pl
  --in_key=Klaptop.bob.signpo.st.+007+09779.private  --in_type=dns_priv
  --action=transform --out_type=pem_priv --out_key=laptop.bob.key

  (I am planning to integrate these operation in the perl script so we
  don't need to call openssl, but I ahven't found yet a sufficient
  certificate managing library )
  4) Generate sign requests for each entity:
  openssl req -new -subj "/C=UK/O=signpost/CN=alice.signpo.st"   -key
  alice.key -out alice.crs
  openssl req -new -subj "/C=UK/O=signpost/CN=bob.signpo.st"   -key
  bob.key -out bob.crs
  openssl req -new -subj "/C=UK/O=signpost/CN=laptop.alice.signpo.st"
  -key laptop.alice.key -out laptop.alice.crs
  openssl req -new -subj "/C=UK/O=signpost/CN=laptop.bob.signpo.st"
  -key laptop.bob.key -out laptop.bob.crs

  5) Self sign certificates
  openssl req -new -x509 -days 365 -subj
  "/C=UK/O=signpost/CN=alice.signpo.st" -key alice.key -out
  alice-alice.crt
  openssl req -new -x509 -days 365 -subj
  "/C=UK/O=signpost/CN=laptop.alice.signpo.st" -key laptop.alice.key
  -out laptop.alice-laptop.alice.crt
  openssl req -new -x509 -days 365 -subj
  "/C=UK/O=signpost/CN=bob.signpo.st" -key bob.key -out bob-bob.crt
  openssl req -new -x509 -days 365 -subj
  "/C=UK/O=signpost/CN=laptop.bob.signpo.st" -key laptop.bob.key -out
  laptop.bob-laptop.bob.crt


  5) Sign all required requests:

  openssl x509 -req -days 365 -in bob.crs -CA
  laptop.alice-laptop.alice.crt -CAkey laptop.alice.key -set_serial 01
  -out laptop.alice-bob.crt
   openssl x509 -req -days 365 -in laptop.alice.crs -CA alice-alice.crt
   -CAkey alice.key -set_serial 01 -out alice-laptop.alice.crt

   openssl x509 -req -days 365 -in alice.crs -CA
   laptop.bob-laptop.bob.crt -CAkey laptop.bob.key -set_serial 01 -out
   laptop.bob-alice.crt
   openssl x509 -req -days 365 -in laptop.bob.crs -CA bob-bob.crt -CAkey
   bob.key -set_serial 01 -out bob-laptop.bob.crt

   6) Create certificate chains:
   cat laptop.alice-laptop.alice.crt laptop.alice-bob.crt >
   laptop.alice-laptop.alice_laptop.alice-bob.crt
   cat laptop.bob-laptop.bob.crt laptop.bob-alice.crt >
   laptop.bob-laptop.bob_laptop.bob-alice.crt

   ubuntu@ip-10-80-151-227:~/openvpn-config$ cat server.conf
   port 1194
   proto udp
   dev tun

   ca laptop.alice-laptop.alice_laptop.alice-bob.crt
   cert alice-laptop.alice.crt
   key laptop.alice.key

   dh dh1024.pem

   server 10.8.1.0 255.255.255.0
   keepalive 10 120
   client-to-client
   comp-lzo
   user nobody
   group nobody
   persist-key
   persist-tun
   status openvpn-status.log
   verb 4

   ubuntu@ip-10-80-151-227:~/openvpn-config$ cat client.conf
   client
   dev tun
   proto udp
   remote 127.0.0.1 1194

   resolv-retry infinite
   nobind

   persist-key
   persist-tun
   pull


   ca laptop.bob-laptop.bob_laptop.bob-alice.crt
   cert bob-laptop.bob.crt
   key laptop.bob.key

   tls-exit

   comp-lzo

   Constricting keys using the DNSSEC chain:
   ----------------------------------------------------------------------

   In this case I will cover the required steps from the perspective of
   laptop.alice. I am assuming that alice has access to alice.key and
   alice-laptop.alice.crt. In this case I will describe the steps in
   order to construct  laptop.alice-laptop.alice_laptop.alice-bob.crt.

   1) Fetch bob's public key:
   ../../signpost/util/key_convert.pl --in_name=bob.signpo.st
   --in_type=dns_pub --action=transform --out_type=pem_pub
   --out_key=bob.pub

   2) fetch bob's public key, and sign it using the key of laptop.alice.signpo.st:
    ../../signpost/util/key_convert.pl --in_name=bob.signpo.st
    --in_ca_priv=../laptop.alice.key
    --in_ca_cert=../laptop.alice-laptop.alice.crt
    --in_ca_priv=../laptop.alice.key --in_type=dns_pub --action=sign
    --out_type=pem_cert --out_key=laptop.alice-bob.crt
    --out_subj="C=UK;O=signpost;CN=bob.signpo.st;"

    the final key can be used to replace the existing laptop.alice-bob.crt
