
![last commit](https://img.shields.io/github/last-commit/groland11/pem-scan.svg)
![release date](https://img.shields.io/github/release-date/groland11/pem-scan.svg)
![languages](https://img.shields.io/github/languages/top/groland11/pem-scan.svg)
![license](https://img.shields.io/github/license/groland11/pem-scan.svg)

# pem-scan
Check single file or directory for one or more X509 PEM certificates and show certificate details.


## Usage
```
./pem-scan.py -h
usage: pem-scan.py [-h] [-e EXPIRES] [-d] [-v] [-V] filename

Script description

positional arguments:
  filename              file or directory containing onw or more x509 certificates in PEM format

optional arguments:
  -h, --help            show this help message and exit
  -e EXPIRES, --expires EXPIRES
                        check if certificate expires in n days or less
  -q, --quiet           only display error messages
  -d, --debug           generate additional debug information
  -v, --verbose         increase output verbosity
  -V, --version         show program's version number and exit
```

## Examples
1. Scan the file ca-certificates.crt, which contains a long list of trusted CA certificates.
- In the output, the first column is the line number, followed by the Common Name (CN) or - if not present - Organisational Unit (OU) of the certificate subject.
- We also check if there are any CA certificates that will expire within the next year.
- You can not only see very clearly which certificates will expire, but also the line number where the certificate is stored in the file.
```
$ pem-scan.py -e 365 /etc/ssl/certs/ca-certificates.crt

/etc/ssl/certs/ca-certificates.crt
    1: ACCVRAIZ1
   45: AC RAIZ FNMT-RCM
   77: Actalis Authentication Root CA
  110: AffirmTrust Commercial
  130: AffirmTrust Networking
  150: AffirmTrust Premium
  181: AffirmTrust Premium ECC
  194: Amazon Root CA 1
  214: Amazon Root CA 2
  245: Amazon Root CA 3
  257: Amazon Root CA 4
  270: Atos TrustedRoot 2011
  291: Autoridad de Certificacion Firmaprofesional CIF A62634068
  326: Baltimore CyberTrust Root
  347: Buypass Class 2 Root CA
  378: Buypass Class 3 Root CA
  409: CA Disig Root R2
  440: CFCA EV ROOT
  472: COMODO Certification Authority
  497: COMODO ECC Certification Authority
  513: COMODO RSA Certification Authority
  547: Certigna
  569: Certum Trusted Network CA
  591: Certum Trusted Network CA 2
  625: Chambers of Commerce Root - 2008
  667: AAA Certificate Services
  692: Cybertrust Global Root
ERROR: FAIL: Certificate expires in 258 days (2021-12-15)
ERROR: Failed checks for Cybertrust Global Root (/etc/ssl/certs/ca-certificates.crt)
  714: D-TRUST Root Class 3 CA 2 2009
  739: D-TRUST Root Class 3 CA 2 EV 2009
  764: DST Root CA X3
ERROR: FAIL: Certificate expires in 182 days (2021-09-30)
ERROR: Failed checks for DST Root CA X3 (/etc/ssl/certs/ca-certificates.crt)
  784: DigiCert Assured ID Root CA
  806: DigiCert Assured ID Root G2
  828: DigiCert Assured ID Root G3
  843: DigiCert Global Root CA
  865: DigiCert Global Root G2
  887: DigiCert Global Root G3
  902: DigiCert High Assurance EV Root CA
  925: DigiCert Trusted Root G4
  957: E-Tugra Certification Authority
  993: EC-ACC
 1024: Entrust.net Certification Authority (2048)
 1049: Entrust Root Certification Authority
 1076: Entrust Root Certification Authority - EC1
 1094: Entrust Root Certification Authority - G2
...
```

2. Same check, this time only display check errors by using the -q option.
```
$ pem-scan.py -e 365 -q /etc/ssl/certs/ca-certificates.crt
/etc/ssl/certs/ca-certificates.crt
ERROR: FAIL: Certificate expires in 258 days (2021-12-15)
ERROR: Failed checks for Cybertrust Global Root (/etc/ssl/certs/ca-certificates.crt)
ERROR: FAIL: Certificate expires in 182 days (2021-09-30)
ERROR: Failed checks for DST Root CA X3 (/etc/ssl/certs/ca-certificates.crt)
```
