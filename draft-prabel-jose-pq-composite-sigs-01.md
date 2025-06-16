---

###
title: "PQ/T Hybrid Composite Signatures for JOSE and COSE"
abbrev: "JOSE/COSE Composite Signatures"
category: std

docname: draft-prabel-jose-pq-composite-sigs-01
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: Security
workgroup: JOSE
keyword:
 - JOSE
 - COSE
 - PQC
 - ML-DSA
 - Signature
 - Hybrid
venue:
  group: Javascript Object Signing and Encryption
  type: Working Group
  mail: jose@ietf.org
  arch: https://mailarchive.ietf.org/arch/browse/jose/
  github: lucasprabel/draft-jose-pq-composite-sigs
  latest: https://example.com/LATEST

author:
 -  ins: L. Prabel
    fullname: Lucas Prabel
    organization: Huawei
    email: lucas.prabel@huawei.com
 -  ins: S. Sun
    fullname: Sun Shuzhou
    organization: Huawei
    email: sunshuzhou@huawei.com
 -  ins: J. Gray
    fullname: John Gray
    organization: Entrust Limited
    abbrev: Entrust
    email: john.gray@entrust.com

normative:
 RFC2119:
 RFC7515:
 RFC7517:
 RFC7518:
 RFC7638:
 RFC9679:
 IANA.JOSE:
   title: "JSON Object Signing and Encryption (JOSE)"
   date: ~
   author:
      org: IANA
   target: https://www.iana.org/assignments/jose/jose.xhtml
 IANA.COSE:
   title: "CBOR Object Signing and Encryption (COSE)"
   date: ~
   author:
      org: IANA
   target: https://www.iana.org/assignments/cose/cose.xhtml

informative:
 RFC9053:
 RFC9054:
 I-D.draft-ietf-lamps-pq-composite-sigs: COMPOSITE-LAMPS
 I-D.draft-ietf-pquip-pqt-hybrid-terminology: HYB-TERMINO
 I-D.draft-ietf-pquip-hybrid-signature-spectrums: HYB-SIG-SPECTRUMS
 I-D.draft-ietf-cose-dilithium: COSE-MLDSA

 FIPS.204:
    title: "Module-Lattice-Based Digital Signature Standard"
    date: August 2024
    author:
      org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf

--- abstract

This document describes JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE) serializations for PQ/T hybrid composite signatures. The composite algorithms described combine ML-DSA as the post-quantum component and ECDSA as the traditional component.

--- middle

# Introduction

The impact of a potential Cryptographically Relevant Quantum Computer (CRQC) on algorithms whose security is based on mathematical problems such as integer factorisation or discrete logarithms over finite fields or elliptic curves raises the need for new algorithms that are perceived to be secure against CRQC as well as classical computers. Such algorithms are called post-quantum, while algorithms based on integer factorisation or discrete logarithms are called traditional.

While switching from a traditional algorithm to a post-quantum one intends to strengthen the security against an adversary possessing a quantum computer, the lack of maturing time of post-quantum algorithms compared to traditional algorithms raises uncertainty about their security. 

Thus, the joint use of a traditional algorithm and a post-quantum algorithm in protocols represents a solution to this problem by providing security as long as at least one of the traditional or post-quantum components remains secure.

This document describes JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE) serializations for hybrid composite signatures. The composite algorithms described combine ML-DSA as the post-quantum component and ECDSA as the traditional component.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document follows the terminology for post-quantum hybrid schemes defined in {{-HYB-TERMINO}}.

This section recalls some of this terminology, but also adds other definitions used throughout the whole document:

"Asymmetric Traditional Cryptographic Algorithm":
         An asymmetric cryptographic algorithm based on integer factorisation, finite field discrete logarithms, elliptic curve discrete logarithms, or related mathematical problems. A related mathematical problem is one that can be solved by solving the integer factorisation, finite field discrete logarithm or elliptic curve discrete logarithm problem. Where there is little risk of confusion asymmetric traditional cryptographic algorithms can also be referred to as traditional algorithms for brevity.

"Post-Quantum Algorithm":
         An asymmetric cryptographic algorithm that is intended to be secure against attacks using quantum computers as well as classical computers. As with all cryptography, it always remains the case that attacks, either quantum or classical, may be found against post-quantum algorithms. Therefore it should not be assumed that just because an algorithm is designed to provide post-quantum security it will not be compromised.

"Post-Quantum Traditional (PQ/T) Hybrid Scheme":
         A multi-algorithm scheme where at least one component algorithm is a post-quantum algorithm and at least one is a traditional algorithm.

"PQ/T Hybrid Digital Signature":
         A multi-algorithm digital signature scheme made up of two or more component digital signature algorithms where at least one is a post-quantum algorithm and at least one is a traditional algorithm.

"Composite Algorithm":
          An algorithm which is a sequence of two component algorithms, as defined in {{-COMPOSITE-LAMPS}}.

"Component Algorithm":
         Each cryptographic algorithm that forms part of a cryptographic scheme.

# Composite Signature Algorithm

The structures of the composite keys and composite signatures follow an approach similar to {{-COMPOSITE-LAMPS}}. The composite design is chosen so that composite keys and signatures can be used as a drop-in replacement in JOSE / COSE object formats. This section gives some details about their construction.

## Composite Key Generation

Composite public and private keys are generated by calling the key generation functions of the two component algorithms and concatenating the keys in an order given by the registered composite algorithm.

```
Composite Public Key <- Public Key of the 1st Algorithm || Public Key of the 2nd Algorithm
```
and

```
Composite Private Key <- Private Key of the 1st Algorithm || Private Key of the 2nd Algorithm
```

For the composite algorithms described in this document (ML-DSA with ECDSA), the Key Generation process is as follows:

~~~
(pk_1, sk_1) <- ML-DSA.KeyGen()
(pk_2 = (x,y), sk_2 = d) <- ECDSA.KeyGen()

Composite Public Key <- pk_1 || pk_2 = pk_1 || x || y
Composite Private Key <- sk_1 || sk_2 = sk_1 || d
~~~

Point compression for ECDSA is not performed for the "AKP-EC" JSON Web Key Type but can be performed for the "AKP-EC2" COSE Key Type. Both key types are defined in {{sec-composite-sig-key-types}}.

In this document, unlike {{-COSE-MLDSA}} but as in {{-COSE-MLDSA}}, the ML-DSA private key MUST be a 32-bytes seed.


## Composite Sign

When signing a message M with the composite Sign algorithm, the signature combiner prepends a prefix as well as a domain separator value specific to the composite algorithm used to bind the two component signatures to the composite algorithm and achieve weak non-separability, as defined in {{-HYB-SIG-SPECTRUMS}}.

It also makes use of a pre-hash randomizer, in a similar fashion to {{-COMPOSITE-LAMPS}}, in order to address collision and second pre-image weaknesses, as well as to prevent specific attacks unique to composite signature schemes. More details about the security benefits added by the use of a pre-hash randomizer can be found in {{-COMPOSITE-LAMPS}}.

However, only the pure ML-DSA component algorithm is used internally.

A composite signature's value MUST include the randomizer and the two signature components and the two components MUST be in the same order as the components from the corresponding signing key.

A composite signature for the message M is generated by:

* computing a 32-byte randomizer r;
* computing the pre-hash of the randomizer concatenated with the message M;
* concatenating the prefix, the domain separator, a byte 0x00, the randomizer and the pre-hash;
* encoding the resulting message;
* calling the two signature component algorithms on this new message;
* concatenating the randomizer and the two output signatures.

For the composite algorithms described in this document (ML-DSA with ECDSA), the signature process of a message M is as follows:

~~~
M' <- Prefix || Domain || 0x00 || r || PH(r || M)
M' <- Encode(M')

sig_1 <- ML-DSA.Sign(sk_1, M', ctx=Domain)
sig_2 <- ECDSA.Sign(sk_2, M')

Composite Signature <- (r, sig_1, sig_2)
~~~

The prefix "Prefix" string is defined as in {{-COMPOSITE-LAMPS}} as the byte encoding of the string "CompositeAlgorithmSignatures2025", which in hex is 436F6D706F73697465416C676F726974686D5369676E61747572657332303235. It can be used by a traditional verifier to detect if the composite signature has been stripped apart.

The domain separator "Domain" is defined as the octets of the ASCII representation of the Composite Signature "alg" (algorithm) Header Parameter value. The specific values can be found in {{tab-sig-alg-oids}}.

Similarly to {{-COSE-MLDSA}} which indicates that the ctx parameter MUST be the empty string, the application context passed in to the composite signature algorithm MUST be the empty string. To align with the structure of the {{-COMPOSITE-LAMPS}} combiner, the byte 0x00 is appended in the message M' after the domain separator to indicate the context has length 0. However, a second non-empty context, defined as the domain separator, is passed down into the underlying pure ML-DSA component algorithm, to bind the Composite-ML-DSA algorithm used.

{{tab-jose-algs}} (resp. {{tab-cose-algs}}) indicates the pre-hash algorithms to use for JOSE (resp. COSE).

For JOSE (resp. COSE), M' is base64url-encoded (resp. binary encoded) before signature computations.

## Composite Verify

The Verify algorithm MUST validates a signature only if all component signatures were successfully validated.

The verification process of a signature sig is as follows:

* separate the composite public key into the component public keys;
* separate the composite signature into the randomizer and the 2 component signatures;
* compute the message M' from the message M whose signature is to be verified;
* encode the resulting message M';
* verify each component signature.

~~~
(pk_1, pk_2) <- pk
(r, sig_1, sig_2) <- sig

M' <- Prefix || Domain || 0x00 || r || PH(r || M)
M' <- Encode(M')

if not ML-DSA.Verify(pk_1, M', ctx=Domain)
    output "Invalid signature"
if not ECDSA.Verify(pk_2, M')
    output "Invalid signature"
if all succeeded, then
    output "Valid signature"
~~~

## Encoding Rules

In each combination, the byte streams of the keys are directly concatenated, and the byte streams of the signatures are directly concatenated with the randomizer r.

```
Randomizer r || Signature of the 1st Algorithm || Signature of the 2nd Algorithm
```

Since all combinations presented in this document start with the ML-DSA algorithm and the key or signature sizes are fixed as defined in {{FIPS.204}}, it is unambiguous to encode or decode a composite key or signature.

{{tab-ml-dsa-size}} lists sizes of the three parameter sets of the ML-DSA algorithm.

| | Private Key (seed) | Private Key | Public Key | Signature Size |
| ----------- | ----------- | ----------- | ----------- |
| ML-DSA-44 | 32 | 2560 | 1312 | 2420 |
| ML-DSA-65 | 32 | 4032 | 1952 | 3309 |
| ML-DSA-87 | 32 | 4896 | 2592 | 4627 |
{: #tab-ml-dsa-size title=" Sizes (in bytes) of keys and signatures of ML-DSA"}

Note that the seed is always 32 bytes, and that  ML-DSA.KeyGen_internal from {{FIPS.204}} is called to produce the expanded private key from the seed, whose size corresponds to the sizes of the private key in the table above.

# Composite Signature Instantiations

The ML-DSA signature scheme supports three possible parameter sets, each of which corresponding to a specific security strength. See {{FIPS.204}} for more considerations on that matter.

The traditional signature algorithm for each combination in {{tab-jose-algs}} and {{tab-cose-algs}} was chosen to match the security level of the ML-DSA post-quantum component. More precisely, NIST security levels 1-3 are matched with 256-bit elliptic curves and NIST security levels 4-5 are matched with 384-bit elliptic curves.

The {{FIPS.204}} specification defines both pure and pre-hash modes for ML-DSA, referred to as "ML-DSA" and "HashML-DSA" respectively. This document only specifies a single mode which is similar in construction to HashML-DSA, with the addition of a pre-hash randomizer. However, because the pre-hashing is done at the composite level, only the oure ML-DSA algorithm is used as the underlying ML-DSA primitivee.

## JOSE algorithms

The following table defines a list of algorithms associated with specific PQ/T combinations to be registered in {{IANA.JOSE}}.

| Name | First Algorithm | Second Algorithm | Pre-Hash | Description 
| ----------- | ----------- |  ----------- | ----------- | ----------- |
| ML-DSA-44-ES256 | ML-DSA-44  | ecdsa-with-SHA256 with secp256r1 | SHA256 | Composite Signature with ML-DSA-44 and ECDSA using P-256 curve and SHA256 |
| ML-DSA-65-ES256  | ML-DSA-65 | ecdsa-with-SHA256 with secp256r1 | SHA512 | Composite Signature with ML-DSA-65 and ECDSA using P-256 curve and SHA256 |
| ML-DSA-87-ES384  | ML-DSA-87 | ecdsa-with-SHA384 with secp384r1 | SHA512 | Composite Signature with ML-DSA-87 and ECDSA using P-384 curve and SHA384 |
{: #tab-jose-algs title="JOSE Composite Signature Algorithms for ML-DSA"}

Examples can be found in {{appdx-jose}}.

## COSE algorithms

The following table defines a list of algorithms associated with specific PQ/T combinations to be registered in {{IANA.COSE}}.


| Name | COSE Value | First Algorithm | Second Algorithm | Pre-Hash | Description
| ----------- | ----------- | ----------- |  ----------- | ----------- |
| ML-DSA-44-ES256         | TBD (request assignment -51) | ML-DSA-44  | ecdsa-with-SHA256 with secp256r1 | SHA256 | Composite Signature with ML-DSA-44 and ECDSA using P-256 curve and SHA256 |
| ML-DSA-65-ES256            | TBD (request assignment -52)  | ML-DSA-65 | ecdsa-with-SHA256 with secp256r1 | SHA512 | Composite Signature with ML-DSA-65 and ECDSA using P-256 curve and SHA256 |
| ML-DSA-87-ES384            | TBD (request assignment -53)  | ML-DSA-87 | ecdsa-with-SHA384 with secp384r1 | SHA512 | Composite Signature with ML-DSA-87 and ECDSA using P-384 curve and SHA384 |
{: #tab-cose-algs title="COSE Composite Signature Algorithms for ML-DSA"}

Examples can be found in {{appdx-cose}}.

## Composite Domain Separators for JOSE and COSE

The JOSE and COSE composite domain separators values are listed in {{tab-sig-alg-oids}}.

| "alg" Header Parameter | Domain Separator (in Hex encoding) |
| ----------- | ----------- |  ----------- | ----------- | ----------- |
| ML-DSA-44-ES256 | 4d4c2d4453412d34342d4553323536  |
| ML-DSA-65-ES256  | 4d4c2d4453412d36352d4553323536 |
| ML-DSA-87-ES384  | 4d4c2d4453412d38372d4553333834 |
{: #tab-sig-alg-oids title="JOSE/COSE Composite Domain Separators"}

# Composite Signature Key Types {#sec-composite-sig-key-types}

## JOSE Key Type

This document requests the registration of the following key type in {{IANA.JOSE}}, for use in the optional JWS Header parameter "jwk".

"AKP" stands for "Algorithm Key Pair" and is used in this document, as in {{-COSE-MLDSA}}, to express the ML-DSA public and private keys. When this key type is used, the JSON Web Key Parameter "alg" is REQUIRED.

| kty | Description |
| ----------- | ----------- | ----------- |
| AKP-EC | JWK key type for composite signature with ECDSA as the traditional component. |
{: #tab-jose-kty title="JWK key type for composite algorithm"}

Examples can be found in {{appdx-jose}}.


## COSE Key type

This document requests the registration of the following key type in {{IANA.COSE}}.

"AKP" stands for "Algorithm Key Pair" and is used in this document, as in {{-COSE-MLDSA}}, to express the ML-DSA public and private keys. When this key type is used, the COSE Key Common Parameter "alg" is REQUIRED.

| Name | kty | Description |
| ----------- | ----------- | ----------- |
| AKP-EC2     | TBD (requested assignment 8) | COSE key type for composite algorithm with ECDSA as the traditional component. |
{: #tab-cose-kty title="COSE key type for composite algorithm"}

Examples can be found in {{appdx-cose}}.

# Composite Signature Web Key and Key Type Parameters {#sec-composite-params}

## JSON Web Key Parameters

This document requests IANA to register the entries described in this section and summarised in the following {{tab-cose-key-params}} to the JSON Web Key Parameters Registry.

It also requests to add "AKP-EC" as a usable "kty" value for the parameters "crv", "x", "y" and "d".

| Parameter Name | Parameter Description | Used with "kty" Value(s) | Parameter Information Class | Change Controller | Specification Document(s)
| ----------- | ----------- |  ----------- | ----------- | ----------- |
| pub | Public Key  | AKP-EC | Public | IETF | RFC xxx |
| priv  | Private Key (seed) | AKP-EC | Private | IETF | RFC xxx |
{: #tab-jose-key-params title="JSON AKP-EC Web Key Parameters"}

For the hybrid algorithms registered in this document, the `priv` key parameter MUST be the seed and its size MUST be 32 bytes.


## COSE Key Type Parameters

This document requests IANA to register the entries described in this section and summarised in the following {{tab-cose-key-params}} to the COSE Key Type Parameters Registry.

| Key Type | Name | Label | CBOR Type | Description 
| ----------- | ----------- |  ----------- | ----------- | ----------- |
| TBD (request assignment 8) | crv  | -1 | int / tstr | EC identifier |
| TBD (request assignment 8)  | x | -2 | bstr | x-coordinate |
| TBD (request assignment 8)  | y | -3 | bstr / bool | y-coordinate |
| TBD (request assignment 8)  | d | -4 | bstr | EC Private key |
| TBD (request assignment 8)  | pub | -5 | bstr | Public Key |
| TBD (request assignment 8)  | priv | -6 | bstr | Private Key (seed) |
{: #tab-cose-key-params title="COSE AKP-EC2 Key Parameters"}

For the hybrid algorithms registered in this document, the `priv` key parameter MUST be the seed and its size MUST be 32 bytes.


# Key Thumbprints

The JWK Thumbprint is computed following the process described in {{RFC7638}}, using the following required parameters, listed in their lexicographic order:

* "alg"
* "crv"
* "kty"
* "pub"
* "x"
* "y"

The COSE Key Thumbprint is computed following the process described in {{RFC9679}} using the following required parameters:

* "kty" (label: 1, data type: int, value: 8)
* "alg" (label: 3, data type: int)
* "crv" (label: -1, data type: int)
* "x" (label: -2, value: bstr)
* "y" (label: -3, value: bstr)
* "pub" (label: -5, value: bstr)


Examples in {{appdx-jose}} and {{appdx-jose}} feature AKP-EC and AKP-EC2 thumbprints, used as the kid values.

# Security Considerations

The security considerations of {{RFC7515}}, {{RFC7517}}, {{RFC9053}} and {{FIPS.204}} also apply to this document.

All security issues that are pertinent to any cryptographic application must be addressed by JWS/JWK agents. Protecting the user's private key and employing countermeasures to various attacks constitute a priority.

For security properties and security issues related to the use of a hybrid signature scheme, the user can refer to {{-HYB-SIG-SPECTRUMS}}. For more information about hybrid composite signature schemes and the different hybrid combinations that appear in this document, the user can read {{-COMPOSITE-LAMPS}}.

In particular, to avoid key reuse, when generating a new composite key, the key generation functions for both component algorithms MUST be executed. Compliant parties MUST NOT use, import or export component keys that are used in other contexts, combinations, or by themselves as keys for standalone algorithm use.

# IANA Considerations

## JOSE Algorithms

The following values of the JWS "alg" (algorithm) are requested to be added to the "JSON Web Signature and Encryption Algorithms" registry.
They are represented following the registration template provided in {{RFC7518}}.

### ML-DSA-44-ES256

* Algorithm Name: ML-DSA-44-ES256
* Algorithm Description: Composite Signature with ML-DSA-44 and ECDSA using P-256 curve and SHA-256
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Specification Document(s): n/a
* Algorithm Analysis Documents(s): TBD

### ML-DSA-65-ES256

* Algorithm Name: ML-DSA-65-ES256
* Algorithm Description: Composite Signature with ML-DSA-65 and ECDSA using P-256 curve and SHA-256
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Specification Document(s): n/a
* Algorithm Analysis Documents(s): TBD

### ML-DSA-87-ES384

* Algorithm Name: ML-DSA-87-ES384
* Algorithm Description: Composite Signature with ML-DSA-87 and ECDSA using P-384 curve and SHA-384
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Specification Document(s): n/a
* Algorithm Analysis Documents(s): TBD

## JOSE Key Types

IANA is requested to add the following entries to the JSON Web Key Types Registry.

### AKP-EC

* "kty" Parameter Value: AKP-EC
* Key Type Description: Composite signature algorithm with ECDSA as the traditional component
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Specification Document(s): RFC xxx


## JOSE Web Key Parameters

IANA is requested to add the following entries to the JSON Web Key Parameters Registry.

### Public Key

* Parameter Name: pub
* Parameter Description: Public or verification key
* Used with "kty" Value(s): AKP-EC
* Parameter Information Class: Public
* Change Controller: IETF
* Specification Document(s): RFC xxx

### Private Key

* Parameter Name: priv
* Parameter Description: Private key (seed)
* Used with "kty" Value(s): AKP-EC
* Parameter Information Class: Private
* Change Controller: IETF
* Specification Document(s): RFC xxx

### Others

The key parameters registered in {{IANA.JOSE}} for use with the kty values "EC" should also be usable with the kty value "AKP-EC" defined in this document.

## COSE Algorithms

The following values are requested to be added to the "COSE Algorithms" registry.
They are represented following the registration template provided in {{RFC9053}}, {{RFC9054}}.

### ML-DSA-44-ES256

* Name: ML-DSA-44-ES256
* Value: TBD (request assignment -51)
* Description: Composite Signature with ML-DSA-44 and ECDSA using P-256 curve and SHA-256
* Capabilities: [kty]
* Change Controller: IETF
* Reference: n/a
* Recommended: Yes

### ML-DSA-65-ES256

* Name: ML-DSA-65-ES256
* Value: TBD (request assignment -52)
* Description: Composite Signature with ML-DSA-65 and ECDSA using P-256 curve and SHA-256
* Capabilities: [kty]
* Change Controller: IETF
* Reference: n/a
* Recommended: Yes

### ML-DSA-87-ES384

* Name: ML-DSA-87-ES384
* Value: TBD (request assignment -53)
* Description: Composite Signature with ML-DSA-87 and ECDSA using P-384 curve and SHA-384
* Capabilities: [kty]
* Change Controller: IETF
* Reference: n/a
* Recommended: Yes

## COSE Key Types

### AKP-EC2

* Name: AKP-EC2
* Value: TBD (request assignment 8)
* Description: COSE Key Type for Composite Signature Algorithm with ECDSA as the traditional component
* Capabilities: [kty(8)]
* Reference: n/a

## COSE Key Type Parameters

### Public Key

* Key Type: TBD
* Name: pub
* Label: -5
* CBOR Type: bstr
* Description: Public key
* Reference: n/a

### Private Key

* Key Type: TBD
* Name: priv
* Label: -6
* CBOR Type: bstr
* Description: Private key (seed)
* Reference: n/a

### Others

The key parameters registered in {{IANA.COSE}} for use with the kty value "EC2" should also be usable with the kty value "AKP-EC2" defined in this document.

--- back

# Examples {#appdx}

Will be completed in later versions.

## JOSE {#appdx-jose}

~~~~~~~~~~
{
  "priv": "0000000000000000000000000000000000000000000000000000000000000000",
  "jwk": {
    "kid": "cQSc4xRvPBBbRLNLrhkbC9pS0DIRoSHAGkKGWzx0JeA",
    "kty": "AKP-EC",
    "alg": "ML-DSA-44-ES256",
    "pub": "unH59k4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMcRPgmu9VuNOVdteXi1zNIXjnqJg_GAAxepLqA00Vc3lO0bzRIKu39VFD8Lhuk8l0V-cFEJC-zm7UihxiQMMUEmOFxe3x1ixkKZ0jqmqP3rKryx8tSbtcXyfea64QhT6XNje2SoMP6FViBDxLHBQo2dwjRls0k5a-XSQSu2OTOiHLoaWsLe8pQ5FLNfTDqmkrawDEdZyxr3oSWJAsHQxRjcIiVzZuvwxYy1zl2STiP2vy_fTBaPemkleynQzqPg7oPCyXEE8bjnJbrfWkbNNN8438e6tHPIX4l7zTuzz98YPhLjt_d6EBdT4MldsYe-Y4KLyjaGHcAlTkk9oa5RhRwW89T0z_t1DSO3dvfKLUGXh8gd1BD6Fz5MfgpF5NjoafnQEqDjsAAhrCXY4b-Y3yYJEdX4_dp3dRGdHG_rWcPmgX4JG7lCnser4f8QGnDriqiAzJYEXeS8LzUngg_0bx0lqv_KcyU5IaLISFO0xZSU5mmEPvdSoDnyAcV8pV44qhLtAvd29n0ehG259oRihtljTWeiu9V60a1N2tbZVl5mEqSK-6_xZvNYA1TCdzNctvweH24unV7U3wer9XA9Q6kvJWDVJ4oKaQsKMrCSMlteBJMRxWbGK7ddUq6F7GdQw-3j2M-qdJvVKm9UPjY9rc1lPgol25-oJxTu7nxGlbJUH-4m5pevAN6NyZ6lfhbjWTKlxkrEKZvQXs_Yf6cpXEwpI_ZJeriq1UC1XHIpRkDwdOY9MH3an4RdDl2r9vGl_IwlKPNdh_5aF3jLgn7PCit1FNJAwC8fIncAXgAlgcXIpRXdfJk4bBiO89GGccSyDh2EgXYdpG3XvNgGWy7npuSoNTE7WIyblAk13UQuO4sdCbMIuriCdyfE73mvwj15xgb07RZRQtFGlFTmnFcIdZ90zDrWXDbANntv7KCKwNvoTuv64bY3HiGbj-NQ-U9eMylWVpvr4hrXcES8c9K3PqHWADZC0iIOvlzFv4VBoc_wVflcOrL_SIoaNFCNBAZZq-2v5lAgpJTqVOtqJ_HVraoSfcKy5g45p-qULunXj6Jwq21fobQiKubBKKOZwcJFyJD7F4ACKXOrz-HIvSHMCWW_9dVrRuCpJw0s0aVFbRqopDNhu446nqb4_EDYQM1tTHMozPd_jKxRRD0sH75X8ZoToxFSpLBDbtdWcenxj-zBf6IGWfZnmaetjKEBYJWC7QDQx1A91pJVJCEgieCkoIfTqkeQuePpIyu48g2FG3P1zjRF-kumhUTfSjo5qS0YiZQy0E1BMs6M11EvuxXRsHClLHoy5nLYI2Sj4zjVjYyxSHyPRPGGo9hwB34yWxzYNtPPGiqXS_dNCpi_zRZwRY4lCGrQ-hYTEWIK1Dm5OlttvC4_eiQ1dv63NiGkLRJ5kJA3bICN0fzCDY-MBqnd1cWn8YVBijVkgtaoascjL9EywDgJdeHnXK0eeOvUxHHhXJVkNqcibn8O4RQdpVU60TSA-uiu675ytIjcBHC6kTv8A8pmkj_4oypPd-F92YIJC741swkYQoeIHj8rE-ThcMUkF7KqC5VORbZTRp8HsZSqgiJcIPaouuxd1-8Rxrid3fXkE6p8bkrysPYoxWEJgh7ZFsRCPDWX-yTeJwFN0PKFP1j0F6YtlLfK5wv-c4F8ZQHA_-yc_gODicy7KmWDZgbTP07e7gEWzw4MFRrndjbDQ",
    "priv": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "crv": "P-256",
    "x": "Puw-n_hwL_Aa2vLOlIikb6JJPNmgkj9uWnyNbl8RqOU",
    "y": "SQ2wmwh8B6oGU3Ru9RlEm7uTyFA7U5RiJ-lElG1Czog",
    "d": "dkJyM18UxrcUb9LP5TO3-ZBkkLukzdhF1YFXYtVoyXs"
  },
  "jws": "eyJhbGciOiJNTC1EU0EtNDQtRVMyNTYiLCJraWQiOiJjUVNjNHhSdlBCQmJSTE5McmhrYkM5cFMwRElSb1NIQUdrS0dXengwSmVBIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.hYTSOt4g5zRXpkRIPMcgURZ87BQmbJhFpKQmlqsAOzhbA4Er71oo-v9RRZ0ALN7MhKDah3ZtW2o12t5nTGehNho0eNlWC9-rGoal7duhXF0GKRAvQOL60GDxal4PsgjbkDwKgDy-J5LH-Y2-sg4bTTuIX2R3V87vUimX95MqIG53kT7J4xp-6BDK2Qi3usjs1U9dK78vbrZSRZI5J21Jf1OLI1YCVm4ytY24sF4z9fcYkkx0LE3L9eAwJVrQR3dDTC3rr7NEqf8O7zZiprzyEdowIHKx3mcLDD27Peb-QhQM9Mt2Yoyj5rjx3dX7rfLrj3CJtKi2_xFvca-P1SpNj3Tm4bhmBVAEjW1Ua25ylNGkaf3XNn-OkxNEtLmLnwiFZlr6v2Fz_0es8G85bm_lSnwHAxU_J0CA3s9__djLQwHwhIjCfQqnviYcBWLDGeQDFiS2hqt-kdh-ivICPclKGEzRB8djRNc8Ir-scYSVXqDn4i7PHDZCzyhTHkjtxLyMS811yq7tC9t43RfmpzpIexMpBS34Na9hbn167KjCkvNMPM4kuYtpG4lYOtOOh3mNbCwsnrkOzGFMqC69klXXxYYY3g_ZQiFArHERbD6lfHFV-d1g6WlF2NwDiqFwDokczKpfnuTk4V4CzyLsV6zyJKYFudUFNfWKv5lov96y9BpdSi2uwyeGn2o4rrf4gEsavxbsofaPuoftYctLy_V3u6MglTiOW1-hTibH8tkCMLmMCC5EUPAgWqwTIPwdHDYvaOq5D5C7Pg3Zikrvc1Z5_-Ety56O_NEzxU6V24ciN6x5Lh9jxbacckhcHaqzZhOej-zGfddWDLMVfLjYe-BGobLj7VZrJFAnEOBNoelvSpmUi-ZmYW15Qz36su0znaDW6HoRHecZlqmYfsDApA7YG0_u--fRTgxi6nImWEqIMxgSmRohJRDnwoIaI6WlmogQ8-NtPHzYw4_B59DqhyOcyIogzyeMyATiCMOvH3LY5CkiwLWQgwrfAGli7yD7d8TEJ_cbdhJxRuP0GAKT86IQf6j6Iw1weDHvPFlqcA_OfVtWdwdMSB0ZsiJcnzlIDnPPG6LsKGB81hVyX4x5tQLigrKre2Z105-TwlA6dk3zzKz0Gu25d2AWXt44nT6rqj93xw_1U0aStB_6UfulYzJVVGG4fZWKt50YUDSovC599K5qR4xLtRn913ZoVzK2P8nJVyCppVp_hceDdWvad1Ian5E8-rF46zvt7d-FPb8i2gvsf1_WRbDUmfDoj9An0CccTg9XoW-QlHzQLmU0sRBQuPDByCbz2imKNod4hF-GiYmxTEbZyxAS6DRyJxsMy6NBtkXm1j51j96vkTwlrsD23cRl_8BZjykkfw2bOsticQGMV2tDWf943Pxib8SeH1zq-mLuDIArm9Fb54YdMWfZwLqlSEBQc55ZCiAPWX6rKjykVwz2lfjv3rnD_7LqnYsG0I9gk2tHQ8-WmJiNLPJrtdfyXpHcxLvbM1RCZ-NxlOBbWzY6xYcbeviOA6z6JDDWaMwhD8VFLxwHtm9Ltryaos7gwQ9118vpjGAbkN5v2oZI3INPcfTYDrCr7QGL9STKq9ilg5fbb69qF2Pr1qX7bzhQeXhDfpXp6V5ttiNLJBiRiwY5vtB3I0ERtD0wHW0QGIeSz9YkXCuV6sJS75Vxkj1Q5vOeEionHQ8J_YUS4yZVirMC77G6ybKanvjdvIP18S37xbilwPYQORKsO06Vku2pVgDjQlH-7UxLYH9FOKVwcOqZRe4WLNoFmSbQ8Easq6ojJ12Ekdnmx-sVkszUnV02xaUlYFraHYQbrDnBsldU16uUkJWDnLhK5Ie_8E6gwodd__n4-QxYQUG6vU4N6-jw66OrLt-WrmPjO72q-F0UlAxdvr5S3BE9S3le0bLHt1ji4qWm8RJ4J6ANPcdF4iI2ZPQFy9W1kIu_lhFNw9rqazsbF2OLu7stDA4hUzyf1vFkU8vT3wx789NrgZvBIBLTQH0-xx3sSsRs0SGOoEouvwk2GToM_fr0h-Jz6hfeG6MDhn1wH6m-e4xmSjqbumKnA8wzUnFwDH5AFiC_SS5-Xe3fHPHPgLqTA3YgoM5wlhqBSTRJaNi4Kgpi6-Ds27DUOwtqgVnLC_hajS1GBA0IX0cICy_G7hkbnJU_amnASfuVD1swklcD4pOsoUFAAsgUwiZ8XhERB2Uy-W6_5Ok73OZQ78cG1G7i6tGcgcHspAN8U62SAbZD4m2Io-xp5x5Ki14Q8aLeAcn0aSZXS1Bb6yDTy8eQ3Z2k1PlRV57NhCLxdNoWUtmDHVKISdbm6nogiZoYuP55cR4-79SODViJX9MXRQnySDbEAkO4yn6M1zVbcnwV1Ym9JF-mgKVxB4Ovni1G3DIiwpL-1mvNGq3zwZ8dWQ7ZlldJqZeXGQN3SaGuLY649j6ZdhfIS8haZmpcjul0F-iP2O9JLEFPzGjaZ0ZDFLo001oI-fK1HylaWK4Rn3eQpQZhbToyqJ0YgyfHfHbjdA8JAs4i6qydFwZQLDzQBy4yK27wtebnFXH1E3H7haT_3ushldlXtGboAwEekukf1ifNopSXP5R19mNoP5mx_bwvy-11Swg0S4tFEVDHKLhQKXG_mIuyIymiw9mV-6WvYf01wguzpsg2PRkQ-lsna1IKaLYhHQVkA-CNFPgkg1w32XuI0opTsen4kFPtVVYZsN7vJiRtPVB-GsCKGGBjnx3wSBsK3FvFgDwgy15oUvTD8w2OiMvMmKefjUxQXNg_0VRZ537bOq79uXkzpampEcBvavETa43oNNCCLkdhzDis-FU7PBtbQ0_QWkU3hopRfZY1LEZEJbZ04bGhwcs1MYAcDPWjrZuezxDCy2_6kCFDmCB4TJGDrLgB5WwOo3PVyTaGWO8_kILIRjpYt4h0Q-1CHMBTAFrWzDT8Lph90TycQNd0ZhSTTeOJAQ8yuP-WjDFJJAQQOQ2Ll2QRx-fsRXQII3hBu8bEne0NwezXMuWsR4iBnJcjDgoAFd3UzC0FWHMZJP6Lg7aEfD8nomI03K8XyU-OJ_LWU24sYUOTudl48wrnqAYFftPAlqJYAYmELnSH-xtxtkzGTJRVnJAtuTQ3_7RjdEVYY1p-Xhb-8j1j3XtwoWe-QIAdnAEEHiEuUI-Rl6uwtcrQ4_H1BAUHFR03OE9TWFplf4OHr7u8v8TLz9La8g0QFSorQUROX3KGi5ScprnU7R0hI0FHoLvj5PYAAAAAAAAAAAAAESo8RlpXyAx0vzV1MFL5CvtoRnfISEzLQXW09Baq3k8glcd_xL40iGCDNuWRQPwDIZhZ6zcYWm13h9In9tDoi4DA-18",
  "raw_randomizer": "8584d23ade20e73457a644483cc72051167cec14266c9845a4a42696ab003b38",
  "raw_to_be_signed": "436f6d706f73697465416c676f726974686d5369676e617475726573323032354d4c2d4453412d34342d4553323536008584d23ade20e73457a644483cc72051167cec14266c9845a4a42696ab003b38f13634a90b90ca4cfe23fbebd764b860c89044a0d2f38602229e3cb91e4a435b",
  "raw_composite_signature": "8584d23ade20e73457a644483cc72051167cec14266c9845a4a42696ab003b385b03812bef5a28faff51459d002cdecc84a0da87766d5b6a35dade674c67a1361a3478d9560bdfab1a86a5eddba15c5d0629102f40e2fad060f16a5e0fb208db903c0a803cbe2792c7f98dbeb20e1b4d3b885f647757ceef522997f7932a206e77913ec9e31a7ee810cad908b7bac8ecd54f5d2bbf2f6eb652459239276d497f538b235602566e32b58db8b05e33f5f718924c742c4dcbf5e030255ad04777434c2debafb344a9ff0eef3662a6bcf211da302072b1de670b0c3dbb3de6fe42140cf4cb76628ca3e6b8f1ddd5fbadf2eb8f7089b4a8b6ff116f71af8fd52a4d8f74e6e1b8660550048d6d546b6e7294d1a469fdd7367f8e931344b4b98b9f0885665afabf6173ff47acf06f396e6fe54a7c0703153f274080decf7ffdd8cb4301f08488c27d0aa7be261c0562c319e4031624b686ab7e91d87e8af2023dc94a184cd107c76344d73c22bfac7184955ea0e7e22ecf1c3642cf28531e48edc4bc8c4bcd75caaeed0bdb78dd17e6a73a487b1329052df835af616e7d7aeca8c292f34c3cce24b98b691b89583ad38e87798d6c2c2c9eb90ecc614ca82ebd9255d7c58618de0fd9422140ac71116c3ea57c7155f9dd60e96945d8dc038aa1700e891cccaa5f9ee4e4e15e02cf22ec57acf224a605b9d50535f58abf9968bfdeb2f41a5d4a2daec327869f6a38aeb7f8804b1abf16eca1f68fba87ed61cb4bcbf577bba32095388e5b5fa14e26c7f2d90230b98c082e4450f0205aac1320fc1d1c362f68eab90f90bb3e0dd98a4aef735679ffe12dcb9e8efcd133c54e95db872237ac792e1f63c5b69c72485c1daab366139e8fecc67dd7560cb3157cb8d87be046a1b2e3ed566b24502710e04da1e96f4a99948be666616d79433dfab2ed339da0d6e87a111de71996a9987ec0c0a40ed81b4feefbe7d14e0c62ea7226584a88331812991a212510e7c2821a23a5a59a8810f3e36d3c7cd8c38fc1e7d0ea87239cc88a20cf278cc804e208c3af1f72d8e42922c0b590830adf006962ef20fb77c4c427f71b76127146e3f4180293f3a2107fa8fa230d707831ef3c596a700fce7d5b5677074c481d19b2225c9f39480e73cf1ba2ec28607cd615725f8c79b502e282b2ab7b6675d39f93c2503a764df3ccacf41aedb97760165ede389d3eabaa3f77c70ff5534692b41ffa51fba56332555461b87d958ab79d185034a8bc2e7df4ae6a478c4bb519fdd776685732b63fc9c95720a9a55a7f85c783756bda77521a9f913cfab178eb3bededdf853dbf22da0bec7f5fd645b0d499f0e88fd027d0271c4e0f57a16f90947cd02e6534b11050b8f0c1c826f3da298a368778845f868989b14c46d9cb1012e83472271b0ccba341b645e6d63e758fdeaf913c25aec0f6ddc465ffc0598f29247f0d9b3acb6271018c576b4359ff78dcfc626fc49e1f5ceafa62ee0c802b9bd15be7861d3167d9c0baa5484050739e590a200f597eab2a3ca4570cf695f8efdeb9c3ffb2ea9d8b06d08f60936b4743cf9698988d2cf26bb5d7f25e91dcc4bbdb33544267e37194e05b5b363ac5871b7af88e03acfa2430d668cc210fc5452f1c07b66f4bb6bc9aa2cee0c10f75d7cbe98c601b90de6fda8648dc834f71f4d80eb0abed018bf524caabd8a58397db6faf6a1763ebd6a5fb6f38507978437e95e9e95e6db6234b2418918b0639bed077234111b43d301d6d10188792cfd6245c2b95eac252ef9571923d50e6f39e122a271d0f09fd8512e326558ab302efb1bac9b29a9ef8ddbc83f5f12dfbc5b8a5c0f6103912ac3b4e9592eda95600e34251feed4c4b607f4538a57070ea9945ee162cda059926d0f046acabaa23275d8491d9e6c7eb1592ccd49d5d36c5a525605ada1d841bac39c1b25754d7ab949095839cb84ae487bff04ea0c2875dfff9f8f90c584141babd4e0debe8f0eba3ab2edf96ae63e33bbdaaf85d14940c5dbebe52dc113d4b795ed1b2c7b758e2e2a5a6f1127827a00d3dc745e2223664f405cbd5b5908bbf96114dc3daea6b3b1b17638bbbbb2d0c0e21533c9fd6f16453cbd3df0c7bf3d36b819bc12012d3407d3ec71dec4ac46cd1218ea04a2ebf0936193a0cfdfaf487e273ea17de1ba303867d701fa9be7b8c664a3a9bba62a703cc335271700c7e401620bf492e7e5deddf1cf1cf80ba93037620a0ce70961a8149344968d8b82a0a62ebe0ecdbb0d43b0b6a8159cb0bf85a8d2d46040d085f47080b2fc6ee191b9c953f6a69c049fb950f5b30925703e293aca1414002c814c2267c5e1111076532f96ebfe4e93bdce650efc706d46ee2ead19c81c1eca4037c53ad9201b643e26d88a3ec69e71e4a8b5e10f1a2de01c9f46926574b505beb20d3cbc790dd9da4d4f951579ecd8422f174da1652d9831d528849d6e6ea7a20899a18b8fe79711e3eefd48e0d58895fd3174509f24836c40243b8ca7e8cd7355b727c15d589bd245fa680a5710783af9e2d46dc3222c292fed66bcd1aadf3c19f1d590ed9965749a9979719037749a1ae2d8eb8f63e997617c84bc85a666a5c8ee97417e88fd8ef492c414fcc68da67464314ba34d35a08f9f2b51f295a58ae119f7790a506616d3a32a89d188327c77c76e3740f0902ce22eaac9d1706502c3cd0072e322b6ef0b5e6e71571f51371fb85a4ffdeeb2195d957b466e803011e92e91fd627cda294973f9475f663683f99b1fdbc2fcbed754b08344b8b451150c728b8502971bf988bb22329a2c3d995fba5af61fd35c20bb3a6c8363d1910fa5b276b520a68b6211d056403e08d14f824835c37d97b88d28a53b1e9f89053ed555619b0deef26246d3d507e1ac08a1860639f1df0481b0adc5bc5803c20cb5e6852f4c3f30d8e88cbcc98a79f8d4c505cd83fd15459e77edb3aaefdb97933a5a9a911c06f6af1136b8de834d0822e4761cc38acf8553b3c1b5b434fd05a4537868a517d96352c464425b674e1b1a1c1cb3531801c0cf5a3ad9b9ecf10c2cb6ffa9021439820784c9183acb801e56c0ea373d5c9368658ef3f9082c8463a58b7887443ed421cc053005ad6cc34fc2e987dd13c9c40d7746614934de389010f32b8ff968c3149240410390d8b976411c7e7ec457408237841bbc6c49ded0dc1ecd732e5ac4788819c97230e0a0015ddd4cc2d0558731924fe8b83b6847c3f27a26234dcaf17c94f8e27f2d6536e2c614393b9d978f30ae7a806057ed3c096a2580189842e7487fb1b71b64cc64c94559c902db93437ffb463744558635a7e5e16fef23d63dd7b70a167be40801d9c01041e212e508f9197abb0b5cad0e3f1f5040507151d37384f53585a657f8387afbbbcbfc4cbcfd2daf20d10152a2b41444e5f72868b949ca6b9d4ed1d21234147a0bbe3e4f600000000000000000000112a3c465a57c80c74bf35753052f90afb684677c8484ccb4175b4f416aade4f2095c77fc4be3488608336e59140fc03219859eb37185a6d7787d227f6d0e88b80c0fb5f",
  "raw_composite_public_key": "ba71f9f64e11baeb58fa9c6fbb6e14e61f18643dab495b47539a9166ca0198131c44f826bbd56e34e55db5e5e2d733485e39ea260fc6000c5ea4ba80d3455cde53b46f34482aedfd5450fc2e1ba4f25d15f9c144242fb39bb52287189030c50498e1717b7c758b190a6748ea9aa3f7acaaf2c7cb526ed717c9f79aeb84214fa5cd8ded92a0c3fa1558810f12c7050a367708d196cd24e5af974904aed8e4ce8872e8696b0b7bca50e452cd7d30ea9a4adac0311d672c6bde8496240b07431463708895cd9bafc31632d7397649388fdafcbf7d305a3de9a495eca7433a8f83ba0f0b25c413c6e39c96eb7d691b34d37ce37f1eead1cf217e25ef34eecf3f7c60f84b8edfdde8405d4f832576c61ef98e0a2f28da187700953924f686b94614705bcf53d33fedd4348edddbdf28b5065e1f20775043e85cf931f829179363a1a7e7404a838ec00086b0976386fe637c98244757e3f769ddd4467471bfad670f9a05f8246ee50a7b1eaf87fc4069c3ae2aa2033258117792f0bcd49e083fd1bc7496abff29cc94e4868b21214ed316525399a610fbdd4a80e7c80715f29578e2a84bb40bdddbd9f47a11b6e7da118a1b658d359e8aef55eb46b5376b5b655979984a922beebfc59bcd600d5309dccd72dbf0787db8ba757b537c1eafd5c0f50ea4bc9583549e2829a42c28cac248c96d78124c47159b18aedd754aba17b19d430fb78f633ea9d26f54a9bd50f8d8f6b73594f828976e7ea09c53bbb9f11a56c9507fb89b9a5ebc037a37267a95f85b8d64ca97192b10a66f417b3f61fe9ca57130a48fd925eae2ab5502d571c8a51903c1d398f4c1f76a7e11743976afdbc697f23094a3cd761ff9685de32e09fb3c28add453490300bc7c89dc01780096071722945775f264e1b0623bcf4619c712c838761205d87691b75ef360196cbb9e9b92a0d4c4ed62326e5024d77510b8ee2c7426cc22eae209dc9f13bde6bf08f5e7181bd3b459450b451a51539a715c21d67dd330eb5970db00d9edbfb2822b036fa13bafeb86d8dc78866e3f8d43e53d78cca5595a6faf886b5dc112f1cf4adcfa875800d90b48883af97316fe1506873fc157e570eacbfd222868d14234101966afb6bf9940829253a953ada89fc756b6a849f70acb9838e69faa50bba75e3e89c2adb57e86d088ab9b04a28e670709172243ec5e0008a5ceaf3f8722f487302596ffd755ad1b82a49c34b3469515b46aa290cd86ee38ea7a9be3f103610335b531cca333ddfe32b14510f4b07ef95fc6684e8c454a92c10dbb5d59c7a7c63fb305fe881967d99e669eb632840582560bb403431d40f75a4954908482278292821f4ea91e42e78fa48caee3c836146dcfd738d117e92e9a15137d28e8e6a4b4622650cb413504cb3a335d44beec5746c1c294b1e8cb99cb608d928f8ce3563632c521f23d13c61a8f61c01df8c96c7360db4f3c68aa5d2fdd342a62ff3459c116389421ab43e8584c45882b50e6e4e96db6f0b8fde890d5dbfadcd88690b449e64240ddb2023747f308363e301aa77757169fc6150628d5920b5aa1ab1c8cbf44cb00e025d7879d72b479e3af5311c785725590da9c89b9fc3b8450769554eb44d203eba2bbaef9cad2237011c2ea44eff00f299a48ffe28ca93ddf85f76608242ef8d6cc24610a1e2078fcac4f9385c314905ecaa82e553916d94d1a7c1ec652aa08897083daa2ebb1775fbc471ae27777d7904ea9f1b92bcac3d8a3158426087b645b1108f0d65fec93789c053743ca14fd63d05e98b652df2b9c2ff9ce05f1940703ffb273f80e0e2732eca9960d981b4cfd3b7bb8045b3c3830546b9dd8db0d3eec3e9ff8702ff01adaf2ce9488a46fa2493cd9a0923f6e5a7c8d6e5f11a8e5490db09b087c07aa0653746ef519449bbb93c8503b53946227e944946d42ce88"
}
~~~~~~~~~~
{: #jose_example_ML_DSA_44_ES256 title="ML-DSA-44-ES256"}


~~~~~~~~~~
{
  "priv": "0000000000000000000000000000000000000000000000000000000000000000",
  "jwk": {
    "kid": "vMQNzG4dJGvyVu6lrFm1muOWHUvLJEEpEfENkb6_-Lg",
    "kty": "AKP-EC",
    "alg": "ML-DSA-65-ES256",
    "pub": "QksvJn5Y1bO0TXGs_Gpla7JpUNV8YdsciAvPof6rRD8JQquL2619cIq7w1YHj22ZolInH-YsdAkeuUr7m5JkxQqIjg3-2AzV-yy9NmfmDVOevkSTAhnNT67RXbs0VaJkgCufSbzkLudVD-_91GQqVa3mk4aKRgy-wD9PyZpOMLzP-opHXlOVOWZ067galJN1h4gPbb0nvxxPWp7kPN2LDlOzt_tJxzrfvC1PjFQwNSDCm_l-Ju5X2zQtlXyJOTZSLQlCtB2C7jdyoAVwrftUXBFDkisElvgmoKlwBks23fU0tfjhwc0LVWXqhGtFQx8GGBQ-zol3e7P2EXmtIClf4KbgYq5u7Lwu848qwaItyTt7EmM2IjxVth64wHlVQruy3GXnIurcaGb_qWg764qZmteoPl5uAWwuTDX292Sa071S7GfsHFxue5lydxIYvpVUu6dyfwuExEubCovYMfz_LJd5zNTKMMatdbBJg-Qd6JPuXznqc1UYC3CccEXCLTOgg_auB6EUdG0b_cy-5bkEOHm7Wi4SDipGNig_ShzUkkot5qSqPZnd2I9IqqToi_0ep2nYLBB3ny3teW21Qpccoom3aGPt5Zl7fpzhg7Q8zsJ4sQ2SuHRCzgQ1uxYlFx21VUtHAjnFDSoMOkGyo4gH2wcLR7-z59EPPNl51pljyNefgCnMSkjrBPyz1wiET-uqi23f8Bq2TVk1jmUFxOwdfLsU7SIS30WOzvwD_gMDexUFpMlEQyL1-Y36kaTLjEWGCi2tx1FTULttQx5JpryPW6lW5oKw5RMyGpfRliYCiRyQePYqipZGoxOHpvCWhCZIN4meDY7H0RxWWQEpiyCzRQgWkOtMViwao6Jb7wZWbLNMebwLJeQJXWunk-gTEeQaMykVJobwDUiX-E_E7fSybVRTZXherY1jrvZKh8C5Gi5VADg5Vs319uN8-dVILRyOOlvjjxclmsRcn6HEvTvxd9MS7lKm2gI8BXIqhzgnTdqNGwTpmDHPV8hygqJWxWXCltBSSgY6OkGkioMAmXjZjYq_Ya9o6AE7WU_hUdm-wZmQLExwtJWEIBdDxrUxA9L9JL3weNyQtaGItPjXcheZiNBBbJTUxXwIYLnXtT1M0mHzMqGFFWXVKsN_AIdHyv4yDzY9m-tuQRfbQ_2K7r5eDOL1Tj8DZ-s8yXG74MMBqOUvlglJNgNcbuPKLRPbSDoN0E3BYkfeDgiUrXy34a5-vU-PkAWCsgAh539wJUUBxqw90V1Du7eTHFKDJEMSFYwusbPhEX4ZTwoeTHg--8Ysn4HCFWLQ00pfBCteqvMvMflcWwVfTnogcPsJb1bEFVSc3nTzhk6Ln8J-MplyS0Y5mGBEtVko_WlyeFsoDCWj4hqrgU7L-ww8vsCRSQfskH8lodiLzj0xmugiKjWUXbYq98x1zSnB9dmPy5P3UNwwMQdpebtR38N9I-jup4Bzok0-JsaOe7EORZ8ld7kAgDWa4K7BAxjc2eD540Apwxs-VLGFVkXbQgYYeDNG2tW1Xt20-XezJqZVUl6-IZXsqc7DijwNInO3fT5o8ZAcLKUUlzSlEXe8sIlHaxjLoJ-oubRtlKKUbzWOHeyxmYZSxYqQhSQj4sheedGXJEYWJ-Y5DRqB-xpy-cftxL10fdXIUhe1hWFBAoQU3b5xRY8KCytYnfLhsFF4O49xhnax3vuumLpJbCqTXpLureoKg5PvWfnpFPB0P-ZWQN35mBzqbb3ZV6U0rU55DvyXTuiZOK2Z1TxbaAd1OZMmg0cpuzewgueV-Nh_UubIqNto5RXCd7vqgqdXDUKAiWyYegYIkD4wbGMqIjxV8Oo2ggOcSj9UQPS1rD5u0rLckAzsxyty9Q5JsmKa0w8Eh7Jwe4Yob4xPVWWbJfm916avRgzDxXo5gmY7txdGFYHhlolJKdhBU9h6f0gtKEtbiUzhp4IWsqAR8riHQs7lLVEz6P537a4kL1r5FjfDf_yjJDBQmy_kdWMDqaNln-MlKK8eENjUO-qZGy0Ql4bMZtNbHXjfJUuSzapA-RqYfkqSLKgQUOW8NTDKhUk73yqCU3TQqDEKaGAoTsPscyMm7u_8QrvUK8kbc-XnxrWZ0BZJBjdinzh2w-QvjbWQ5mqFp4OMgY94__tIU8vvCUNJiYA1RdyodlfPfH5-avpxOCvBD6C7ZIDyQ-6huGEQEAb6DP8ydWIZQ8xY603DoEKKXkJWcP6CJo3nHFEdj_vcEbDQ-WESDpcQFa1fRIiGuALj-sEWcjGdSHyE8QATOcuWl4TLVzRPKAf4tCXx1zyvhJbXQu0jf0yfzVpOhPun4n-xqK4SxPBCeuJOkQ2VG9jDXWH4pnjbAcrqjveJqVti7huMXTLGuqU2uoihBw6mGqu_WSlOP2-XTEyRyvxbv2t-z9V6GPt1V9ceBukA0oGwtJqgD-q7NXFK8zhw7desI5PZMXf3nuVgbJ3xdvAlzkmm5f9RoqQS6_hqwPQEcclq1MEZ3yML5hc99TDtZWy9gGkhR0Hs3QJxxgP7bEqGFP-HjTPnJsrGaT6TjKP7qCxJlcFKLUr5AU_kxMULeUysWWtSGJ9mpxBvsyW1Juo",
    "priv": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "crv": "P-256",
    "x": "4U0ypoe3poM6z2DIGAVEncenknXydBqacvc69cA1o88",
    "y": "wxW1-blrydc3h3NVjGC7MSIMrXF466uD88ca2qFq7C4",
    "d": "8Bh0E7d_lkcFm91XxN6vaQjO3TOH0HCmWcHv17nXxeo"
  },
  "jws": "eyJhbGciOiJNTC1EU0EtNjUtRVMyNTYiLCJraWQiOiJ2TVFOekc0ZEpHdnlWdTZsckZtMW11T1dIVXZMSkVFcEVmRU5rYjZfLUxnIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.oqk_oJN9_XYvnw9J3ArkfvCzAu5SNlDjb9W6gwrHAU1NrD5vj6Yy5b402BIrFqfcWZ5r-v42UHK-2r5avmDhotYbbvSY0gIXYqc8fn-9lRwRpLy5b4SkQxcYF9Z9MdWe3ep-ZGwTqnEShK7qddABDCCtBp01A_4fA7b0P_cDa2OzaNgUaI6-4mx89EbSCmXJBM3jddX2QPlLHLsFvVfk2NE5xWezqeQhFuNMDGxpKnied4gaTKa3oeH9-tRt84LwOLGEzVQ4hsZuicn_oqJVupIo3Z2TGiuxlPR3i40QBAfLazqh0tAjHXoKGPfxc3Jgn7tov4-AiidAtu5_Wid-hwSZLQ60bZlgQaT5BmJlvKWoLxCi8AmsNEmdtcF8uu6tS6z5jx0thxXkbgdieCNLOmID1jHdPTFXokJ7rbqdtMTgcDvCv7GMZ5cZqkBcuutSoQ-S9BbenLgcUXNMVL8rxr7toq99roh81kpJnunphh545vKD-2UjB-YcOiEXKJZgZHlvva9pE-nFtYTritPZPWzgUWXcGbhISdnxJYKUmFz7mZHZm56yxrtbNEAtYS6MRu0ES9l5WSwK0l_78u8NPjxcVBfV1VHJNOqWI9rgihRQa9PyXWty9PGil5VcVhKCOjx4zGV3ajni0VHTRqCCbJJZ8EHj-qx0iLwp3FKOqpQnB_Qy91sH7lOhnGVYfGdwzUOWoOalTe8XruAZgnyu7nU1eigqj9DGIXedSWf5wQKfZqMyiuw6E52QYoNgkmSlcpSE7fDKbOyowiFtcFu5fdmotsCc7aYdK9-Gt75OlDO8uqLfagBdD8lNw1PBMM40H5dObco9umMzNSv1w_jJT9nbKxHIflYD_wSVK1PrB1pV7hrVeORF2Bdmz5zGhlpttKPvVUShtbswyZxPxVLAgCX3vq3TmUrS3pj_y2zTVpmVIF4eR5Ts6r8mSOBtOMQltXZJUWdsLQzbKV5-XbGD9A5y9QqIRsOFCX3Bar1_OQpsUEEnkoJ1fIKhSzeqk5aj2AETpPn6vGiqfACkhzvCweIc9PDkxB_ofC0tCZGOHoPmyeGn1BUCcwCwaS3qYvxtIRk51nWfVbREQsHq3gqEkg6kvGCs7NnEedqh8h9ptL0S2OURO_LirB2-vm3Yka0oa6S9X45vJXcB6z0e3JtwQFWcnqUPOb6rVfu367So6bLiAYck35_SWeFbDvY5yRcpbvQJnJZ4qQFRuKAJLi9OKyIoXQCVZLJ6Ezz_MusuM8wcME539jf_nXrgGBcPzHW3c9SckASwMDdmGu20l4Cl_c3LT8dwhK1rarWRw5EMCzfAqI7CUTNB6N-H463rr4bTvkqPeU6KFwi1e6reJZQBI_lO-NF5tNHOoZS7NZcr79p5Zw0NRg4_DOj_x2oSSb-olLe6D_0BARHcbhNyUw-lpbu2wt0BmEhYNYKJb-gXpppNxbRV0EwqWCf4zweB0OVSRtVQQyATQrwtaLhyuU7kdd-9gZ2zhOOclUFgVzVsdJDOeLmRZ7dzq0FUoU2duI6-pLI5AEEw2ltinnE48uOd-LHhe8vUckLwgfjq8719K9jtkGjzPz2boiZt3hpLw5Q8Nfs_LC3Cg5-k_w1D5P0BrRZ-mmOPvVGZtz3GHaCxIUbzXH-CpJlX8qld50f-NxucAivwN-qATCsgRoPtJYQc_BhcZzKK2kO3fZNkJwL30dYSLE3uQFHAEg-z4kW3ZJ_e65MMYGZSkO6LxcpItkcTuHXrkz0bDpI5u-VG_VdfNNFfQWBW-F5dk8wjTxOD9074SzsgZ3KFft5r3gd1OSUkbUb_EiYJtzDZFqF-NgNTPccGNnEz717QyKwk1tcucN0aS2SnupvyhmjLuVbXEBSAa6iOJkzofurrQW8QTolZ2ZXa2vRo0HmQ8U3_BLcc6y4uyYkZSeQWRMNMdx8OZC2tYkqD0RnTwY6NeAWOw2DxZNuNJg__DSfn5ciwNKxnPi_hhiMHwg9RSQWN9q5Oc-6BQDzcjescV1uw5Oh4FKbVcWoqgRZ4m6HwQMxga5HZafY9TOSMH6kOYjPGvi1GWo3wV0mYCFgN6GehnD8PQI3aiXuKwNGmb7dYqP7phaIv3nTniKf60-vmB8Tw3Cmgo9UptcY4fBfNvOatn6mmG8CsXt52g7X7Ef5edYKUKxWUfgkwjFjnUhib8VqICbdabrMyp3CYlpkigVn9WBoCuGZaFqEVqmMhAjHJKpXi-qRBaymp1bZyCsFrJ5lpKY-nsDqJi6dMplmsELbkrE5mNwHAn6W57-ZIe6tKMkueIE7xqjTTDFi7LGDYJRThouANzz2u4ITT3KlKNgQLIvvobzwWiM6LLjcOUegyUigrB4KfBzZ7B9rfO7CkNhmVbd7yMOcOJ9iFSIFtcA9CP1O3JzXLYvR7Ha0GgLj6MriIwGTDXgN5--bOS6avZxlKuM4tWzxFPn9L9kQJiRXAlQlS7y-KFf55eCLcYt6nTcy8p3PH-OCfIESs_ST6SwfR4PRb6CgL-cDTricm_kFFsRi13feUN16Mktp9grDzzoIvUcFzJuFvgzdpumbPQrvnNBDwwE8lHWqsZqZqrGgHk0PQ3RbgOoYgSIHLbfd_ZzXyb1HZLzHhHqOPOeo9QuFoPyoNYDjglxMuEoIj0bwvaNw_gIn6ZwDshU0aZi63CUDTMil3HJGyNzb1C3bkp5sDZ1BI996f-F2AHWNMkeMK3bJIDvE2Yf2n4rchNyCX2z9ScozaPoS8IaHYsd3lyALHL9Dgn7oc4y3oWL7shPQ4y5Ep-E0E7TPNwh4B11Si7vgGLJylZ74OSxi8ceHky75AlfNVhj4VWR6yThPEPI2gai7eucQuF5SrtVy3vz4Kq1TGTTJwJpNTFtVJm7pMuLQoNKTsEmDLHYncr2rq-ZiAAx91zRTzO--NhKIRLTUconH9foBPfyfYWIsXP2SMr9ex8EmCDsGbhN8_UVmVGcFwc1J6CZUgGVs9jDLyYdO8rhkAVlfwKg40dzaSNTeExGZtacnLrJrsZn5BC5JaCBLeDzNdYIlQ3QjVFjmYt51Pe8FoGCSWo8OkidBvv4yZcqGiFVCTqLcqOA_nNlW9EUfHhNnjw7dSwldLqcxpYYsB0hd90YKi29md32JEsRiRg5VjmnhfArmK48oZCN3nFOBcZ1jSvTkpRMKv45Z0c3lRUkO8XQ93uSMKjCO2qB76m9apu27esvRwNVVrAI6NNZAw8hdjn4sqw-aHy0dWgO5F3W7ASUGMRRSh6hZP_yd5cvPdlk0E4rkYgT1RDQoKBp14vgsky5fuaOPsvP9DxOMlXLhXNb0G1LHD06Y0mG_LeSOvi9nVxa0B7ga8XAu1_fr4PeMv05TbytgkTw9aNZYZmnvkRVxAaN7y67KEHbLAdixjR1aRVMJnFpsO30nWxTiQPmcwyZDQZy7i-5hmp_0KZSkCYiFtPm6mSq1zW_3K7mAOZuGEbvBIxh7gk5ddPptdC1n6rxXCzTFhjHsU7EzHcdZMn3cXauGFvdnlIefT_e6Yxo5LLWNjYL7tOb_4OvnHPHnBHycyvfWKbjpVSILfTFZ1_BdeHyWgvUiqmjfxeZOLED3yJcCLd7KTB9zQcsZ3pvzaGUNqW2fj20dCUSlgwziwHcmI82Qy6w1fOZ3o-rGZLwFWd--R33Vuh-A0oYRKj-ge6FGcft7ut8wwwiPKKv-Z9oNiONzZfFQh018g5sWBRyOzOHJhA0VJ2duNO3AffRZliPZnlIMEnW0lbUycarn_IVM7oTI2EVDiO-IK4cARdsBn0VRczp8cqje9ZspLH9vvpjeRLPRN7QOMGyU1JC0NBLNVHEjytVhr6f8-DHAl3lTUrie4N45QYM91O6reF0lvRJF_Qof-eBtC8GVMfzFuAIUuonIOOFsm5k2ai-7NbqAn48DziTpbl6RoWTPyQKP_8NA2MJpVCi3xb6bWZuO_PesjkAD55mO3zPztVuPEOPyC-8ILMPKbGPRCqAqNTksBZr8tleLrKAa1oWreT57tkpmmxws9flMrlAeSiO7ly21il38fp6C-vgeaxytj03LEuyHT6lNJ7Jc5uMdk_XldS51EUxY_D3B7a-Hk5dhsIjgVtYIfN7BqCQqnd9DLM9C0TZAAZU0TfEaN5UPvDj7UKeLry7PHiXq-RxA2pPIMfzidAsqMgm67nWo3rI1UVHVW2JEq2QoKP15kiFmh9bqIaCE0a1tjwfNsUGOm-plP9bi4Y2EEh98VgMGcQhPHZFxa2jDfolwrfVplmZgXsqnzEOHyoAtXysddbUV4tKy8P-ZWGHWzjRWBrnDLbhbpvdKBSRV2-ICWUeLMGbO9IMRm_JefUF2xKjnnz5HMf4uXTu5njxZGRRcYKji45EhshYqhowFfZnKFna7M09x3e5ayut74N0BvwdoOetYAAAAAAAAAAAAAAAAAAAAAAAAGDBYdIiVbeeroO6LZ-GVQDD5siLxRZ_ZZBIQlnzCNqcp9BTL5zcqYwVxwhFcFDmTJylfozkpabjaMOBkUVkOFq0a2Knww",
  "raw_randomizer": "a2a93fa0937dfd762f9f0f49dc0ae47ef0b302ee523650e36fd5ba830ac7014d",
  "raw_to_be_signed": "436f6d706f73697465416c676f726974686d5369676e617475726573323032354d4c2d4453412d36352d455332353600a2a93fa0937dfd762f9f0f49dc0ae47ef0b302ee523650e36fd5ba830ac7014deaaf875877379af456d4bae371ad49f7118aa9a2540328c05fb3e5e1e0c3905a653104abd330d7c11594a9ff9397ea6a08e6afe9d337f490c82f512cbcd4c8e1",
  "raw_composite_signature": "a2a93fa0937dfd762f9f0f49dc0ae47ef0b302ee523650e36fd5ba830ac7014d4dac3e6f8fa632e5be34d8122b16a7dc599e6bfafe365072bedabe5abe60e1a2d61b6ef498d2021762a73c7e7fbd951c11a4bcb96f84a443171817d67d31d59eddea7e646c13aa711284aeea75d0010c20ad069d3503fe1f03b6f43ff7036b63b368d814688ebee26c7cf446d20a65c904cde375d5f640f94b1cbb05bd57e4d8d139c567b3a9e42116e34c0c6c692a789e77881a4ca6b7a1e1fdfad46df382f038b184cd543886c66e89c9ffa2a255ba9228dd9d931a2bb194f4778b8d100407cb6b3aa1d2d0231d7a0a18f7f17372609fbb68bf8f808a2740b6ee7f5a277e8704992d0eb46d996041a4f9066265bca5a82f10a2f009ac34499db5c17cbaeead4bacf98f1d2d8715e46e076278234b3a6203d631dd3d3157a2427badba9db4c4e0703bc2bfb18c679719aa405cbaeb52a10f92f416de9cb81c51734c54bf2bc6beeda2af7dae887cd64a499ee9e9861e78e6f283fb652307e61c3a211728966064796fbdaf6913e9c5b584eb8ad3d93d6ce05165dc19b84849d9f1258294985cfb9991d99b9eb2c6bb5b34402d612e8c46ed044bd979592c0ad25ffbf2ef0d3e3c5c5417d5d551c934ea9623dae08a14506bd3f25d6b72f4f1a297955c5612823a3c78cc65776a39e2d151d346a0826c9259f041e3faac7488bc29dc528eaa942707f432f75b07ee53a19c65587c6770cd4396a0e6a54def17aee019827caeee75357a282a8fd0c621779d4967f9c1029f66a3328aec3a139d906283609264a5729484edf0ca6ceca8c2216d705bb97dd9a8b6c09ceda61d2bdf86b7be4e9433bcbaa2df6a005d0fc94dc353c130ce341f974e6dca3dba6333352bf5c3f8c94fd9db2b11c87e5603ff04952b53eb075a55ee1ad578e445d81766cf9cc6865a6db4a3ef5544a1b5bb30c99c4fc552c08025f7beadd3994ad2de98ffcb6cd3569995205e1e4794eceabf2648e06d38c425b5764951676c2d0cdb295e7e5db183f40e72f50a8846c385097dc16abd7f390a6c5041279282757c82a14b37aa9396a3d80113a4f9fabc68aa7c00a4873bc2c1e21cf4f0e4c41fe87c2d2d09918e1e83e6c9e1a7d415027300b0692dea62fc6d211939d6759f55b44442c1eade0a84920ea4bc60acecd9c479daa1f21f69b4bd12d8e5113bf2e2ac1dbebe6dd891ad286ba4bd5f8e6f257701eb3d1edc9b7040559c9ea50f39beab55fbb7ebb4a8e9b2e2018724df9fd259e15b0ef639c917296ef4099c9678a90151b8a0092e2f4e2b22285d009564b27a133cff32eb2e33cc1c304e77f637ff9d7ae018170fcc75b773d49c9004b03037661aedb49780a5fdcdcb4fc77084ad6b6ab591c3910c0b37c0a88ec2513341e8df87e3adebaf86d3be4a8f794e8a1708b57baade25940123f94ef8d179b4d1cea194bb35972befda79670d0d460e3f0ce8ffc76a1249bfa894b7ba0ffd010111dc6e1372530fa5a5bbb6c2dd019848583582896fe817a69a4dc5b455d04c2a5827f8cf0781d0e55246d55043201342bc2d68b872b94ee475dfbd819db384e39c95416057356c7490ce78b99167b773ab4154a14d9db88ebea4b239004130da5b629e7138f2e39df8b1e17bcbd47242f081f8eaf3bd7d2bd8ed9068f33f3d9ba2266dde1a4bc3943c35fb3f2c2dc2839fa4ff0d43e4fd01ad167e9a638fbd5199b73dc61da0b12146f35c7f82a49957f2a95de747fe371b9c022bf037ea804c2b204683ed25841cfc185c67328ada43b77d93642702f7d1d6122c4dee4051c0120fb3e245b7649fdeeb930c60665290ee8bc5ca48b64713b875eb933d1b0e9239bbe546fd575f34d15f416056f85e5d93cc234f1383f74ef84b3b206772857ede6bde07753925246d46ff122609b730d916a17e3603533dc706367133ef5ed0c8ac24d6d72e70dd1a4b64a7ba9bf28668cbb956d71014806ba88e264ce87eeaeb416f104e8959d995dadaf468d07990f14dff04b71ceb2e2ec9891949e41644c34c771f0e642dad624a83d119d3c18e8d78058ec360f164db8d260fff0d27e7e5c8b034ac673e2fe1862307c20f5149058df6ae4e73ee81403cdc8deb1c575bb0e4e87814a6d5716a2a8116789ba1f040cc606b91d969f63d4ce48c1fa90e6233c6be2d465a8df057499808580de867a19c3f0f408dda897b8ac0d1a66fb758a8fee985a22fde74e788a7fad3ebe607c4f0dc29a0a3d529b5c6387c17cdbce6ad9fa9a61bc0ac5ede7683b5fb11fe5e7582942b15947e09308c58e752189bf15a8809b75a6eb332a770989699228159fd581a02b8665a16a115aa63210231c92a95e2faa4416b29a9d5b6720ac16b279969298fa7b03a898ba74ca659ac10b6e4ac4e663701c09fa5b9efe6487bab4a324b9e204ef1aa34d30c58bb2c60d82514e1a2e00dcf3daee084d3dca94a36040b22fbe86f3c1688ce8b2e370e51e83252282b07829f07367b07dadf3bb0a43619956ddef230e70e27d88548816d700f423f53b72735cb62f47b1dad0680b8fa32b888c064c35e0379fbe6ce4ba6af67194ab8ce2d5b3c453e7f4bf644098915c0950952ef2f8a15fe797822dc62dea74dccbca773c7f8e09f2044acfd24fa4b07d1e0f45be8280bf9c0d3ae2726fe4145b118b5ddf794375e8c92da7d82b0f3ce822f51c17326e16f833769ba66cf42bbe73410f0c04f251d6aac66a66aac68079343d0dd16e03a86204881cb6df77f6735f26f51d92f31e11ea38f39ea3d42e1683f2a0d6038e097132e128223d1bc2f68dc3f8089fa6700ec854d1a662eb70940d33229771c91b23736f50b76e4a79b03675048f7de9ff85d801d634c91e30addb2480ef13661fda7e2b721372097db3f52728cda3e84bc21a1d8b1dde5c802c72fd0e09fba1ce32de858beec84f438cb9129f84d04ed33cdc21e01d754a2eef8062c9ca567be0e4b18bc71e1e4cbbe4095f355863e15591eb24e13c43c8da06a2edeb9c42e1794abb55cb7bf3e0aab54c64d327026935316d5499bba4cb8b42834a4ec1260cb1d89dcaf6aeaf99880031f75cd14f33bef8d84a2112d351ca271fd7e804f7f27d8588b173f648cafd7b1f049820ec19b84df3f51599519c17073527a099520195b3d8c32f261d3bcae19005657f02a0e34773692353784c4666d69c9cbac9aec667e410b925a0812de0f335d608950dd08d5163998b79d4f7bc168182496a3c3a489d06fbf8c9972a1a2155093a8b72a380fe73655bd1147c784d9e3c3b752c2574ba9cc69618b01d2177dd182a2dbd99ddf6244b118918395639a785f02b98ae3ca1908dde714e05c6758d2bd392944c2afe396747379515243bc5d0f77b9230a8c23b6a81efa9bd6a9bb6edeb2f47035556b008e8d359030f217639f8b2ac3e687cb475680ee45dd6ec049418c4514a1ea164fff277972f3dd964d04e2b918813d510d0a0a069d78be0b24cb97ee68e3ecbcff43c4e3255cb85735bd06d4b1c3d3a634986fcb7923af8bd9d5c5ad01ee06bc5c0bb5fdfaf83de32fd394dbcad8244f0f5a3596199a7be4455c4068def2ebb2841db2c0762c6347569154c267169b0edf49d6c538903e6730c990d0672ee2fb9866a7fd0a65290262216d3e6ea64aad735bfdcaee600e66e1846ef048c61ee093975d3e9b5d0b59faaf15c2cd31618c7b14ec4cc771d64c9f77176ae185bdd9e521e7d3fdee98c68e4b2d636360beed39bff83af9c73c79c11f2732bdf58a6e3a554882df4c5675fc175e1f25a0bd48aa9a37f179938b103df225c08b77b29307dcd072c677a6fcda19436a5b67e3db4742512960c338b01dc988f36432eb0d5f399de8fab1992f015677ef91df756e87e034a1844a8fe81ee8519c7edeeeb7cc30c223ca2aff99f6836238dcd97c5421d35f20e6c5814723b3387261034549d9db8d3b701f7d166588f6679483049d6d256d4c9c6ab9ff21533ba132361150e23be20ae1c01176c067d1545cce9f1caa37bd66ca4b1fdbefa637912cf44ded038c1b2535242d0d04b3551c48f2b5586be9ff3e0c7025de54d4ae27b8378e5060cf753baade17496f44917f4287fe781b42f0654c7f316e00852ea2720e385b26e64d9a8beecd6ea027e3c0f3893a5b97a4685933f240a3fff0d036309a550a2df16fa6d666e3bf3deb239000f9e663b7ccfced56e3c438fc82fbc20b30f29b18f442a80a8d4e4b0166bf2d95e2eb2806b5a16ade4f9eed9299a6c70b3d7e532b94079288eee5cb6d62977f1fa7a0bebe079ac72b63d372c4bb21d3ea5349ec9739b8c764fd795d4b9d4453163f0f707b6be1e4e5d86c223815b5821f37b06a090aa777d0cb33d0b44d9000654d137c468de543ef0e3ed429e2ebcbb3c7897abe471036a4f20c7f389d02ca8c826ebb9d6a37ac8d54547556d8912ad90a0a3f5e648859a1f5ba886821346b5b63c1f36c5063a6fa994ff5b8b863610487df1580c19c4213c7645c5ada30dfa25c2b7d5a65999817b2a9f310e1f2a00b57cac75d6d4578b4acbc3fe6561875b38d1581ae70cb6e16e9bdd281491576f8809651e2cc19b3bd20c466fc979f505db12a39e7cf91cc7f8b974eee678f16464517182a38b8e4486c858aa1a3015f6672859daeccd3dc777b96b2badef837406fc1da0e7ad6000000000000000000000000000000000000060c161d22255b79eae83ba2d9f865500c3e6c88bc5167f6590484259f308da9ca7d0532f9cdca98c15c708457050e64c9ca57e8ce4a5a6e368c381914564385ab46b62a7c30",
  "raw_composite_public_key": "424b2f267e58d5b3b44d71acfc6a656bb26950d57c61db1c880bcfa1feab443f0942ab8bdbad7d708abbc356078f6d99a252271fe62c74091eb94afb9b9264c50a888e0dfed80cd5fb2cbd3667e60d539ebe44930219cd4faed15dbb3455a264802b9f49bce42ee7550feffdd4642a55ade693868a460cbec03f4fc99a4e30bccffa8a475e5395396674ebb81a94937587880f6dbd27bf1c4f5a9ee43cdd8b0e53b3b7fb49c73adfbc2d4f8c54303520c29bf97e26ee57db342d957c893936522d0942b41d82ee3772a00570adfb545c1143922b0496f826a0a970064b36ddf534b5f8e1c1cd0b5565ea846b45431f0618143ece89777bb3f61179ad20295fe0a6e062ae6eecbc2ef38f2ac1a22dc93b7b126336223c55b61eb8c0795542bbb2dc65e722eadc6866ffa9683beb8a999ad7a83e5e6e016c2e4c35f6f7649ad3bd52ec67ec1c5c6e7b9972771218be9554bba7727f0b84c44b9b0a8bd831fcff2c9779ccd4ca30c6ad75b04983e41de893ee5f39ea7355180b709c7045c22d33a083f6ae07a114746d1bfdccbee5b9043879bb5a2e120e2a4636283f4a1cd4924a2de6a4aa3d99ddd88f48aaa4e88bfd1ea769d82c10779f2ded796db542971ca289b76863ede5997b7e9ce183b43ccec278b10d92b87442ce0435bb1625171db5554b470239c50d2a0c3a41b2a38807db070b47bfb3e7d10f3cd979d69963c8d79f8029cc4a48eb04fcb3d708844febaa8b6ddff01ab64d59358e6505c4ec1d7cbb14ed2212df458ecefc03fe03037b1505a4c9444322f5f98dfa91a4cb8c45860a2dadc7515350bb6d431e49a6bc8f5ba956e682b0e513321a97d1962602891c9078f62a8a9646a31387a6f09684264837899e0d8ec7d11c565901298b20b345081690eb4c562c1aa3a25bef06566cb34c79bc0b25e4095d6ba793e81311e41a3329152686f00d4897f84fc4edf4b26d545365785ead8d63aef64a87c0b91a2e5500383956cdf5f6e37cf9d5482d1c8e3a5be38f17259ac45c9fa1c4bd3bf177d312ee52a6da023c05722a8738274dda8d1b04e99831cf57c87282a256c565c296d0524a063a3a41a48a83009978d98d8abf61af68e8013b594fe151d9bec199902c4c70b49584201743c6b53103d2fd24bdf078dc90b5a188b4f8d772179988d0416c94d4c57c0860b9d7b53d4cd261f332a1851565d52ac37f008747cafe320f363d9beb6e4117db43fd8aeebe5e0ce2f54e3f0367eb3cc971bbe0c301a8e52f96094936035c6ee3ca2d13db483a0dd04dc16247de0e0894ad7cb7e1ae7ebd4f8f900582b20021e77f70254501c6ac3dd15d43bbb7931c5283244312158c2eb1b3e1117e194f0a1e4c783efbc62c9f81c21562d0d34a5f042b5eaaf32f31f95c5b055f4e7a2070fb096f56c415549cde74f3864e8b9fc27e3299724b4639986044b55928fd6972785b280c25a3e21aab814ecbfb0c3cbec0914907ec907f25a1d88bce3d319ae8222a35945db62af7cc75cd29c1f5d98fcb93f750dc3031076979bb51dfc37d23e8eea78073a24d3e26c68e7bb10e459f2577b90080359ae0aec10318dcd9e0f9e34029c31b3e54b1855645db420618783346dad5b55eddb4f977b326a655525ebe2195eca9cec38a3c0d2273b77d3e68f1901c2ca5149734a51177bcb089476b18cba09fa8b9b46d94a2946f358e1decb1998652c58a90852423e2c85e79d19724461627e6390d1a81fb1a72f9c7edc4bd747dd5c85217b5856141028414ddbe71458f0a0b2b589df2e1b051783b8f718676b1defbae98ba496c2a935e92eeadea0a8393ef59f9e914f0743fe65640ddf9981cea6dbdd957a534ad4e790efc974ee89938ad99d53c5b680775399326834729bb37b082e795f8d87f52e6c8a8db68e515c277bbea82a7570d4280896c987a0608903e306c632a223c55f0ea3682039c4a3f5440f4b5ac3e6ed2b2dc900cecc72b72f50e49b2629ad30f0487b2707b86286f8c4f55659b25f9bdd7a6af460cc3c57a3982663bb717461581e196894929d84153d87a7f482d284b5b894ce1a78216b2a011f2b88742cee52d5133e8fe77edae242f5af91637c37ffca32430509b2fe4756303a9a3659fe32528af1e10d8d43bea991b2d109786cc66d35b1d78df254b92cdaa40f91a987e4a922ca81050e5bc3530ca85493bdf2a825374d0a8310a6860284ec3ec732326eeeffc42bbd42bc91b73e5e7c6b599d016490637629f3876c3e42f8db590e66a85a7838c818f78fffb4853cbef09434989803545dca87657cf7c7e7e6afa71382bc10fa0bb6480f243eea1b861101006fa0cff3275621943cc58eb4dc3a0428a5e425670fe82268de71c511d8ffbdc11b0d0f961120e971015ad5f448886b802e3fac11672319d487c84f1001339cb969784cb57344f2807f8b425f1d73caf8496d742ed237f4c9fcd5a4e84fba7e27fb1a8ae12c4f0427ae24e910d951bd8c35d61f8a678db01caea8ef789a95b62ee1b8c5d32c6baa536ba88a1070ea61aabbf59294e3f6f974c4c91cafc5bbf6b7ecfd57a18fb7557d71e06e900d281b0b49aa00feabb35714af33870edd7ac2393d93177f79ee5606c9df176f025ce49a6e5ff51a2a412ebf86ac0f40471c96ad4c119df230be6173df530ed656cbd8069214741ecdd0271c603fb6c4a8614ff878d33e726cac6693e938ca3fba82c4995c14a2d4af9014fe4c4c50b794cac596b52189f66a7106fb325b526eae14d32a687b7a6833acf60c81805449dc7a79275f2741a9a72f73af5c035a3cfc315b5f9b96bc9d7378773558c60bb31220cad7178ebab83f3c71adaa16aec2e"
}
~~~~~~~~~~
{: #jose_example_ML_DSA_65_ES256 title="ML-DSA-65-ES256"}


~~~~~~~~~~
{
  "priv": "0000000000000000000000000000000000000000000000000000000000000000",
  "jwk": {
    "kid": "2ZLkivrjerxTjBM5LF-YVxa8hZBAYip2rzxPSWTKQCU",
    "kty": "AKP-EC",
    "alg": "ML-DSA-87-ES384",
    "pub": "5F_8jMc9uIXcZi5ioYzY44AylxF_pWWIFKmFtf8dt7Roz8gruSnx2Gt37RT1rhamU2h3LOUZEkEBBeBFaXWukf22Q7US8STV5gvWi4x-Mf4Bx7DcZa5HBQHMVlpuHfz8_RJWVDPEr-3VEYIeLpYQxFJ14oNt7jXO1p1--mcv0eQxi-9etuiX6LRRqiAt7QQrKq73envj9pkUbaIpqL2z_6SWRFln51IXv7yQSPmVZEPYcx-DPrMN4Q2slv_-fPZeoERcPjHoYB4TO-ahAHZP4xluJncmRB8xdR-_mm9YgGRPTnJ15X3isPEF5NsFXVDdHJyTT931NbjeKLDHTARJ8iLNLtC7j7x3XM7oyUBmW0D3EvT34AdQ6eHkzZz_JdGUXD6bylPM1PEu7nWBhW69aPJoRZVuPnvrdh8P51vdMb_i-gGBEzl7OHvVnWKmi4r3-iRauTLmn3eOLO79ITBPu4CZ6hPY6lfBgTGXovda4lEHW1Ha04-FNmnp1fmKNlUJiUGZOhWUhg-6cf5TDuXCn1jyl4r2iMy3Wlg4o1nBEumOJahYOsjawfhh_Vjir7pd5aUuAgkE9bQrwIdONb788-YRloR2jzbgCPBHEhd86-YnYHOB5W6q7hYcFym43lHb3kdNSMxoJJ6icWK4eZPmDITtbMZCPLNnbZ61CyyrWjoEnvExOB1iP6b7y8nbHnzAJeoEGLna0sxszU6V-izsJP7spwMYp1Fxa3IT9j7b9lpjM4NX-Dj5TsBxgiwkhRJIiFEHs9HE6SRnjHYU6hrwOBBGGfKuNylAvs-mninLtf9sPiCke-Sk90usNMEzwApqcGrMxv_T2OT71pqZcE4Sg8hQ2MWNHldTzZWHuDxMNGy5pYE3IT7BCDTGat_iu1xQGo7y7K3Rtnej3xpt64br8HIsT1Aw4g-QGN1bb8U-6iT9kre1tAJf6umW0-SP1MZQ2C261-r5NmOWmFEvJiU9LvaEfIUY6FZcyaVJXG__V83nMjiCxUp9tHCrLa-P_Sv3lPp8aS2ef71TLuzB14gOLKCzIWEovii0qfHRUfrJeAiwvZi3tDphKprIZYEr_qxvR0YCd4QLUqOwh_kWynztwPdo6ivRnqIRVfhLSgTEAArSrgWHFU1WC8Ckd6T5MpqJhN0x6x8qBePZGHAdYwz8qa9h7wiNLFWBrLRj5DmQLl1CVxnpVrjW33MFso4P8n060N4ghdKSSZsZozkNQ5b7O6yajYy-rSp6QpD8msb8oEX5imFKRaOcviQ2D4TRT45HJxKs63Tb9FtT1JoORzfkdv_E1bL3zSR6oYbTt2Stnpz-7kVqc8KR2N45EkFKxDkRw3IXOte0cq81xoU87S_ntf4KiVZaszuqb2XN2SgxnXBl4EDnpehPmqkD92SAlLrQcTaxaSe47G28K-8MwoVt4eeVkj4UEsSfJN7rbCH2yKl2XJx5huDaS0xn2ODQyNRmgk-5I9hXMUiZDNLvEzx4zuyrcu2d0oXFo3ZoUtVFNCB__TQCf2x27ej9GjLXLDAEi7qnl9Xfb94n0IfeVyGte3-j6NP3DWv8OrLiUjNTaLv6Fay1yzfUaU6LI86-Jd6ckloiGhg7kE0_hd-ZKakZxU1vh0Vzc6DW7MFAPky75iCZlDXoBpZjTNGo5HR-mCW_ozblu60U9zZA8bn-voANuu_hYwxh-uY1sHTFZOqp2xicnnMChz_GTm1Je8XCkICYegeiHUryEHA6T6B_L9gW8S_R4ptMD0Sv6b1KHqqKeubwKltCWPUsr2En9iYypnz06DEL5Wp8KMhrLid2AMPpLI0j1CWGJExXHpBWjfIC8vbYH4YKVl-euRo8eDcuKosb5hxUGM9Jvy1siVXUpIKpkZt2YLP5pEBP_EVOoHPh5LJomrLMpORr1wBKbEkfom7npX1g817bK4IeYmZELI8zXUUtUkx3LgNTckwjx90Vt6oVXpFEICIUDF_LAVMUftzz6JUvbwOZo8iAZqcnVslAmRXeY_ZPp5eEHFfHlsb8VQ73Rd_p8XlFf5R1WuWiUGp2TzJ-VQvj3BTdQfOwSxR9RUk4xjqNabLqTFcQ7As246bHJXH6XVnd4DbEIDPfNa8FaWb_DNEgQAiXGqa6n7l7aFq5_6Kp0XeBBM0sOzJt4fy8JC6U0DEcMnWxKFDtMM7q06LubQYFCEEdQ5b1Qh2LbQZ898tegmeF--EZ4F4hvYebZPV8sM0ZcsKBXyCr585qs00PRxr0S6rReekGRBIvXzMojmid3dxc6DPpdV3x5zxlxaIBxO3i_6axknSSdxnS04_bemWqQ3CLf6mpSqfTIQJT1407GB4QINAAC9Ch3AXUR_n1jr64TGWzbIr8uDcnoVCJlOgmlXpmOwubigAzJattbWRi7k4QYBnA3_4QMjt73n2Co4-F_Qh4boYLpmwWG2SwcIw2PeXGr2LY2zwkPR4bcSyx1Z6UK5trQpWlpQCxgsvV_RvGzpN22RtHoihPH74K0cBIzCz7tK-jqeuWl1A7af7KmQ66fpRBr5ykTLOsa17WblkcIB_jDvqKfEcdxhPWJUwmOo4TIQS-xH8arLOy_NQFG2m14_yxwUemXC-QxLUYi6_FIcqwPBKjCdpQtadRdyftQSKO0SP-GxUvamMZzWI780rXuOBkq5kyYLy9QF9bf_-bL6QLpe1WMCQlOeXZaCPoncgYoT0WZ17jB52Xb2lPWsyXYK54npszkbKJ4OIqfvF8xqRXcVe22VwJuqT9Uy4-4KKQgQ7TXla7Gdm2H7mKl8YXQlsGCT2Ypc8O4t0Sfw7qYAuaDGf752Hbm3fl1bupcB2huIPlIaDP6IRR9XvTYIW2flbwYfhKLmoVKnG85uUi2qtqCjPOIuU3-peT0othfmwKQXaoOqO-V4r6wPL1VHxVFtIYmEdVt0RccUOvpOVR_OAHG9uHOzTmueK5557Qxp0ojtZCHyN-hgoMZJLrvdKkTCxPNo2-mZQbHoVh2FnThZ9JbO49dB8lKXP4_MU5xAnjXMgKXtbfI8w6ZWATE_XWgf2VQMUpGp4wpy44yWQTxHxh_4T9540BGwG0FU0bkgrwA_erseGZnepqdmz5_ScCs84O5Xr5MbYhJLCGGxY6O5GqS-ooB2w0Mt87KbbE4bpYje9CAHH8FX3pDrJyLsyasA3zxmk4OmGpG7Z70ofONJtHRe56R5287vFmuazEEutXn81kNzB-3aJT1ga3vnWZw4CSvFKoWYSA7auLgrHSHFZdITfOrgtmQmGbFhM9kSBdY1UCnpzf65oos3PZWRa2twfUxxLAnPNtrxpRGyvtsapw7ljUagZmuyh3hLCjhAxYmnoE1dbyIWvpCqSlEtVjL1yb_nuLEzgvmZuV02fHxGuWgHTOMVGXpf81Rce3eoBK3lapW1wkzezlk3tcA2bZOtA9qbxdsbVR37kemzQ9K1e3Y0OWhtSj",
    "priv": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "crv": "P-384",
    "x": "G9WS2mTk3bYkdgBV075Kt2DLFH5_2vJujAu2tKVGaMd_oIIHEZx6_bo-m_YsWWjP",
    "y": "DZYVj-vQvAfjzPak715BeJkcmbwKtDetVrZ4UMVZYCFy4ZS-D-tsRTyLjKLE5Gym",
    "d": "fhRKk-EHiD_kQdjgIV3pfG2ym8PrN6BBAEj7Qv4DODnuzZ_21-iZwx5UAJyXX5dZ"
  },
  "jws": "eyJhbGciOiJNTC1EU0EtODctRVMzODQiLCJraWQiOiIyWkxraXZyamVyeFRqQk01TEYtWVZ4YThoWkJBWWlwMnJ6eFBTV1RLUUNVIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.I45qfSQnBtqqfzdq5uNCq4tMypEwVoHHkGDTjFzBr49b6kpBS9nnO81sM6_-pe43E-gzFJrC9AANw3TOn_KLFbBwo3i0s_sWe99QYKUpJCwW91WR6wz0JSAfOAdhh9wFB5KX8l-M2QzRyiLkkt8AsjxqYssfb1AZsWsWKmtrDBIaba35jQ7Wtd62ORFK9s49w6yVPFiP2wD6rPOuMFqOJqbtiza-LgKlecsQkS1G1_pks8Qyz5L2yD-iXNJzWHnwlubjx3POkZgmsHRdZFryGKLym6CyeivjvC6awVqj1HLeCQlFkcnbwUGDkjhsc1jvHiXNoU7IyQBIOF9VtdGfgIwUYJoD0L_Nc1zovAYO8m_MyPsJqQiMWbB9yyv4dbRtv9rFuywpjPlmN2fsDTNnZ8mjZP3tSTrLxBa2us8do5eZOXoh1vhCiolH05JowdinL3asPMlqyhAh6KJNx51r1bzt0hK9lu-v1JTy9Em_wBrdirLRZ8kSxwAx1kjdP0bJumsslSXOnV7JiyaFlpQLtBxF1kRRjiOVRr3VFZFqKtceIgnR8m6MHQQPEkOd94OKAh86G_oglW0i83s-SHx5cQZMu2IdM__4ZFUt0BWErlIx-5cYs4hNk0HuRgmS94tK62zMgMR8TIV-oXBgq7ukHxycO6BbgpEYACPEs4fpHA3cLDVkAcCS3PepOLjoexWGsnPaJCnAMsCq2NeRn85r7yIhkZa7faPossZDt1E7N_yRE_OwA5po4vs5L4cAoJO43ZRO_yrNDXWqSRCkIrciDteCaxmb0pkoFmxAvRoq0s2vICcF0iexeDwHdsGHJdLHT-B_QN8tdM1q-2aDtJRk50vC132sXX7PBMQW44EYzFL3ujNpQgwGXseRJfUXJSZffpfZ9tlkalS3X7429AN5FN71PK3A8noReGseXFgDewRhhrmQrzst5T-uTw3mcCoSkf2Lm3qk5MF2bZXf1Hk54Zfg-rYH3s44TmTBIk4Q3qpJ5QPvpet8-gtgo9NTcMDe2hdgjWdPSsJrcpXu2DP5h5fVFVEWwkI_rztWzvAxyDQ2Nv1iUZYkqQYGjagkePQCutTzobxsHDCcXZ67aeusYhtbi2v5mdfh4GSjeQ-7F97BxIl6EgL5cXO2-OxjZPon-UOpB5BCiFLdD0yYQujh6bxGHdVRQNTkSf9Q5LTlCC5mof-V3LQdbO21kuzB2Z8bApPnwk-vmcfwQf6PokgBMLvrLdl7Rtj6KJMQ_Jfv4AtH309mOTYs7uCORMzoflneFcIe4W0l0qIpEsU9kSU9zTh8t5kjXCmAqGvCIrG6oaw2UHm1kSMorhBYZonX3k3L5HthiV3DhEibwicy1VbvnIQYh8IFXsh_bjZnJYmb5mxfKRBtlVmbmEd2Nx4zX0de4Nul590PkML9oykyuEYQ6zyf9dnWCp-Jd2B3wt4TCS6ZOduyIJA3CGiWmMoKLChMYP4uHaHhnnorFcO9VZUyleyo8-hPdbl2brKPYpS9ur6tCoRDyXjO8jGF6CRHsRf25TXbfdf0eZvdyAg4PRsfuMdLEwzs7eoGgjk4D9_B1w4e0vsoYO_iQJIY4mfkY8Il-C9Ei7fEwTiExLQN-UIqLcHw8YkVu666maaIMbIwr-m68VqbER6aoQOE1U9Csxj_LLVwkqvHwGm-2L555F-DOUb8i4PQYNtfgdxHUhh-Cj2lgsf2n8em_Ixw8WC70JSAmsNWWnHy3oF_7APtyAay3oEWKeZiUnioLN0ZeqgjkVgeiz16GGHY3FFIeO_Cw7TDLXaE_L-t3xZ6_E_sJHvPc3jK65y6cXlBUQgQAR5JvaHLrIbBgJtMxAEWQxz1HqJuvaCExyvOMnMc0SwfTDg3LgjtkEJGmCrVzGQAXDHev02kYHPU_pEqEzA2qGsl8hsJ1xubMje2M9EWkWEJt1u5_MQPxsEnZYY7SacojenxORYAKSIfVizIQU53Z7QAhuzTwA1khrX54poU8_XDlZ7Uf4F0R-xk910ciriWYuNH1ObYB8376RoqOQFX_BM0gM_G3SLkdNIxKYEWDy9p3fvKZMgPx7Kt4kwzFREt17NXgIQo0wfPXbDF8I6gv0ywE27RITCuNxNjf5zO0e6Xk4JWsvmwXnPSEjbyq3wWYxGHLLhjMyA0jBBsWTqGyP0jQu1jf8wVfs6pNW27G2vczxNcjjfkHB8CBtBW3mUVZWrrNct-9dnsrm4Ro63Ko_U9Sznl6z-LNrmzVCWHP6ge625aTfi0LWu9KGhVdny8E6cliERpKr4NzBuC-OJH6fnTgc0I2NBifusbMhYOy3FTxiKCGp9tgVHcoryC_IGgv7eHjPq6XMRlwdkO-W-zrQnpLdF5huvjPjI_z8d3b8X3ieHM_hEP4yo2lND_aqSpHg2dwGlTTZo3GLMnCMgLFAdP2m8J5XlUWAqzHlMvTOGbJbsBs-aWC6oOG9b4nYbVPxC29jAeXqn_TZDN51jYXshXYC_3cLDRzJw6jMgHFKSPGfR3o0QoDuGRYX_dvyDqNm5UVNVQPDqwogSMzm0imLhbA11H2ZZeR55Le4a6s3Wsc99hX8NN3GehIBb8c4OscHwT7dbBZ9CgMS1Ax0UIFQ6TQoM5kKip4z0HUOI1jCkbuCoVY5zUJhYdusBHFrGu_gM8aYXAl02aFLeRxeiLS_6zR_dBgujP4MNiCwnnmdNg3UmXRd7B1w3Fy2sDHhrXRSfbK3UJODH7gVSNRuG2B7p6d1sEjbZH2ABmDDeqbpm6a55FhdzQ3s7Sbh-C_aqkrcxlkIfSxqT_3MMnLlILt75NMzCgN80jOrLzQLi-Vt7rYqu3c8IPUSeC_m6tKvoAYWw3x_HpDzLEWTeB5xrklkvXQ1LsuQ6Ej7bKSi3DnIBAkQ1VvhPdLmzKsA93qwkzOmQjkuihw9UWs9zT0qsT7fs1V2QcK8r9zcm40pgbPrdJd8HdMiX1GY0DxhpRVN_NV2GnwQu9lMWPWpTab8KOGLZJ_l3a8OKeTPu4Nygp566FpGJO3xYBT3FvuLMJC7CDEefY1SmWmXAF1puiIKPAahtKKir_WJM43FU5WHm2sRSyGHFc-zEGw2eCBpKIF-udvx2YsnMuIkVdEtnlKp9lwNwJhJVla0zqzndLIdzkbydjW3VivC3JEzkR3CBasMcQnhrGCo0fW0fg2wLNvkX4CL32bgSnpyCL2Rp7fWlDDUjeuPvKjuqVCaQCYLhCyF2Lxkecag8aH7xFqi1TAqkGV0B-4X1wJroPhL_vVaMi2EDBwBNijiyD1YjteBniaRrMGp11nhDgtuKTZELcW3tC4bigYTV3Rp-rETAEVZhn-TgDWRN7Yqv5zQald7pOX73Knh7fXw0cg17QZALnEkH0ON2Ty2Sh7B3ohmBiCOuQidDhr81k41yR-qTYX8Zq3rRn7oSG4U0U2ZOfsVnKWiJd_upxlEAnJt0EgkoSLgRGrTV019jbS-2dUD2XixtMtta_hK-kATOF2gSYv5y-7-dPuDo3JdXGsk0r1UpgEjsPEn9pFwxZ0BpRH8pPwHgvTWsyQs0t11Z_j2XbKc1KzpBqjpohr1D3Lst2MFlVUfCgVTwgitaEbDUzIWMGuG_xB6d6Okq50GaEs3x_t4D3Ssa4bQmP4dXmYmtQy89Ke49vDeBJQiuP-pz6BqkZhML4mhKibtcB73e31k1OP1o8xaf2NEqF9X0GJBaHQT6DJ7bxJ4zJj4aLMPmG51Xx5g5--9IohlOwCD0zbunTU7aPbmhhpHIw1RwB8bgVvubGcL66m1IhALWpwALzpUFLwyCF4qSCALc5BwH9J3lA1fk5yaUaJpMDFGXCcMihMwJpH3MzrzM_lh0yV8LtCOgtSIeEtcKnOQTpXK4-TyKTK2Db5v6Sx4WyE_AmrGQU76qx1auACI9HcCLBT2ylw8tRWn0csk-XhxDaiI-QpfdZuiRoUbIHgyr88HTbwWMolByljQrWhaagM5ZHyemJWEJdArJMXPEWAuxP5HgaW-KOKYXHXAsuA9JvViPpjAakL80YoSG3OVDYpWhHhYFh-dWfeg1MPK4UeoBHYTcBz_xb2awfwP7jm1dtEjaSBbP6V7vlypYPeLGAIjNFjNivSghuId5_uIf0QD2xztFL2ekE4bTwf4BzJ0ArjWb9KGWh0l2dhSuLMEqT4fbkC8-3lLe4xNkg406WysGWSIVDYyT21X9AdY_jg5DVQDN_OxEwHC3rLHEq4Pa_0dROleMIwRSboczVYJPzgE4p3Ub45h7DV8-7NiDi00djfuRafFEXMEGwcBHfBg7JAvFmVabfsvM5T_Vqfw_K9OY-NWLjO2jbLV195EwPnXoqS5kKvIJ8gRmnCO03s39A3O-JpI-3jDZUdfKp9-k6WvyXR3r87j6_2kIbRqRHUHOSLrfVMlEN8ffILED--k50CwCB5k-7dSrhVTini0psogFnNsUd_UZqNiUQvFhZARoANQjvAexYxRjcvm-0yJQQZJG2zwbTKLGkdNeHrAhVVkINmin9i4rC_aI7Id8SeFVlBsh1QxxKPXTjnXkAcXHKrOIvKwcVIAuzmQrO0wnDajMvp3aCa0-CQwf2foE-neYlgMnflgJfnrxRVROwxe6Xo9gMpnN9Hs6YY6gkthdKSUiPUWBLE3rtlSOezamLlHdjhHyw8IIIcqAA07wxI4aQXC9QS5tx889XeFXWpuWMjuHR5LEq6aV0MsHxXP4REQapoGPpLz7yCZEq8TyBpL14zCZlDzejyINu_0tErgXsanaO7JaO6FhH56brtU-uIprpO-AYTo9ky9A9aHM8Em-HpL30rZJoCLkfKTP3M47yx5sv_aNtcFnEdo6jggFzT_DuixVSeUpOLOHDtMDOvq1JOKgjJMmc4Nd26ysYNxi9L8hVr78ABHoUTqHIkp806wtD75wWEOX4oTK9SwUW7DkJ4zATj8pqa1On2_JcujTd3JEVr6dzPcAIWgLAP8D649sd84XveKOyyt07k_AQCyPf67MmP9gGFgK_Yom9M8oJn0jxna3kFlwZlwgiZxIQVXTGHlRuAnVm16ImqJW0dqSe4vjcCzQQdJRb75SWle50lKL4bxqXRaW3jzC0tT3SQlFq8D26LkQOYsKF6KW-cp0vrrbu-RoAReJnoAw-C8FmYCZ1FGUd4eeWcYHBZo-mzjxk3h4jSo-1XLMsYXYZnIs_FRjcEQYP-qW5PNntf_6ZSAOoQGXZnjksWLshlyo8m6Sezt0Xzv0ff1TQQmUKKqs-eUAVPnBoWfy8nOZLRb0P2-NZ1J756vzZhGDbwSXKjCfl6m8mrLaHTr-yHSnCBwTCM3zj0K9Jtlm6iU1Wre0Od_e5sp0iAsmiQvu4KlPZDeW7Z3gaahY67UIfs88LsDhJ8GBOVFNjRyzf427X452IGXgqbYMcxuMDxeJDq8OZ7BY2j5EoolsfFCii1XyanqXY2notvG15I4PuK7pnnQZZoE0gvaaX25z1CAXkfuyozreAvbdubFzi5OWzsdGAprPETnnBonEcGkI-wLfAB7dVexbvnQYVB6pGeYvwB2vXbx1l4S2vOMFYdmMNYj6EO6k8N-kKinshVG_kpq5piPMlmOq41iAg2gNjkY8Yfrkm7e1H5ovwhCnUWsdFvOHbDDjR68id4pDO4xt0dJv1BXLIUs8IJEydETAJuWaCFE_4_Tqqgs1AxLZjkKQEkNgD-FxiXyTd3NFvkfY7g-z4r0k2_LKV_fe_SsZ8flEVzOgErtob3Vc-FYeupFrKbebm1imrOKgOLKMLj_pWdClAQPVTWDeoexJP0LXQXrscLx_0QaVRbGeAbj3u58YyHyyuPPoRY09ivAMiPY-ZRRnir7TURK2bWHn_uejvJWeAKyPTwnpuPMRFNPDWQ1wr5Tye0QmTXp07OPnB_BN-OAjFM-m_RNfzVzy72Lj-o0c7h8qTARJOAV5NTjP2rCxMsvnx2fkgs1hSZnlheUXPLsr3Y5YFf6VJ4WEvO_sBaku1ptnV5KRWMpQuMk49UMzpkkrokYr7rP5E6RpQP0GS6-717Nxha-1sx5WnGQY86rOba2bFQ08NulAxPvYOLHYv4fiVqNK7JDxYmhYcIVF25esMNVZdaWzaSmh_obk7Rho3d6Ws5WNzgpXL2uXuCStob3OOlKWssMvfGz5BV2t8jZS45QAAAAAAAAAAAAAAAAAAAAAAAAcOExUbIy85xntcuTatyHeRT6GB43r-uSch_ZOTTwjq9-0a7gvVsX2-XPmNTwhwEb_DSRLQIL5VYeW7JDJ-q5PsRVoPRese2bR0bxy062yCYgLH8qFV-0_DMUJtgTZTWbNN4G1fkfov",
  "raw_randomizer": "238e6a7d242706daaa7f376ae6e342ab8b4cca91305681c79060d38c5cc1af8f",
  "raw_to_be_signed": "436f6d706f73697465416c676f726974686d5369676e617475726573323032354d4c2d4453412d38372d455333383400238e6a7d242706daaa7f376ae6e342ab8b4cca91305681c79060d38c5cc1af8f332c7a7f11cd6c6906b789dcfa84fd2a9eedcfa67cdee6c8f157f0960e9510f9f7d40d079ba2fa7d3db8d78cd999182a9eb73a41290ee9061d83e3b08ab7c9eb",
  "raw_composite_signature": "238e6a7d242706daaa7f376ae6e342ab8b4cca91305681c79060d38c5cc1af8f5bea4a414bd9e73bcd6c33affea5ee3713e833149ac2f4000dc374ce9ff28b15b070a378b4b3fb167bdf5060a529242c16f75591eb0cf425201f38076187dc05079297f25f8cd90cd1ca22e492df00b23c6a62cb1f6f5019b16b162a6b6b0c121a6dadf98d0ed6b5deb639114af6ce3dc3ac953c588fdb00faacf3ae305a8e26a6ed8b36be2e02a579cb10912d46d7fa64b3c432cf92f6c83fa25cd2735879f096e6e3c773ce919826b0745d645af218a2f29ba0b27a2be3bc2e9ac15aa3d472de09094591c9dbc1418392386c7358ef1e25cda14ec8c90048385f55b5d19f808c14609a03d0bfcd735ce8bc060ef26fccc8fb09a9088c59b07dcb2bf875b46dbfdac5bb2c298cf9663767ec0d336767c9a364fded493acbc416b6bacf1da39799397a21d6f8428a8947d39268c1d8a72f76ac3cc96aca1021e8a24dc79d6bd5bcedd212bd96efafd494f2f449bfc01add8ab2d167c912c70031d648dd3f46c9ba6b2c9525ce9d5ec98b268596940bb41c45d644518e239546bdd515916a2ad71e2209d1f26e8c1d040f12439df7838a021f3a1bfa20956d22f37b3e487c7971064cbb621d33fff864552dd01584ae5231fb9718b3884d9341ee460992f78b4aeb6ccc80c47c4c857ea17060abbba41f1c9c3ba05b8291180023c4b387e91c0ddc2c356401c092dcf7a938b8e87b1586b273da2429c032c0aad8d7919fce6bef22219196bb7da3e8b2c643b7513b37fc9113f3b0039a68e2fb392f8700a093b8dd944eff2acd0d75aa4910a422b7220ed7826b199bd29928166c40bd1a2ad2cdaf202705d227b1783c0776c18725d2c74fe07f40df2d74cd6afb6683b49464e74bc2d77dac5d7ecf04c416e38118cc52f7ba3369420c065ec79125f51725265f7e97d9f6d9646a54b75fbe36f4037914def53cadc0f27a11786b1e5c58037b046186b990af3b2de53fae4f0de6702a1291fd8b9b7aa4e4c1766d95dfd47939e197e0fab607dece384e64c1224e10deaa49e503efa5eb7cfa0b60a3d35370c0deda17608d674f4ac26b7295eed833f98797d5155116c2423faf3b56cef031c8343636fd62519624a906068da82478f402bad4f3a1bc6c1c309c5d9ebb69ebac621b5b8b6bf999d7e1e064a3790fbb17dec1c4897a1202f97173b6f8ec6364fa27f943a90790428852dd0f4c9842e8e1e9bc461dd55140d4e449ff50e4b4e5082e66a1ff95dcb41d6cedb592ecc1d99f1b0293e7c24faf99c7f041fe8fa2480130bbeb2dd97b46d8fa289310fc97efe00b47df4f6639362ceee08e44cce87e59de15c21ee16d25d2a22912c53d91253dcd387cb799235c2980a86bc222b1baa1ac365079b5912328ae10586689d7de4dcbe47b61895dc384489bc22732d556ef9c841887c2055ec87f6e366725899be66c5f29106d95599b984776371e335f475ee0dba5e7dd0f90c2fda32932b84610eb3c9ff5d9d60a9f89776077c2de13092e9939dbb220903708689698ca0a2c284c60fe2e1da1e19e7a2b15c3bd55953295eca8f3e84f75b9766eb28f6294bdbabead0a8443c978cef23185e82447b117f6e535db7dd7f4799bddc808383d1b1fb8c74b130cecedea068239380fdfc1d70e1ed2fb2860efe2409218e267e463c225f82f448bb7c4c13884c4b40df9422a2dc1f0f18915bbaeba99a68831b230afe9baf15a9b111e9aa10384d54f42b318ff2cb57092abc7c069bed8be79e45f833946fc8b83d060db5f81dc4752187e0a3da582c7f69fc7a6fc8c70f160bbd094809ac3565a71f2de817fec03edc806b2de811629e6625278a82cdd197aa82391581e8b3d7a1861d8dc514878efc2c3b4c32d7684fcbfaddf167afc4fec247bcf7378caeb9cba717941510810011e49bda1cbac86c1809b4cc40116431cf51ea26ebda084c72bce32731cd12c1f4c38372e08ed904246982ad5cc64005c31debf4da46073d4fe912a133036a86b25f21b09d71b9b3237b633d116916109b75bb9fcc40fc6c12765863b49a7288de9f139160029221f562cc8414e7767b40086ecd3c00d6486b5f9e29a14f3f5c3959ed47f817447ec64f75d1c8ab89662e347d4e6d807cdfbe91a2a390157fc133480cfc6dd22e474d2312981160f2f69ddfbca64c80fc7b2ade24c3315112dd7b357808428d307cf5db0c5f08ea0bf4cb0136ed12130ae3713637f9cced1ee97938256b2f9b05e73d21236f2ab7c166311872cb8633320348c106c593a86c8fd2342ed637fcc157ecea9356dbb1b6bdccf135c8e37e41c1f0206d056de6515656aeb35cb7ef5d9ecae6e11a3adcaa3f53d4b39e5eb3f8b36b9b35425873fa81eeb6e5a4df8b42d6bbd286855767cbc13a7258844692abe0dcc1b82f8e247e9f9d381cd08d8d0627eeb1b32160ecb7153c622821a9f6d8151dca2bc82fc81a0bfb7878cfaba5cc465c1d90ef96fb3ad09e92dd17986ebe33e323fcfc7776fc5f789e1ccfe110fe32a3694d0ff6aa4a91e0d9dc069534d9a3718b32708c80b14074fda6f09e57954580ab31e532f4ce19b25bb01b3e6960baa0e1bd6f89d86d53f10b6f6301e5ea9ff4d90cde758d85ec857602ff770b0d1cc9c3a8cc80714a48f19f477a344280ee191617fddbf20ea366e5454d5503c3ab0a2048cce6d2298b85b035d47d9965e479e4b7b86bab375ac73df615fc34ddc67a12016fc7383ac707c13edd6c167d0a0312d40c74508150e9342833990a8a9e33d0750e2358c291bb82a15639cd426161dbac04716b1aefe033c6985c0974d9a14b791c5e88b4bfeb347f74182e8cfe0c3620b09e799d360dd499745dec1d70dc5cb6b031e1ad74527db2b75093831fb81548d46e1b607ba7a775b048db647d800660c37aa6e99ba6b9e4585dcd0deced26e1f82fdaaa4adcc659087d2c6a4ffdcc3272e520bb7be4d3330a037cd233ab2f340b8be56deeb62abb773c20f512782fe6ead2afa00616c37c7f1e90f32c4593781e71ae4964bd74352ecb90e848fb6ca4a2dc39c8040910d55be13dd2e6ccab00f77ab09333a642392e8a1c3d516b3dcd3d2ab13edfb3557641c2bcafdcdc9b8d2981b3eb74977c1dd3225f5198d03c61a5154dfcd5761a7c10bbd94c58f5a94da6fc28e18b649fe5ddaf0e29e4cfbb8372829e7ae85a4624edf16014f716fb8b3090bb08311e7d8d52996997005d69ba220a3c06a1b4a2a2aff589338dc55395879b6b114b218715cfb3106c3678206928817eb9dbf1d98b2732e22455d12d9e52a9f65c0dc098495656b4ceace774b21dce46f27635b7562bc2dc9133911dc205ab0c7109e1ac60a8d1f5b47e0db02cdbe45f808bdf66e04a7a7208bd91a7b7d69430d48deb8fbca8eea9509a40260b842c85d8bc6479c6a0f1a1fbc45aa2d5302a90657407ee17d7026ba0f84bfef55a322d840c1c013628e2c83d588ed7819e2691acc1a9d759e10e0b6e2936442dc5b7b42e1b8a0613577469fab113004559867f9380359137b62abf9cd06a577ba4e5fbdca9e1edf5f0d1c835ed06402e71241f438dd93cb64a1ec1de886606208eb9089d0e1afcd64e35c91faa4d85fc66adeb467ee8486e14d14d9939fb159ca5a225dfeea7194402726dd04824a122e0446ad3574d7d8db4bed9d503d978b1b4cb6d6bf84afa4013385da0498bf9cbeefe74fb83a3725d5c6b24d2bd54a60123b0f127f69170c59d01a511fca4fc0782f4d6b3242cd2dd7567f8f65db29cd4ace906a8e9a21af50f72ecb7630595551f0a0553c208ad6846c3533216306b86ff107a77a3a4ab9d06684b37c7fb780f74ac6b86d098fe1d5e6626b50cbcf4a7b8f6f0de049422b8ffa9cfa06a91984c2f89a12a26ed701ef77b7d64d4e3f5a3cc5a7f6344a85f57d06241687413e8327b6f1278cc98f868b30f986e755f1e60e7efbd2288653b0083d336ee9d353b68f6e6861a47230d51c01f1b815bee6c670beba9b522100b5a9c002f3a5414bc32085e2a48200b7390701fd277940d5f939c9a51a2693031465c270c8a13302691f7333af333f961d3257c2ed08e82d488784b5c2a73904e95cae3e4f22932b60dbe6fe92c785b213f026ac6414efaab1d5ab80088f477022c14f6ca5c3cb515a7d1cb24f978710da888f90a5f759ba246851b207832afcf074dbc16328941ca58d0ad685a6a0339647c9e98958425d02b24c5cf11602ec4fe4781a5be28e2985c75c0b2e03d26f5623e98c06a42fcd18a121b73950d8a56847858161f9d59f7a0d4c3cae147a8047613701cffc5bd9ac1fc0fee39b576d12369205b3fa57bbe5ca960f78b1802233458cd8af4a086e21de7fb887f4403db1ced14bd9e904e1b4f07f807327402b8d66fd2865a1d25d9d852b8b304a93e1f6e40bcfb794b7b8c4d920e34e96cac1964885436324f6d57f40758fe38390d540337f3b11301c2deb2c712ae0f6bfd1d44e95e308c1149ba1ccd56093f3804e29dd46f8e61ec357cfbb3620e2d347637ee45a7c51173041b07011df060ec902f16655a6dfb2f3394ff56a7f0fcaf4e63e3562e33b68db2d5d7de44c0f9d7a2a4b990abc827c8119a708ed37b37f40dcef89a48fb78c365475f2a9f7e93a5afc97477afcee3ebfda421b46a4475073922eb7d532510df1f7c82c40fefa4e740b0081e64fbb752ae15538a78b4a6ca2016736c51dfd466a362510bc5859011a003508ef01ec58c518dcbe6fb4c894106491b6cf06d328b1a474d787ac085556420d9a29fd8b8ac2fda23b21df1278556506c875431c4a3d74e39d79007171caace22f2b0715200bb3990aced309c36a332fa776826b4f824307f67e813e9de62580c9df96025f9ebc515513b0c5ee97a3d80ca6737d1ece9863a824b6174a49488f51604b137aed95239ecda98b947763847cb0f0820872a000d3bc312386905c2f504b9b71f3cf577855d6a6e58c8ee1d1e4b12ae9a57432c1f15cfe111106a9a063e92f3ef209912af13c81a4bd78cc26650f37a3c8836eff4b44ae05ec6a768eec968ee85847e7a6ebb54fae229ae93be0184e8f64cbd03d68733c126f87a4bdf4ad926808b91f2933f7338ef2c79b2ffda36d7059c4768ea38201734ff0ee8b1552794a4e2ce1c3b4c0cebead4938a82324c99ce0d776eb2b183718bd2fc855afbf00047a144ea1c8929f34eb0b43ef9c1610e5f8a132bd4b0516ec3909e330138fca6a6b53a7dbf25cba34dddc9115afa7733dc0085a02c03fc0fae3db1df385ef78a3b2cadd3b93f0100b23dfebb3263fd8061602bf6289bd33ca099f48f19dade4165c199708226712105574c61e546e027566d7a226a895b476a49ee2f8dc0b341074945bef949695ee7494a2f86f1a9745a5b78f30b4b53dd242516af03dba2e440e62c285e8a5be729d2faeb6eef91a0045e267a00c3e0bc16660267514651de1e7967181c1668fa6ce3c64de1e234a8fb55cb32c6176199c8b3f1518dc11060ffaa5b93cd9ed7ffe994803a84065d99e392c58bb21972a3c9ba49ecedd17cefd1f7f54d042650a2aab3e7940153e706859fcbc9ce64b45bd0fdbe359d49ef9eafcd98460dbc125ca8c27e5ea6f26acb6874ebfb21d29c20704c2337ce3d0af49b659ba894d56aded0e77f7b9b29d2202c9a242fbb82a53d90de5bb67781a6a163aed421fb3cf0bb03849f0604e545363472cdfe36ed7e39d8819782a6d831cc6e303c5e243abc399ec16368f9128a25b1f1428a2d57c9a9ea5d8da7a2dbc6d792383ee2bba679d0659a04d20bda697db9cf50805e47eeca8ceb780bdb76e6c5ce2e4e5b3b1d180a6b3c44e79c1a2711c1a423ec0b7c007b7557b16ef9d061507aa46798bf0076bd76f1d65e12daf38c15876630d623e843ba93c37e90a8a7b21546fe4a6ae6988f32598eab8d62020da0363918f187eb926eded47e68bf08429d45ac745bce1db0c38d1ebc89de290cee31b74749bf50572c852cf08244c9d113009b96682144ff8fd3aaa82cd40c4b66390a40490d803f85c625f24dddcd16f91f63b83ecf8af4936fcb295fdf7bf4ac67c7e5115cce804aeda1bdd573e1587aea45aca6de6e6d629ab38a80e2ca30b8ffa5674294040f5535837a87b124fd0b5d05ebb1c2f1ff441a5516c67806e3deee7c6321f2cae3cfa11634f62bc03223d8f994519e2afb4d444ad9b5879ffb9e8ef2567802b23d3c27a6e3cc44534f0d6435c2be53c9ed109935e9d3b38f9c1fc137e3808c533e9bf44d7f3573cbbd8b8fea3473b87ca9301124e015e4d4e33f6ac2c4cb2f9f1d9f920b358526679617945cf2ecaf76396057fa549e1612f3bfb016a4bb5a6d9d5e4a45632942e324e3d50cce9924ae8918afbacfe44e91a503f4192ebeef5ecdc616bed6cc795a719063ceab39b6b66c5434f0dba50313ef60e2c762fe1f895a8d2bb243c589a161c215176e5eb0c35565d696cda4a687fa1b93b461a3777a5ace563738295cbdae5ee092b686f738e94a5acb0cbdf1b3e41576b7c8d94b8e5000000000000000000000000000000000000070e13151b232f39c67b5cb936adc877914fa181e37afeb92721fd93934f08eaf7ed1aee0bd5b17dbe5cf98d4f087011bfc34912d020be5561e5bb24327eab93ec455a0f45eb1ed9b4746f1cb4eb6c826202c7f2a155fb4fc331426d81365359b34de06d5f91fa2f",
  "raw_composite_public_key": "e45ffc8cc73db885dc662e62a18cd8e3803297117fa5658814a985b5ff1db7b468cfc82bb929f1d86b77ed14f5ae16a65368772ce51912410105e0456975ae91fdb643b512f124d5e60bd68b8c7e31fe01c7b0dc65ae470501cc565a6e1dfcfcfd12565433c4afedd511821e2e9610c45275e2836dee35ced69d7efa672fd1e4318bef5eb6e897e8b451aa202ded042b2aaef77a7be3f699146da229a8bdb3ffa496445967e75217bfbc9048f9956443d8731f833eb30de10dac96fffe7cf65ea0445c3e31e8601e133be6a100764fe3196e267726441f31751fbf9a6f5880644f4e7275e57de2b0f105e4db055d50dd1c9c934fddf535b8de28b0c74c0449f222cd2ed0bb8fbc775ccee8c940665b40f712f4f7e00750e9e1e4cd9cff25d1945c3e9bca53ccd4f12eee7581856ebd68f26845956e3e7beb761f0fe75bdd31bfe2fa018113397b387bd59d62a68b8af7fa245ab932e69f778e2ceefd21304fbb8099ea13d8ea57c1813197a2f75ae251075b51dad38f853669e9d5f98a3655098941993a1594860fba71fe530ee5c29f58f2978af688ccb75a5838a359c112e98e25a8583ac8dac1f861fd58e2afba5de5a52e020904f5b42bc0874e35befcf3e6119684768f36e008f04712177cebe627607381e56eaaee161c1729b8de51dbde474d48cc68249ea27162b87993e60c84ed6cc6423cb3676d9eb50b2cab5a3a049ef131381d623fa6fbcbc9db1e7cc025ea0418b9dad2cc6ccd4e95fa2cec24feeca70318a751716b7213f63edbf65a63338357f838f94ec071822c24851248885107b3d1c4e924678c7614ea1af038104619f2ae372940becfa69e29cbb5ff6c3e20a47be4a4f74bac34c133c00a6a706accc6ffd3d8e4fbd69a99704e1283c850d8c58d1e5753cd9587b83c4c346cb9a58137213ec10834c66adfe2bb5c501a8ef2ecadd1b677a3df1a6deb86ebf0722c4f5030e20f9018dd5b6fc53eea24fd92b7b5b4025feae996d3e48fd4c650d82dbad7eaf936639698512f26253d2ef6847c8518e8565cc9a5495c6fff57cde7323882c54a7db470ab2daf8ffd2bf794fa7c692d9e7fbd532eecc1d7880e2ca0b3216128be28b4a9f1d151fac97808b0bd98b7b43a612a9ac865812bfeac6f47460277840b52a3b087f916ca7cedc0f768ea2bd19ea21155f84b4a04c4000ad2ae0587154d560bc0a477a4f9329a8984dd31eb1f2a05e3d918701d630cfca9af61ef088d2c5581acb463e439902e5d425719e956b8d6df7305b28e0ff27d3ad0de2085d292499b19a3390d4396fb3bac9a8d8cbead2a7a4290fc9ac6fca045f98a614a45a39cbe24360f84d14f8e472712aceb74dbf45b53d49a0e4737e476ffc4d5b2f7cd247aa186d3b764ad9e9cfeee456a73c291d8de3912414ac43911c372173ad7b472af35c6853ced2fe7b5fe0a89565ab33baa6f65cdd928319d7065e040e7a5e84f9aa903f7648094bad07136b16927b8ec6dbc2bef0cc2856de1e795923e1412c49f24deeb6c21f6c8a9765c9c7986e0da4b4c67d8e0d0c8d466824fb923d8573148990cd2ef133c78ceecab72ed9dd285c5a3766852d54534207ffd34027f6c76ede8fd1a32d72c30048bbaa797d5df6fde27d087de5721ad7b7fa3e8d3f70d6bfc3ab2e252335368bbfa15acb5cb37d4694e8b23cebe25de9c925a221a183b904d3f85df9929a919c54d6f87457373a0d6ecc1403e4cbbe620999435e80696634cd1a8e4747e9825bfa336e5bbad14f73640f1b9febe800dbaefe1630c61fae635b074c564eaa9db189c9e7302873fc64e6d497bc5c29080987a07a21d4af210703a4fa07f2fd816f12fd1e29b4c0f44afe9bd4a1eaa8a7ae6f02a5b4258f52caf6127f62632a67cf4e8310be56a7c28c86b2e277600c3e92c8d23d42586244c571e90568df202f2f6d81f860a565f9eb91a3c78372e2a8b1be61c5418cf49bf2d6c8955d4a482a9919b7660b3f9a4404ffc454ea073e1e4b2689ab2cca4e46bd7004a6c491fa26ee7a57d60f35edb2b821e6266442c8f335d452d524c772e0353724c23c7dd15b7aa155e91442022140c5fcb0153147edcf3e8952f6f0399a3c88066a72756c9409915de63f64fa797841c57c796c6fc550ef745dfe9f179457f94755ae5a2506a764f327e550be3dc14dd41f3b04b147d454938c63a8d69b2ea4c5710ec0b36e3a6c72571fa5d59dde036c42033df35af056966ff0cd1204008971aa6ba9fb97b685ab9ffa2a9d1778104cd2c3b326de1fcbc242e94d0311c3275b12850ed30ceead3a2ee6d060508411d4396f5421d8b6d067cf7cb5e826785fbe119e05e21bd879b64f57cb0cd1972c2815f20abe7ce6ab34d0f471af44baad179e90644122f5f33288e689ddddc5ce833e9755df1e73c65c5a201c4ede2ffa6b19274927719d2d38fdb7a65aa43708b7fa9a94aa7d3210253d78d3b181e1020d0000bd0a1dc05d447f9f58ebeb84c65b36c8afcb83727a1508994e826957a663b0b9b8a003325ab6d6d6462ee4e106019c0dffe10323b7bde7d82a38f85fd08786e860ba66c161b64b0708c363de5c6af62d8db3c243d1e1b712cb1d59e942b9b6b4295a5a500b182cbd5fd1bc6ce9376d91b47a2284f1fbe0ad1c048cc2cfbb4afa3a9eb9697503b69feca990eba7e9441af9ca44cb3ac6b5ed66e591c201fe30efa8a7c471dc613d6254c263a8e132104bec47f1aacb3b2fcd4051b69b5e3fcb1c147a65c2f90c4b5188bafc521cab03c12a309da50b5a7517727ed41228ed123fe1b152f6a6319cd623bf34ad7b8e064ab993260bcbd405f5b7fff9b2fa40ba5ed5630242539e5d96823e89dc818a13d16675ee3079d976f694f5acc9760ae789e9b3391b289e0e22a7ef17cc6a4577157b6d95c09baa4fd532e3ee0a290810ed35e56bb19d9b61fb98a97c617425b06093d98a5cf0ee2dd127f0eea600b9a0c67fbe761db9b77e5d5bba9701da1b883e521a0cfe88451f57bd36085b67e56f061f84a2e6a152a71bce6e522daab6a0a33ce22e537fa9793d28b617e6c0a4176a83aa3be578afac0f2f5547c5516d218984755b7445c7143afa4e551fce0071bdb873b34e6b9e2b9e79ed0c69d288ed6421f237e860a0c6492ebbdd2a44c2c4f368dbe99941b1e8561d859d3859f496cee3d741f252973f8fcc539c409e35cc80a5ed6df23cc3a65601313f5d681fd9540c5291a9e30a72e38c96413c47c61ff84fde78d011b01b4154d1b920af003f7abb1e1999dea6a766cf9fd2702b3ce0ee57af931b62124b0861b163a3b91aa4bea28076c3432df3b29b6c4e1ba588def420071fc157de90eb2722ecc9ab00df3c669383a61a91bb67bd287ce349b4745ee7a479dbceef166b9acc412eb579fcd6437307edda253d606b7be7599c38092bc52a8598480edab8b82b1d21c565d2137ceae0b6642619b16133d91205d6355029e9cdfeb9a28b373d95916b6b707d4c712c09cf36daf1a511b2bedb1aa70ee58d46a0666bb287784b0a3840c589a7a04d5d6f2216be90aa4a512d5632f5c9bfe7b8b13382f999b95d367c7c46b968074ce315197a5ff3545c7b77a804ade56a95b5c24cdece5937b5c0366d93ad03da9bc5db1b551dfb91e9b343d2b57b763439686d4a31bd592da64e4ddb624760055d3be4ab760cb147e7fdaf26e8c0bb6b4a54668c77fa08207119c7afdba3e9bf62c5968cfd96158febd0bc07e3ccf6a4ef5e4178991c99bc0ab437ad56b67850c559602172e194be0feb6c453c8b8ca2c4e46ca6"
}
~~~~~~~~~~
{: #jose_example_ML_DSA_87_ES384 title="ML-DSA-87-ES384"}

## COSE {#appdx-cose}


# Acknowledgments

We thank Orie Steele for his valuable comments on this document.
