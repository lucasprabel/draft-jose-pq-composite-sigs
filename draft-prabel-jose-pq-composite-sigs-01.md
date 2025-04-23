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
 I-D.draft-connolly-cfrg-hybrid-sig-considerations: HYB-SEC-CONSIDERATIONS

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

In this document, as it is allowed in {{ FIPS.204 }} and specified in {{-COSE-MLDSA}}, the ML-DSA private key can be stored as a 32-byte seed, or as a semi-expended private key, or both can be stored. As in {{-COSE-MLDSA}}, if both "seed" and "priv" parameters are present, then the seed in "seed" parameter MUST expand to the key in "priv" parameter following the seed expansion procedure for the associated "alg" value. 


## Composite Sign

When signing a message M with the composite Sign algorithm, the signature combiner prepends a prefix and also a domain separator value specific to the composite algorithm used to bind the two component signatures to the composite algorithm and achieve weak non-separability, as defined in {{-HYB-SIG-SPECTRUMS}}.

A composite signature's value MUST include two signature components and MUST be in the same order as the components from the corresponding signing key.

Composite signatures are generated by:

* concatenating the message with a prefix and a domain separator;
* appending a 0 byte after the domain separator to indicate that the context string is empty for the composite signature algorithm;
* encoding the resulting message;
* calling the two signature component algorithms on this new message;
* concatenating the two output signatures.

For the composite algorithms described in this document (ML-DSA with ECDSA), the signature process of a message M is as follows:

~~~
M' <- Prefix || Domain || 0 || M
M' <- Encode(M')

sig_1 <- ML-DSA.Sign(sk_1, M', ctx=Domain)
sig_2 <- ECDSA.Sign(sk_2, M')

Composite Signature <- (sig_1, sig_2)
~~~

The prefix "Prefix" string is defined as in {{-COMPOSITE-LAMPS}} as the byte encoding of the string "CompositeAlgorithmSignatures2025", which in hex is 436F6D706F73697465416C676F726974686D5369676E61747572657332303235. It can be used by a traditional verifier to detect if the composite signature has been stripped apart.

The domain separator "Domain" is defined as the octets of the ASCII representation of the Composite Signature "alg" (algorithm) Header Parameter value.

Similarly to {{-COSE-MLDSA}} which indicates that the ctx parameter MUST be the empty string, the application context passed in to the composite signature algorithm MUST be the empty string. To align with the structure of the {{-COMPOSITE-LAMPS}} combiner, the byte 0 is appended in the message M' after the domain separator to indicate the context has length 0. However, a second non-empty context, defined as the domain separator, is passed down into the underlying ML-DSA component algorithm, to bind the Composite-ML-DSA algorithm used.

For JOSE (resp. COSE), M' is base64url-encoded (resp. binary encoded) before signature computations.

## Composite Verify

The Verify algorithm MUST validate a signature only if all component signatures were successfully validated.

The verification process of a signature sig is as follows:

* separate the composite public key and signature into the component public keys and component signatures;
* compute the message M' from the message M whose signature is to be verified;
* encode the resulting message M';
* verify each component signature.

~~~
(pk_1, pk_2) <- pk
(sig_1, sig_2) <- sig

M' <- Prefix || Domain || 0 || M
M' <- Encode(M')

if not ML-DSA.Verify(pk_1, M', ctx=Domain)
    output "Invalid signature"
if not ECDSA.Verify(pk_2, M')
    output "Invalid signature"
if all succeeded, then
    output "Valid signature"
~~~

## Encoding Rules

In each combination, the byte streams of the keys or signatures are directly concatenated.

```
Signature of the 1st Algorithm || Signature of the 2nd Algorithm
```

Since all combinations presented in this document start with the ML-DSA algorithm and the key or signature sizes are fixed as defined in {{FIPS.204}}, it is unambiguous to encode or decode a composite key or signature.

{{tab-ml-dsa-size}} lists sizes of the three parameter sets of the ML-DSA algorithm.

| | Seed | Private Key | Public Key | Signature Size |
| ----------- | ----------- | ----------- | ----------- |
| ML-DSA-44 | 32 | 2560 | 1312 | 2420 |
| ML-DSA-65 | 32 | 4032 | 1952 | 3309 |
| ML-DSA-87 | 32 | 4896 | 2592 | 4627 |
{: #tab-ml-dsa-size title=" Sizes (in bytes) of keys and signatures of ML-DSA"}

Note that the seed is always 32 bytes, and that  ML-DSA.KeyGen_internal from {{FIPS.204}} is called to produce the private key from the seed, whose size corresponds to the sizes of the private key in the table above.

# Composite Signature Instantiations

The ML-DSA signature scheme supports three possible parameter sets, each of which corresponding to a specific security strength. See {{FIPS.204}} for more considerations on that matter.

The traditional signature algorithm for each combination in {{tab-jose-algs}} and {{tab-cose-algs}} was chosen to match the security level of the ML-DSA post-quantum component. More precisely, NIST security levels 1-3 are matched with 256-bit elliptic curves and NIST security levels 4-5 are matched with 384-bit elliptic curves.

The {{FIPS.204}} specification defines both pure and pre-hash modes for ML-DSA, referred to as "ML-DSA" and "HashML-DSA" respectively. This document only specifies the pure mode of ML-DSA, and doesn't use HashML-DSA, as it is recommended in {{-HYB-SEC-CONSIDERATIONS}}.

## JOSE algorithms

The following table defines a list of algorithms associated with specific PQ/T combinations to be registered in {{IANA.JOSE}}.

| Name | First Algorithm | Second Algorithm | Pre-Hash | Description 
| ----------- | ----------- |  ----------- | ----------- | ----------- |
| ML-DSA44-ES256 | ML-DSA-44  | ecdsa-with-SHA256 with secp256r1 | id-sha256 | Composite Signature with ML-DSA-44 and ECDSA using P-256 curve and SHA-256 |
| ML-DSA65-ES256  | ML-DSA-65 | ecdsa-with-SHA256 with secp256r1 | id-sha256 | Composite Signature with ML-DSA-65 and ECDSA using P-256 curve and SHA-256 |
| ML-DSA87-ES384  | ML-DSA-87 | ecdsa-with-SHA384 with secp384r1 | id-sha384 | Composite Signature with ML-DSA-87 and ECDSA using P-384 curve and SHA-384 |
{: #tab-jose-algs title="JOSE Composite Signature Algorithms for ML-DSA"}

Examples can be found in {{appdx-jose}}.

## COSE algorithms

The following table defines a list of algorithms associated with specific PQ/T combinations to be registered in {{IANA.COSE}}.


| Name | COSE Value | First Algorithm | Second Algorithm | Pre-Hash | Description
| ----------- | ----------- | ----------- |  ----------- | ----------- |
| ML-DSA44-ES256         | TBD (request assignment -51) | ML-DSA-44  | ecdsa-with-SHA256 with secp256r1 | id-sha256 | Composite Signature with ML-DSA-44 and ECDSA using P-256 curve and SHA-256 |
| ML-DSA65-ES256            | TBD (request assignment -52)  | ML-DSA-65 | ecdsa-with-SHA256 with secp256r1 | id-sha256 | Composite Signature with ML-DSA-65 and ECDSA using P-256 curve and SHA-256 |
| ML-DSA87-ES384            | TBD (request assignment -53)  | ML-DSA-87 | ecdsa-with-SHA384 with secp384r1 | id-sha384 | Composite Signature with ML-DSA-87 and ECDSA using P-384 curve and SHA-384 |
{: #tab-cose-algs title="COSE Composite Signature Algorithms for ML-DSA"}

Examples can be found in {{appdx-cose}}.

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
| priv  | Private Key | AKP-EC | Private | IETF | RFC xxx |
| seed  | Seed used to derive the private key | AKP-EC | Private | IETF | RFC xxx |
{: #tab-jose-key-params title="JSON AKP-EC Web Key Parameters"}


## COSE Key Type Parameters

This document requests IANA to register the entries described in this section and summarised in the following {{tab-cose-key-params}} to the COSE Key Type Parameters Registry.

| Key Type | Name | Label | CBOR Type | Description 
| ----------- | ----------- |  ----------- | ----------- | ----------- |
| TBD (request assignment 8) | crv  | -1 | int / tstr | EC identifier |
| TBD (request assignment 8)  | x | -2 | bstr | x-coordinate |
| TBD (request assignment 8)  | y | -3 | bstr / bool | y-coordinate |
| TBD (request assignment 8)  | d | -4 | bstr | EC Private key |
| TBD (request assignment 8)  | pub | -5 | bstr | Public Key |
| TBD (request assignment 8)  | priv | -6 | bstr | Private Key |
| TBD (request assignment 8)  | seed | -7 | bstr | Seed used to derive the private key |
{: #tab-cose-key-params title="COSE AKP-EC2 Key Parameters"}


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
* Parameter Description: Private key
* Used with "kty" Value(s): AKP-EC
* Parameter Information Class: Private
* Change Controller: IETF
* Specification Document(s): RFC xxx

### Seed

* Parameter Name: seed
* Parameter Description: Seed used to derive the private key
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
* Description: Private key
* Reference: n/a

### Seed

* Key Type: TBD
* Name: seed
* Label: -7
* CBOR Type: bstr
* Description: Seed used to derive the private key
* Reference: n/a

### Others

The key parameters registered in {{IANA.COSE}} for use with the kty value "EC2" should also be usable with the kty value "AKP-EC2" defined in this document.

--- back

# Examples {#appdx}

Will be completed in later versions.

## JOSE {#appdx-jose}

~~~~~~~~~~
{
  "seed": "0000000000000000000000000000000000000000000000000000000000000000",
  "jwk": {
    "kid": "pY9ZABO9FunId3L3tDs_peWTLFSfWxyO5nQvvlGsYQI",
    "kty": "AKP-EC",
    "alg": "ML-DSA-44-ES256",
    "pub": "unH59k4RuutY-pxvu24U5h8YZD2rSVtHU5qRZsoBmBMcRPgmu9VuNOVdteXi1zNIXjnqJg_GAAxepLqA00Vc3lO0bzRIKu39VFD8Lhuk8l0V-cFEJC-zm7UihxiQMMUEmOFxe3x1ixkKZ0jqmqP3rKryx8tSbtcXyfea64QhT6XNje2SoMP6FViBDxLHBQo2dwjRls0k5a-XSQSu2OTOiHLoaWsLe8pQ5FLNfTDqmkrawDEdZyxr3oSWJAsHQxRjcIiVzZuvwxYy1zl2STiP2vy_fTBaPemkleynQzqPg7oPCyXEE8bjnJbrfWkbNNN8438e6tHPIX4l7zTuzz98YPhLjt_d6EBdT4MldsYe-Y4KLyjaGHcAlTkk9oa5RhRwW89T0z_t1DSO3dvfKLUGXh8gd1BD6Fz5MfgpF5NjoafnQEqDjsAAhrCXY4b-Y3yYJEdX4_dp3dRGdHG_rWcPmgX4JG7lCnser4f8QGnDriqiAzJYEXeS8LzUngg_0bx0lqv_KcyU5IaLISFO0xZSU5mmEPvdSoDnyAcV8pV44qhLtAvd29n0ehG259oRihtljTWeiu9V60a1N2tbZVl5mEqSK-6_xZvNYA1TCdzNctvweH24unV7U3wer9XA9Q6kvJWDVJ4oKaQsKMrCSMlteBJMRxWbGK7ddUq6F7GdQw-3j2M-qdJvVKm9UPjY9rc1lPgol25-oJxTu7nxGlbJUH-4m5pevAN6NyZ6lfhbjWTKlxkrEKZvQXs_Yf6cpXEwpI_ZJeriq1UC1XHIpRkDwdOY9MH3an4RdDl2r9vGl_IwlKPNdh_5aF3jLgn7PCit1FNJAwC8fIncAXgAlgcXIpRXdfJk4bBiO89GGccSyDh2EgXYdpG3XvNgGWy7npuSoNTE7WIyblAk13UQuO4sdCbMIuriCdyfE73mvwj15xgb07RZRQtFGlFTmnFcIdZ90zDrWXDbANntv7KCKwNvoTuv64bY3HiGbj-NQ-U9eMylWVpvr4hrXcES8c9K3PqHWADZC0iIOvlzFv4VBoc_wVflcOrL_SIoaNFCNBAZZq-2v5lAgpJTqVOtqJ_HVraoSfcKy5g45p-qULunXj6Jwq21fobQiKubBKKOZwcJFyJD7F4ACKXOrz-HIvSHMCWW_9dVrRuCpJw0s0aVFbRqopDNhu446nqb4_EDYQM1tTHMozPd_jKxRRD0sH75X8ZoToxFSpLBDbtdWcenxj-zBf6IGWfZnmaetjKEBYJWC7QDQx1A91pJVJCEgieCkoIfTqkeQuePpIyu48g2FG3P1zjRF-kumhUTfSjo5qS0YiZQy0E1BMs6M11EvuxXRsHClLHoy5nLYI2Sj4zjVjYyxSHyPRPGGo9hwB34yWxzYNtPPGiqXS_dNCpi_zRZwRY4lCGrQ-hYTEWIK1Dm5OlttvC4_eiQ1dv63NiGkLRJ5kJA3bICN0fzCDY-MBqnd1cWn8YVBijVkgtaoascjL9EywDgJdeHnXK0eeOvUxHHhXJVkNqcibn8O4RQdpVU60TSA-uiu675ytIjcBHC6kTv8A8pmkj_4oypPd-F92YIJC741swkYQoeIHj8rE-ThcMUkF7KqC5VORbZTRp8HsZSqgiJcIPaouuxd1-8Rxrid3fXkE6p8bkrysPYoxWEJgh7ZFsRCPDWX-yTeJwFN0PKFP1j0F6YtlLfK5wv-c4F8ZQHA_-yc_gODicy7KmWDZgbTP07e7gEWzw4MFRrndjbDcqBRA7L8q1mTBSnIlDc9XfuoRuFyUPaCpJkzgZiubrwIYhzx8qUJ8vh9stOrXqu9lD-IO-rJOxXXXRrFT3UeRw",
    "seed": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "crv": "P-256",
    "x": "yoFEDsvyrWZMFKciUNz1d-6hG4XJQ9oKkmTOBmK5uvA",
    "y": "IYhzx8qUJ8vh9stOrXqu9lD-IO-rJOxXXXRrFT3UeRw",
    "d": "EgCj2tjGpPz0YRv2qC7pRNlTiiqzIjRNhFwCHzHZwzE"
  },
  "jws": "eyJhbGciOiJNTC1EU0EtNDQtRVMyNTYiLCJraWQiOiJwWTlaQUJPOUZ1bklkM0wzdERzX3BlV1RMRlNmV3h5TzVuUXZ2bEdzWVFJIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.nubRLNUaLqscXqlD9dqq3r9J0PJu7-3FDndYm-i_GCK1hN8Sk1BRZUXekohjV1RpT9SOv0pTnBERNopkCMttOHDw1nMLJke2T2Z-OPxRJmY66by_C5e9GLK7eekejLLaBITS33dIEEmCbTjY-MA1-IuWHT0zmP8ZajOxLqNjcN_VmXK8ZCGO65LTTlGnO9s30kAt3-OCmIVuHufRbZS17yZrgG1RpGC-BO83__ak82z30Ewno08Jftimj2eff5Fqx4PKqu_Y01a9_aRK_rUOwGVNGPbmRKZrGz742k6Pp1eiSx5ecSZW37MbO504pGUizqfzAjf2R2pC03AATgorMIoyYcEI_PecJTdXW_2huIyn9lavsNx524tqGUCIl4J7TF0teWNOVeRdK22ccYeIk-ashtkbOaaQdVur5TFhspMC7ObARyicTDV9Wd8laGwCynivbeQ11EqJp2snVlplQ6RCQViJMTj1JQ4rdS-RtjR--WZlml3uKWDP0dnPPLc7j-_zLSl-k4GlR0Dojl2V4l8ycbXPcdXy384-Q26hyLSEgpg4HUbTBPB2zPr3cXINiDpiIIDPXgSksNtlOye2NvgQ6cwdRj79YW9zDSy7cM_7gSNkiO2nyjKJIJ5edkEcUSBMO4vyURfsw1UaTWmnEERgum3BkDjEGa6m1fW14N87b7uLQGfykOTZTFAskFhiSImYyOHMUe1NiN6B-iilD8gHQLpkhIaOtHEowBq8ZAvDhEz6R2MT30h1Va6CGPskkLz6BP41opwNifcOv0ARlejtLWlkeBUOKcXkTZX57gh-oQa2so2HU-42pdtF6fGhgiVzmxfeEb8J5UmDGiQjKe7Q0oZh0pFemOUL_qqC-tpzIhelO7ZTDKyJcloIlcF1a2Llawmx7s9-RvfDM2cfNDZ_2QESjV_1kDDzP-P3Tm_9J5D8Fxl8-HsvJHPTo3_lhYCMmvPhvQuHEvO8cx11fJ_Xcn5pCWmfeAd_WEQ7BHyE1XBhOZVJyGibR_ym0wpb2TxsSf3MQEVuU5QuPynXS667jB1YI8e5rgAzQVeKGBzVBIGhw61S0ScsDt5Ig2Y1AuD4dqtkpKtsFoVy6XDfsfHae1HOvd4KdRWuisstn0j8Kolt1m_xfb4d4YjABo_cp2c1Sut6OxaHTPX2tGLn-i7I7sOQn74pIKH-HjePqggx7v8tym5ByBsZCuwsOa8PcUcS_Ngx_ecjMtVGyP9UR4zJQK29lCO5_YLyh8w31x9a9tYerLjt6EtWquqUZpeqFiFDAZ1Fk_hYOH2IvSxX-hdd3NdBMzbx9QCLgxqte23i8pReWvVYkxuXgo681Q-kBQLZJOcNTlNsJWUjwcAi0_SEjwJhcSzfP0gSowDraQ4-7fDBgaeyDFxJrzNZwatMHeREV94Y7P0niX7j9kgMJS_EM20aWHrm7U3vn8-r80uYR3-hqu5DYEqDYQV2MQtcDyRCCz9GrhaG056JVEBT2o-rr0lUZzFsTd8PuGM7BfwQKrENgCN7jxhXFVj7LJG5ynUUKsi_akJhewqSiywLTnHM7RsvoYH85Nl08yRcZH3bCJc8ysIGIyqEHAE2L_jYQj62-lP_x9nLWOula2FzLQWiA6yQZt-OuxTJvMsiQT-2gyQ14bIjSvmU6mTBuYcimZCHf02Bnc6QM-FwMchK7_MEUHPmtv9JRZcpZIB3ZuHhokTRJ_bJv1f0SbxMYeZ5ZH8eEyX3K9FpM2-KxwE9RANUDGCAU6G9Mhm0gJgY4bWiTVpsTNTrUKzu0s3_4IdC4CEdt_pw3kpx5V-FosndRXx879xhSzG9ZBTpotPqsguiz2FUD0_lIOso195AN7GpjWflwt6W6WUpNeTfo2UUGy03pJYtWsMGZfoY9pqpj-DLVdq2i77ehTyFoN3YH5_J31jGDXr--nTPosrBvOtEKDJS2Ymu464hwxkrByJTkgn_Hpv0q7tzw6RQpp6fRRYTz5I_qqnAww3mZzPNR0z4QLR0MqtFkMKUKvrWN72STVflmfeQrQnRAZJeELChE5YsRnQZVudNHkAtojkTW5byAsYa_jV6OflX8BMRBWiWI6FeEq_uQuoPb2k3a5FiXZ120_st9ONKWmHM_DeQlsDDIQKPQoKZDwdPkDtKhuVSuyg7rozTGy5Beo9BlobEuAmOt77lDYvc1EMvKqiPOyj449lscyrCTvaymKXkeDziY-N_jZNm_jkWP2-g1mDUrLEdQU-RULxoo3W_wM6eMgV9KS6Mxyz7cCjlw7ZCdbd85g7f4eqptPpQ4zA5FVqrTxcAUySrIu154WyNvz01aqhFOCx2JuuN5edRnTt25ZgWh9SDQTe8tDoNrIbM0C95DVzetlUoXYBN-FNtsAXAeXIDYodzA-fp2ntFzSTv5H9H71q4aOcSQkn_7BrLggnN8qO8hbFYjH29Wl4UFYOvXHdTZ_iakY3jlamqsmrynWvXeDTRVFqFGAKA0dOOJuvjmLTJjl3UyeAtQrfW-pKp59yiyJ30h2pZF2o1v5EX-1Viq6zDgYdkrPq-348ExuFEQlDU61flOLmd-pd3H5vZoGnN9a1K8wZpvEq3OQBohgaBKridZO1OwFTkOPGgH_c1UoW-6VBITfxm-MQhmMPAv1BVxHnFWTx06wWsYDmNn0c-hO7O5GVwcYATZFzV0-rIDsEfhVtRvsIep_jMdrN2nCmhYG3vaSy6fncb7lZ-8DHeOIhfkj29E-JGG5JxAnld9t7WRX674aSu0xvhxkTJEocyW8-Kij1dYiPEQQZHr-UVfP3yTIT4GVWu2O7Q45CU9HFgy4pnfgr4VVrorMq6zTVTl2xvmcyOloqZIpRQWSHTKAdYpRzt5jIVZAVRKeGPpjZlAmtaxDs-v3KAXIPmo25pRopB87O-pIoQJvCCeFYyvzkwOjdnH7elvfofUUpAA7NB7MDO6l84rRLkwmnmleVMaiusgodxXo6VmRtpKcSepYgzYOQqJJKo43piKOuzfNjJvKqRuZmtN8XCrX1TijafgP8J8nLboipj4v-xCBLP_Yz_qh4eEuVkq5ZG8nRdrBAKj5mXXMudX_0-YxX2cWIb71knRfiBxiZ-Zc5Qa2Y7L70RGikzSlxggJevt7i5vMnV2OX4CBIkKC1Mfquzv8jM8PL9ERssLS80Pkheb5ikv9Hh9_oMMTM3TGyGlqWsw8rO0Nfi7_MAAAAAAAAAAAAAABMiM0UqW3kylGKOZYpRpvT9uUYL4-TIhNBPPDT0Cl_LKHR8qg0pv_lQnUMMVoSUoeFUEj-FXRUEIj2ux1OdXE0v-N86",
  "raw_to_be_signed": "436f6d706f73697465416c676f726974686d5369676e617475726573323032354d4c2d4453412d34342d45533235360065794a68624763694f694a4e54433145553045744e44517452564d794e5459694c434a72615751694f694a7757546c6151554a504f555a31626b6c6b4d30777a6445527a5833426c5631524d526c4e6d56336835547a567555585a326245647a5756464a496e302e53585469674a6c7a494745675a4746755a3256796233567a49474a3163326c755a584e7a4c434247636d396b627977675a323970626d63676233563049486c76645849675a473976636934",
  "raw_composite_signature": "9ee6d12cd51a2eab1c5ea943f5daaadebf49d0f26eefedc50e77589be8bf1822b584df129350516545de9288635754694fd48ebf4a539c1111368a6408cb6d3870f0d6730b2647b64f667e38fc5126663ae9bcbf0b97bd18b2bb79e91e8cb2da0484d2df77481049826d38d8f8c035f88b961d3d3398ff196a33b12ea36370dfd59972bc64218eeb92d34e51a73bdb37d2402ddfe38298856e1ee7d16d94b5ef266b806d51a460be04ef37fff6a4f36cf7d04c27a34f097ed8a68f679f7f916ac783caaaefd8d356bdfda44afeb50ec0654d18f6e644a66b1b3ef8da4e8fa757a24b1e5e712656dfb31b3b9d38a46522cea7f30237f6476a42d370004e0a2b308a3261c108fcf79c2537575bfda1b88ca7f656afb0dc79db8b6a19408897827b4c5d2d79634e55e45d2b6d9c71878893e6ac86d91b39a690755babe53161b29302ece6c047289c4c357d59df25686c02ca78af6de435d44a89a76b27565a6543a4424158893138f5250e2b752f91b6347ef966659a5dee2960cfd1d9cf3cb73b8feff32d297e9381a54740e88e5d95e25f3271b5cf71d5f2dfce3e436ea1c8b4848298381d46d304f076ccfaf771720d883a622080cf5e04a4b0db653b27b636f810e9cc1d463efd616f730d2cbb70cffb81236488eda7ca3289209e5e76411c51204c3b8bf25117ecc3551a4d69a7104460ba6dc19038c419aea6d5f5b5e0df3b6fbb8b4067f290e4d94c502c905862488998c8e1cc51ed4d88de81fa28a50fc80740ba6484868eb47128c01abc640bc3844cfa476313df487555ae8218fb2490bcfa04fe35a29c0d89f70ebf401195e8ed2d696478150e29c5e44d95f9ee087ea106b6b28d8753ee36a5db45e9f1a18225739b17de11bf09e549831a242329eed0d28661d2915e98e50bfeaa82fada732217a53bb6530cac89725a0895c1756b62e56b09b1eecf7e46f7c333671f34367fd901128d5ff59030f33fe3f74e6ffd2790fc17197cf87b2f2473d3a37fe585808c9af3e1bd0b8712f3bc731d757c9fd7727e6909699f78077f58443b047c84d57061399549c8689b47fca6d30a5bd93c6c49fdcc40456e53942e3f29d74baebb8c1d5823c7b9ae003341578a181cd50481a1c3ad52d1272c0ede4883663502e0f876ab64a4ab6c168572e970dfb1f1da7b51cebdde0a7515ae8acb2d9f48fc2a896dd66ff17dbe1de188c0068fdca767354aeb7a3b16874cf5f6b462e7fa2ec8eec3909fbe2920a1fe1e378faa0831eeff2dca6e41c81b190aec2c39af0f714712fcd831fde72332d546c8ff54478cc940adbd9423b9fd82f287cc37d71f5af6d61eacb8ede84b56aaea946697aa162143019d4593f858387d88bd2c57fa175ddcd7413336f1f5008b831aad7b6de2f2945e5af558931b97828ebcd50fa40502d924e70d4e536c256523c1c022d3f4848f0261712cdf3f4812a300eb690e3eedf0c181a7b20c5c49af3359c1ab4c1de44457de18ecfd27897ee3f6480c252fc4336d1a587ae6ed4def9fcfabf34b98477fa1aaee43604a83610576310b5c0f24420b3f46ae1686d39e89544053da8fabaf495467316c4ddf0fb8633b05fc102ab10d80237b8f18571558fb2c91b9ca75142ac8bf6a42617b0a928b2c0b4e71cced1b2fa181fce4d974f3245c647ddb08973ccac206232a841c01362ff8d8423eb6fa53ffc7d9cb58eba56b61732d05a203ac9066df8ebb14c9bccb22413fb6832435e1b2234af994ea64c1b987229990877f4d819dce9033e17031c84aeff3045073e6b6ff4945972964807766e1e1a244d127f6c9bf57f449bc4c61e679647f1e1325f72bd169336f8ac7013d4403540c608053a1bd3219b4809818e1b5a24d5a6c4cd4eb50aceed2cdffe08742e0211db7fa70de4a71e55f85a2c9dd457c7cefdc614b31bd6414e9a2d3eab20ba2cf61540f4fe520eb28d7de4037b1a98d67e5c2de96e9652935e4dfa365141b2d37a4962d5ac30665fa18f69aa98fe0cb55dab68bbede853c85a0ddd81f9fc9df58c60d7afefa74cfa2cac1bceb44283252d989aee3ae21c3192b0722539209ff1e9bf4abbb73c3a450a69e9f451613cf923faaa9c0c30de66733cd474cf840b47432ab4590c2942afad637bd924d57e599f790ad09d101925e10b0a113962c46741956e74d1e402da239135b96f202c61afe357a39f957f0131105689623a15e12afee42ea0f6f69376b91625d9d76d3fb2df4e34a5a61ccfc379096c0c321028f4282990f074f903b4a86e552bb283bae8cd31b2e417a8f419686c4b8098eb7bee50d8bdcd4432f2aa88f3b28f8e3d96c732ac24ef6b298a5e4783ce263e37f8d9366fe39163f6fa0d660d4acb11d414f9150bc68a375bfc0ce9e32057d292e8cc72cfb7028e5c3b64275b77ce60edfe1eaa9b4fa50e33039155aab4f17005324ab22ed79e16c8dbf3d356aa845382c7626eb8de5e7519d3b76e5981687d4834137bcb43a0dac86ccd02f790d5cdeb655285d804df8536db005c079720362877303e7e9da7b45cd24efe47f47ef5ab868e7124249ffec1acb8209cdf2a3bc85b1588c7dbd5a5e141583af5c775367f89a918de395a9aab26af29d6bd77834d1545a85180280d1d38e26ebe398b4c98e5dd4c9e02d42b7d6fa92a9e7dca2c89df4876a59176a35bf9117fb5562abacc3818764acfabedf8f04c6e1444250d4eb57e538b99dfa97771f9bd9a069cdf5ad4af30669bc4ab73900688606812ab89d64ed4ec054e438f1a01ff7355285bee950484dfc66f8c42198c3c0bf5055c479c5593c74eb05ac60398d9f473e84eecee46570718013645cd5d3eac80ec11f855b51bec21ea7f8cc76b3769c29a1606def692cba7e771bee567ef031de38885f923dbd13e2461b927102795df6ded6457ebbe1a4aed31be1c644c91287325bcf8a8a3d5d6223c4410647afe5157cfdf24c84f81955aed8eed0e39094f47160cb8a677e0af8555ae8accabacd3553976c6f99cc8e968a992294505921d3280758a51cede6321564055129e18fa63665026b5ac43b3ebf72805c83e6a36e69468a41f3b3bea48a1026f082785632bf39303a37671fb7a5bdfa1f514a4003b341ecc0ceea5f38ad12e4c269e695e54c6a2bac8287715e8e95991b6929c49ea5883360e42a2492a8e37a6228ebb37cd8c9bcaa91b999ad37c5c2ad7d538a369f80ff09f272dba22a63e2ffb10812cffd8cffaa1e1e12e564ab9646f2745dac100a8f99975ccb9d5ffd3e6315f671621bef592745f881c6267e65ce506b663b2fbd111a29334a5c608097afb7b8b9bcc9d5d8e5f8081224282d4c7eabb3bfc8ccf0f2fd111b2c2d2f343e485e6f98a4bfd1e1f7fa0c3133374c6c8696a5acc3caced0d7e2eff30000000000000000000000132233452a5b793294628e658a51a6f4fdb9460be3e4c884d04f3c34f40a5fcb28747caa0d29bff9509d430c568494a1e154123f855d1504223daec7539d5c4d2ff8df3a",
  "raw_composite_public_key": "ba71f9f64e11baeb58fa9c6fbb6e14e61f18643dab495b47539a9166ca0198131c44f826bbd56e34e55db5e5e2d733485e39ea260fc6000c5ea4ba80d3455cde53b46f34482aedfd5450fc2e1ba4f25d15f9c144242fb39bb52287189030c50498e1717b7c758b190a6748ea9aa3f7acaaf2c7cb526ed717c9f79aeb84214fa5cd8ded92a0c3fa1558810f12c7050a367708d196cd24e5af974904aed8e4ce8872e8696b0b7bca50e452cd7d30ea9a4adac0311d672c6bde8496240b07431463708895cd9bafc31632d7397649388fdafcbf7d305a3de9a495eca7433a8f83ba0f0b25c413c6e39c96eb7d691b34d37ce37f1eead1cf217e25ef34eecf3f7c60f84b8edfdde8405d4f832576c61ef98e0a2f28da187700953924f686b94614705bcf53d33fedd4348edddbdf28b5065e1f20775043e85cf931f829179363a1a7e7404a838ec00086b0976386fe637c98244757e3f769ddd4467471bfad670f9a05f8246ee50a7b1eaf87fc4069c3ae2aa2033258117792f0bcd49e083fd1bc7496abff29cc94e4868b21214ed316525399a610fbdd4a80e7c80715f29578e2a84bb40bdddbd9f47a11b6e7da118a1b658d359e8aef55eb46b5376b5b655979984a922beebfc59bcd600d5309dccd72dbf0787db8ba757b537c1eafd5c0f50ea4bc9583549e2829a42c28cac248c96d78124c47159b18aedd754aba17b19d430fb78f633ea9d26f54a9bd50f8d8f6b73594f828976e7ea09c53bbb9f11a56c9507fb89b9a5ebc037a37267a95f85b8d64ca97192b10a66f417b3f61fe9ca57130a48fd925eae2ab5502d571c8a51903c1d398f4c1f76a7e11743976afdbc697f23094a3cd761ff9685de32e09fb3c28add453490300bc7c89dc01780096071722945775f264e1b0623bcf4619c712c838761205d87691b75ef360196cbb9e9b92a0d4c4ed62326e5024d77510b8ee2c7426cc22eae209dc9f13bde6bf08f5e7181bd3b459450b451a51539a715c21d67dd330eb5970db00d9edbfb2822b036fa13bafeb86d8dc78866e3f8d43e53d78cca5595a6faf886b5dc112f1cf4adcfa875800d90b48883af97316fe1506873fc157e570eacbfd222868d14234101966afb6bf9940829253a953ada89fc756b6a849f70acb9838e69faa50bba75e3e89c2adb57e86d088ab9b04a28e670709172243ec5e0008a5ceaf3f8722f487302596ffd755ad1b82a49c34b3469515b46aa290cd86ee38ea7a9be3f103610335b531cca333ddfe32b14510f4b07ef95fc6684e8c454a92c10dbb5d59c7a7c63fb305fe881967d99e669eb632840582560bb403431d40f75a4954908482278292821f4ea91e42e78fa48caee3c836146dcfd738d117e92e9a15137d28e8e6a4b4622650cb413504cb3a335d44beec5746c1c294b1e8cb99cb608d928f8ce3563632c521f23d13c61a8f61c01df8c96c7360db4f3c68aa5d2fdd342a62ff3459c116389421ab43e8584c45882b50e6e4e96db6f0b8fde890d5dbfadcd88690b449e64240ddb2023747f308363e301aa77757169fc6150628d5920b5aa1ab1c8cbf44cb00e025d7879d72b479e3af5311c785725590da9c89b9fc3b8450769554eb44d203eba2bbaef9cad2237011c2ea44eff00f299a48ffe28ca93ddf85f76608242ef8d6cc24610a1e2078fcac4f9385c314905ecaa82e553916d94d1a7c1ec652aa08897083daa2ebb1775fbc471ae27777d7904ea9f1b92bcac3d8a3158426087b645b1108f0d65fec93789c053743ca14fd63d05e98b652df2b9c2ff9ce05f1940703ffb273f80e0e2732eca9960d981b4cfd3b7bb8045b3c3830546b9dd8db0dca81440ecbf2ad664c14a72250dcf577eea11b85c943da0a9264ce0662b9baf0218873c7ca9427cbe1f6cb4ead7aaef650fe20efab24ec575d746b153dd4791c"
}
~~~~~~~~~~
{: #jose_example_ML_DSA_44_ES256 title="ML-DSA-44-ES256"}


~~~~~~~~~~
{
    "seed": "0000000000000000000000000000000000000000000000000000000000000000",
    "jwk": {
      "kid": "eQi1KRPK5mmI9knTLNUfCEL_Q_tWXxIdda4xUWeOagU",
      "kty": "AKP-EC",
      "alg": "ML-DSA-65-ES256",
      "pub": "QksvJn5Y1bO0TXGs_Gpla7JpUNV8YdsciAvPof6rRD8JQquL2619cIq7w1YHj22ZolInH-YsdAkeuUr7m5JkxQqIjg3-2AzV-yy9NmfmDVOevkSTAhnNT67RXbs0VaJkgCufSbzkLudVD-_91GQqVa3mk4aKRgy-wD9PyZpOMLzP-opHXlOVOWZ067galJN1h4gPbb0nvxxPWp7kPN2LDlOzt_tJxzrfvC1PjFQwNSDCm_l-Ju5X2zQtlXyJOTZSLQlCtB2C7jdyoAVwrftUXBFDkisElvgmoKlwBks23fU0tfjhwc0LVWXqhGtFQx8GGBQ-zol3e7P2EXmtIClf4KbgYq5u7Lwu848qwaItyTt7EmM2IjxVth64wHlVQruy3GXnIurcaGb_qWg764qZmteoPl5uAWwuTDX292Sa071S7GfsHFxue5lydxIYvpVUu6dyfwuExEubCovYMfz_LJd5zNTKMMatdbBJg-Qd6JPuXznqc1UYC3CccEXCLTOgg_auB6EUdG0b_cy-5bkEOHm7Wi4SDipGNig_ShzUkkot5qSqPZnd2I9IqqToi_0ep2nYLBB3ny3teW21Qpccoom3aGPt5Zl7fpzhg7Q8zsJ4sQ2SuHRCzgQ1uxYlFx21VUtHAjnFDSoMOkGyo4gH2wcLR7-z59EPPNl51pljyNefgCnMSkjrBPyz1wiET-uqi23f8Bq2TVk1jmUFxOwdfLsU7SIS30WOzvwD_gMDexUFpMlEQyL1-Y36kaTLjEWGCi2tx1FTULttQx5JpryPW6lW5oKw5RMyGpfRliYCiRyQePYqipZGoxOHpvCWhCZIN4meDY7H0RxWWQEpiyCzRQgWkOtMViwao6Jb7wZWbLNMebwLJeQJXWunk-gTEeQaMykVJobwDUiX-E_E7fSybVRTZXherY1jrvZKh8C5Gi5VADg5Vs319uN8-dVILRyOOlvjjxclmsRcn6HEvTvxd9MS7lKm2gI8BXIqhzgnTdqNGwTpmDHPV8hygqJWxWXCltBSSgY6OkGkioMAmXjZjYq_Ya9o6AE7WU_hUdm-wZmQLExwtJWEIBdDxrUxA9L9JL3weNyQtaGItPjXcheZiNBBbJTUxXwIYLnXtT1M0mHzMqGFFWXVKsN_AIdHyv4yDzY9m-tuQRfbQ_2K7r5eDOL1Tj8DZ-s8yXG74MMBqOUvlglJNgNcbuPKLRPbSDoN0E3BYkfeDgiUrXy34a5-vU-PkAWCsgAh539wJUUBxqw90V1Du7eTHFKDJEMSFYwusbPhEX4ZTwoeTHg--8Ysn4HCFWLQ00pfBCteqvMvMflcWwVfTnogcPsJb1bEFVSc3nTzhk6Ln8J-MplyS0Y5mGBEtVko_WlyeFsoDCWj4hqrgU7L-ww8vsCRSQfskH8lodiLzj0xmugiKjWUXbYq98x1zSnB9dmPy5P3UNwwMQdpebtR38N9I-jup4Bzok0-JsaOe7EORZ8ld7kAgDWa4K7BAxjc2eD540Apwxs-VLGFVkXbQgYYeDNG2tW1Xt20-XezJqZVUl6-IZXsqc7DijwNInO3fT5o8ZAcLKUUlzSlEXe8sIlHaxjLoJ-oubRtlKKUbzWOHeyxmYZSxYqQhSQj4sheedGXJEYWJ-Y5DRqB-xpy-cftxL10fdXIUhe1hWFBAoQU3b5xRY8KCytYnfLhsFF4O49xhnax3vuumLpJbCqTXpLureoKg5PvWfnpFPB0P-ZWQN35mBzqbb3ZV6U0rU55DvyXTuiZOK2Z1TxbaAd1OZMmg0cpuzewgueV-Nh_UubIqNto5RXCd7vqgqdXDUKAiWyYegYIkD4wbGMqIjxV8Oo2ggOcSj9UQPS1rD5u0rLckAzsxyty9Q5JsmKa0w8Eh7Jwe4Yob4xPVWWbJfm916avRgzDxXo5gmY7txdGFYHhlolJKdhBU9h6f0gtKEtbiUzhp4IWsqAR8riHQs7lLVEz6P537a4kL1r5FjfDf_yjJDBQmy_kdWMDqaNln-MlKK8eENjUO-qZGy0Ql4bMZtNbHXjfJUuSzapA-RqYfkqSLKgQUOW8NTDKhUk73yqCU3TQqDEKaGAoTsPscyMm7u_8QrvUK8kbc-XnxrWZ0BZJBjdinzh2w-QvjbWQ5mqFp4OMgY94__tIU8vvCUNJiYA1RdyodlfPfH5-avpxOCvBD6C7ZIDyQ-6huGEQEAb6DP8ydWIZQ8xY603DoEKKXkJWcP6CJo3nHFEdj_vcEbDQ-WESDpcQFa1fRIiGuALj-sEWcjGdSHyE8QATOcuWl4TLVzRPKAf4tCXx1zyvhJbXQu0jf0yfzVpOhPun4n-xqK4SxPBCeuJOkQ2VG9jDXWH4pnjbAcrqjveJqVti7huMXTLGuqU2uoihBw6mGqu_WSlOP2-XTEyRyvxbv2t-z9V6GPt1V9ceBukA0oGwtJqgD-q7NXFK8zhw7desI5PZMXf3nuVgbJ3xdvAlzkmm5f9RoqQS6_hqwPQEcclq1MEZ3yML5hc99TDtZWy9gGkhR0Hs3QJxxgP7bEqGFP-HjTPnJsrGaT6TjKP7qCxJlcFKLUr5AU_kxMULeUysWWtSGJ9mpxBvsyW1Juo",
      "seed": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "crv": "P-256",
      "x": "jUzUIRLZt3tlHqWrTj310Qft7BnSr_26faiCGxtlG5g",
      "y": "9jP3S3Rjkqjgro5T2Q849SI-ny77fvXZaWmtzajhKcg",
      "d": "rqVUtld5LDi0TLp8-sxR06hZ2ydOl8Qhs3Z9_XcXadg"
    },
    "jws": "eyJhbGciOiJNTC1EU0EtNjUtRVMyNTYiLCJraWQiOiJlUWkxS1JQSzVtbUk5a25UTE5VZkNFTF9RX3RXWHhJZGRhNHhVV2VPYWdVIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.46RTEDL5c3ntPTu1OhdDwgxhMtXotslbJazLQzLPOqMajxzyPc_KB_hmg6U2AHEJcnSYbM-Qtb8ryndRWW6Vt30rncmiDdDRO_PhNCHHVm_SHpvXGuLB2nn0_fWLJirwx_wGQekCzi8ZD3_4bBEtimCDdci2V3D7lT7ZeSGhyYJDfEFZhqUXwWmKwPGuKpEyJuZ4u_O45VAFeAbzUinQ997-MYjge6EQTnkihMl-nVrppGZx04DqDDoEFDuuUyNR27GOkcTjyLHgQmVcYnF19Yd3E6dzeai8lYdGsQh5aeEUSoQHVJj6QhMY3FfC13Z8_6YCIDkj5yZ3ar8K83zYPm5gYTAFGNTmDhh9cuzl74SeOrAznWobtd0NzGC2-WcqhoSKyy-ZWpjVkvijfJLLur0gyBjHbIdfuk-vvENzrjEMpRuVrQcAi0PcQeJfAmNv4YdV-iYsaIRBwwplmir94-jSr8_A2GTSq9CVor7-ZNI-3F17UpB7UwPK6gtsBXGzRE6ZRzqWCR74WZ8PnUOFWY8ZpEGjS3FAvQnndHZxpaVy34KuX8FJd5_WkgEl9PoTufCzWFWAmvsgehDVje71re13WZQEVCLXkyC-QNx35AWyBc2j11PJ_FKtXxOvB0JgYLwbM3tctxVxt-iNxd_usjJzwLaCTtSrkkvSzZR_RiRXFIuhaGy8qaP_G5byg7cCgr3WVvyMBvOM0vdDRHwKpjFsNvF23vzh5Wdf1zAE38jvgDHz6Xk9NBmjm294sBF13gA3NvouqQp9e8sQMpo0DAV1HQZ76J67nRo-vtwfDpND2SnRZHBumPxh2sQpYEzMVhBh8n8lFA996g_3tngcf23XI-pzWTcrNT2VXNp7-ebuVdPCbxgZbnKXwGgAg4ibLlG-ZDYsAbV3Ooq6sol9FgvRj6Wie1HVM2i-tek6iu73WH1lnd4ghutcPnvnx6d9WDgBaBQSDfC2lwqXHKsYYDyEJx2Ux87M3oiq5QcP7VtBsqOkM0zCwSqgXZIs7HmxJxrgI-fsAc1bgF9348jmnMtiLi8Z1iHcl8VGGwLzQ-qCDs9N7DpZFXFZ3dX5bA6_levPGu5NwiTH_tS8QQDyMAtlllGquu6mOOmLc5PB7pMN2oKHKZHAXlwhZeCu_wE6feleulmpE1pMMM8GdzJfnGwRsMjPZAMx1Pn2sis0sWV2qtVHDuA6TkDaHgcI-8ke0Pdy6ySRk3jH2rA2KINF_UK3_oJLAin7nDjlf-V-uhhzpjVch9xNXV80tynM9agg_Hf7jAjZCzpKuZVGqy9SyDOgoVdblM3Qz6Ew596iX07IkQQeyE-fu-TAALckpXXKk3QRJGduroRrnlZsWFWOAdnr0JT3V2M4tcVZFDGmaIsEiQ0XzNxLoSOIx_OTvXgC_m2ptnODgXkNe24UIqv8-LZ9E5THz9bVMNR8-KZYeA1GjsKrss2ZfZ2wTK-Q8bOX2i58QM6EW0McLEZ7QZVoZpTlcj8hZaF7L_626h0yb-ortgfnMBHzSMzwMLpS-SJEbL3ajKb_H5z5Hh83sVTeupHJSfPwf0y8w7-LWn19nQgZaKBdKLxjSgOW7i5qmd8jDlrMtiZxg6JBFNV3PG9iFayPFJe07ShDx7-DAq6F8TPGJ5x6jyUIRb0T56FpB99rRSHS422PPOFBirGjEpKcw_c14TRFqp0ySEy5bQS06aY9ciaXmooD8LPmGFT7DjCCkHJi150xDgryPvM5SVB1ar-qBQWnz6CJcIlp9K7g6ioG6IQuj7b2APIkWeKY8e4Ru3j_LkKmgmmFrDVarvY4FfzmvmHd6rf7OlB_g4uIgcVB7a1ZncbuAaqd_SA6FSldcdHK5GSlodXWyo_T0WgaLwQNeR1V4m1wHLJSnfN_kXnkcKTIEDre-PlWNmePWDiB1Nz3uA11gA-0BSXzZ2TbnAN8M-37Fu-2nOSG8t7cXboUSOTjX6mt1zSjfGjrWe_jBobL30CPdhISrrNcGkwVBoh6OUmtnk_3XDKySBAZ2s1B6Rpn5DFt2V4LC5iwiJlEC2KchrP5lTs8woRsE8djGnXkwwzj7DsxISj8kyXS7q12_6WjGNSptzz06u8BvbAH2ZHk-lsnQeUf3obQaWNFVfzDDtXT-83MUVJNPMQvGtyGhiPu2OxEYD5_BxufV4SK0EF5OHrUSX8Xg8aD8b-zW66On9bk_shoa2TtUHiCgfWxX1xMel6szBF6jtDB3pjiYmjFu10jrCmwzSN6ZgCn9XSQ9TETcRRZonMt-_xO1OWI6I6eRoHc6TzM5y8FFw6mmSuEZMPMOQLK_dH3TXNolmo0zRqi_XC7w3IJ8bzf6NoCOW9g3pbs8LRbnswzoeXR-MBT8IxIs5sI7HP3AIxoWGI907h98jh3MCsLXvvKdYfG7eabFAd-_65hph4mm_AWzueGt_8rIgwbT6bwP1dL0yBIdoHXxJHPsaz3d-SzgzEj744enWGT8aaW0iWb7GgxR7ZNgzll5ikT7wlfVq6MkOfNz_UXcD9gZLcZZ1bM-FnGyacvCPVxJUfgyII0gGgoMGaj3m7WrxZH3TYlqx74BoE-gKh-swNC8ukczCODakdkel1GPOo9U9MLjuOgrx3CYZDBAukLxG9XJZvaMpoHs1sg_XaPyzAbuIinwOX7svDaHAaYwvfQMAtRO5R88FZDI7QOBNKjZNRHBhRDojlHQtVnpBwh5VAOvTqVMlR1hTgYgRSm8_5pQR0ADChuG3z44Gmt0VdBGO9eoYO7YnagPsun8LDHneCDtXWoP2TcxJ8GJUK3k9VFGROPueTCQF-wijizmJyfnGqAFaj2Ng86wQwwaQMeStBHW8AVUTnB6mzI5gghlGyGSLymbdanUDMcvIPAByhZ8yLnBc3_xZ47ujbjNKz-isPGu76SaqnFZT0tqQRUN7yjyvTig46dcTqPY4dSGlRmBiV3G1bf_bMKI-2p_KewFqEJ2crF5x2Y8peNSf7_VKiUlJkS42-aQC6wxuD2d5-bqqoKpyUL90JRcxjTDABUKUU0Qq36aJSFjP6ltwthPfe6vhGBNZ8gLoNKIyjg2wBQagvK2pjbgi48N5MjH3POp-7ZMiJiVH-UhTcvOzTMnZ9MS6VAWsQRTlWxB21M_O_I3WqQjocYnjpn41KroJYEL6cdapoCv0iE7CeRn9RAjsTNuRYT86uRUDt-Mv3vw8RDSLusbpxoRb_rql1PxSPoOuKTfWM1lXBXShYRZ1yNV2uw4831r4U4cU86P1Guyjakjkm8eMh4XFFpxEzux9YIDFIpxCpQq51GKMnCKLfnLB8LwTPM02YITLrhis8aHYrsluZ5GWuiiBxM0D4GhFBEBTSBsxDZsvaQ1yXypOLJkRMJCZOIWIVDoGQ64mSGQyQ6J0nBsJGDQ77HQQYcssIkrH4Yip6CjiES7cVvnQVagBj-NtFqdTIli0RQ_eVW2lEqazpA0DyNuXgMX7ZVP98vFlXln0ElgLjfvWt4LsXZ6ZIRY5UXn7hSy8ctp5ac_165X4_tNRGqQ75YDeexbtWfj84wff496qj_lo_2jtyEu0UlmoGGHjWyMQmxbrXiRXPtmm0KiHV51TSocnEIH82PnLXLqdN5PF4SvaeSnwOp8G7zKfXCm2g8-aHhHfAhwmq_QNCJgOzlWr2y8iDwi6kvYFwj1eM6yzC6SuBCtQs7rpKqTy-JfzCcwtAhj2vcYyCWhH3J9xpblo3d3vUXpA8byTa1OcF3m2kzTDYy69gGbuvEirdWX3a8nOEXEKh4wSZWTr2w-NfRe-U5M2urnZly6jb3xI8K6BgDJ4P6jCou5Jt7H9jBQocsN-35PYq30tj6ALn_zOQnTlJwWo8PaZ2_2_rfg6GJLwX1HVLm1vmt7YHF8F6YcSsuhPpDDqqTAbf-pRnX882JE6H7eLBhzbOCx09W41OuBxfNbhtQd54Ui1tDzP5x2fOnBG6ECfGhGQmWmt4ScuI-gtN77zFXkotlQVKAiq9WSvjCtftTMn1lAkp6_evEOjsqiivfsFhITW8O7GDN_BMwVEd5H3WCFBAXOJy6yjXx9Q73p8uP8OSxY5JX7ZWXF6eYTqVjz1CZEJ87_icK5pbY3xmi4Ba9XJPz1S5K8JX4l05t-d1ONax81WVxSsDwug0b5PTlvZJ7yz47hb6U8gBUAYq7Mc3ZW7EGz6qM8PGHipshzh9Oy8bfpOLW4nFDFFl22hVkIoLbWE9jSUvU6WzhpcQbD9hI2T30TRqBazmnM_LkJJ9KtFbLqw0qGZpERtzegHP_WRwiZyiftU-XJ9QSsAFMw4cpsVganmAkWN2bTJfcY74hNDVAQWfAH0d2i5OpvQGnr8XYPD1FW3CYMjpQbHidpN73-Lfe6eoAAAAAAAAAAAAAAAAAAAAABw4TGSMnY1A-oDDQqbtD_77c6JN7GVyl-ld20FTjQYGb8s46lJfdXY9tS9JaNtuDt7W9NfEfqaSmabTLDOj8tcwaqtZWBg",
    "raw_to_be_signed": "436f6d706f73697465416c676f726974686d5369676e617475726573323032354d4c2d4453412d36352d45533235360065794a68624763694f694a4e54433145553045744e6a557452564d794e5459694c434a72615751694f694a584e5456456444564e52326f744d564e494e574a57596e6c52565749345a30785a4c584661647a4a4d4f5759796147524862334178656a4256496e302e53585469674a6c7a494745675a4746755a3256796233567a49474a3163326c755a584e7a4c434247636d396b627977675a323970626d63676233563049486c76645849675a473976636934",
    "raw_composite_signature": "e3a4531032f97379ed3d3bb53a1743c20c6132d5e8b6c95b25accb4332cf3aa31a8f1cf23dcfca07f86683a5360071097274986ccf90b5bf2bca7751596e95b77d2b9dc9a20dd0d13bf3e13421c7566fd21e9bd71ae2c1da79f4fdf58b262af0c7fc0641e902ce2f190f7ff86c112d8a608375c8b65770fb953ed97921a1c982437c415986a517c1698ac0f1ae2a913226e678bbf3b8e550057806f35229d0f7defe3188e07ba1104e792284c97e9d5ae9a46671d380ea0c3a04143bae532351dbb18e91c4e3c8b1e042655c627175f5877713a77379a8bc958746b1087969e1144a84075498fa421318dc57c2d7767cffa602203923e726776abf0af37cd83e6e6061300518d4e60e187d72ece5ef849e3ab0339d6a1bb5dd0dcc60b6f9672a86848acb2f995a98d592f8a37c92cbbabd20c818c76c875fba4fafbc4373ae310ca51b95ad07008b43dc41e25f02636fe18755fa262c688441c30a659a2afde3e8d2afcfc0d864d2abd095a2befe64d23edc5d7b52907b5303caea0b6c0571b3444e99473a96091ef8599f0f9d4385598f19a441a34b7140bd09e7747671a5a572df82ae5fc149779fd6920125f4fa13b9f0b35855809afb207a10d58deef5aded775994045422d79320be40dc77e405b205cda3d753c9fc52ad5f13af07426060bc1b337b5cb71571b7e88dc5dfeeb23273c0b6824ed4ab924bd2cd947f462457148ba1686cbca9a3ff1b96f283b70282bdd656fc8c06f38cd2f743447c0aa6316c36f176defce1e5675fd73004dfc8ef8031f3e9793d3419a39b6f78b01175de003736fa2ea90a7d7bcb10329a340c05751d067be89ebb9d1a3ebedc1f0e9343d929d164706e98fc61dac429604ccc561061f27f25140f7dea0ff7b6781c7f6dd723ea7359372b353d955cda7bf9e6ee55d3c26f18196e7297c0680083889b2e51be64362c01b5773a8abab2897d160bd18fa5a27b51d53368beb5e93a8aeef7587d659dde2086eb5c3e7be7c7a77d5838016814120df0b6970a971cab18603c84271d94c7ceccde88aae5070fed5b41b2a3a4334cc2c12aa05d922cec79b1271ae023e7ec01cd5b805f77e3c8e69ccb622e2f19d621dc97c5461b02f343ea820ecf4dec3a59157159ddd5f96c0ebf95ebcf1aee4dc224c7fed4bc4100f2300b659651aabaeea638e98b7393c1ee930dda82872991c05e5c2165e0aeff013a7de95eba59a9135a4c30cf0677325f9c6c11b0c8cf640331d4f9f6b22b34b16576aad5470ee03a4e40da1e0708fbc91ed0f772eb24919378c7dab036288345fd42b7fe824b0229fb9c38e57fe57eba1873a6355c87dc4d5d5f34b729ccf5a820fc77fb8c08d90b3a4ab99546ab2f52c833a0a1575b94cdd0cfa130e7dea25f4ec891041ec84f9fbbe4c000b724a575ca93741124676eae846b9e566c58558e01d9ebd094f7576338b5c5591431a6688b04890d17ccdc4ba12388c7f393bd7802fe6da9b6738381790d7b6e1422abfcf8b67d1394c7cfd6d530d47cf8a658780d468ec2abb2cd997d9db04caf90f1b397da2e7c40ce845b431c2c467b4195686694e5723f2165a17b2ffeb6ea1d326fea2bb607e73011f348ccf030ba52f922446cbdda8ca6ff1f9cf91e1f37b154deba91c949f3f07f4cbcc3bf8b5a7d7d9d081968a05d28bc634a0396ee2e6a99df230e5accb6267183a24114d5773c6f6215ac8f1497b4ed2843c7bf8302ae85f133c6279c7a8f250845bd13e7a16907df6b4521d2e36d8f3ce1418ab1a312929cc3f735e13445aa9d32484cb96d04b4e9a63d7226979a8a03f0b3e61854fb0e3082907262d79d310e0af23ef3394950756abfaa0505a7cfa089708969f4aee0ea2a06e8842e8fb6f600f22459e298f1ee11bb78ff2e42a6826985ac355aaef63815fce6be61ddeab7fb3a507f838b8881c541edad599dc6ee01aa9dfd203a15295d71d1cae464a5a1d5d6ca8fd3d1681a2f040d791d55e26d701cb2529df37f9179e470a4c8103adef8f95636678f583881d4dcf7b80d75800fb40525f36764db9c037c33edfb16efb69ce486f2dedc5dba1448e4e35fa9add734a37c68eb59efe30686cbdf408f761212aeb35c1a4c1506887a3949ad9e4ff75c32b2481019dacd41e91a67e4316dd95e0b0b98b08899440b629c86b3f9953b3cc2846c13c7631a75e4c30ce3ec3b312128fc9325d2eead76ffa5a318d4a9b73cf4eaef01bdb007d991e4fa5b2741e51fde86d069634555fcc30ed5d3fbcdcc51524d3cc42f1adc868623eed8ec44603e7f071b9f57848ad04179387ad4497f1783c683f1bfb35bae8e9fd6e4fec8686b64ed50788281f5b15f5c4c7a5eaccc117a8ed0c1de98e26268c5bb5d23ac29b0cd237a6600a7f57490f53113711459a2732dfbfc4ed4e588e88e9e4681dce93ccce72f05170ea6992b8464c3cc3902cafdd1f74d7368966a34cd1aa2fd70bbc37209f1bcdfe8da02396f60de96ecf0b45b9ecc33a1e5d1f8c053f08c48b39b08ec73f7008c6858623dd3b87df23877302b0b5efbca7587c6ede69b14077effae61a61e269bf016cee786b7ff2b220c1b4fa6f03f574bd320487681d7c491cfb1acf777e4b3833123ef8e1e9d6193f1a696d2259bec683147b64d833965e62913ef095f56ae8c90e7cdcff517703f6064b7196756ccf859c6c9a72f08f5712547e0c882348068283066a3de6ed6af1647dd3625ab1ef806813e80a87eb30342f2e91ccc23836a47647a5d463cea3d53d30b8ee3a0af1dc26190c102e90bc46f57259bda329a07b35b20fd768fcb301bb888a7c0e5fbb2f0da1c0698c2f7d0300b513b947cf0564323b40e04d2a364d447061443a2394742d567a41c21e5500ebd3a953254758538188114a6f3fe69411d000c286e1b7cf8e069add1574118ef5ea183bb6276a03ecba7f0b0c79de083b575a83f64dcc49f062542b793d54519138fb9e4c2405fb08a38b3989c9f9c6a8015a8f6360f3ac10c3069031e4ad0475bc0155139c1ea6cc8e60821946c8648bca66dd6a750331cbc83c0072859f322e705cdffc59e3bba36e334acfe8ac3c6bbbe926aa9c5653d2da9045437bca3caf4e2838e9d713a8f6387521a54660625771b56dffdb30a23eda9fca7b016a109d9cac5e71d98f2978d49feff54a894949912e36f9a402eb0c6e0f6779f9baaaa0aa7250bf742517318d30c005429453442adfa6894858cfea5b70b613df7babe1181359f202e834a2328e0db00506a0bcada98db822e3c3793231f73cea7eed9322262547f9485372f3b34cc9d9f4c4ba5405ac4114e55b1076d4cfcefc8dd6a908e87189e3a67e352aba096042fa71d6a9a02bf4884ec27919fd4408ec4cdb91613f3ab91503b7e32fdefc3c44348bbac6e9c6845bfebaa5d4fc523e83ae2937d63359570574a1611675c8d576bb0e3cdf5af8538714f3a3f51aeca36a48e49bc78c8785c5169c44ceec7d6080c5229c42a50ab9d4628c9c228b7e72c1f0bc133ccd366084cbae18acf1a1d8aec96e679196ba2881c4cd03e06845044053481b310d9b2f690d725f2a4e2c9911309099388588543a0643ae2648643243a2749c1b0918343bec741061cb2c224ac7e188a9e828e2112edc56f9d055a8018fe36d16a7532258b4450fde556da512a6b3a40d03c8db9780c5fb6553fdf2f1655e59f412580b8dfbd6b782ec5d9e992116395179fb852cbc72da7969cff5eb95f8fed3511aa43be580de7b16ed59f8fce307dfe3deaa8ff968ff68edc84bb45259a81861e35b23109b16eb5e24573ed9a6d0a887579d534a87271081fcd8f9cb5cba9d3793c5e12bda7929f03a9f06ef329f5c29b683cf9a1e11df021c26abf40d08980ece55abdb2f220f08ba92f605c23d5e33acb30ba4ae042b50b3bae92aa4f2f897f309cc2d0218f6bdc632096847dc9f71a5b968ddddef517a40f1bc936b539c1779b69334c3632ebd8066eebc48ab7565f76bc9ce11710a878c126564ebdb0f8d7d17be539336bab9d9972ea36f7c48f0ae818032783fa8c2a2ee49b7b1fd8c142872c37edf93d8ab7d2d8fa00b9ffcce4274e52705a8f0f699dbfdbfadf83a1892f05f51d52e6d6f9aded81c5f05e98712b2e84fa430eaa9301b7fea519d7f3cd8913a1fb78b061cdb382c74f56e353ae0717cd6e1b50779e148b5b43ccfe71d9f3a7046e8409f1a11909969ade1272e23e82d37bef3157928b654152808aaf564af8c2b5fb53327d65024a7afdebc43a3b2a8a2bdfb058484d6f0eec60cdfc13305447791f7582141017389cbaca35f1f50ef7a7cb8ff0e4b1639257ed959717a7984ea563cf5099109f3bfe270ae696d8df19a2e016bd5c93f3d52e4af095f8974e6df9dd4e35ac7cd565714ac0f0ba0d1be4f4e5bd927bcb3e3b85be94f20054018abb31cdd95bb106cfaa8cf0f1878a9b21ce1f4ecbc6dfa4e2d6e27143145976da15642282db584f63494bd4e96ce1a5c41b0fd848d93df44d1a816b39a733f2e4249f4ab456cbab0d2a199a4446dcde8073ff591c2267289fb54f9727d412b0014cc38729b1581a9e602458dd9b4c97dc63be213435404167c01f47768b93a9bd01a7afc5d83c3d455b7098323a506c789da4def7f8b7dee9ea00000000000000000000000000000000070e1319232763503ea030d0a9bb43ffbedce8937b195ca5fa5776d054e341819bf2ce3a9497dd5d8f6d4bd25a36db83b7b5bd35f11fa9a4a669b4cb0ce8fcb5cc1aaad65606",
    "raw_composite_public_key": "424b2f267e58d5b3b44d71acfc6a656bb26950d57c61db1c880bcfa1feab443f0942ab8bdbad7d708abbc356078f6d99a252271fe62c74091eb94afb9b9264c50a888e0dfed80cd5fb2cbd3667e60d539ebe44930219cd4faed15dbb3455a264802b9f49bce42ee7550feffdd4642a55ade693868a460cbec03f4fc99a4e30bccffa8a475e5395396674ebb81a94937587880f6dbd27bf1c4f5a9ee43cdd8b0e53b3b7fb49c73adfbc2d4f8c54303520c29bf97e26ee57db342d957c893936522d0942b41d82ee3772a00570adfb545c1143922b0496f826a0a970064b36ddf534b5f8e1c1cd0b5565ea846b45431f0618143ece89777bb3f61179ad20295fe0a6e062ae6eecbc2ef38f2ac1a22dc93b7b126336223c55b61eb8c0795542bbb2dc65e722eadc6866ffa9683beb8a999ad7a83e5e6e016c2e4c35f6f7649ad3bd52ec67ec1c5c6e7b9972771218be9554bba7727f0b84c44b9b0a8bd831fcff2c9779ccd4ca30c6ad75b04983e41de893ee5f39ea7355180b709c7045c22d33a083f6ae07a114746d1bfdccbee5b9043879bb5a2e120e2a4636283f4a1cd4924a2de6a4aa3d99ddd88f48aaa4e88bfd1ea769d82c10779f2ded796db542971ca289b76863ede5997b7e9ce183b43ccec278b10d92b87442ce0435bb1625171db5554b470239c50d2a0c3a41b2a38807db070b47bfb3e7d10f3cd979d69963c8d79f8029cc4a48eb04fcb3d708844febaa8b6ddff01ab64d59358e6505c4ec1d7cbb14ed2212df458ecefc03fe03037b1505a4c9444322f5f98dfa91a4cb8c45860a2dadc7515350bb6d431e49a6bc8f5ba956e682b0e513321a97d1962602891c9078f62a8a9646a31387a6f09684264837899e0d8ec7d11c565901298b20b345081690eb4c562c1aa3a25bef06566cb34c79bc0b25e4095d6ba793e81311e41a3329152686f00d4897f84fc4edf4b26d545365785ead8d63aef64a87c0b91a2e5500383956cdf5f6e37cf9d5482d1c8e3a5be38f17259ac45c9fa1c4bd3bf177d312ee52a6da023c05722a8738274dda8d1b04e99831cf57c87282a256c565c296d0524a063a3a41a48a83009978d98d8abf61af68e8013b594fe151d9bec199902c4c70b49584201743c6b53103d2fd24bdf078dc90b5a188b4f8d772179988d0416c94d4c57c0860b9d7b53d4cd261f332a1851565d52ac37f008747cafe320f363d9beb6e4117db43fd8aeebe5e0ce2f54e3f0367eb3cc971bbe0c301a8e52f96094936035c6ee3ca2d13db483a0dd04dc16247de0e0894ad7cb7e1ae7ebd4f8f900582b20021e77f70254501c6ac3dd15d43bbb7931c5283244312158c2eb1b3e1117e194f0a1e4c783efbc62c9f81c21562d0d34a5f042b5eaaf32f31f95c5b055f4e7a2070fb096f56c415549cde74f3864e8b9fc27e3299724b4639986044b55928fd6972785b280c25a3e21aab814ecbfb0c3cbec0914907ec907f25a1d88bce3d319ae8222a35945db62af7cc75cd29c1f5d98fcb93f750dc3031076979bb51dfc37d23e8eea78073a24d3e26c68e7bb10e459f2577b90080359ae0aec10318dcd9e0f9e34029c31b3e54b1855645db420618783346dad5b55eddb4f977b326a655525ebe2195eca9cec38a3c0d2273b77d3e68f1901c2ca5149734a51177bcb089476b18cba09fa8b9b46d94a2946f358e1decb1998652c58a90852423e2c85e79d19724461627e6390d1a81fb1a72f9c7edc4bd747dd5c85217b5856141028414ddbe71458f0a0b2b589df2e1b051783b8f718676b1defbae98ba496c2a935e92eeadea0a8393ef59f9e914f0743fe65640ddf9981cea6dbdd957a534ad4e790efc974ee89938ad99d53c5b680775399326834729bb37b082e795f8d87f52e6c8a8db68e515c277bbea82a7570d4280896c987a0608903e306c632a223c55f0ea3682039c4a3f5440f4b5ac3e6ed2b2dc900cecc72b72f50e49b2629ad30f0487b2707b86286f8c4f55659b25f9bdd7a6af460cc3c57a3982663bb717461581e196894929d84153d87a7f482d284b5b894ce1a78216b2a011f2b88742cee52d5133e8fe77edae242f5af91637c37ffca32430509b2fe4756303a9a3659fe32528af1e10d8d43bea991b2d109786cc66d35b1d78df254b92cdaa40f91a987e4a922ca81050e5bc3530ca85493bdf2a825374d0a8310a6860284ec3ec732326eeeffc42bbd42bc91b73e5e7c6b599d016490637629f3876c3e42f8db590e66a85a7838c818f78fffb4853cbef09434989803545dca87657cf7c7e7e6afa71382bc10fa0bb6480f243eea1b861101006fa0cff3275621943cc58eb4dc3a0428a5e425670fe82268de71c511d8ffbdc11b0d0f961120e971015ad5f448886b802e3fac11672319d487c84f1001339cb969784cb57344f2807f8b425f1d73caf8496d742ed237f4c9fcd5a4e84fba7e27fb1a8ae12c4f0427ae24e910d951bd8c35d61f8a678db01caea8ef789a95b62ee1b8c5d32c6baa536ba88a1070ea61aabbf59294e3f6f974c4c91cafc5bbf6b7ecfd57a18fb7557d71e06e900d281b0b49aa00feabb35714af33870edd7ac2393d93177f79ee5606c9df176f025ce49a6e5ff51a2a412ebf86ac0f40471c96ad4c119df230be6173df530ed656cbd8069214741ecdd0271c603fb6c4a8614ff878d33e726cac6693e938ca3fba82c4995c14a2d4af9014fe4c4c50b794cac596b52189f66a7106fb325b526ea8d4cd42112d9b77b651ea5ab4e3df5d107edec19d2affdba7da8821b1b651b98f633f74b746392a8e0ae8e53d90f38f5223e9f2efb7ef5d96969adcda8e129c8"
}
~~~~~~~~~~
{: #jose_example_ML_DSA_65_ES256 title="ML-DSA-65-ES256"}


~~~~~~~~~~
{
    "seed": "0000000000000000000000000000000000000000000000000000000000000000",
    "jwk": {
      "kid": "9_fvZ18WqbLNofkngEFEVdsY52TczhKAroRkt-oH1Ihi0ci8FMxw5hS_lH7U-l5b",
      "kty": "AKP-EC",
      "alg": "ML-DSA-87-ES384",
      "pub": "5F_8jMc9uIXcZi5ioYzY44AylxF_pWWIFKmFtf8dt7Roz8gruSnx2Gt37RT1rhamU2h3LOUZEkEBBeBFaXWukf22Q7US8STV5gvWi4x-Mf4Bx7DcZa5HBQHMVlpuHfz8_RJWVDPEr-3VEYIeLpYQxFJ14oNt7jXO1p1--mcv0eQxi-9etuiX6LRRqiAt7QQrKq73envj9pkUbaIpqL2z_6SWRFln51IXv7yQSPmVZEPYcx-DPrMN4Q2slv_-fPZeoERcPjHoYB4TO-ahAHZP4xluJncmRB8xdR-_mm9YgGRPTnJ15X3isPEF5NsFXVDdHJyTT931NbjeKLDHTARJ8iLNLtC7j7x3XM7oyUBmW0D3EvT34AdQ6eHkzZz_JdGUXD6bylPM1PEu7nWBhW69aPJoRZVuPnvrdh8P51vdMb_i-gGBEzl7OHvVnWKmi4r3-iRauTLmn3eOLO79ITBPu4CZ6hPY6lfBgTGXovda4lEHW1Ha04-FNmnp1fmKNlUJiUGZOhWUhg-6cf5TDuXCn1jyl4r2iMy3Wlg4o1nBEumOJahYOsjawfhh_Vjir7pd5aUuAgkE9bQrwIdONb788-YRloR2jzbgCPBHEhd86-YnYHOB5W6q7hYcFym43lHb3kdNSMxoJJ6icWK4eZPmDITtbMZCPLNnbZ61CyyrWjoEnvExOB1iP6b7y8nbHnzAJeoEGLna0sxszU6V-izsJP7spwMYp1Fxa3IT9j7b9lpjM4NX-Dj5TsBxgiwkhRJIiFEHs9HE6SRnjHYU6hrwOBBGGfKuNylAvs-mninLtf9sPiCke-Sk90usNMEzwApqcGrMxv_T2OT71pqZcE4Sg8hQ2MWNHldTzZWHuDxMNGy5pYE3IT7BCDTGat_iu1xQGo7y7K3Rtnej3xpt64br8HIsT1Aw4g-QGN1bb8U-6iT9kre1tAJf6umW0-SP1MZQ2C261-r5NmOWmFEvJiU9LvaEfIUY6FZcyaVJXG__V83nMjiCxUp9tHCrLa-P_Sv3lPp8aS2ef71TLuzB14gOLKCzIWEovii0qfHRUfrJeAiwvZi3tDphKprIZYEr_qxvR0YCd4QLUqOwh_kWynztwPdo6ivRnqIRVfhLSgTEAArSrgWHFU1WC8Ckd6T5MpqJhN0x6x8qBePZGHAdYwz8qa9h7wiNLFWBrLRj5DmQLl1CVxnpVrjW33MFso4P8n060N4ghdKSSZsZozkNQ5b7O6yajYy-rSp6QpD8msb8oEX5imFKRaOcviQ2D4TRT45HJxKs63Tb9FtT1JoORzfkdv_E1bL3zSR6oYbTt2Stnpz-7kVqc8KR2N45EkFKxDkRw3IXOte0cq81xoU87S_ntf4KiVZaszuqb2XN2SgxnXBl4EDnpehPmqkD92SAlLrQcTaxaSe47G28K-8MwoVt4eeVkj4UEsSfJN7rbCH2yKl2XJx5huDaS0xn2ODQyNRmgk-5I9hXMUiZDNLvEzx4zuyrcu2d0oXFo3ZoUtVFNCB__TQCf2x27ej9GjLXLDAEi7qnl9Xfb94n0IfeVyGte3-j6NP3DWv8OrLiUjNTaLv6Fay1yzfUaU6LI86-Jd6ckloiGhg7kE0_hd-ZKakZxU1vh0Vzc6DW7MFAPky75iCZlDXoBpZjTNGo5HR-mCW_ozblu60U9zZA8bn-voANuu_hYwxh-uY1sHTFZOqp2xicnnMChz_GTm1Je8XCkICYegeiHUryEHA6T6B_L9gW8S_R4ptMD0Sv6b1KHqqKeubwKltCWPUsr2En9iYypnz06DEL5Wp8KMhrLid2AMPpLI0j1CWGJExXHpBWjfIC8vbYH4YKVl-euRo8eDcuKosb5hxUGM9Jvy1siVXUpIKpkZt2YLP5pEBP_EVOoHPh5LJomrLMpORr1wBKbEkfom7npX1g817bK4IeYmZELI8zXUUtUkx3LgNTckwjx90Vt6oVXpFEICIUDF_LAVMUftzz6JUvbwOZo8iAZqcnVslAmRXeY_ZPp5eEHFfHlsb8VQ73Rd_p8XlFf5R1WuWiUGp2TzJ-VQvj3BTdQfOwSxR9RUk4xjqNabLqTFcQ7As246bHJXH6XVnd4DbEIDPfNa8FaWb_DNEgQAiXGqa6n7l7aFq5_6Kp0XeBBM0sOzJt4fy8JC6U0DEcMnWxKFDtMM7q06LubQYFCEEdQ5b1Qh2LbQZ898tegmeF--EZ4F4hvYebZPV8sM0ZcsKBXyCr585qs00PRxr0S6rReekGRBIvXzMojmid3dxc6DPpdV3x5zxlxaIBxO3i_6axknSSdxnS04_bemWqQ3CLf6mpSqfTIQJT1407GB4QINAAC9Ch3AXUR_n1jr64TGWzbIr8uDcnoVCJlOgmlXpmOwubigAzJattbWRi7k4QYBnA3_4QMjt73n2Co4-F_Qh4boYLpmwWG2SwcIw2PeXGr2LY2zwkPR4bcSyx1Z6UK5trQpWlpQCxgsvV_RvGzpN22RtHoihPH74K0cBIzCz7tK-jqeuWl1A7af7KmQ66fpRBr5ykTLOsa17WblkcIB_jDvqKfEcdxhPWJUwmOo4TIQS-xH8arLOy_NQFG2m14_yxwUemXC-QxLUYi6_FIcqwPBKjCdpQtadRdyftQSKO0SP-GxUvamMZzWI780rXuOBkq5kyYLy9QF9bf_-bL6QLpe1WMCQlOeXZaCPoncgYoT0WZ17jB52Xb2lPWsyXYK54npszkbKJ4OIqfvF8xqRXcVe22VwJuqT9Uy4-4KKQgQ7TXla7Gdm2H7mKl8YXQlsGCT2Ypc8O4t0Sfw7qYAuaDGf752Hbm3fl1bupcB2huIPlIaDP6IRR9XvTYIW2flbwYfhKLmoVKnG85uUi2qtqCjPOIuU3-peT0othfmwKQXaoOqO-V4r6wPL1VHxVFtIYmEdVt0RccUOvpOVR_OAHG9uHOzTmueK5557Qxp0ojtZCHyN-hgoMZJLrvdKkTCxPNo2-mZQbHoVh2FnThZ9JbO49dB8lKXP4_MU5xAnjXMgKXtbfI8w6ZWATE_XWgf2VQMUpGp4wpy44yWQTxHxh_4T9540BGwG0FU0bkgrwA_erseGZnepqdmz5_ScCs84O5Xr5MbYhJLCGGxY6O5GqS-ooB2w0Mt87KbbE4bpYje9CAHH8FX3pDrJyLsyasA3zxmk4OmGpG7Z70ofONJtHRe56R5287vFmuazEEutXn81kNzB-3aJT1ga3vnWZw4CSvFKoWYSA7auLgrHSHFZdITfOrgtmQmGbFhM9kSBdY1UCnpzf65oos3PZWRa2twfUxxLAnPNtrxpRGyvtsapw7ljUagZmuyh3hLCjhAxYmnoE1dbyIWvpCqSlEtVjL1yb_nuLEzgvmZuV02fHxGuWgHTOMVGXpf81Rce3eoBK3lapW1wkzezlk3tcA2bZOtA9qbxdsbVR37kemzQ9K1e3Y0OWhtSj",
      "seed": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "crv": "P-384",
      "x": "_8nV9fbDlAuoctd_ceTVbGgImjz41g_D9UkBnfFxh7WeXEyIQOoL5RIBCbJ5lO6c",
      "y": "GQ9bXoklJs0T7XxXWqh_joj2c5wce86LImWywYI7csKbRPFzO6Hn4zdKgZVxSEqa",
      "d": "EjLOJnyUy_s3HG7tf1tlTjRjQ0YLWqZLK4W_u2JJTw9jsp6E6_FcioUU8JPOWkb0"
    },
    "jws": "eyJhbGciOiJNTC1EU0EtODctRVMzODQiLCJraWQiOiI5X2Z2WjE4V3FiTE5vZmtuZ0VGRVZkc1k1MlRjemhLQXJvUmt0LW9IMUloaTBjaThGTXh3NWhTX2xIN1UtbDViIn0.SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4.ON--mVCuVDRRihm5gw7gCI6F4-_a5cuPlfx7-XfmMCiVRtcjl2FjnrcBMcflHT0Uk0AYxQWhxbYSGqkRJpcJWbwqId0et0EswnoPxcVn1kIeW49zUCOq9CS-86dh88UZ6IgaedTYWlePIU6UOejhNP2p__VxfIVBAuHehTuQc8GGhs48sRseLTu2eB_qFtE8fNogP-4fZJjbA-jMnP8aPQibeH-5KgRxe6JZyxX-CHFq0PfoxgFmRY7W3BPfTzrT_NFjlUwSe3GEFRN0dfCZ4hGqMPXADmS8wRpjGEhLide0aPZFt6hZLeyYBw9Yy3neAYTcNjXRljimTKPnb9xHxm-UF5uq_BWG79TG7_IjJaIhX1W-X5py2NsIdjUNaRsDCuMn1mT1ADc9ORLvVouo3MjcnJE-py2o7M_tY0-uwPD-3gPyHD6s_UZ0hAhfqMpdFEIXLYZTG85hbNKUcRTTV5cJ0llikCPGfCGAzxDseVWo_YnTJoZpeht56pA8PTOk6P7ehBfyWIArmGOFamch9iw3V38OEpY-Yue9lbjDgavfHKIVwdkVksE2_Oczb2yLxU6xCgOB_zTjuMHsoPIKE2No_I9CoI7Q2mWoR44AREqLViub57fLW2pR4rNroDEll6ZV7880pb1lcobq6M4skG_4jV1FM6vBmyFCtz50ohJ0astv1pKTvCnGVIvItMkF7VjoJQbevw_Q-iXc2wJjtBEBhupmfNTlCdRFIY8kg3KGf5jGpCE1jHOwGwSH__oLRLYchsRJz_z1FQlP0-oy68Eep6YwMet6sg7Sin7JiutrfE-g-iEUmp8E2YL0mZZMYyYV8TMWA4sMHVuJzSWJbjej1YWiAQMSnpyTtE0-uYzz-lBA6bShxa53fQ0fC2MEbvLqWTUEU10rruBz1UXBlaq0GakZqlsMNFfzqwYlWt67gDhfQQR1IirxpUFsmtiKyM4OUZEETy_ec53EWKtTvHjMn80PHAJPpB-v2XtAhvHLZz9KxzMklTz3Wi10zvLEcPVmT2htcG5gsTBvahHpDi1L5Xz0XygBgfwWtNjqYllDLX6CIMTCQrrqCwlDFzTWJ2C1dqqi9sLh_CeE7pt75SjWJO6mRPbU3OigFJTtJbyiQvVqqnrCyvU-z68KCXrf0QzLkxVf1V8OrMcA2MD8xSajH61aatx_BDK17LE-cxAA8rw9Syj-BtPtDkBaILaB4O0LrxWLpF3KrnEA5XJOqMm1OjOHlo0wv47xFJkPF9eXaSLdSFPDydYHQ13zLjuxUcHr4WhPpo5wxh3ecqEiLZl69Sq_1LKasNWTX7QYSAMHzbxmX7u6YabN0i5oqqeh88ocRWK0tzUn61bPXr4ewus25ie1mUyAZfc10_JlsFojnv2FnZN3ZaAtu2780uzAzM2t33lxkjbEPPuTZf8nB8V8C1Cg-oB11p_BrBKm0pbweiEndGyJd63WOi8v0flcquk86DjxC8k9mYkG_sBYOvAiksl6S7pY7Fw1fP0ooTqY9JzEOnnYSzDUu2C3epgfDDfsxOO7LpUEdnBlo5Etf3CC3hMXMEEClAuR2OX2L5Jhjg6_iWoR_lHcMQux-PUHhM03LP6vXxB-RxgK9S_cz7JQpiQGhSKKljzy6snqSgE0M6DzYvnE-vYcjixfC1OGfTJCFHSb-FUVVjxCq5UvrjUZ2Uxv4gW4GIG4DeDFriE_OJhW2kc0DCA5MjkoNuiOsqrRyN9b-Y5IR0l9otk4zHC5qm5Vk8fZavHPV2_OVU2iu8DB3xiOvbIKLLqNUzYQVTTIl4rsBq8rAEfqYCAUxgvfhWKTzCkypB0L6U-6tFBtUxY5o8YOc6MEK24JBySPQHEYEUi34aVuJeinNwaRt426pxsAwPZh8yc1ajxdCAu95uP6a8Q2mKG02uPyexPInO3OJEhBRE1dzU-zF1RMXjlOwedD2eXbUgS5BPpHbCal5E0cAqE4j40MGaQplqGuzMa6I2C5Nizbx0Zeu0EoG0TY6rmv8uwtojZDe67dUELtSk7ZUSvRiiCmrChJc1d4K7lglgWbuA3QU831EhwfP3qvU70u-oXMjHHd53iAq5GpV3JYwKiN1zbeZJtgmfSeSW_9GfVPBS119ijXZI-7uqVdMdLDCQCSHezwPSbQODH0Yn7zwdhLnT38zeZMEdZW_cfHFDdSwSVHMtuXTtjkP8rYzaDBaPB2Dng9awSojz_kgnY5NMyYrnTpTkKCJR3rCGY5xEMfSoVZ_MHrqLHbZ7tyd_TtItUyok4Ic_MAeQkrB-0ZogacMW8yoooKX0HtFjr-o3iuLp3PykOoZ1I33o3tvWfvRejyGWdHISrpvBd_GZ6zP-KHrW9Fn6vS_P3CdLQ6pL24j--0G4Yvfs2acPwqUhfEw4S8ckrvQN20-LUcHso2QrDl6uCJjTffECB_tiPJWAPLpoWgQkvyB6YTf6xBTaNIyjW1YP7Z1ufQ3xFDUVUfrfF2uWbNlDtmOyg-rPO9kDE-rbpiGvcFLV5IPARR4F4Scg5rHJQhnolebhqODqeCX580eWOCUAVtu7kb2yweKti3wIodIbTC1tFyVRrt55Hb0Z-mpKgguHIcIO__7bUWboNtoxyO5bPnoL6RrcJ6Do9l_QOnWt61M7hT21iymQc1WUd-uvWxN7c2IzN-aqVIok0OxIVLwK28H-MPkZnGnDHkg-Xr0ID2Xq30wO0LccU_L2E6IW3NsZWy0gY18UWt0He-mhsv8riQ5SUbFT0bJbYwx9Uk_auRH-_WXaqfxsDWoif_euLj2U0gJZj-Tq6rRfN1t2tFK32B4_6KfwGdg0rwO2tyjfZuBGkQpli2Wlsy4GUUpVMNecyv6Ub2pMTgLRutFfU7UTkIOMhu0kCUK_Lta29GYsONO16GV6gWHCkmKM2djp5dyWFREAXxObwz-hGpVdnUW0k3L9h9ca_S1Y7Df0K8K8hgc792-4ooDe_KPeI_Ck6izwLYdZTvJekVSmvooIvtJcedjGsbsWLm3yFilOaBXhJL5f5UUkrEBxfSazoTa5jD7tOOzBJwKypSqi6g71qMu_Dv9ijWan6ukUTtG1SqyXavRdmiEu6QuRDuBg8yUgSF0t-mLpuYMV0cqA4uEks_ie-TGtFe5mnBjayXP3azZDEtBjrFVY8uPvjT-_pvZ2-r7Mvq6pBHqzzUCB8fsjGNAJdIlzwZJ0HnF7Qxk6cmrOWirVIHwfdykZTrKj1XwFK6wUC3KshLrR8EmxcGxZP3c-y5xu3nxUiBUuL1B8VFvvQ4-BgvcgFnxwrSxQXuPp83FgZAOg_whSFh6dfTBUt5PoPK11j9iXef49ZVjU4EvPK9xIdYo6JwNbOMNslpFKIXjdH9GvauNCrIACWBoBlkATAM3is8Ecw_smS2_1oAKXQ6crwLaP28GYKNMegjRbuttbNfiuzr3UxTMT81tyK4yXqRl50n7FcEwjjY7lEbI04Y7zIcS1QoX2lviUBQTp3db-wSiC1UyDg8OUB3ctg8P9XnG9ZGyJnQUDtIOPI8QTtaRJKiLePRTi5Bonub09nbfbvIgRoif-Z4pmx-4-_v-INorv6Es6siGE886PLJXzb713B0V4MZnQ4ew6jVJq33jq3X8ofsE0iGABND1Ap2M8DiK_EuUDoKDpwoV0kNMQoSjvuzTwz83b8YknLmLDeCREoi_xGX0vsUno6YEEerKj9-Z2oKjRvv6TB6iYc3Ws-iblOj9QI87uLA_SKFqKuO-ij9CFasD6Yo7Y7Fv3mgH8MoKSgflwIASk0NtlWLeGAce6hln8t4BxBzHPWKyWGX8PGzwGyy3K0DVjVNd_-g3KpbmM12ptLHFjRf0FlCt3W5tFTs3iz5n-8GbqzC6CQD_c17iPd9wk8VrQoL_r4V4I3Eirhyl4wqgHbdFWfZa9WsmrdWfNcZEjg40H0S-sVbrgb5sp3tQDbm6xUjsqaXAE28gNFvtoWIs-RmTo0cKtguDqGFOIng22TuLM2lELbIIN2cjth3BfmDDzIjIZX_I66H1Wj3AiAjwXXjykt5cYZVhgnAQ_QYXdrFznLmC7bb8eNeP4ivkF3QY9AaSxFcvAnRoMFbxeTmHURXW6HqGOkhNh-CWk4omXiL0tetiK6OIbfJ0hdMa_t67FvN_vjHKpYosvwu_wlLRQC25FNmEHvYHTncEfUzBX1HFlq8FPl0EReKHPBOoFsEVPw1lt5NlBzcWxqQJUvKUAFZplVNH3VIOXX4YjVH-6Omq1N92qdoSxNnWanWFGQ65CsOk9cePCe5InJ5SNPpJxXzoVWefQb7l5Hj1Xvpzmzi3dizv9JLjfw7G2YKISq6SR714eIpIlwfeVT4mdmoSdxqWzioJgL7O-vR0wTuVWXWPeAUP1rPv1Rkj1VfrCh6nlgK2cUNGAqU1cVB6PcksoExZM9U2ge6BETz9tVbIcHAv8x1HsMRx1babAGLGguIXMkDGpqcVLnxwp58EFcGbVLVmND6hmkcwiVkPsOBOrXD-tK0xIM3atduGjVJxVeTqUcJpZGK_IZYmdFSumXIyo_FL9wvzy8EAHgNRBq6p47rs0D8j0pmTvMPibv7ay8wBqWGyXAA3aZLLpwnLYQd5L9pYnM_iLQTHJeKURxPP7yqH9num-9RpejQIVJNi7eeqiwkuVtKn9KhcDweH8JrCzxAORfECkGgcZDC36YOLpuj8EHSvBlXL25WUzRvt4VQTczsotQ_AW5a3aJPjqCuoUyO9WkFdtZH8WHbCIIkUYISsdH5tA5k4w4OZtIDW35mm0xoh716JoxwwMNnpZjy1VjNlte2nncS2HIKkz29XdSRvxxcXuATVBuXCHVhesRl-9Fcf0_ei_S9-TgNiXv9Y3_RWu8bpJqUd8iA7goVBzgjcQmUZDron4zjt0Y-k0e5mpV7_WfZ3e9cfSr5s5U7gUBYP3CilpSTcWvsZdv7hBx0rfTF0bInB6eUZ7RWRFcQgu9Lv3JagSDM4EOi4RY5lBIggJWC4xdbeI0kW9_YR8iQnHWSZ9yQF7h5vu9Ya16b34MfSrQb8auFl77NUSvlIf4Yqo4_4CcGfWj-2jTr7rTI3S0X1gSamxy5BYWMUOSX8dPoAHAYtW2VOLRh7lGICW1fd8zKJBTI1UmDI7UwX21c4woTd_LLZUwsFe8c9-nyHsqb3hkskw5uzG1ilF5teVib5UO0AX06rXL-gldxdm4YVeYkpfPSHbdYedMq971j-GizPhbXmczWG4KJWwFXlXOkSjwwt5jpaq_yGr24IPOVwPB4tkzZWr0M6Yi1QLnbfsyLJNJH5Wzkw7MVUZNsqnF5t0HxfI_kC801cXzr6q2dux2s0o20QiC4mbENYCjkCQn9qoIxc0SiejQ_YZbfH6Tv0d5rKONaesPiQVWbN6eDZ-vQV9FO0o_058hrwu3RVZFvoFj0EUw4AL2Z3gN5p7danwe5rPMigfzH8RKeLwZKyakkM0UdgQBs_dWOY4p84pf2FVSlIs21S6GD_55XiW-v8G8GY0oqtxRgk31cHFOKVdOOCkZKRsmf6In7Q6XpbDtm-fTxcYknBovOs8zBIsL-oChy6ypZ9xZcJwX83RN-eYrg5wAH0m_pCxr2Kb4cSzfJtqjDmIRUeMxS2rsnzHirgz0zjAdEUDQSHtOTcZFnOHesBy7jrlGzPTEYbtz5OcRchNU5GK_shZscdfMdBapEjb5umw69yc0zmtZsl0gSctoCT_FIhpu3NcjqaB9zbnFaaJdt50OmNqYo1GI7TMuM94PCIwpBrbOMXIlEFO5wgJKCfnVCcTb5_Ze8kse6K9Vy7gmnOKz0bkrE3oIvXbwHEE0Ievxh0dA83dROUFwbtRc28_fOplbYdxMGSYZ23R-yJ1DyD2EaXkyjrarMaR5DOkKaVD_Bz4EItA9c25TmkocPutL2uqCvp9BAzFZAyVKKXbJjljOu7Zob63oV0R4BbCMh8LFRGSMgygkbUg5YUZr-IOyw384Gdkmei05TdzdoOVg6U3Yti6EzsljXp2wpjLj0YVrDPVsUn9qp2b9EM27wBvxqaYkPbJ0eI6GmzdTd6AMwX5O_w8_j6EKo4A11qrvN3OLnRFSlq_cIKlF3osjP5OfsCCEjPkSytsXJzfgMFRhqtMTg_QAAAAAAAAAAAAAAAAAIERQcISs2PmlD5dzBugqTwQLGMzM87fu5LZu6imta1cEL13QWF75qGBJk6aK43BVq51W09hgOg71GezTiUnykdG7QcfIv6gOWpvIlbSTWV9igXE0Qo6P57BkUtHgn6d1OxxfgYQb3yA",
    "raw_to_be_signed": "436f6d706f73697465416c676f726974686d5369676e617475726573323032354d4c2d4453412d38372d45533338340065794a68624763694f694a4e54433145553045744f44637452564d7a4f4451694c434a72615751694f69493558325a32576a453456334669544535765a6d74755a30564752565a6b63316b314d6c526a656d684c51584a76556d74304c5739494d556c6f6154426a61546847545868334e576854583278494e31557462445669496e302e53585469674a6c7a494745675a4746755a3256796233567a49474a3163326c755a584e7a4c434247636d396b627977675a323970626d63676233563049486c76645849675a473976636934",
    "raw_composite_signature": "38dfbe9950ae5434518a19b9830ee0088e85e3efdae5cb8f95fc7bf977e630289546d7239761639eb70131c7e51d3d14934018c505a1c5b6121aa91126970959bc2a21dd1eb7412cc27a0fc5c567d6421e5b8f735023aaf424bef3a761f3c519e8881a79d4d85a578f214e9439e8e134fda9fff5717c854102e1de853b9073c18686ce3cb11b1e2d3bb6781fea16d13c7cda203fee1f6498db03e8cc9cff1a3d089b787fb92a04717ba259cb15fe08716ad0f7e8c60166458ed6dc13df4f3ad3fcd163954c127b718415137475f099e211aa30f5c00e64bcc11a6318484b89d7b468f645b7a8592dec98070f58cb79de0184dc3635d19638a64ca3e76fdc47c66f94179baafc1586efd4c6eff22325a2215f55be5f9a72d8db0876350d691b030ae327d664f500373d3912ef568ba8dcc8dc9c913ea72da8eccfed634faec0f0fede03f21c3eacfd467484085fa8ca5d1442172d86531bce616cd2947114d3579709d259629023c67c2180cf10ec7955a8fd89d32686697a1b79ea903c3d33a4e8fede8417f258802b9863856a6721f62c37577f0e12963e62e7bd95b8c381abdf1ca215c1d91592c136fce7336f6c8bc54eb10a0381ff34e3b8c1eca0f20a136368fc8f42a08ed0da65a8478e00444a8b562b9be7b7cb5b6a51e2b36ba0312597a655efcf34a5bd657286eae8ce2c906ff88d5d4533abc19b2142b73e74a212746acb6fd69293bc29c6548bc8b4c905ed58e82506debf0fd0fa25dcdb0263b4110186ea667cd4e509d445218f248372867f98c6a421358c73b01b0487fffa0b44b61c86c449cffcf515094fd3ea32ebc11ea7a63031eb7ab20ed28a7ec98aeb6b7c4fa0fa21149a9f04d982f499964c632615f13316038b0c1d5b89cd25896e37a3d585a20103129e9c93b44d3eb98cf3fa5040e9b4a1c5ae777d0d1f0b63046ef2ea593504535d2baee073d545c195aab419a919aa5b0c3457f3ab06255adebb80385f410475222af1a5416c9ad88ac8ce0e5191044f2fde739dc458ab53bc78cc9fcd0f1c024fa41fafd97b4086f1cb673f4ac73324953cf75a2d74cef2c470f5664f686d706e60b1306f6a11e90e2d4be57cf45f280181fc16b4d8ea6259432d7e8220c4c242baea0b09431734d62760b576aaa2f6c2e1fc2784ee9b7be528d624eea644f6d4dce8a01494ed25bca242f56aaa7ac2caf53ecfaf0a097adfd10ccb93155fd55f0eacc700d8c0fcc526a31fad5a6adc7f0432b5ecb13e731000f2bc3d4b28fe06d3ed0e405a20b681e0ed0baf158ba45dcaae7100e5724ea8c9b53a3387968d30bf8ef114990f17d7976922dd4853c3c9d607435df32e3bb151c1ebe1684fa68e70c61dde72a1222d997af52abfd4b29ab0d5935fb418480307cdbc665fbbba61a6cdd22e68aaa7a1f3ca1c4562b4b73527eb56cf5ebe1ec2eb36e627b5994c8065f735d3f265b05a239efd859d937765a02dbb6efcd2ecc0cccdaddf79719236c43cfb9365ff2707c57c0b50a0fa8075d69fc1ac12a6d296f07a2127746c8977add63a2f2fd1f95caae93ce838f10bc93d998906fec0583af02292c97a4bba58ec5c357cfd28a13a98f49cc43a79d84b30d4bb60b77a981f0c37ecc4e3bb2e9504767065a3912d7f7082de1317304102940b91d8e5f62f92618e0ebf896a11fe51dc310bb1f8f50784cd372cfeaf5f107e47180af52fdccfb250a6240685228a963cf2eac9ea4a013433a0f362f9c4faf61c8e2c5f0b53867d324214749bf85515563c42ab952fae3519d94c6fe205b81881b80de0c5ae213f389856da47340c203932392836e88eb2aad1c8df5bf98e4847497da2d938cc70b9aa6e5593c7d96af1cf576fce554da2bbc0c1df188ebdb20a2cba8d5336105534c8978aec06af2b0047ea602014c60bdf856293cc2932a41d0be94fbab4506d531639a3c60e73a3042b6e0907248f4071181148b7e1a56e25e8a7370691b78dbaa71b00c0f661f327356a3c5d080bbde6e3fa6bc43698a1b4dae3f27b13c89cedce244841444d5dcd4fb317544c5e394ec1e743d9e5db5204b904fa476c26a5e44d1c02a1388f8d0c19a42996a1aeccc6ba2360b9362cdbc7465ebb41281b44d8eab9aff2ec2da236437baedd5042ed4a4ed9512bd18a20a6ac28497357782bb96096059bb80dd053cdf5121c1f3f7aaf53bd2efa85cc8c71dde77880ab91a9577258c0a88dd736de649b6099f49e496ffd19f54f052d75f628d7648fbbbaa55d31d2c30900921decf03d26d03831f4627ef3c1d84b9d3dfccde64c11d656fdc7c7143752c1254732db974ed8e43fcad8cda0c168f0760e783d6b04a88f3fe482763934cc98ae74e94e4282251deb086639c4431f4a8559fcc1eba8b1db67bb7277f4ed22d532a24e0873f30079092b07ed19a2069c316f32a28a0a5f41ed163afea378ae2e9dcfca43a8675237de8dedbd67ef45e8f2196747212ae9bc177f199eb33fe287ad6f459fabd2fcfdc274b43aa4bdb88fefb41b862f7ecd9a70fc2a5217c4c384bc724aef40ddb4f8b51c1eca3642b0e5eae0898d37df10207fb623c95803cba685a0424bf207a6137fac414da348ca35b560fed9d6e7d0df114351551fadf176b966cd943b663b283eacf3bd90313eadba621af7052d5e483c0451e05e12720e6b1c94219e895e6e1a8e0ea7825f9f3479638250056dbbb91bdb2c1e2ad8b7c08a1d21b4c2d6d172551aede791dbd19fa6a4a820b8721c20efffedb5166e836da31c8ee5b3e7a0be91adc27a0e8f65fd03a75adeb533b853db58b299073559477ebaf5b137b73623337e6aa548a24d0ec4854bc0adbc1fe30f9199c69c31e483e5ebd080f65eadf4c0ed0b71c53f2f613a216dcdb195b2d20635f145add077be9a1b2ff2b890e5251b153d1b25b630c7d524fdab911fefd65daa9fc6c0d6a227ff7ae2e3d94d202598fe4eaeab45f375b76b452b7d81e3fe8a7f019d834af03b6b728df66e046910a658b65a5b32e06514a5530d79ccafe946f6a4c4e02d1bad15f53b51390838c86ed240942bf2ed6b6f4662c38d3b5e8657a8161c292628cd9d8e9e5dc961511005f139bc33fa11a955d9d45b49372fd87d71afd2d58ec37f42bc2bc86073bf76fb8a280defca3de23f0a4ea2cf02d87594ef25e9154a6be8a08bed25c79d8c6b1bb162e6df216294e6815e124be5fe54524ac40717d26b3a136b98c3eed38ecc12702b2a52aa2ea0ef5a8cbbf0eff628d66a7eae9144ed1b54aac976af45d9a212ee90b910ee060f32520485d2dfa62e9b98315d1ca80e2e124b3f89ef931ad15ee669c18dac973f76b364312d063ac5558f2e3ef8d3fbfa6f676fabeccbeaea9047ab3cd4081f1fb2318d009748973c192741e717b43193a726ace5a2ad5207c1f7729194eb2a3d57c052bac140b72ac84bad1f049b1706c593f773ecb9c6ede7c5488152e2f507c545bef438f8182f720167c70ad2c505ee3e9f371606403a0ff0852161e9d7d3054b793e83cad758fd89779fe3d6558d4e04bcf2bdc48758a3a27035b38c36c96914a2178dd1fd1af6ae342ac8002581a0196401300cde2b3c11cc3fb264b6ff5a0029743a72bc0b68fdbc19828d31e82345bbadb5b35f8aecebdd4c53313f35b722b8c97a91979d27ec5704c238d8ee511b234e18ef321c4b54285f696f8940504e9ddd6fec12882d54c8383c39407772d83c3fd5e71bd646c899d0503b4838f23c413b5a4492a22de3d14e2e41a27b9bd3d9db7dbbc8811a227fe678a66c7ee3efeff88368aefe84b3ab22184f3ce8f2c95f36fbd770745783199d0e1ec3a8d526adf78eadd7f287ec134886001343d40a7633c0e22bf12e503a0a0e9c2857490d310a128efbb34f0cfcddbf189272e62c3782444a22ff1197d2fb149e8e981047ab2a3f7e676a0a8d1befe9307a8987375acfa26e53a3f5023ceee2c0fd2285a8ab8efa28fd0856ac0fa628ed8ec5bf79a01fc32829281f9702004a4d0db6558b78601c7ba8659fcb780710731cf58ac96197f0f1b3c06cb2dcad0356354d77ffa0dcaa5b98cd76a6d2c716345fd05942b775b9b454ecde2cf99fef066eacc2e82403fdcd7b88f77dc24f15ad0a0bfebe15e08dc48ab872978c2a8076dd1567d96bd5ac9ab7567cd719123838d07d12fac55bae06f9b29ded4036e6eb1523b2a697004dbc80d16fb68588b3e4664e8d1c2ad82e0ea1853889e0db64ee2ccda510b6c820dd9c8ed87705f9830f32232195ff23ae87d568f7022023c175e3ca4b797186558609c043f4185ddac5ce72e60bb6dbf1e35e3f88af905dd063d01a4b115cbc09d1a0c15bc5e4e61d44575ba1ea18e921361f825a4e2899788bd2d7ad88ae8e21b7c9d2174c6bfb7aec5bcdfef8c72a9628b2fc2eff094b4500b6e45366107bd81d39dc11f533057d47165abc14f97411178a1cf04ea05b0454fc3596de4d941cdc5b1a90254bca500159a6554d1f75483975f8623547fba3a6ab537ddaa7684b136759a9d614643ae42b0e93d71e3c27b922727948d3e92715f3a1559e7d06fb9791e3d57be9ce6ce2ddd8b3bfd24b8dfc3b1b660a212aba491ef5e1e229225c1f7954f899d9a849dc6a5b38a82602fb3bebd1d304ee5565d63de0143f5acfbf54648f555fac287a9e580ad9c50d180a94d5c541e8f724b2813164cf54da07ba0444f3f6d55b21c1c0bfcc751ec311c756da6c018b1a0b885cc9031a9a9c54b9f1c29e7c1057066d52d598d0fa86691cc225643ec3813ab5c3fad2b4c483376ad76e1a3549c55793a94709a5918afc865899d152ba65c8ca8fc52fdc2fcf2f0400780d441abaa78eebb340fc8f4a664ef30f89bbfb6b2f3006a586c97000dda64b2e9c272d841de4bf6962733f88b4131c978a511c4f3fbcaa1fd9ee9bef51a5e8d021524d8bb79eaa2c24b95b4a9fd2a1703c1e1fc26b0b3c403917c40a41a07190c2dfa60e2e9ba3f041d2bc19572f6e5653346fb785504dcceca2d43f016e5adda24f8ea0aea14c8ef5690576d647f161db088224518212b1d1f9b40e64e30e0e66d2035b7e669b4c6887bd7a268c70c0c367a598f2d558cd96d7b69e7712d8720a933dbd5dd491bf1c5c5ee013541b970875617ac465fbd15c7f4fde8bf4bdf9380d897bfd637fd15aef1ba49a9477c880ee0a15073823710994643ae89f8ce3b7463e9347b99a957bfd67d9ddef5c7d2af9b3953b8140583f70a2969493716bec65dbfb841c74adf4c5d1b22707a79467b45644571082ef4bbf725a8120cce043a2e11639941220809582e3175b788d245bdfd847c8909c759267dc9017b879beef586b5e9bdf831f4ab41bf1ab8597becd512be521fe18aa8e3fe027067d68feda34ebeeb4c8dd2d17d6049a9b1cb905858c50e497f1d3e8007018b56d9538b461ee5188096d5f77ccca2414c8d5498323b5305f6d5ce30a1377f2cb654c2c15ef1cf7e9f21eca9bde192c930e6ecc6d62945e6d79589be543b4017d3aad72fe825771766e1855e624a5f3d21db75879d32af7bd63f868b33e16d799ccd61b82895b01579573a44a3c30b798e96aaff21abdb820f395c0f078b64cd95abd0ce988b540b9db7ecc8b24d247e56ce4c3b31551936caa7179b741f17c8fe40bcd35717cebeaad9dbb1dacd28db44220b899b10d6028e40909fdaa82317344a27a343f6196df1fa4efd1de6b28e35a7ac3e241559b37a78367ebd057d14ed28ff4e7c86bc2edd155916fa058f4114c3800bd99de0379a7b75a9f07b9acf32281fcc7f1129e2f064ac9a92433451d81006cfdd58e638a7ce297f61554a522cdb54ba183ff9e57896faff06f06634a2ab71460937d5c1c538a55d38e0a464a46c99fe889fb43a5e96c3b66f9f4f1718927068bceb3ccc122c2fea02872eb2a59f7165c2705fcdd137e798ae0e70007d26fe90b1af629be1c4b37c9b6a8c398845478cc52dabb27cc78ab833d338c07445034121ed3937191673877ac072ee3ae51b33d31186edcf939c45c84d53918afec859b1c75f31d05aa448dbe6e9b0ebdc9cd339ad66c97481272da024ff148869bb735c8ea681f736e715a68976de743a636a628d4623b4ccb8cf783c2230a41adb38c5c894414ee708092827e75427136f9fd97bc92c7ba2bd572ee09a738acf46e4ac4de822f5dbc07104d087afc61d1d03cddd44e505c1bb51736f3f7cea656d8771306498676dd1fb22750f20f611a5e4ca3adaacc691e433a429a543fc1cf8108b40f5cdb94e692870fbad2f6baa0afa7d040cc5640c9528a5db2639633aeed9a1beb7a15d11e016c2321f0b151192320ca091b520e58519afe20ecb0dfce0676499e8b4e5377376839583a53762d8ba133b258d7a76c298cb8f4615ac33d5b149fdaa9d9bf44336ef006fc6a69890f6c9d1e23a1a6cdd4dde803305f93bfc3cfe3e842a8e00d75aabbcddce2e74454a5abf7082a5177a2c8cfe4e7ec0821233e44b2b6c5c9cdf80c15186ab4c4e0fd000000000000000000000000000811141c212b363e6943e5dcc1ba0a93c102c633333cedfbb92d9bba8a6b5ad5c10bd7741617be6a181264e9a2b8dc156ae755b4f6180e83bd467b34e2527ca4746ed071f22fea0396a6f2256d24d657d8a05c4d10a3a3f9ec1914b47827e9dd4ec717e06106f7c8",
    "raw_composite_public_key": "e45ffc8cc73db885dc662e62a18cd8e3803297117fa5658814a985b5ff1db7b468cfc82bb929f1d86b77ed14f5ae16a65368772ce51912410105e0456975ae91fdb643b512f124d5e60bd68b8c7e31fe01c7b0dc65ae470501cc565a6e1dfcfcfd12565433c4afedd511821e2e9610c45275e2836dee35ced69d7efa672fd1e4318bef5eb6e897e8b451aa202ded042b2aaef77a7be3f699146da229a8bdb3ffa496445967e75217bfbc9048f9956443d8731f833eb30de10dac96fffe7cf65ea0445c3e31e8601e133be6a100764fe3196e267726441f31751fbf9a6f5880644f4e7275e57de2b0f105e4db055d50dd1c9c934fddf535b8de28b0c74c0449f222cd2ed0bb8fbc775ccee8c940665b40f712f4f7e00750e9e1e4cd9cff25d1945c3e9bca53ccd4f12eee7581856ebd68f26845956e3e7beb761f0fe75bdd31bfe2fa018113397b387bd59d62a68b8af7fa245ab932e69f778e2ceefd21304fbb8099ea13d8ea57c1813197a2f75ae251075b51dad38f853669e9d5f98a3655098941993a1594860fba71fe530ee5c29f58f2978af688ccb75a5838a359c112e98e25a8583ac8dac1f861fd58e2afba5de5a52e020904f5b42bc0874e35befcf3e6119684768f36e008f04712177cebe627607381e56eaaee161c1729b8de51dbde474d48cc68249ea27162b87993e60c84ed6cc6423cb3676d9eb50b2cab5a3a049ef131381d623fa6fbcbc9db1e7cc025ea0418b9dad2cc6ccd4e95fa2cec24feeca70318a751716b7213f63edbf65a63338357f838f94ec071822c24851248885107b3d1c4e924678c7614ea1af038104619f2ae372940becfa69e29cbb5ff6c3e20a47be4a4f74bac34c133c00a6a706accc6ffd3d8e4fbd69a99704e1283c850d8c58d1e5753cd9587b83c4c346cb9a58137213ec10834c66adfe2bb5c501a8ef2ecadd1b677a3df1a6deb86ebf0722c4f5030e20f9018dd5b6fc53eea24fd92b7b5b4025feae996d3e48fd4c650d82dbad7eaf936639698512f26253d2ef6847c8518e8565cc9a5495c6fff57cde7323882c54a7db470ab2daf8ffd2bf794fa7c692d9e7fbd532eecc1d7880e2ca0b3216128be28b4a9f1d151fac97808b0bd98b7b43a612a9ac865812bfeac6f47460277840b52a3b087f916ca7cedc0f768ea2bd19ea21155f84b4a04c4000ad2ae0587154d560bc0a477a4f9329a8984dd31eb1f2a05e3d918701d630cfca9af61ef088d2c5581acb463e439902e5d425719e956b8d6df7305b28e0ff27d3ad0de2085d292499b19a3390d4396fb3bac9a8d8cbead2a7a4290fc9ac6fca045f98a614a45a39cbe24360f84d14f8e472712aceb74dbf45b53d49a0e4737e476ffc4d5b2f7cd247aa186d3b764ad9e9cfeee456a73c291d8de3912414ac43911c372173ad7b472af35c6853ced2fe7b5fe0a89565ab33baa6f65cdd928319d7065e040e7a5e84f9aa903f7648094bad07136b16927b8ec6dbc2bef0cc2856de1e795923e1412c49f24deeb6c21f6c8a9765c9c7986e0da4b4c67d8e0d0c8d466824fb923d8573148990cd2ef133c78ceecab72ed9dd285c5a3766852d54534207ffd34027f6c76ede8fd1a32d72c30048bbaa797d5df6fde27d087de5721ad7b7fa3e8d3f70d6bfc3ab2e252335368bbfa15acb5cb37d4694e8b23cebe25de9c925a221a183b904d3f85df9929a919c54d6f87457373a0d6ecc1403e4cbbe620999435e80696634cd1a8e4747e9825bfa336e5bbad14f73640f1b9febe800dbaefe1630c61fae635b074c564eaa9db189c9e7302873fc64e6d497bc5c29080987a07a21d4af210703a4fa07f2fd816f12fd1e29b4c0f44afe9bd4a1eaa8a7ae6f02a5b4258f52caf6127f62632a67cf4e8310be56a7c28c86b2e277600c3e92c8d23d42586244c571e90568df202f2f6d81f860a565f9eb91a3c78372e2a8b1be61c5418cf49bf2d6c8955d4a482a9919b7660b3f9a4404ffc454ea073e1e4b2689ab2cca4e46bd7004a6c491fa26ee7a57d60f35edb2b821e6266442c8f335d452d524c772e0353724c23c7dd15b7aa155e91442022140c5fcb0153147edcf3e8952f6f0399a3c88066a72756c9409915de63f64fa797841c57c796c6fc550ef745dfe9f179457f94755ae5a2506a764f327e550be3dc14dd41f3b04b147d454938c63a8d69b2ea4c5710ec0b36e3a6c72571fa5d59dde036c42033df35af056966ff0cd1204008971aa6ba9fb97b685ab9ffa2a9d1778104cd2c3b326de1fcbc242e94d0311c3275b12850ed30ceead3a2ee6d060508411d4396f5421d8b6d067cf7cb5e826785fbe119e05e21bd879b64f57cb0cd1972c2815f20abe7ce6ab34d0f471af44baad179e90644122f5f33288e689ddddc5ce833e9755df1e73c65c5a201c4ede2ffa6b19274927719d2d38fdb7a65aa43708b7fa9a94aa7d3210253d78d3b181e1020d0000bd0a1dc05d447f9f58ebeb84c65b36c8afcb83727a1508994e826957a663b0b9b8a003325ab6d6d6462ee4e106019c0dffe10323b7bde7d82a38f85fd08786e860ba66c161b64b0708c363de5c6af62d8db3c243d1e1b712cb1d59e942b9b6b4295a5a500b182cbd5fd1bc6ce9376d91b47a2284f1fbe0ad1c048cc2cfbb4afa3a9eb9697503b69feca990eba7e9441af9ca44cb3ac6b5ed66e591c201fe30efa8a7c471dc613d6254c263a8e132104bec47f1aacb3b2fcd4051b69b5e3fcb1c147a65c2f90c4b5188bafc521cab03c12a309da50b5a7517727ed41228ed123fe1b152f6a6319cd623bf34ad7b8e064ab993260bcbd405f5b7fff9b2fa40ba5ed5630242539e5d96823e89dc818a13d16675ee3079d976f694f5acc9760ae789e9b3391b289e0e22a7ef17cc6a4577157b6d95c09baa4fd532e3ee0a290810ed35e56bb19d9b61fb98a97c617425b06093d98a5cf0ee2dd127f0eea600b9a0c67fbe761db9b77e5d5bba9701da1b883e521a0cfe88451f57bd36085b67e56f061f84a2e6a152a71bce6e522daab6a0a33ce22e537fa9793d28b617e6c0a4176a83aa3be578afac0f2f5547c5516d218984755b7445c7143afa4e551fce0071bdb873b34e6b9e2b9e79ed0c69d288ed6421f237e860a0c6492ebbdd2a44c2c4f368dbe99941b1e8561d859d3859f496cee3d741f252973f8fcc539c409e35cc80a5ed6df23cc3a65601313f5d681fd9540c5291a9e30a72e38c96413c47c61ff84fde78d011b01b4154d1b920af003f7abb1e1999dea6a766cf9fd2702b3ce0ee57af931b62124b0861b163a3b91aa4bea28076c3432df3b29b6c4e1ba588def420071fc157de90eb2722ecc9ab00df3c669383a61a91bb67bd287ce349b4745ee7a479dbceef166b9acc412eb579fcd6437307edda253d606b7be7599c38092bc52a8598480edab8b82b1d21c565d2137ceae0b6642619b16133d91205d6355029e9cdfeb9a28b373d95916b6b707d4c712c09cf36daf1a511b2bedb1aa70ee58d46a0666bb287784b0a3840c589a7a04d5d6f2216be90aa4a512d5632f5c9bfe7b8b13382f999b95d367c7c46b968074ce315197a5ff3545c7b77a804ade56a95b5c24cdece5937b5c0366d93ad03da9bc5db1b551dfb91e9b343d2b57b763439686d4a3ffc9d5f5f6c3940ba872d77f71e4d56c68089a3cf8d60fc3f549019df17187b59e5c4c8840ea0be5120109b27994ee9c190f5b5e892526cd13ed7c575aa87f8e88f6739c1c7bce8b2265b2c1823b72c29b44f1733ba1e7e3374a819571484a9a"
}
~~~~~~~~~~
{: #jose_example_ML_DSA_87_ES256 title="ML-DSA-87-ES384"}

## COSE {#appdx-cose}


# Acknowledgments

We thank Orie Steele for his valuable comments of this document.
