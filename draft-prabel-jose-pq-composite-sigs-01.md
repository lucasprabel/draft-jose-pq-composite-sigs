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
  github: USER/REPO
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

The Verify algorithm MUST validates a signature only if all component signatures were successfully validated.

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
| AKP-EC2     | TBD | COSE key type for composite algorithm with ECDSA as the traditional component. |
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
* Specification Document(s): n/a


## JOSE Web Key Parameters

IANA is requested to add the following entries to the JSON Web Key Parameters Registry.

### Public Key

* Parameter Name: pub
* Parameter Description: Public or verification key
* Used with "kty" Value(s): AKP-EC
* Parameter Information Class: Public
* Change Controller: IETF
* Specification Document(s): n/a

### Private Key

* Parameter Name: priv
* Parameter Description: Private key
* Used with "kty" Value(s): AKP-EC
* Parameter Information Class: Private
* Change Controller: IETF
* Specification Document(s): n/a

### Seed

* Parameter Name: seed
* Parameter Description: Seed used to derive the private key
* Used with "kty" Value(s): AKP-EC
* Parameter Information Class: Private
* Change Controller: IETF
* Specification Document(s): n/a

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
{: #jose_example_ML_DSA_44 title="ML-DSA-44-ES256"}

## COSE {#appdx-cose}


# Acknowledgments

We thank Orie Steele for his valuable comments of this document.
