---

###
title: "PQ/T Hybrid Composite Signatures for JOSE and COSE"
abbrev: "JOSE/COSE Composite Signatures"
category: std

docname: draft-prabel-jose-pq-composite-sigs-01
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus:
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
| ML-DSA65-ES512  | ML-DSA-65 | ecdsa-with-SHA512 with secp256r1 | id-sha512 | Composite Signature with ML-DSA-65 and ECDSA using P-256 curve and SHA-512 |
| ML-DSA87-ES512  | ML-DSA-87 | ecdsa-with-SHA512 with secp384r1 | id-sha512 | Composite Signature with ML-DSA-87 and ECDSA using P-384 curve and SHA-512 |
{: #tab-jose-algs title="JOSE Composite Signature Algorithms for ML-DSA"}

Examples can be found in {{appdx-jose}}.

## COSE algorithms

The following table defines a list of algorithms associated with specific PQ/T combinations to be registered in {{IANA.COSE}}.


| Name | COSE Value | First Algorithm | Second Algorithm | Description
| ----------- | ----------- | ----------- |  ----------- | ----------- |
| ML-DSA44-ES256         | TBD (request assignment -51) | ML-DSA-44  | ecdsa-with-SHA256 with secp256r1 | id-sha256 | Composite Signature with ML-DSA-44 and ECDSA using P-256 curve and SHA-256 |
| ML-DSA65-ES512            | TBD (request assignment -52)  | ML-DSA-65 | ecdsa-with-SHA512 with secp256r1 | id-sha512 | Composite Signature with ML-DSA-65 and ECDSA using P-256 curve and SHA-512 |
| ML-DSA87-ES512            | TBD (request assignment -53)  | ML-DSA-87 | ecdsa-with-SHA512 with secp384r1 | id-sha512 | Composite Signature with ML-DSA-87 and ECDSA using P-384 curve and SHA-512 |
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

### ML-DSA-65-ES512

* Algorithm Name: ML-DSA-65-ES512
* Algorithm Description: Composite Signature with ML-DSA-65 and ECDSA using P-256 curve and SHA-256
* Algorithm Usage Location(s): alg
* JOSE Implementation Requirements: Optional
* Change Controller: IETF
* Specification Document(s): n/a
* Algorithm Analysis Documents(s): TBD

### ML-DSA-87-ES512

* Algorithm Name: ML-DSA-87-ES512
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

### ML-DSA-65-ES512

* Name: ML-DSA-65-ES512
* Value: TBD (request assignment -52)
* Description: Composite Signature with ML-DSA-65 and ECDSA using P-256 curve and SHA-256
* Capabilities: [kty]
* Change Controller: IETF
* Reference: n/a
* Recommended: Yes

### ML-DSA-87-ES512

* Name: ML-DSA-87-ES512
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
* Label: -1
* CBOR Type: bstr
* Description: Public key
* Reference: n/a

### Private Key

* Key Type: TBD
* Name: priv
* Label: -2
* CBOR Type: bstr
* Description: Private key
* Reference: n/a

### Seed

* Key Type: TBD
* Name: seed
* Label: -3
* CBOR Type: bstr
* Description: Seed used to derive the private key
* Reference: n/a

### Others

The key parameters registered in {{IANA.COSE}} for use with the kty value "EC2" should also be usable with the kty value "AKP-EC2" defined in this document.

--- back

# Examples {#appdx}

Will be added in later versions.

## JOSE {#appdx-jose}

## COSE {#appdx-cose}

# Acknowledgments

We thank Orie Steele for his valuable comments of this document.
