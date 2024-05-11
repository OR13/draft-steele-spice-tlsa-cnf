---
title: "Credential Confirmation with DNS"
category: info

docname: draft-steele-spice-tlsa-cnf-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Secure Patterns for Internet CrEdentials"
keyword:
 - Digital Credentials
 - TLS Authentication Record
 - Domain Binding
 - Confirmation Claim
venue:
  group: "Secure Patterns for Internet CrEdentials"
  type: "Working Group"
  mail: "spice@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/spice/"
  github: "OR13/draft-steele-spice-tlsa-cnf"
  latest: "https://OR13.github.io/draft-steele-spice-tlsa-cnf/draft-steele-spice-tlsa-cnf.html"

author:
 -
    fullname: "Orie Steele"
    organization: Transmute
    email: "orie@transmute.industries"

normative:
  RFC7519: JWT
  RFC8392: CWT
  RFC7800: JWT-CNF
  RFC8747: CWT-CNF
  RFC6698: DANE
  RFC9278: JKT
  I-D.draft-ietf-cose-key-thumbprint: CKT

informative:
  BCP205:
  RFC5895: IDNA2008
  RFC9449: DPoP
  I-D.draft-ietf-oauth-attestation-based-client-auth: OAuth-Attestation-Based-Client-Authentication
  I-D.draft-ietf-cbor-edn-literals: EDN
  I-D.draft-vesco-vcauthtls-01: VC-AUTH-TLS
  I-D.draft-carter-high-assurance-dids-with-dns: DIDS-WITH-DNS
  I-D.draft-latour-dns-and-digital-trust: DIDS-TRUST-REGISTRIES
  I-D.draft-mayrhofer-did-dns: DID-DNS
  I-D.draft-barnes-mls-userinfo-vc: USERINFO-VC
  I-D.draft-ietf-oauth-sd-jwt-vc: SD-JWT-VC
  I-D.draft-prorock-spice-cose-sd-cwt: SD-CWT

  UTS46:
    title: UTS46
    target: https://www.unicode.org/reports/tr46/


--- abstract

Digital Crededentials on the Internet often JSON Web Token (JWT) and CBOR Web Token (CWT), which depends on third parties to certify the keys used.
This document improves on that situation by enabling the administrators of domain names to specify the keys used in that domain's digital credentials.
This is accomplished by describing how to discover thumbprints for proof-of-possession keys, as described in RFC 7800 and RFC 8747, using TLSA Records as described in RFC 6698.
This approach can be leveraged to develop revocation and assurance capabilities for digital credentials.

--- middle

# Introduction

JSON Web Token (JWT) and CBOR Web Token (CWT) based digital credential formats can express claims made by an Issuer (iss) and a Subject (sub).
The confirmation claim (cnf) can be used to bind proof-of-possession keys to the Subject claim (sub), which can be a string or URI.
In cases where the Subject is a URL, the JSON Web Key Thumbprint (jkt) or COSE Key Thumbprint (ckt) can be published to the Domain Name System (DNS).
This document describes how digital credentials can leverage specifications developed to support Internet X.509 Public Key Infrastructure Certificate (PKIX), Transport Layer Security (TLS), DNS-Based Authentication of Named Entities (DANE), in order to enable conceptually similar functionality, based on JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE).

# Terminology

{::boilerplate bcp14-tagged}

JWT is described in {{-JWT}}, CWT is described in {{-CWT}}.
Confirmation claim `cnf` is described in {{-JWT-CNF}} and {{-CWT-CNF}}.
JWT, CWT and CNF related claims such as `iss`, `sub`, and `nonce` are shared by both token formats.
TLSA Resource Record and related terminology are described in {{-DANE}}.

This document does not introduce new terminology.

# Confirmation Claim

This section provides a summary of the confirmation claim and its possible structures in JOSE and COSE, and does not alter or extend the definition of `cnf` in {{-JWT-CNF}} or {{-CWT-CNF}}.

The confirmation claim is an object or map, supporting one or more confirmation methods.

The following informative example of a decoded JWT claimset is provided:

~~~ json5
{
  "iss": "https://iss.example",
  "sub": "https://jwt.vc",
  "exp": 1361398824,
  "cnf": {
    "jwk":{
      "kty": "EC",
      "alg": "ES256",
      "crv": "P-256",
      "x": "18wHLeIgW9wVN6VD1Txgpqy2LszYkMf6J8njVAibvhM",
      "y": "-V4dS4UaLMgP_4fY4j8ir7cl1TXlFdAgcx55o7TkcSA"
    },
    // "jkt": "NzbLs...",
    // "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLs..."
    // "x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o..."
    // "jwe": "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSF..."
  },
  // ...
}
~~~
{: #fig-jose-cnf-example-1 title="Confirmation claim in JOSE"}

A similar example of a CWT claimset, is provided in Extended Diagnostic Notation (EDN), see {{-EDN}} for more details.

~~~ cbor-diag
{
  /iss/ 1 : "coaps://iss.example",
  /sub/ 2 : "coaps://jwt.vc",
  /exp/ 4 : 1361398824,
  /cnf/ 8 : {
    /COSE_Key/ 1 : h'deebd8afa...423da25ffff'
    /ckt .../
    /Encrypted_COSE_Key .../
  }
  ...
}
~~~
{: #fig-cose-cnf-example-1 title="Confirmation claim in COSE"}

In order to be compatible with {{-DANE}}, the value of the confirmation claim must be reducible to a hash in a verifiable way.

For JWK and COSE_Key, the hash is produced according to {{-JKT}} and {{-CKT}} respectively.
For JKT and CKT, the hash is already present, but must be converted to hexadecimal before use in TLSA Records.
For JWE and Encrypted_COSE_Key, the key must be decrypted and then the process for JWK and COSE_Key is applied.

## Key Binding

The confirmation claim can be used to establish key binding, as described in {{-SD-JWT-VC}}, {{-SD-CWT}} and {{-USERINFO-VC}}.

Publishing a confirmation key associated with a subject, and using globally unique identifiers to identify subjects has additional impact on privacy and traceability.

See this document's privacy considerations for additional details.

# Confirmation Claim Record

This section describes the structure of the confirmation claim record.

As described in {{-DANE}}, there are several components of a TLSA record, including:

- TLSA Certificate Usages
- TLSA Selectors
- TLSA Matching Types

Until the associated IANA registries contain an entry specific to this draft, the value reserved for private use (255) MUST be used.

Similar to the process for deriving a prefxied DNS domain name as described in {{Section 3 of RFC6698}}, the structure of the confirmation claim needs to be converted to a prefixed DNS domain name.

In JOSE, the string claim names are used, but in COSE the integer values are used.

For example:

The COSE credential claimset:

~~~ cbor-diag
{
  /iss/ 1 : "coaps://iss.example",
  /sub/ 2 : "coaps://jwt.vc",
  /cnf/ 8 : {
    /COSE_Key/ 1 : h'deebd8afa...423da25ffff'
  }
  ...
}
~~~
{: #fig-cose-tlsa-cnf-example-1 title="Example COSE Claimset"}

Produces the following prefixed DNS domain name:

~~~
1.8.jwt.vc
~~~

The following command can be run to retrieve the confirmation claim record:

~~~
dig @pam.ns.cloudflare.com. 1.8.jwt.vc. TLSA
~~~
{: #fig-cose-tlsa-cnf-example-1-query title="Example cnf query"}

The following informative example of an answer is provided:

~~~
;; ...
;; ANSWER SECTION:
1.8.jwt.vc.    300  IN  TLSA  255 255 255 123533...66AAF8
~~~
{: #fig-cose-tlsa-cnf-example-1-answer title="Example cnf query answer"}

The JOSE credential claimset:

~~~ json5
{
  "iss": "https://iss.example",
  "sub": "https://jwt.vc",
  "exp": 1361398824,
  "cnf": {
    "jwk":{
      "kty": "EC",
      "alg": "ES256",
      "crv": "P-256",
      "x": "18wHLeIgW9wVN6VD1Txgpqy2LszYkMf6J8njVAibvhM",
      "y": "-V4dS4UaLMgP_4fY4j8ir7cl1TXlFdAgcx55o7TkcSA"
    },
  },
}
~~~
{: #fig-jose-tlsa-cnf-example-1 title="Example JOSE Claimset"}

Produces the following prefixed DNS domain name:

~~~
jwk.cnf.jwt.vc
~~~

The following command can be run to retrieve the confirmation claim record:

~~~
dig @pam.ns.cloudflare.com. jwk.cnf.jwt.vc. TLSA
~~~
{: #fig-jose-tlsa-cnf-example-1-query title="Example cnf query"}

The following informative example of an answer is provided:

~~~
;; ...
;; ANSWER SECTION:
jwk.cnf.jwt.vc.    300  IN  TLSA  255 255 255 12353...6AAF8
~~~
{: #fig-jose-tlsa-cnf-example-1-answer title="Example cnf query answer"}

In both of the preceeding examples, the claimset contained a key, but the tlsa cnf record contained a thumbprint.

In order to match the claimset confirmation method to the hash retrieved from the cnf record, the process described in Section 1 MUST be followed.

TODO: Consider merkle root instead of single key thumbprint, confirm multiple keys with a single record.

TODO: Consider BBS / accumulator alternatives to set membership with merkle proofs.

TODO: Consider relationship to Key Transparency, Metadata & Capability Discovery, Certificate Transparency.

# Usage

## Before Issuance

The issuer needs to first authenticate the subject, and establishing that they control a confirmation key.

There are several established mechanisms which might be relevant to this step, including {{-DPoP}} and {{-OAuth-Attestation-Based-Client-Authentication}}.

At this stage the issuer SHOULD perform the following additional actions:

- Resolve the subject's confirmation claim record as described in Section 2
- Confirm the record contains a thumbprint which matches confirmation claim as described in Section 1

This step is not always required, because of the timing and availability issues associated with setting the confirmation claim record.

## After Verification

After verifying the presentation of a digital credential which included a confirmation claim, the verifier has confirmed the issuer's signature matches their public key, and that the subject's confirmation key is in their possession.

Additional validation checks MUST be performed first, including reviewing the valid from and valid until related claims, and checking the

At this stage the verifier SHOULD perform the following additional actions:

- Convert the verified claim set to the confirmation claim record, and resolve it as described in Section 2.
- Verify that the confirmation claim record contains a hash that matches the confirmation claim in the credential as described in Section 1.

## Revocation

This section builds on the After Verification process described above, and applies it to the concrete use case of Subject initiated credential revocation.

In the event that a device or service controlling the proof-of-possession key for a credential is stolen or compromised, the subject can revoke the confirmation claim the issuer commited to, by deleteing the associated confirmation record.

After deleting the record, the subject can contact the issuer and obtain a fresh credential with a new confirmation key, and add a new confirmation record to their domain name.

Due to the timeing and availability constraints of the DNS, verifiers can still be deceived by presentations of the stolen credential.

The utility of this subject directed revocation depends on the responsiveness and realtime revocation capabilities of the issuer.

For example, if an issuer could revoke the credential in 5 minutes, and the DNS takes 30 minutes to update, the issuer should be contacted to revoke the credential first.

However, if the issuer can only revoke credentials in a 24 hour window, and the DNS takes 30 minutes to propagate the subject's revocation of the credential, the subject should revoke the credential first, and then contact the issuer.

## Assurance

This section builds on the Before Isssunace process described above, and applies it to the concrete use case of providing the issuer with increased assurance that a subject identified with a URL and presenting a given public key, controls the associated domain, and the associated private key.

In this case, the DNS enables the subject to publish and unpublish the thumbprint of the public key they wish to use for digital credentials on the associated domain.

This approach could be extended to other protocols, and is inspired by similar approaches to demonstrating control of resources or proving possession for example Automated Certificate Management Environment (acme) and DNS-Based Authentication of Named Entities (DANE).

# Privacy Considerations

As noted in {{Section 5 of RFC7800}}, A proof-of-possession key can be used as a correlation handle if the same key is used with multiple parties.
Thus, for privacy reasons, it is recommended that different proof-of-possession keys be used when interacting with different parties.

By publishing the confirmation key thumbprint, a domain operator is intentionaly enabling this type of correlation.

Resolving confirmation key thumbprints at the time of verification reveals timing information related to credential processing.

TODO: additional privacy considerations.

# Security Considerations

The security considerations of {{-JWT}}, {{-CWT}}, {{-JWT-CNF}}, {{-CWT-CNF}}, and {{-DANE}} apply.

After verification of a credential which includes a confirmation claim or a key binding token, it is essential that the verifier confirm the key is still published under the domain associated with the subject.
Prior to the issuance or digital credentials it is essential that the issuer obtain proof that the subject of the credential controls the associated proof of possession key.

TODO: additional security considerations.

# Internationalization Considerations

This specification is not limited to URLs that rely on HTTPS.

Considerations for international domain names in {{UTS46}} and {{-IDNA2008}} both apply.

For example: ☕.example becomes xn--53h.example when converting from a subject identifier to a TLSA record.

TODO: additional i18n considerations.

# IANA Considerations

This document has no IANA actions.


# Implementation Status

Note to RFC Editor: Please remove this section as well as references to {{BCP205}} before AUTH48, and then find replace "jwt.vc" with "vendor.example".

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in {{BCP205}}.
The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs.
Please note that the listing of any individual implementation here does not imply endorsement by the IETF.
Furthermore, no effort has been spent to verify the information presented here that was supplied by IETF contributors.
This is not intended as, and must not be construed to be, a catalog of available implementations or their features.
Readers are advised to note that other implementations may exist.

According to {{BCP205}}, "this will allow reviewers and working groups to assign due consideration to documents that have the benefit of running code, which may serve as evidence of valuable experimentation and feedback that have made the implemented protocols more mature.
It is up to the individual working groups to use this information as they see fit".

## Transmute Prototype

Organization: Transmute Industries Inc

Name: https://github.com/transmute-industries/jwt.vc

Description: An application demonstrating the concepts is available at [https://jwt.vc](https://jwt.vc)

Maturity: Prototype

Coverage: The current version ('main') implements a post verification check similar to the one described in this document.

License: Apache-2.0

Implementation Experience: No interop testing has been done yet. The code works as proof of concept, but is not yet production ready.

Contact: Orie Steele (orie@transmute.industries)

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

Thanks to the authors of the following drafts:

- {{-VC-AUTH-TLS}}
- {{-DIDS-WITH-DNS}}
- {{-DIDS-TRUST-REGISTRIES}}
- {{-DID-DNS}}
- {{-USERINFO-VC}}
- {{-SD-JWT-VC}}
- {{-SD-CWT}}

--back
