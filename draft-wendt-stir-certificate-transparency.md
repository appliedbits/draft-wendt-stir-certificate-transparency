---
title: "STI Certificate Transparency"
abbrev: "STI CT"
category: info

docname: draft-wendt-stir-certificate-transparency-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number: 00
date:
consensus: true
v: 3
area: "Applications and Real-Time"
workgroup: "Secure Telephone Identity Revisited"
keyword:
 - stir
 - certificates
 - delegate certificates
venue:
  group: "Secure Telephone Identity Revisited"
  type: "Working Group"
  mail: "stir@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/stir/"
  github: "appliedbits/draft-wendt-stir-certificate-transparency"
  latest: "https://appliedbits.github.io/draft-wendt-stir-certificate-transparency/draft-wendt-stir-certificate-transparency.html"

author:
 -
    fullname: Chris Wendt
    organization: Somos, Inc.
    email: chris@appliedbits.com
 _
    fullname: Rob Sliwa
    organization: Somos, Inc.
    email: robjsliwa@gmail.com

normative:
  RFC8224:
  RFC8226:
  RFC9060:
  RFC9118:
  RFC9448:

informative:


--- abstract

This document describes a framework for the use of the Certificate Transparency (CT) protocol for publicly logging the existence of Secure Telephone Identity (STI) certificates as they are issued or observed, in a manner that allows anyone to audit STI certification authority (CA) activity and notice the issuance of suspect certificates as well as to audit the certificate logs themselves. The intent is establish a level of trust in the STI eco-system that verification of calls would required and refuse to honor STI certificates that do not appear in a log, effectively forcing STI CAs to add all issued certificates to the logs, establishing trust that STI certificates are unique to the authorized provider or assignee of a telephone number resource. The primary role of certificate transparency in the STI ecosystem is the avoidance of issuance of unauthorized or duplicate provider level certificates or, of particular importance, telephone number level delegate certificates.  This provides a robust mechanism for the detection of unauthorized creation of certificate credentials for illegitimate spoofing of telephone numbers. 

--- middle

# Introduction

Certificate Transparency (CT) aims to mitigate the problem of misissued certificates by providing append-only logs of issued certificates. The logs do not themselves prevent misissuance, but they ensure that interested parties (particularly those named in certificates or certificate chains) can detect such misissuance. This general mechanism that could also be used for transparently logging metadata associations via JWTClaimConstraints defined in {{RFC8226}} and {{RFC9118}} or potentially other ways defined in future extensions of this document.

{{RFC9162}} describes the core protocols and mechanisms for use of CT for the purposes of public TLS server certificates associated with a domain name as part of the public domain name system (DNS). This document describes the direct use of the same fundamental protocols and processes of certificate transparency but applies them to Secure Telephone Identity (STI) certificates {{RFC8226}} and delegate certificates {{RFC9060}}. 

Telephone numbers (TNs) and their management and assignment by telephone service providers and Responsible Organizations (RespOrgs) for toll-free numbers share many similarities to the Domain Name System (DNS) where there is a global uniqueness and established association of telephone numbers to regulatory jurisdictions that manage the globally unique allocation and assignment of telephone numbers under country codes and a set of numeric digits for routing telephone calls and messages over telephone networks. STI Certificates use a TNAuthList extension defined in {{RFC8226}} to specifically associate either telephone service providers or telephone numbers to the issuance of STI certificates and certificate change that are intended to represent the authorized right to use a telephone number. This trusted association can be establish via mechanisms such as Authority tokens for TNAuthList defined in {{RFC9448}}. Certificate transparency is generally meant to provide a public representation of the creation of certificates in order for the eco-system of interested parties to provide a publicly verifiable log of certificates created by Certification Authorities to protect against misissuance of certificates that may be misrepresenting information.

There is three primary actors in the certificate transparency framework. There is the STI certification authorities that submit all created certificates to logs, this could be to one or more log services. The log services are network services that implement the protocol operations for submissions of STI certificates and queries. They are hosted by interested parties in the STI ecosystem and can accept certificate log submissions from any other CA participant.  Monitors play the role of monitoring the CT logs to check for potential misissuance.  This role can be played by any STI ecosystem participant that is interested in the trust of the ecosystem.

The details that follow in this document will try to provide a high level overview of the use of Certificate Transparency for STI certificates.  It will provide high level details with assumptions that the details of the use of Merkel Tree and API interfaces largely follow {{RFC9162}} protocols and only when there is specific details and differences to {{RFC9162}} will that be defined normatively.

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# The Use of Certificate Transparency for STI Certificates

Each log contains certificate chains, which can be submitted by anyone. It is expected that STI CAs will contribute all their newly issued certificates to one or more logs; however, it is possible for certificate holders can also directly contribute their own certificate chains, as can interested third parties. In order to avoid logs being rendered useless by the submission of large numbers of spurious certificates, it is required that each chain ends with a trust anchor that is accepted by the log. A log may also limit the length of the chain it is willing to accept; such chains must also end with an acceptable trust anchor. When a chain is accepted by a log, a signed timestamp is returned, which can later be used to provide evidence to STIR verification services (VS), defined in {{RFC8224}}, that the chain has been submitted. A VS can thus require that all certificates they accept as valid are accompanied by signed timestamps once certificate transparency is well established in the ecosystem to maintain trust.

Those who are concerned about misissuance of provider or TN-based delegate certificates can monitor the logs, asking them regularly for all new entries, and can thus check whether domains for which they are responsible have had certificates issued that they did not expect. What they do with this information, particularly when they find that a misissuance has happened, is beyond the scope of this document. However, broadly speaking, because many existing STI ecosystems have a connection to regulated and industry environments that govern the issuance of STI certificates, they can invoke existing mechanisms for dealing with issues such as misissued certificates, such as working with the CA to get the certificate revoked or with maintainers of trust anchor lists to get the CA removed. 

# Submitters

Submitters submit certificates to logs for public auditing. In order to enable attribution of each logged certificate to its issuer, each submission MUST be accompanied by all additional certificates required to verify the chain up to an accepted trust anchor. The trust anchor (a root or intermediate CA certificate) MAY be omitted from the submission.

If a log accepts a submission, it will return a Signed Certificate Timestamp (SCT) (see Section 4.8 {{RFC9162}}). The submitter SHOULD validate the returned SCT, as described in Section 8.1 of {{RFC9162}}, if they understand its format and they intend to use it to construct an STI certificate.

## Certificates

Any entity can submit a certificate (Section 5.1 of {{RFC9162}}) to a log. Since it is anticipated that STIR verification services could reject certificates that are not logged, it is expected that certificate issuers and subjects will be strongly motivated to submit them.

# Log Format and Operation

A log is a single, append-only Merkle Tree of submitted certificate entries.  Log procedures MUST follow log format and operation procedures defined in Section 4 of {{RFC9162}}.

Author note: Do we need a separate IANA registry for Log OIDs specific to STI eco-system?

# Log Client Messages

Log Client Messages and API MUST follow same protocols, formats and procedures as described in Section 5 of  {{RFC9162}}

Author Note: I don't believe this is any parallel to TLS servers directly participating in CT in the STI world

# STI Certification Authorities

The Transparency Information X.509v3 extension including rules of inclusion in OCSP responses MUST follow descriptions and procedures defined in Section 7 of {{RFC9162}}.

# Clients

There are various different functions clients of logs might perform. In this document, the client generally refers to the STI verification service defined in {{RFC8224}}, or more generally an entity that performs the verification of a PASSporT defined in {{RFC8225}}. We describe here some typical clients and how they should function.

## STI Verification Service

### Receiving SCTs and Inclusion Proofs

STI Verification Services receive SCTs and inclusion proofs in certificates. 

### Reconstructing the TBSCertificate

Validation of an SCT for a certificate (where the type of the TransItem is x509_sct_v2) uses the unmodified TBSCertificate component of the certificate.

### Validating SCTs

In order to make use of a received SCT, the STI Verification Service MUST first validate it as follows:

Compute the signature input by constructing a TransItem of type x509_entry_v2, depending on the SCT's TransItem type. The TimestampedCertificateEntryDataV2 structure is constructed in the following manner:
timestamp is copied from the SCT.
tbs_certificate is the reconstructed TBSCertificate portion of the server certificate, as described in Section 8.1.2 of {{RFC9162}}.
issuer_key_hash is computed as described in Section 4.7 of {{RFC9162}}.
sct_extensions is copied from the SCT.
Verify the SCT's signature against the computed signature input using the public key of the corresponding log, which is identified by the log_id. The required signature algorithm is one of the log's parameters.
If the STI Verification Service does not have the corresponding log's parameters, it cannot attempt to validate the SCT. When evaluating compliance (see Section 8.1.6 of {{RFC9162}}), the STI Verification Service will consider only those SCTs that it was able to validate.

Note that SCT validation is not a substitute for the normal validation of the server certificate and its chain.

### Fetching Inclusion Proofs

When a STI Verification Service has validated a received SCT but does not yet possess a corresponding inclusion proof, the STI Verification Service MAY request the inclusion proof directly from a log using get-proof-by-hash (Section 5.4 of {{RFC9162}}) or get-all-by-hash (Section 5.5 of {{RFC9162}}).

### Validating Inclusion Proofs

When a STI Verification Service has received, or fetched, an inclusion proof (and an STH), it SHOULD proceed to verify the inclusion proof to the provided STH. The STI Verification Service SHOULD also verify consistency between the provided STH and an STH it knows about.

If the STI Verification Service holds an STH that predates the SCT, it MAY, in the process of auditing, request a new STH from the log (Section 5.2 of {{RFC9162}}) and then verify it by requesting a consistency proof (Section 5.3 of {{RFC9162}}). Note that if the STI Verification Service uses get-all-by-hash, then it will already have the new STH.

### Evaluating Compliance

It is up to a client's local policy to specify the quantity and form of evidence (SCTs, inclusion proofs, or a combination) needed to achieve compliance and how to handle noncompliance.

## Monitor

Monitors watch logs to check for correct behavior, for certificates of interest, or for both. For example, a monitor may be configured to report on all certificates that apply to a specific domain name when fetching new entries for consistency validation.

A monitor MUST at least inspect every new entry in every log it watches, and it MAY also choose to keep copies of entire logs.

## Auditing

Auditing ensures that the current published state of a log is reachable from previously published states that are known to be good and that the promises made by the log, in the form of SCTs, have been kept. Audits are performed by monitors or STI Verification Services.


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions, yet.

--- back

# Acknowledgments
{:numbered="false"}

The authors would like to thank the authors and contributors to the protocols and ideas around Certificate Transparency {{RFC9162}} which sets the basis for the STI eco-system to adopt in a very straight forward way, providing trust and transparency in the telephone number world.

