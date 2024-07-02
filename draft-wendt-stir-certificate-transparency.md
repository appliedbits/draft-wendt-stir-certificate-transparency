---
title: "STI Certificate Transparency"
abbrev: "STI CT"
category: info

docname: draft-wendt-stir-certificate-transparency-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number: 01
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
    country: US
 -
    fullname: Rob Sliwa
    organization: Somos, Inc.
    email: robjsliwa@gmail.com
    country: US
 -
    fullname: Alec Fenichel
    organization: TransNexus
    email: alec.fenichel@transnexus.com
    country: US
 -
    fullname: Vinit Anil Gaikwad
    organization: Twilio
    email: vanilgaikwad@twilio.com
    country: US

normative:
  RFC5652:
  RFC8224:
  RFC8225:
  RFC8226:
  RFC9060:
  RFC9118:
  RFC9162:
  RFC9448:

informative:


--- abstract

This document describes a framework for the use of the Certificate Transparency (CT) protocol for publicly logging the existence of Secure Telephone Identity (STI) certificates as they are issued or observed. This allows any interested party that is part of the STI eco-system to audit STI certification authority (CA) activity and audit both the issuance of suspect certificates and the certificate logs themselves. The intent is for the establishment of a level of trust in the STI eco-system that depends on the verification of telephone numbers requiring and refusing to honor STI certificates that do not appear in a established log. This effectively establishes the precedent that STI CAs must add all issued certificates to the logs and thus establishes unique association of STI certificates to an authorized provider or assignee of a telephone number resource. The primary role of CT in the STI ecosystem is for verifiable trust in the avoidance of issuance of unauthorized duplicate telephone number level delegate certificates or provider level certificates.  This provides a robust auditable mechanism for the detection of unauthorized creation of certificate credentials for illegitimate spoofing of telephone numbers.

--- middle

# Introduction

Certificate Transparency (CT) aims to mitigate the problem of misissued certificates by providing append-only logs of issued certificates. The logs do not themselves prevent misissuance, but ensure that interested parties (particularly those named in certificates or certificate chains) can detect such misissuance. {{RFC9162}} describes the core protocols and mechanisms for use of CT for the purposes of public TLS server certificates associated with a domain name as part of the public domain name system (DNS). This document describes the direct use of the same fundamental protocols and processes of certificate transparency but applies them to Secure Telephone Identity (STI) certificates {{RFC8226}} and delegate certificates {{RFC9060}}.

Telephone numbers (TNs) and their management and assignment by telephone service providers and Responsible Organizations (RespOrgs) for toll-free numbers share many similarities to the Domain Name System (DNS) where there is a global uniqueness and established association of telephone numbers to regulatory jurisdictions that manage the allocation and assignment of telephone numbers under country codes and a set of numeric digits for routing telephone calls and messages over telephone networks. STI Certificates use a TNAuthList extension defined in {{RFC8226}} to specifically associate either telephone service providers or telephone numbers to the issuance of STI certificates and certificate change that are intended to represent the authorized right to use a telephone number. This trusted association can be establish via mechanisms such as Authority tokens for TNAuthList defined in {{RFC9448}}. Certificate transparency is generally meant to provide a publically verifiable and auditable representation of the creation of certificates in order to establish transparency and trust to interested parties as part of a stir related eco-system.

There is three primary actors in the certificate transparency framework. There is the STI Certification Authorities (CAs) that submit all certificates to be issued to one or more log services. The log services are network services that implement the protocol operations for submissions of STI certificates and subsequent queries. They are hosted by interested parties in the STI ecosystem and can accept certificate log submissions from any other CA participant.  Monitors play the role of monitoring the CT logs to check for potential misissuance as well as auditing of the log services.  This role can be played by any STI ecosystem participant interested in the trust of the ecosystem or the integrity of the telephone number or provider level certificates produced in the eco-system.

The details that follow in this document will try to provide a high level overview of the use of Certificate Transparency for STI certificates.  It will provide only the necessary details related to STI certificates. The details of the use of Merkel Tree and API interfaces largely follow the protocols defined in {{RFC9162}} and only when there is specific details and differences to {{RFC9162}} will that be noted and defined in this document.

This general mechanism could also be used for transparently logging other important stir related metadata associations perhaps via JWTClaimConstraints defined in {{RFC8226}} and {{RFC9118}} or other ways defined in potential future extensions of this document.

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# The Use of Certificate Transparency for STI Certificates

Each log contains certificate chains, which can be submitted by any CA authorized in the stir eco-system. It is expected that these CAs will contribute all their newly issued certificates to one or more logs.  Note, in {{RFC9162}} it is possible for certificate holders to directly contribute their own certificate chains or interested third parties, however because in stir eco-systems that generally consist of regulated entities or are authorized to be assigned telephone number resources, this does not seem to be a likely scenario. Generally, many stir eco-systems have a controlled set of CAs that are authorized to participate as valid trust anchors. It is required that each chain ends with a trust anchor that is accepted by the log which would include those authorized trust anchors or a subset of them. When a chain is accepted by a log, a signed timestamp is returned, which is later used to provide evidence to STIR verification services (VS), defined in {{RFC8224}}, that the chain has been submitted. A VS can thus require that all certificates they accept as valid are accompanied by signed timestamps.

Those concerned about misissuance of stir certificates can monitor the logs, asking them regularly for all new entries, and can thus check whether the providers or telephone numbers for which they are responsible have had certificates issued that they did not expect. What they do with this information, particularly when they find that a misissuance has happened, is beyond the scope of this document. However, broadly speaking, because many existing STI ecosystems have a connection to regulated and industry environments that govern the issuance of STI certificates, they can invoke existing mechanisms for dealing with issues such as misissued certificates, such as working with the CA to get the certificate revoked or with maintainers of trust anchor lists to get the CA removed.

# Submitters

Submitters submit certificates or preannouncements of certificates prior to issuance (precertificates) to logs for public auditing. In order to enable attribution of each logged certificate or precertificate to its issuer, each submission MUST be accompanied by all additional certificates required to verify the chain up to an accepted trust anchor. The trust anchor (a root or intermediate CA certificate) MAY be omitted from the submission.

If a log accepts a submission, it will return a Signed Certificate Timestamp (SCT) (see Section 4.8 {{RFC9162}}). The submitter SHOULD validate the returned SCT, as described in Section 8.1 of {{RFC9162}}, if they understand its format and they intend to use it to construct an STI certificate.

## Certificates

Any entity can submit a certificate (Section 5.1 of {{RFC9162}}) to a log. Since it is anticipated that verification services could reject certificates that are not logged, it is expected that certificate issuers and subjects will be strongly motivated to submit them.

Author note: consider the exclusive use of precertificates, so this section may not be needed

## Precertificates

CAs may preannounce a certificate prior to issuance by submitting a precertificate (Section 5.1 of {{RFC9162}}) that the log can use to create an entry that will be valid against the issued certificate. If the CA is submitting the precertificate to only one log, it MUST incorporate the returned SCT in the issued certificate. The returned SCT MAY not be incorporated in the issued certificate is when a CA sends the precertificate to multiple logs and only incorporates the SCTs that are returned first.

A precertificate is a CMS {{RFC5652}} signed-data object that conforms to the profile detailed in Section 3.2 of {{RFC9162}}.

# Log Format and Operation

A log is a single, append-only Merkle Tree of submitted certificate entries.  Log procedures MUST follow log format and operation procedures defined in Section 4 of {{RFC9162}}.

Author note: Do we need a separate IANA registry for Log OIDs specific to STI eco-system?

# Log Client Messages

Log Client Messages and API MUST follow same protocols, formats and procedures as described in Section 5 of  {{RFC9162}}

# STIR Authentication Services

STIR Authentication Services {{RFC8224}} MUST present on or more SCTs from one or more logs by the inclusion of the stir certificate that has CT information encoded as an extension in the X.509v3 certificate (see Section 7.1.2 of {{RFC9162}}).

# STI Certification Authorities

A certification authority MUST include a Transparency Information X.509v3 extension in a certificate.  All included SCTs and inclusion proofs MUST be for a precertificate that corresponds to this certificate.

# Clients

There are various different functions clients of logs might perform. In this document, the client generally refers to the STI verification service defined in {{RFC8224}}, or more generally an entity that performs the verification of a PASSporT defined in {{RFC8225}}. We describe here some typical clients and how they should function.

## Submission and Handling of SCTs

1. **STI-CA/STI-SCA Submits STI Certificate to Transparency Logs**:
   - **Step 1**: The STI Certificate Authority (STI-CA) or STI Subordinate Certificate Authority (STI-SCA) issues a new STI certificate.
   - **Step 2**: The STI-CA/STI-SCA submits the issued STI certificate to one or more transparency logs using the `submit-entry` API.

   **API Call**:
   ```http
   POST <Base URL>/ct/v2/submit-entry
   Content-Type: application/json

   {
       "submission": "base64-encoded-sti-certificate",
       "type": 1,
       "chain": [
           "base64-encoded-CA-cert-1",
           "base64-encoded-CA-cert-2"
       ]
   }
   ```

   **Expected Response**:
   ```json
   {
       "sct": "base64-encoded-sct",
       "sth": "base64-encoded-signed_tree_head",
       "inclusion": "base64-encoded-inclusion_proof"
   }
   ```

2. **Transparency Log Generates SCT**:
   - **Step 3**: Each transparency log processes the submission and generates a Signed Certificate Timestamp (SCT).
   - **Step 4**: The transparency log returns the SCT to the STI-CA/STI-SCA.

3. **STI-CA/STI-SCA Passes SCT(s) to STI-AS**:
   - **Step 5**: The STI-CA/STI-SCA passes the generated SCT(s) to the STI Authentication Service (STI-AS). This can be done via a non-prescriptive method such as including SCT(s) in the certificate issuance metadata or through a separate communication channel.

4. **STI-AS Includes SCTs in `sct` Claim**:
   - **Step 6**: The STI-AS includes the SCTs in the `sct` claim of the PASSporT (Personal Assertion Token) when signing a call identity.

   **Example PASSporT with SCT Claim**:
   ```json
   {
       "alg": "ES256",
       "typ": "passport",
       "x5u": "https://sti-ca.example.com/certificates/stica-cert.pem",
       "iat": 1577836800,
       "orig": "+12155551212",
       "dest": "+12155559876",
       "attest": "A",
       "origid": "123e4567-e89b-12d3-a456-426614174000",
       "sct": ["base64-encoded-sct1", "base64-encoded-sct2"]
   }
   ```

   - **Step 7**: If some logs are slow to respond, their SCTs may be skipped to ensure timely processing.

5. **STI-VS Verifies PASSporT and SCTs**:
   - **Step 8**: The STI Verification Service (STI-VS) receives the signed PASSporT from the STI-AS.
   - **Step 9**: The STI-VS verifies that the PASSporT contains matching SCTs for the certificate it was signed with. The STI-VS checks for the presence of SCT(s) and trusts them for quick verification.
   - **Step 10**: In the background, a separate process can periodically gather and verify the SCTs with the transparency logs to ensure their validity and integrity.

## Example API Calls for Step-by-Step Flow

1. **Submit Entry to Log**:
   ```http
   POST <Base URL>/ct/v2/submit-entry
   Content-Type: application/json

   {
       "submission": "base64-encoded-sti-certificate",
       "type": 1,
       "chain": [
           "base64-encoded-CA-cert-1",
           "base64-encoded-CA-cert-2"
       ]
   }
   ```

2. **Retrieve Latest STH (optional for background process)**:
   ```http
   GET <Base URL>/ct/v2/get-sth
   ```

   **Expected Response**:
   ```json
   {
       "sth": "base64-encoded-signed_tree_head_v2"
   }
   ```

3. **Retrieve Merkle Inclusion Proof by Leaf Hash (optional for background process)**:
   ```http
   GET <Base URL>/ct/v2/get-proof-by-hash?hash=base64-encoded-hash&tree_size=tree-size
   ```

   **Expected Response**:
   ```json
   {
       "inclusion": "base64-encoded-inclusion_proof_v2",
       "sth": "base64-encoded-signed_tree_head_v2"
   }
   ```

4. **Retrieve Entries and STH from Log (optional for background process)**:
   ```http
   GET <Base URL>/ct/v2/get-entries?start=0&end=99
   ```

   **Expected Response**:
   ```json
   {
       "entries": [
           {
               "log_entry": "base64-encoded-log-entry",
               "submitted_entry": {
                   "submission": "base64-encoded-sti-certificate",
                   "chain": [
                       "base64-encoded-CA-cert-1",
                       "base64-encoded-CA-cert-2",
                       "base64-encoded-trust-anchor-cert"
                   ]
               },
               "sct": "base64-encoded-sct"
           }
       ],
       "sth": "base64-encoded-signed_tree_head_v2"
   }
   ```

## Monitor

Monitors watch logs to check for correct behavior, for certificates of interest, or for both. For example, a monitor may be configured to report on all certificates that apply to a specific domain name when fetching new entries for consistency validation.

A monitor MUST at least inspect every new entry in every log it watches, and it MAY also choose to keep copies of entire logs.

To inspect all of the existing entries, the monitor SHOULD follow the steps detailed in Section 8.2 of {{RFC9162}}.

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

