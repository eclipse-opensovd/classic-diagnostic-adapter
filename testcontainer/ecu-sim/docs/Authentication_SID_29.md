# Authentication

This document explains the authentication schemes support in the simulation.


## General

Since we don't want to create and verify certificates properly at this time, the fields for challenges returned are filled with sequential numbers, in which the first byte represents the fields number, uniquely for that response.

The authentication itself is done through the ProofOfOwnership call, in which the target authentication role is always provided in the parameter `proofOfOwnershipClient` as ASCII-text.

Valid roles are:
- `AFTER_MARKET`
- `AFTER_SALES`
- `DEVELOPMENT`

## Authentication with PKI Certificate Exchange (APCE)

### Unidirectional

1. VerifyCertificateUnidirectional (29 01)
2. ProofOfOwnership (29 03)

### Bidirectional

1. VerifyCertificateBidirectional (29 02)
2. ProofOfOwnership (29 03)


## Authentication with Challenge Response (ACR)

### Unidirectional
 
1. RequestChallengeForAuthentication (29 05)
2. VerifyProofOfOwnershipUnidirectional (29 06)

### Bidirectional

1. RequestChallengeForAuthentication (29 05)
2. VerifyProofOfOwnershipBidirectional (29 07)

## Deauthentication

Use service Deauthenticate (29 00)
