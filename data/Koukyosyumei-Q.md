## QA Report about `axelar-amplifier`

### 1. **Code Spelling Errors**

**Description:** Several spelling errors have been identified in the codebase, which may lead to confusion or potential bugs.

- **File:** `./axelar-amplifier/contracts/gateway/src/state.rs`
    - **Line:** 108
    - **Error:** `unkown` should be `unknown`
    - **Details:** The identifier `unkown_id` should be corrected to `unknown_id`.
- **File:** `./axelar-amplifier/contracts/voting-verifier/src/contract/execute.rs`
    - **Line:** 234
    - **Error:** `substract` should be `subtract`
    - **Details:** The error message in the `.expect` call should be updated from `failed to substract poll results` to `failed to subtract poll results`.
- **File:** `./axelar-amplifier/contracts/service-registry/src/contract.rs`
    - **Line:** 70
    - **Error:** `veriier` should be `verifier`
    - **Details:** The variable `veriier` should be renamed to `verifier` for consistency.
- **File:** `./axelar-amplifier/ampd/src/handlers/multisig.rs`
    - **Line:** 159
    - **Error:** `unspported` should be `unsupported`
    - **Details:** The identifier `unspported` should be corrected to `unsupported` in both occurrences.
- **File:** `./axelar-amplifier/contracts/multisig-prover/src/contract/execute.rs`
    - **Lines:** 372, 376
    - **Error:** `symetric` should be `symmetric`
    - **Details:** The function names and comments should use `symmetric` instead of `symetric`.

### 2. **RustSec Advisory Vulnerabilities**

**Crate:** `curve25519-dalek`

- **Version:** 3.2.0
- **Title:** Timing variability in `curve25519-dalek`'s `Scalar29::sub`/`Scalar52::sub`
- **Date:** 2024-06-18
- **ID:** RUSTSEC-2024-0344
- **URL:** [RustSec Advisory](https://rustsec.org/advisories/RUSTSEC-2024-0344)
- **Solution:** Upgrade to `>=4.1.3`

**Crate:** `rustls`

- **Version:** 0.19.1
- **Title:** `rustls::ConnectionCommon::complete_io` could fall into an infinite loop based on network input
- **Date:** 2024-04-19
- **ID:** RUSTSEC-2024-0336
- **URL:** [RustSec Advisory](https://rustsec.org/advisories/RUSTSEC-2024-0336)
- **Severity:** 7.5 (high)
- **Solution:** Upgrade to `>=0.23.5` OR `>=0.22.4`, `<0.23.0` OR `>=0.21.11`, `<0.22.0`
- **Version:** 0.20.9
- **Title:** `rustls::ConnectionCommon::complete_io` could fall into an infinite loop based on network input
- **Date:** 2024-04-19
- **ID:** RUSTSEC-2024-0336
- **URL:** [RustSec Advisory](https://rustsec.org/advisories/RUSTSEC-2024-0336)
- **Severity:** 7.5 (high)
- **Solution:** Upgrade to `>=0.23.5` OR `>=0.22.4`, `<0.23.0` OR `>=0.21.11`, `<0.22.0`

**Crate:** `webpki`

- **Version:** 0.21.4
- **Title:** webpki: CPU denial of service in certificate path building
- **Date:** 2023-08-22
- **ID:** RUSTSEC-2023-0052
- **URL:** [RustSec Advisory](https://rustsec.org/advisories/RUSTSEC-2023-0052)
- **Severity:** 7.5 (high)
- **Solution:** Upgrade to `>=0.22.2`

**Crate:** `zerovec`

- **Version:** 0.10.2
- **Title:** Incorrect usage of `#[repr(packed)]`
- **Date:** 2024-07-01
- **ID:** RUSTSEC-2024-0347
- **URL:** [RustSec Advisory](https://rustsec.org/advisories/RUSTSEC-2024-0347)
- **Solution:** Upgrade to `>=0.10.4` OR `>=0.9.7`, `<0.10.0`

### Recommendations

1. **Address Spelling Errors:** Update the codebase to fix all identified spelling errors. This will enhance code readability and reduce potential misunderstandings.
2. **Update Vulnerable Crates:** Review and update the specified crates according to the recommended solutions to mitigate known vulnerabilities. Ensuring up-to-date dependencies is crucial for maintaining the security and stability of the codebase.