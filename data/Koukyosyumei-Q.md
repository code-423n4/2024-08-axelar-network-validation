## QA Report about `axelar-amplifier`

### 1. **Error in `toTrimmedString` Function**

#### Description

The `toTrimmedString` function in the `Bytes32ToString` library is causing an error when decoding the returned string in certain scenarios. Specifically, the function returns an error related to ABI decoding when feeding malformed bytestrings, which suggests an issue with memory management or length extraction.

#### Vulnerability

The function uses inline assembly for memory management and string conversion. It extracts the length from the last byte of the bytes32 data and allocates memory based on this length. However, improper handling of memory allocation or invalid length values can lead to ABI decoding errors and unexpected behavior.

#### Proof of Concept

- Contract

```jsx
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library Bytes32ToString {
    function toTrimmedString(bytes32 stringData) internal pure returns (string memory converted) {
        uint256 length = 0xff & uint256(stringData);

        // Length is extracted from the last byte, so we'll use assembly to allocate memory
        assembly {
            converted := mload(0x40)
            // mstore to allocate memory based on the extracted length
            mstore(0x40, add(converted, 0x40))
            mstore(converted, length)
            mstore(add(converted, 0x20), stringData)
        }
    }
}

contract DemoAssemblyRisk {
    using Bytes32ToString for bytes32;

    function retrieveString(bytes32 manipulatedInput) public pure returns (string memory) {
        return manipulatedInput.toTrimmedString();
    }
}

```

- Test with `hardhat`

```jsx
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("DemoAssemblyRisk", function () {
    let demoAssemblyRisk;
    let owner;

    beforeEach(async function () {
        // Deploy the DemoAssemblyRisk contract
        const DemoAssemblyRisk = await ethers.getContractFactory("DemoAssemblyRisk");
        demoAssemblyRisk = await DemoAssemblyRisk.deploy();
        await demoAssemblyRisk.waitForDeployment();

        [owner] = await ethers.getSigners();
    });

    it("should correctly handle valid bytes32 input", async function () {
        // Valid input: "hello" with correct length byte (5)
        const validInput = ethers.encodeBytes32String("hello")
        const validLengthByte = '0f';
        const paddedString = validInput.slice(0, -2) + validLengthByte;
        console.log("input: ", paddedString);

        const result = await demoAssemblyRisk.retrieveString(paddedString);
        console.log("result: ", result)
    });

    it("should handle invalid bytes32 input (length > actual data length)", async function () {
        // Invalid input: "hello" with incorrect length byte (255)
        const invalidInput = ethers.encodeBytes32String("hello");
        const invalidLengthByte = 'ff';
        const paddedString = invalidInput.slice(0, -2) + invalidLengthByte;
        console.log("input: ", paddedString);

        const result = await demoAssemblyRisk.retrieveString(paddedString);
        console.log("result: ", result)
    });
});

```

This test causes the following error:

```
  DemoAssemblyRisk
input:  0x68656c6c6f00000000000000000000000000000000000000000000000000000f
result:  hello
    ✔ should correctly handle valid bytes32 input
input:  0x68656c6c6f0000000000000000000000000000000000000000000000000000ff
    1) should handle invalid bytes32 input (length > actual data length)

  1 passing (68ms)
  1 failing

  1) DemoAssemblyRisk
       should handle invalid bytes32 input (length > actual data length):
     Error: deferred error during ABI decoding triggered accessing index 0
      at throwError (node_modules/ethers/src.ts/abi/coders/abstract-coder.ts:33:21)
      at Object.get (node_modules/ethers/src.ts/abi/coders/abstract-coder.ts:143:29)
      at staticCall (node_modules/ethers/src.ts/contract/contract.ts:304:49)
      at Proxy.retrieveString (node_modules/ethers/src.ts/contract/contract.ts:351:41)
      at Context.<anonymous> (test/ToTrimString.js:35:24)

```

#### Potential Cause

The issue likely stems from improper memory management and validation in the assembly code. Specifically:

The length extracted from `stringData` is not validated, which can lead to memory allocation issues if the `length` is outside the expected range.
Memory allocation in the assembly code does not properly account for the length of the string, which may result in incorrect ABI encoding.
Proof of Concept

#### Suggested Fix

Appropriate input validation with `require` statement or input sanitization might be helpful.

### 2. **Code Spelling Errors**

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

### 3. **RustSec Advisory Vulnerabilities**

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