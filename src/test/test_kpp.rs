/*
 * $Id$
 *
 * Copyright (c) 2021, Purushottam A. Kulkarni.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and
 * or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE
 *
 */

// The KPP (DH / ECDH) tests require the out-of-tree `algif_kpp` AF_ALG patches,
// which are not present in the upstream Linux kernel. Like the akcipher tests,
// they are therefore #[ignore]d by default. Run them with
// `cargo test -- --ignored` on a kernel that exposes the KPP AF_ALG interface.
#[cfg(test)]
mod tests {
    use crate::kpp::{KcapiKPP, ECC_CURVE_NIST_P256};
    use crate::ACCESS_HEURISTIC;

    // A full two-party ephemeral ECDH key agreement: each party generates an
    // ephemeral key pair on the same curve, exchanges public keys, and computes
    // the shared secret. Both parties must arrive at the same shared secret.
    #[test]
    #[ignore]
    fn test_ecdh_shared_secret() {
        let (alice, alice_pub) = crate::kpp::ecdh_ephemeral_keygen(ECC_CURVE_NIST_P256)
            .expect("Failed to generate Alice's ECDH key pair");
        let (bob, bob_pub) = crate::kpp::ecdh_ephemeral_keygen(ECC_CURVE_NIST_P256)
            .expect("Failed to generate Bob's ECDH key pair");

        let alice_ss = alice
            .ssgen(bob_pub, ACCESS_HEURISTIC)
            .expect("Failed to generate Alice's shared secret");
        let bob_ss = bob
            .ssgen(alice_pub, ACCESS_HEURISTIC)
            .expect("Failed to generate Bob's shared secret");

        assert!(!alice_ss.is_empty());
        assert_eq!(alice_ss, bob_ss);
    }

    // Drive the `KcapiKPP` API directly rather than through the convenience
    // helper, exercising new/ecdh_setcurve/setkey/keygen/ssgen.
    #[test]
    #[ignore]
    fn test_ecdh_manual() {
        let mut alice = KcapiKPP::new("ecdh", 0).expect("Failed to init Alice's KPP handle");
        alice
            .ecdh_setcurve(ECC_CURVE_NIST_P256)
            .expect("Failed to set Alice's curve");
        alice
            .setkey(Vec::new())
            .expect("Failed to set Alice's ephemeral key");
        let alice_pub = alice
            .keygen(ACCESS_HEURISTIC)
            .expect("Failed to generate Alice's public key");

        let mut bob = KcapiKPP::new("ecdh", 0).expect("Failed to init Bob's KPP handle");
        bob.ecdh_setcurve(ECC_CURVE_NIST_P256)
            .expect("Failed to set Bob's curve");
        bob.setkey(Vec::new())
            .expect("Failed to set Bob's ephemeral key");
        let bob_pub = bob
            .keygen(ACCESS_HEURISTIC)
            .expect("Failed to generate Bob's public key");

        let alice_ss = alice
            .ssgen(bob_pub, ACCESS_HEURISTIC)
            .expect("Failed to generate Alice's shared secret");
        let bob_ss = bob
            .ssgen(alice_pub, ACCESS_HEURISTIC)
            .expect("Failed to generate Bob's shared secret");

        assert_eq!(alice_ss, bob_ss);
    }
}
