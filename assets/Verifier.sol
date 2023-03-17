// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x0d3751102975af0b3114ef1fb7a557fc459920d9e20e5b99be465c05eb972b16), uint256(0x06acb95f91ec071889ef27b4b812536d29a2bbf7ecd9ff48e449af947f685ef7));
        vk.beta = Pairing.G2Point([uint256(0x2a5d28795e01efe5b1632f29650bcf076771135fefd31f62cb156dd6d85510ce), uint256(0x29ae1cec0271b6f5a473470b928bc5ae1a1224275fb1d23b06d8eade993cd17d)], [uint256(0x26eb5dd28894dcb2f37b2715e4a9d281928e34255a3a85a9c0aa54db2384604a), uint256(0x0498844c34da713f2acc1edf9bd7918e4e2586b1f635a4a1524468b90e1c97c0)]);
        vk.gamma = Pairing.G2Point([uint256(0x15746f5af73db8404995ce7addca56ce58f40efdce5097b144c4942f80a47b0a), uint256(0x09c197efbf8f64744459873d8825fe94f8fab4f1a3f2757a5db58414c5a8446e)], [uint256(0x0ba5c1a57dd5054955696f90a3ddc1d3c3851707ddac8373613a1e21439afcc2), uint256(0x29f4c0b8f7d00261a8a95c0b2b94bc458501cda6fd7776b85ddb1851e8ee50e7)]);
        vk.delta = Pairing.G2Point([uint256(0x1ef4bc7a2c201e43894c86083611a7ef34235d5d08597b6bcd73a6145e63465f), uint256(0x2342622010255b4f5f5d616bf2693fa4136cccd831b9154c4ffe7b26c53e6425)], [uint256(0x15bb0929bf924fe01bb0c1b662f1f56043eac79f6df8f02ebacebed8362b80c3), uint256(0x2f42a1463b272e12a9dab2d80c53116ffded487620bb36fab7d96e0fe61c1f61)]);
        vk.gamma_abc = new Pairing.G1Point[](8);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x26bcda80c3c98f4ab8b6949856b3fef1823cc32c906bb93b2220d77455e16077), uint256(0x05879043204ee093d420d7069e935c077b21f2be48b7ce62a3e42fa403942597));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x148bc10b967abb2b656b0172850de3d00a121d5fdf269ac48a4c7da24a5f32cc), uint256(0x0cb870867da15a4cd47b7104c568a8d9f7158a921ac10668bb3d5d5c52afc47f));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x12bf3109975d642c22daf007deadf86fb1d7e47e6f21e97f708c63d7985d0885), uint256(0x124085eb7910849b39f615228b49ad0ddbf9e7b6e1304c63528fcd5dc0342f70));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x236f625996543502a3e3fccedab08142da8d82571c8af9b1748d0a5ba0cbe7c6), uint256(0x2145a5ef61152f8305afbf93718268f051d20921e374c4b0a7d4dbd386847c5b));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x016784275227ef9fa6228c436b0d00c382936a415f1c269d991fcc7ded76835a), uint256(0x03c93b186bdc00314cd2d48bdf9f86ff4b1c2a6f593c8f3b39fc847caf7e9ada));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2c3c3a06a0ca721da40b1297a3ca8c932c4fd37edcd2babead2597b76c56d209), uint256(0x1db977fd45bcb9bc3d49dcb16b8118484876e03f7b12c11e7d904e4cfc5bc729));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x01de610474475710ecc57135756d6f6daa7d746656c1556e53f518767889ef47), uint256(0x052798840af5c921e413104a57d0e9a7ce75ecd4f5cd2370b3f82486f03da5e1));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x15b270bed5315880f2115332ee411928d38bc978dd539ffd085552ffb18b3e89), uint256(0x017f75b6d9b2cfbef9a35ba7df90ef10b0874575286e339c8cc212887403375a));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[7] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](7);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
