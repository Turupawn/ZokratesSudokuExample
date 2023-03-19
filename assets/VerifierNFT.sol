// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import "@openzeppelin/contracts/token/ERC721/ERC721.sol"; // NFTs change
import "@openzeppelin/contracts/utils/Counters.sol"; // NFTs change

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

contract Verifier is ERC721 { // NFT change

    // NFT changes begin
    address URISetter;
    using Counters for Counters.Counter;
    Counters.Counter private _tokenIds;
    string URI;
    constructor() ERC721("ZK Sudoku Token", "ZKST") {
        URISetter = msg.sender;
    }

    function setURI(string memory _URI) public
    {
        require(msg.sender == URISetter);
        URI = _URI;
    }

    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");
        return URI;
    }

    function mintWithProof(Proof memory proof, uint[7] memory input) public
    {
        require(verifyTx(proof, input));
        _mint(msg.sender, _tokenIds.current());
        _tokenIds.increment();
    }
    // NFT changes end

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
        vk.alpha = Pairing.G1Point(uint256(0x191bd19ad7e2a6db1bbde516a626a33f0575ee2431966439b34a2e1c7a6dc724), uint256(0x2cc21ef02914b2b3b649448279c51163cffed5a677f47d076917be372b3b9ba4));
        vk.beta = Pairing.G2Point([uint256(0x1a70d7c8c153884ef2b7885402250e76d60563b286d934e98ea5c636f9794d71), uint256(0x29347050229a6429bd10ad42e11256489353bc61ebdbab860b4c4b4b188fe6b6)], [uint256(0x2b3590981dc9c2438cf180641f3a3d749ccbff2811056fff8817300633a5fe6e), uint256(0x0fb65da2a6cb3d585cab052b71deb95fcd65a45084a6ac3f59f88099a373fbe2)]);
        vk.gamma = Pairing.G2Point([uint256(0x15455cd805cdfeffb710097f505119922ec60809ed9f7f46c0ecbc73698eaae3), uint256(0x14245b2ae835a47cafab94a15900cb3e95d70c4f98527cce7148953d2a9d322f)], [uint256(0x0c6c6e638005c22b015b57e82a83d31b44161f71cd3a96300b41e5ea6d474816), uint256(0x12797c702f20efaa0c9697edcad587fb52c6204f076c40216f70d09fd014891f)]);
        vk.delta = Pairing.G2Point([uint256(0x169f5b09722c26b708b52857a102ec694274aa975537e3b274129b486415304d), uint256(0x20f2fae12e42d68c9bb0745041d619af49214aa512ccd7733d840eb8ca475958)], [uint256(0x2a5458a669d55c62a00a4e9b3e477fed444c433a2c8414e1f05804bc54ea8f12), uint256(0x13197e25ea771f36efb87ca251b344af1a9b3b0c5bc1164be8306c412062757b)]);
        vk.gamma_abc = new Pairing.G1Point[](8);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x25c21772840009543fd735aea8c7624b675be66376257a27407cf5fe6ab26ddc), uint256(0x12ee83e5353d3a048074f633573cd079df982ce9824e931bb93400e12ce187c2));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x06333d44614a87e71a6274d3ee38ce53ecf898d147938a70433764acbc3a165f), uint256(0x09ac5744ab1d50672e393032f88322d61205477b27d3b03c189fb4e936ee47e6));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x213a3cbd9bdc291904bd1070bf7b1125c2ad4840ca16cfd1701c5caaa378ef0f), uint256(0x20a7a53fbf371a6efe557a2dfc874900f7ef39e2c74cff9e57d4fd736cfe3950));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x22f3f392fec76938a298e21b6cfde95ce619b5a5556545ba00191dc19ffe719e), uint256(0x16363160e4b41fe8b62dc1940024d05563f44d7f78db8bc6ed316f52aebec746));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x033958f5d487a2b77a4a1aa06f25843e27eb8bb4ec3399caf74eb8e701e6f835), uint256(0x13f0551498614f4aca19f3ed12895942a009de63f22c9982f985f3dddc9fc4ff));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x25cf0099e0771f6786aaea5072d3033f2b27949137ae67ee1f1d1ddff96b4adf), uint256(0x07270e15ec320d8775a25b3875fce86e5733dc172d6e31e45b0082cd5942f6f9));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x053feee8d12922f1df8fff4835a36fe00d223224a17818de9ef3b38ed55eeae5), uint256(0x0b09fb0c0398d5750b0360c53c66fc8116f8c4be4bdf1b7afe0794a758d0d187));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x14b46348f9e55ce49fdf03ab9dee73775a87db120eeb02baac513bdf00242642), uint256(0x0eff5dbfb6795f9316e3e1e456054833bcf85b636e8cb61b1c77d7927d6ee2bb));
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
