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

contract Verifier is ERC721 {

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
        vk.alpha = Pairing.G1Point(uint256(0x11e4a73b06f0e41db57f9fc706aef491c928edaf7543a390f3d82c8fcf5b680c), uint256(0x2419f4dca5f10655b0682a31cc1b834a378328294b1b826dbda2bf7cab253b11));
        vk.beta = Pairing.G2Point([uint256(0x1f7a4d3fcff71feb92286ca8bad3001123e479488cdf5e07c47e1c558b3705a0), uint256(0x1d899658b33725f68f3337f154d3e3828eeb971563403dcf63b35bf325034ced)], [uint256(0x07812e23313dfb1df557337a622c8725da0ea54743d1584c440b9fe3c84bda36), uint256(0x0df313ee72b7ec5118760013e3d9e6a2a6b380765f9d67c453a46499b17e3568)]);
        vk.gamma = Pairing.G2Point([uint256(0x042829f001bc0ac12477da0e591efcd4b5be5f7c46c580696888a9de582be73b), uint256(0x1c1b7dc0e5c953ea20472a17d1d76d9472fec34ed6aeefa358be237dbd92c7a6)], [uint256(0x09c20eef3809d2745387f07d0c8769ea228f43313c8be53ec65326aa75ba8365), uint256(0x09383e4b0709eed9045dc72998d7f284729297e79e240151c54fd3c326db762c)]);
        vk.delta = Pairing.G2Point([uint256(0x2811380bbb431e57f242aab3225671169388fb077a09ed9afafbb6c1472f1953), uint256(0x09fee06e3b0f4a71c2499fbf7020c8ab04ff41f2571b57a56afab42f09c12630)], [uint256(0x0f825dd4247aae98c614dac29f9e700849a6e16f0a6e13299b7132e007004643), uint256(0x0b042b0754e8c3769017f477abcd9f752032eab9684f9258d3e871e752443edc)]);
        vk.gamma_abc = new Pairing.G1Point[](8);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x02fa7d8296755d4f258bc1a5810ed9b20f5f42a4a6c2421a7d8a462f483e79fe), uint256(0x2d3cb1d78acc3cefda9691dc1caa572f77505699e90e69e3b77055e217d39aaa));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1e12c09ab9f6d83ff5698019a66a20b0202e5dd98b192fab9a5b07748638131b), uint256(0x2ce885764980e3eb733d920c1263b1e3195e6b4f460aea03711bd15107bb711a));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0db03c7748032dde4b2d0e215eb2592341d562773157db6e966a1799ca5948ea), uint256(0x0ade5bbfae3875c314750f10628c0309e2ca9334d76ddf40212ae8a405647e73));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2aafc0fb201f00c0b4b77919a858393def9212a0722ae405cc5b8ca9d1abef7c), uint256(0x1c8c8223b3015459cc14a0079295e7516d056de6537ce5f0d78355a1de30f02a));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x04f44a9058a96a075484e33b9a0a9b9f87d4356f0a3ac454c62e31a912d7d5d0), uint256(0x2a8b4011288223f02ac7cc1dd242a0c5d2837915b899b93fb6a9be5890ea4d23));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x13bbb6a86e79ea1be3b2aa67f47a11314804c7513649893cc533910aa66192cd), uint256(0x03156d14f789a4cb59f74823839c7c2e3a04e46691e34510caf46355a65912e8));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x05f2c9467041638dab00523c8bf5fca1ea32ccf0338c4ece958f01463e2bf1dd), uint256(0x0459610767657b6732a1748cf4fcbdd7b4aed2c853249bdd0dc03be427d3983a));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2489255f94b5b68eb2214ed3e247c63eb52cd0727bc1d21a19419af6c0a0689c), uint256(0x15a135437257b70cd24abf4556ca4aaa7fd05583db106dacad9229fc1a7bd65d));
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
