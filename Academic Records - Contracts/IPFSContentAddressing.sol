// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract IPFSContentAddressing {
    mapping(bytes32 => bool) private _verifiedIPFSHashes;

    modifier onlyVerifiedIPFSHash(bytes32 hash) {
        require(
            _verifiedIPFSHashes[hash],
            "IPFSContentAddressing: hash is not verified"
        );
        _;
    }

    function verifyIPFSHash(bytes32 hash) public view returns (bool) {
        return _verifiedIPFSHashes[hash];
    }

    function addVerifiedIPFSHash(bytes32 hash) public {
        _verifiedIPFSHashes[hash] = true;
    }
}
