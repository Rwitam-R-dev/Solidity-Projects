# AcademicRecord Contract

This Solidity smart contract is designed to manage academic records with role-based access control, multi-signature approvals, and IPFS content addressing.

## Contract Code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./IPFSContentAddressing.sol";

contract AcademicRecord is AccessControl, Pausable, IPFSContentAddressing {
    using ECDSA for bytes32;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant FACULTY_ROLE = keccak256("FACULTY_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    struct Record {
        string name;
        string degree;
        bool verified;
        bytes32 metadataCid;
        address owner;
        uint256 verificationExpiry;
        mapping(uint256 => string) recordHistory;
    }

    mapping(address => Record[]) private academicRecords;
    mapping(address => uint256) private verificationNonce;
    mapping(address => mapping(uint256 => bytes32)) private verificationKeys;
    mapping(address => bool) public isVerifier;

    event RecordAdded(address indexed user, string name, string degree, bytes32 metadataCid);
    event RecordVerified(address indexed user, uint256 indexed recordIndex, bool verified);
    event RecordUpdated(address indexed user, uint256 indexed recordIndex, string name, string degree, bytes32 metadataCid);
    event RecordDeleted(address indexed user, uint256 indexed recordIndex);
    event RecordOwnershipTransferred(uint256 indexed recordIndex, address indexed from, address indexed to);
    event BatchRecordVerification(address indexed user, bool verified);
    event VerificationExpiryUpdated(uint256 indexed recordIndex, uint256 verificationExpiry);
    event MultiSigApprovalRequested(uint256 indexed recordIndex, address indexed requester);
    event MultiSigApprovalGranted(uint256 indexed recordIndex, address indexed approver);

    modifier onlyOwner() {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Only the contract owner can perform this action.");
        _;
    }

    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "Only admins can perform this action.");
        _;
    }

    modifier onlyAdminOrFaculty() {
        require(hasRole(ADMIN_ROLE, msg.sender) || hasRole(FACULTY_ROLE, msg.sender), "Only admins or faculty can perform this action.");
        _;
    }

    modifier hasPermission(address _user) {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender) || hasRole(ADMIN_ROLE, msg.sender) || msg.sender == _user, "You don't have permission to perform this action.");
        _;
    }

    modifier contractNotPaused() {
        require(!paused(), "Contract is currently paused.");
        _;
    }

    modifier notContractUpgradable() {
        require(!isVersionUpgradable[msg.sender], "Contract upgrade is in progress for your version.");
        _;
    }

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(ADMIN_ROLE, msg.sender);
        upgradeableContractVersions[upgradeableContractVersion] = msg.sender;
    }

    function addAdmin(address _admin) public onlyOwner {
        grantRole(ADMIN_ROLE, _admin);
    }

    function removeAdmin(address _admin) public onlyOwner {
        revokeRole(ADMIN_ROLE, _admin);
    }

    function addFaculty(address _faculty) public onlyAdmin {
        grantRole(FACULTY_ROLE, _faculty);
    }

    function removeFaculty(address _faculty) public onlyAdmin {
        revokeRole(FACULTY_ROLE, _faculty);
    }

    function pauseContract(bool _paused) public onlyOwner {
        if (_paused) {
            _pause();
        } else {
            _unpause();
        }
    }

    function setVerificationExpiryDuration(uint256 _duration) public onlyAdmin {
        verificationExpiryDuration = _duration;
    }

    function addRecord(string memory _name, string memory _degree, bytes32 _metadataCid) public contractNotPaused {
        academicRecords[msg.sender].push(Record(_name, _degree, false, _metadataCid, msg.sender, 0));
        emit RecordAdded(msg.sender, _name, _degree, _metadataCid);
    }

    function getRecordCount(address _user) public view returns (uint256) {
        return academicRecords[_user].length;
    }

    function getRecord(address _user, uint256 _index) public view returns (string memory name, string memory degree, bool verified, bytes32 metadataCid, address owner, uint256 verificationExpiry) {
        require(_index < academicRecords[_user].length, "Record index out of range.");
        Record storage record = academicRecords[_user][_index];
        return (record.name, record.degree, record.verified, record.metadataCid, record.owner, record.verificationExpiry);
    }

    function updateRecord(uint256 _index, string memory _name, string memory _degree, bytes32 _metadataCid) public contractNotPaused {
        require(_index < academicRecords[msg.sender].length, "Record index out of range.");
        Record storage record = academicRecords[msg.sender][_index];
        record.name = _name;
        record.degree = _degree;
        record.metadataCid = _metadataCid;

        uint256 historyIndex = record.recordHistory.length;
        record.recordHistory[historyIndex] = _metadataCid;

        emit RecordUpdated(msg.sender, _index, _name, _degree, _metadataCid);
    }

    function deleteRecord(uint256 _index) public contractNotPaused {
        require(_index < academicRecords[msg.sender].length, "Record index out of range.");
        require(academicRecords[msg.sender][_index].owner == msg.sender, "Only the record owner can delete the record.");
        delete academicRecords[msg.sender][_index];
        emit RecordDeleted(msg.sender, _index);
    }

    function transferRecordOwnership(address _newOwner, uint256 _index) public contractNotPaused {
        require(_index < academicRecords[msg.sender].length, "Record index out of range.");
        require(academicRecords[msg.sender][_index].owner == msg.sender, "Only the record owner can transfer ownership.");
        academicRecords[msg.sender][_index].owner = _newOwner;
        emit RecordOwnershipTransferred(_index, msg.sender, _newOwner);
    }

    function requestMultiSigApproval(uint256 _index) public contractNotPaused {
        require(_index < academicRecords[msg.sender].length, "Record index out of range.");
        require(academicRecords[msg.sender][_index].owner == msg.sender, "Only the record owner can request multi-sig approval.");
        academicRecords[msg.sender][_index].verified = false;
        academicRecords[msg.sender][_index].verificationExpiry = 0;
        emit MultiSigApprovalRequested(_index, msg.sender);
    }

    function approveMultiSigApproval(uint256 _index) public onlyAdminOrFaculty {
        require(_index < academicRecords[msg.sender].length, "Record index out of range.");
        Record storage record = academicRecords[msg.sender][_index];
        require(!record.verified, "Record is already verified.");
        record.verified = true;
        record.verificationExpiry = block.timestamp + verificationExpiryDuration;
        emit MultiSigApprovalGranted(_index, msg.sender);
        emit RecordVerified(msg.sender, _index, true);
    }

    function revokeVerification(uint256 _index) public onlyAdminOrFaculty {
        require(_index < academicRecords[msg.sender].length, "Record index out of range.");
        Record storage record = academicRecords[msg.sender][_index];
        require(record.verified, "Record is not verified.");
        record.verified = false;
        record.verificationExpiry = 0;
        emit RecordVerified(msg.sender, _index, false);
    }

    function upgradeContract() public {
        require(isVersionUpgradable[msg.sender], "Upgradeable contract not available for your version.");
        address previousVersion = upgradeableContractVersions[upgradeableContractVersion - 1];
        require(previousVersion != address(0), "Upgradeable contract not available for upgrade.");
        AcademicRecord previousContract = AcademicRecord(previousVersion);
        require(previousContract.getRoleMemberCount(ADMIN_ROLE) == 1, "Only the owner of the previous contract can upgrade.");
        upgradeableContractVersion++;
        upgradeableContractVersions[upgradeableContractVersion] = msg.sender;
        delete isVersionUpgradable[msg.sender];
    }

    function getVersion() public view returns (uint256) {
        return upgradeableContractVersion;
    }

    function isContractPaused() public view returns (bool) {
        return paused();
    }

    function isUserVerifier(address _user) public view returns (bool) {
        return isVerifier[_user];
    }

    function addVerifier(address _verifier) public onlyAdmin {
        isVerifier[_verifier] = true;
        grantRole(VERIFIER_ROLE, _verifier);
    }

    function removeVerifier(address _verifier) public onlyAdmin {
        isVerifier[_verifier] = false;
        revokeRole(VERIFIER_ROLE, _verifier);
    }

    function getRecordHistory(address _user, uint256 _index) public view returns (bytes32[] memory) {
        require(_index < academicRecords[_user].length, "Record index out of range.");
        Record storage record = academicRecords[_user][_index];
        uint256 historyLength = record.recordHistory.length;
        bytes32[] memory history = new bytes32[](historyLength);
        for (uint256 i = 0; i < historyLength; i++) {
            history[i] = record.recordHistory[i];
        }
        return history;
    }

    function verifyRecordWithSignature(address _user, uint256 _recordIndex, bytes memory _signature, bytes32 _messageHash) public onlyVerifier contractNotPaused {
        require(_recordIndex < academicRecords[_user].length, "Record index out of range.");
        address recoveredSigner = _messageHash.toEthSignedMessageHash().recover(_signature);
        require(recoveredSigner == _user, "Invalid signature.");
        Record storage record = academicRecords[_user][_recordIndex];
        record.verified = true;
        record.verificationExpiry = block.timestamp + verificationExpiryDuration;
        emit RecordVerified(_user, _recordIndex, true);
    }

    function isRecordVerified(address _user, uint256 _recordIndex) public view returns (bool) {
        require(_recordIndex < academicRecords[_user].length, "Record index out of range.");
        Record storage record = academicRecords[_user][_recordIndex];
        return record.verified;
    }

    function generateVerificationKey(address _user, uint256 _recordIndex) public view returns (bytes32) {
        require(_recordIndex < academicRecords[_user].length, "Record index out of range.");
        bytes32 verificationKey = keccak256(abi.encodePacked(_user, _recordIndex, verificationNonce[_user]));
        return verificationKey;
    }

    function verifyIPFSHash(bytes32 _ipfsHash, bytes32 _verificationKey, bytes memory _signature) public pure returns (bool) {
        bytes32 messageHash = keccak256(abi.encodePacked(_ipfsHash, _verificationKey));
        address recoveredSigner = messageHash.toEthSignedMessageHash().recover(_signature);
        return recoveredSigner == _verificationKey.toEthAddress();
    }
}

