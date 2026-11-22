// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Blind Labs (https://blindlabs.ai)
pragma solidity ^0.8.24;

/// @title BlindCoreRootAnchor
/// @notice Base L2 epoch state-root anchor and EIP-712 v2 receipt settlement
///         verifier for BlindCore confidential compute (EIP-2 low-s guarded,
///         indexed for Ponder/Dune, and ERC-8004 / ACP validation compatible).
contract BlindCoreRootAnchor {
    // -------------------------------------------------------------------------
    // Constants & EIP-712 Domain
    // -------------------------------------------------------------------------

    bytes32 public constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 public constant DOMAIN_NAME_HASH = keccak256("BlindCoreRootAnchor");
    bytes32 public constant DOMAIN_VERSION_HASH = keccak256("2");

    bytes32 public constant SETTLE_TYPEHASH = keccak256(
        "SettleReceipt(uint64 epochSeq,address payer,bytes32 tableHash,bytes32 receiptHash,uint64 feeUsdcMicro,uint8 opTier)"
    );

    // secp256k1n / 2 (EIP-2 strict low-s upper bound preventing signature malleability)
    uint256 internal constant SECP256K1_HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    uint256 internal immutable INITIAL_CHAIN_ID;
    bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    address public sequencer;
    address public pendingSequencer;
    uint64 public latestEpoch;
    uint256 public settledCount;

    mapping(address => bool) public authorizedRelayers;
    mapping(uint64 => bytes32) public epochRoots;
    mapping(bytes32 => bool) public settledDigests;
    mapping(bytes32 => address) public settledPayer;
    mapping(bytes32 => uint64) public settledEpoch;
    mapping(bytes32 => uint8) public settledOpTier;

    // -------------------------------------------------------------------------
    // Events (Indexed for Ponder / Dune / Goldsky zero-join analytics)
    // -------------------------------------------------------------------------

    event RootAnchored(
        uint64 indexed epochSeq,
        bytes32 indexed stateRoot,
        uint64 rowCount,
        uint64 anchoredAt
    );

    event ReceiptSettled(
        uint64 indexed epochSeq,
        address indexed payer,
        bytes32 indexed tableHash,
        bytes32 digest,
        bytes32 receiptHash,
        uint64 feeUsdcMicro,
        uint8 opTier
    );

    event SequencerProposed(address indexed currentSequencer, address indexed proposedSequencer);
    event SequencerAccepted(address indexed previousSequencer, address indexed newSequencer);
    event PendingSequencerCancelled(address indexed cancelledSequencer);
    event RelayerUpdated(address indexed relayer, bool allowed);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    error Unauthorized();
    error ZeroAddress();
    error ZeroHash();
    error StaleEpoch();
    error EpochNotAnchored();
    error InvalidOpTier();
    error AlreadySettled();
    error InvalidSignature();

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    modifier onlySequencer() {
        if (msg.sender != sequencer) revert Unauthorized();
        _;
    }

    modifier onlyRelayer() {
        if (msg.sender != sequencer && !authorizedRelayers[msg.sender]) revert Unauthorized();
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    constructor(address initialSequencer) {
        if (initialSequencer == address(0)) revert ZeroAddress();
        sequencer = initialSequencer;
        authorizedRelayers[initialSequencer] = true;
        INITIAL_CHAIN_ID = block.chainid;
        INITIAL_DOMAIN_SEPARATOR = _computeDomainSeparator();
    }

    // -------------------------------------------------------------------------
    // EIP-712 Domain & Digest Views
    // -------------------------------------------------------------------------

    function DOMAIN_SEPARATOR() public view returns (bytes32) {
        return block.chainid == INITIAL_CHAIN_ID
            ? INITIAL_DOMAIN_SEPARATOR
            : _computeDomainSeparator();
    }

    function _computeDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                DOMAIN_NAME_HASH,
                DOMAIN_VERSION_HASH,
                block.chainid,
                address(this)
            )
        );
    }

    function computeSettleDigest(
        uint64 epochSeq,
        address payer,
        bytes32 tableHash,
        bytes32 receiptHash,
        uint64 feeUsdcMicro,
        uint8 opTier
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                SETTLE_TYPEHASH,
                epochSeq,
                payer,
                tableHash,
                receiptHash,
                feeUsdcMicro,
                opTier
            )
        );
        return keccak256(abi.encodePacked(hex"1901", DOMAIN_SEPARATOR(), structHash));
    }

    // -------------------------------------------------------------------------
    // Sequencer & Relayer Governance (2-Step Safe Rotation / BFT Quorum Upgrade Path)
    // -------------------------------------------------------------------------

    function setRelayer(address relayer, bool allowed) external onlySequencer {
        if (relayer == address(0)) revert ZeroAddress();
        authorizedRelayers[relayer] = allowed;
        emit RelayerUpdated(relayer, allowed);
    }

    function proposeSequencer(address nextSequencer) external onlySequencer {
        if (nextSequencer == address(0)) revert ZeroAddress();
        if (nextSequencer == sequencer) revert Unauthorized();
        pendingSequencer = nextSequencer;
        emit SequencerProposed(sequencer, nextSequencer);
    }

    function cancelPendingSequencer() external onlySequencer {
        address cancelled = pendingSequencer;
        pendingSequencer = address(0);
        emit PendingSequencerCancelled(cancelled);
    }

    function acceptSequencer() external {
        if (msg.sender != pendingSequencer) revert Unauthorized();
        address prev = sequencer;
        sequencer = msg.sender;
        authorizedRelayers[msg.sender] = true;
        pendingSequencer = address(0);
        emit SequencerAccepted(prev, msg.sender);
    }

    // -------------------------------------------------------------------------
    // Epoch Anchoring & Receipt Settlement
    // -------------------------------------------------------------------------

    function anchorRoot(uint64 epochSeq, bytes32 stateRoot, uint64 rowCount) external onlySequencer {
        if (epochSeq <= latestEpoch) revert StaleEpoch();
        if (stateRoot == bytes32(0)) revert ZeroHash();
        latestEpoch = epochSeq;
        epochRoots[epochSeq] = stateRoot;
        emit RootAnchored(epochSeq, stateRoot, rowCount, uint64(block.timestamp));
    }

    function settleReceipt(
        uint64 epochSeq,
        address payer,
        bytes32 tableHash,
        bytes32 receiptHash,
        uint64 feeUsdcMicro,
        uint8 opTier,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external onlyRelayer returns (bytes32 digest) {
        if (payer == address(0)) revert ZeroAddress();
        if (epochSeq == 0 || epochRoots[epochSeq] == bytes32(0)) revert EpochNotAnchored();
        if (tableHash == bytes32(0) || receiptHash == bytes32(0)) revert ZeroHash();
        if (opTier == 0) revert InvalidOpTier();

        digest = computeSettleDigest(
            epochSeq,
            payer,
            tableHash,
            receiptHash,
            feeUsdcMicro,
            opTier
        );
        if (settledDigests[digest]) revert AlreadySettled();

        // Strict EIP-2 low-s, non-zero r, and v check to block signature malleability
        if (v != 27 && v != 28) revert InvalidSignature();
        if (r == bytes32(0)) revert InvalidSignature();
        if (uint256(s) == 0 || uint256(s) > SECP256K1_HALF_N) revert InvalidSignature();

        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0) || signer != sequencer) revert InvalidSignature();

        settledDigests[digest] = true;
        settledPayer[digest] = payer;
        settledEpoch[digest] = epochSeq;
        settledOpTier[digest] = opTier;
        unchecked {
            settledCount += 1;
        }

        emit ReceiptSettled(
            epochSeq,
            payer,
            tableHash,
            digest,
            receiptHash,
            feeUsdcMicro,
            opTier
        );
    }

    // -------------------------------------------------------------------------
    // ERC-8004 Validation Registry & ACP (ERC-8183) Consumer Views
    // -------------------------------------------------------------------------

    function isReceiptSettled(bytes32 digest) external view returns (bool) {
        return settledDigests[digest];
    }

    function validateReceiptForAgent(
        bytes32 digest,
        address expectedPayer
    ) external view returns (bool valid, uint64 epochSeq, uint8 opTier) {
        if (!settledDigests[digest]) {
            return (false, 0, 0);
        }
        if (expectedPayer != address(0) && settledPayer[digest] != expectedPayer) {
            return (false, 0, 0);
        }
        return (true, settledEpoch[digest], settledOpTier[digest]);
    }
}
