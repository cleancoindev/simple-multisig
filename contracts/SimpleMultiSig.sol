pragma solidity 0.5.11;


contract SimpleMultiSig {
  // Used when constructing a transaction from the multisig.
  bytes32 private constant _TXTYPE_HASH = bytes32(
    0x3ee892349ae4bbe61dce18f95115b5dc02daf49204cc602458cd4c1f540d56d7
  );

  uint256 private _nonce; // only mutable state
  address private _destination;
  uint256 private _threshold;
  mapping(address => bool) private _isOwner;
  address[] private _owners;
  bytes32 private _DOMAIN_SEPARATOR; // EIP712 hash (takes contract address as an input)
  
  // Note: Owners must be strictly increasing in order to prevent duplicates.
  constructor(
    address destination, uint256 threshold, address[] memory owners, uint256 chainId
  ) public {
    require(destination != address(0), "Destination cannot be null address.");
    require(owners.length <= 10, "Cannot have more than 10 owners.");
    require(threshold <= owners.length, "Owners cannot exceed threshold.");
    require(threshold > 0, "Threshold cannot be zero.");

    // EIP712 Domain separator inputs and hashes
    bytes memory EIP712DomainType = abi.encodePacked(
      "EIP712Domain(string name,string version,uint256 chainId,",
      "address verifyingContract,bytes32 salt)"
    );
    bytes32 EIP712DomainTypeHash = bytes32(
      0xd87cd6ef79d4e2b95e15ce8abf732db51ec771f1ca2edccf22a46c729ac56472
    );
    require(
      keccak256(EIP712DomainType) == EIP712DomainTypeHash,
      "EIP712 Domain Type Hash is incorrect."
    );

    bytes memory name = abi.encodePacked("Simple MultiSig");
    bytes32 nameHash = bytes32(
      0xb7a0bfa1b79f2443f4d73ebb9259cddbcd510b18be6fc4da7d1aa7b1786e73e6
    );
    require(keccak256(name) == nameHash, "Name hash is incorrect.");

    bytes memory version = abi.encodePacked("2");
    bytes32 versionHash = bytes32(
      0xad7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5
    );
    require(keccak256(version) == versionHash, "Version hash is incorrect.");

    // Note: nothing to verify salt against.
    bytes32 salt = bytes32(
      0x251543af6a222378665a76fe38dbceae4871a070b7fdaf5c6c30cf758dc33cc0
    );

    // Validate _TXTYPE_HASH constant.
    bytes memory txType = abi.encodePacked(
      "MultiSigTransaction(address destination,uint256 value,bytes data,",
      "uint256 nonce,address executor,uint256 gasLimit)"
    );
    require(
      keccak256(txType) == _TXTYPE_HASH, "Transaction type Hash is incorrect."
    );

    address lastAdd = address(0);
    for (uint i = 0; i < owners.length; i++) {
      require(owners[i] > lastAdd);
      _isOwner[owners[i]] = true;
      lastAdd = owners[i];
    }
    _owners = owners;
    _threshold = threshold;
    _destination = destination;

    _DOMAIN_SEPARATOR = keccak256(
      abi.encode(
        EIP712DomainTypeHash, nameHash, versionHash, chainId, address(this), salt
      )
    );
  }

  function getNextHash(
    bytes calldata data,
    address executor,
    uint256 gasLimit
  ) external view returns (bytes32 hash) {
    hash = _getHash(data, executor, gasLimit, _nonce);
  }

  function getHash(
    bytes calldata data,
    address executor,
    uint256 gasLimit,
    uint256 nonce
  ) external view returns (bytes32 hash) {
    hash = _getHash(data, executor, gasLimit, nonce);
  }

  function getNonce() external view returns (uint256 nonce) {
    nonce = _nonce;
  }

  function getOwners() external view returns (address[] memory owners) {
    owners = _owners;
  }

  function getThreshold() external view returns (uint256 threshold) {
    threshold = _threshold;
  }

  // Note: addresses recovered from signatures must be strictly increasing.
  function execute(
    bytes calldata data,
    address executor,
    uint256 gasLimit,
    bytes calldata signatures
  ) external returns (bool success, bytes memory returnData) {
    require(
      executor == msg.sender || executor == address(0),
      "Must call from the executor account if one is specified."
    );

    // Derive the message hash and wrap in the eth signed messsage hash.
    bytes32 totalHash = _toEthSignedMessageHash(
      _getHash(data, executor, gasLimit, _nonce)
    );

    // Recover each signer from the provided signatures.
    address[] memory signers = _recoverGroup(totalHash, signatures);

    require(signers.length == _threshold, "Total signers must equal threshold.");

    // Verify that each signatory is an owner and is strictly increasing.
    address lastAdd = address(0); // cannot have address(0) as an owner
    for (uint256 i = 0; i < signers.length; i++) {
      require(
        _isOwner[signers[i]], "Signature does not correspond to an owner."
      );
      require(
        signers[i] > lastAdd, "Signer addresses must be strictly increasing."
      );
      lastAdd = signers[i];
    }

    // Increment the nonce and execute the transaction.
    _nonce++;
    (success, returnData) = _destination.call.gas(gasLimit)(data);
  }

  function _getHash(
    bytes memory data,
    address executor,
    uint256 gasLimit,
    uint256 nonce
  ) internal view returns (bytes32 hash) {
    // EIP712 scheme: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md
    bytes32 txInputHash = keccak256(
      abi.encode(
        _TXTYPE_HASH,
        _destination, // fixed destination
        uint256(0), // no value
        keccak256(data),
        nonce,
        executor,
        gasLimit
      )
    );

    // Note: this needs to be used to create a personal signed message hash.
    hash = keccak256(
      abi.encodePacked("\x19\x01", _DOMAIN_SEPARATOR, txInputHash)
    );
  }

  /**
   * @dev Returns each address that signed a hashed message (`hash`) from a
   * collection of `signatures`.
   *
   * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
   * this function rejects them by requiring the `s` value to be in the lower
   * half order, and the `v` value to be either 27 or 28.
   *
   * NOTE: This call _does not revert_ if a signature is invalid, or if the
   * signer is otherwise unable to be retrieved. In those scenarios, the zero
   * address is returned for that signature.
   *
   * IMPORTANT: `hash` _must_ be the result of a hash operation for the
   * verification to be secure: it is possible to craft signatures that recover
   * to arbitrary addresses for non-hashed data.
   */
  function _recoverGroup(
    bytes32 hash,
    bytes memory signatures
  ) internal pure returns (address[] memory signers) {
    // Ensure that the signatures length is a multiple of 65.
    if (signatures.length % 65 != 0) {
      return new address[](0);
    }

    // Create an appropriately-sized array of addresses for each signer.
    signers = new address[](signatures.length / 65);

    // Get each signature location and divide into r, s and v variables.
    bytes32 signatureLocation;
    bytes32 r;
    bytes32 s;
    uint8 v;

    for (uint256 i = 0; i < signers.length; i++) {
      assembly {
        signatureLocation := add(signatures, mul(i, 65))
        r := mload(add(signatureLocation, 32))
        s := mload(add(signatureLocation, 64))
        v := byte(0, mload(add(signatureLocation, 96)))
      }

      // EIP-2 still allows signature malleability for ecrecover(). Remove
      // this possibility and make the signature unique.
      if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
        continue;
      }

      if (v != 27 && v != 28) {
        continue;
      }

      // If signature is valid & not malleable, add signer address.
      signers[i] = ecrecover(hash, v, r, s);
    }
  }

  function _toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
    return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
  }
}