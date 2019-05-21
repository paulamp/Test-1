pragma solidity 0.5.5;

contract Sign{

  event DocumentAdded(bytes32 hashDocument, address minter);

  mapping (bytes32 => bool) public hashDocuments;
  mapping (bytes32 => address) public hashOwner;
  mapping (bytes32 => address[]) public documentValidators;
  mapping (bytes32 => mapping (address => bool)) public hashValidatorUser;
  mapping (bytes32 => mapping (address => string)) public documentComments;

  function newDocument(bytes32 hashDocument) public returns (bool added){
    if (hashExists(hashDocument)){
      added = false;
    }
    else{
      hashDocuments[hashDocument] = true;
      hashOwner[hashDocument] = msg.sender;
      added = true;
    }
    emit DocumentAdded(hashDocument, msg.sender);
    return added;
  }

  function hashExists(bytes32 hashDocument) private view returns (bool exists){
    exists = false;
    if (hashDocuments[hashDocument]) {
      exists = true;
    }
    return exists;
  }

  function addValidatorUser(bytes32 hashDocument, address user) public returns (bool added){
    added = false;
    if (hashDocuments[hashDocument] && hashOwner[hashDocument] == msg.sender) {
      if (!hashValidatorUser[hashDocument][user]) {
        hashValidatorUser[hashDocument][user] = true;
        documentValidators[hashDocument].push(user);
        documentComments[hashDocument][user] = "Pending";
        added = true;
      }
    }
    return added;
  }

}
