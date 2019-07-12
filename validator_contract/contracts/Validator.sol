pragma solidity 0.5.5;

contract Validator{

  event DocumentAdded(bytes32 hashDocument, address minter);
  event NewInvitation(bytes32 hashDocument, address user);
  event ActionAdded(bytes32 hashDocument, address user, string comment);

  mapping (bytes32 => bool) public hashDocuments;
  mapping (bytes32 => address) public hashOwner;
  mapping (bytes32 => address[]) public documentValidators;
  mapping (bytes32 => mapping (address => bool)) public hashValidatorUser;
  mapping (bytes32 => mapping (address => string)) public documentComments;

  function newDocument(bytes32 hashDocument) public {
    require(!hashExists(hashDocument), 'This document already exist');
    hashDocuments[hashDocument] = true;
    hashOwner[hashDocument] = msg.sender;
    emit DocumentAdded(hashDocument, msg.sender);
  }

  function hashExists(bytes32 hashDocument) private view returns (bool exists){
    exists = false;
    if (hashDocuments[hashDocument]) {
      exists = true;
    }
    return exists;
  }

  function addValidatorUser(bytes32 hashDocument, address user) public {
    require(hashExists(hashDocument), 'This document does not exist');
    require(user != hashOwner[hashDocument], 'The owner can not be a validator user');
    if (hashOwner[hashDocument] == msg.sender) {
      if (!hashValidatorUser[hashDocument][user]) {
        hashValidatorUser[hashDocument][user] = true;
        documentValidators[hashDocument].push(user);
        documentComments[hashDocument][user] = "Pending";
        emit NewInvitation(hashDocument, user);
      }
    }
  }

  function addValidationUser(bytes32 hashDocument, address user, string memory comment) public {
    require(hashExists(hashDocument), 'This document does not exist');
    require(user != hashOwner[hashDocument], 'The owner can not be a validator user');
    require(hashValidatorUser[hashDocument][user], 'You are not a validating user of this document');
    documentComments[hashDocument][user] = comment;
    emit ActionAdded(hashDocument, user, comment);
  }

}
