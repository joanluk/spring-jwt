#!/bin/bash

set -e

BASE_URL="http://localhost:8080"
HEADERS_FILE="response-headers.txt"

function cleanUpHeadersFile {
  if [ -f $HEADERS_FILE ] ; then
    rm $HEADERS_FILE
  fi
}

function requestToken {
  echo "Request token $1:$2"
  cleanUpHeadersFile

  curl --dump-header $HEADERS_FILE \
    -X POST \
    -u $1:$2 \
    $BASE_URL/api/auth/login

  TOKEN=$(grep Authorization $HEADERS_FILE | cut -d' ' -f3)

  cleanUpHeadersFile

  echo "Obtained token: $TOKEN" 
}

function readPets {
  echo "Reading pets"
  curl -H "Authorization: Bearer $TOKEN" $BASE_URL/api/pets
  echo
}

function postPet {
  echo "Posting pet"
  curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"name":"Nero"}' $BASE_URL/api/pets
  echo
}

requestToken "alice" "alice"
readPets
postPet

requestToken "bob" "bob"
readPets
postPet
