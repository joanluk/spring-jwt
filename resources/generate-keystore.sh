#!/bin/bash

set -e

TARGET_FILE="sample-jwt.p12"
TARGET_FILE_CERT="sample-jwt.cer"
TARGET_PWD="changeit"
TARGET_ALIAS="sample-jwt"
KEY_SIZE="2048"
KEY_ALG="SHA256withRSA"

if [ -f $TARGET_FILE ] ; then
  rm $TARGET_FILE
fi
if [ -f $TARGET_FILE_CERT ] ; then
  rm $TARGET_FILE_CERT
fi

keytool -keystore $TARGET_FILE \
        -keyalg RSA -keysize $KEY_SIZE -sigalg $KEY_ALG \
        -storepass $TARGET_PWD \
        -keypass $TARGET_PWD \
        -dname 'CN=sample-jwt, OU=joanluk, O=labcabrera, L=Madrid, ST=Madrid, C=ES' \
        -genkey -alias $TARGET_ALIAS \
        -storetype pkcs12

keytool -list \
        -keystore $TARGET_FILE \
        -storepass $TARGET_PWD \
        -storetype pkcs12

keytool -export -keystore $TARGET_FILE \
        -alias $TARGET_ALIAS \
        -file $TARGET_FILE_CERT \
        -storetype pkcs12 \
        -storepass $TARGET_PWD