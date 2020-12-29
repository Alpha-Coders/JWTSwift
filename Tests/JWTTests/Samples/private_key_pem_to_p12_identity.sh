#!/bin/bash

INPUT=$1
NAME=$2
DIRECTORY=`dirname "$INPUT"`
FILENAME=`basename "$INPUT"`
TARGET_BASE_PATH="$DIRECTORY"/$NAME
echo $1
echo $TARGET_BASE_PATH
echo "$TARGET_BASE_PATH".csr
echo "$TARGET_BASE_PATH".crt

#Create a certificate signing request with the private key
openssl req -new -key $INPUT -out "$TARGET_BASE_PATH".csr

#Create a self-signed certificate with the private key and signing request
openssl x509 -req -days 3650 -in "$TARGET_BASE_PATH".csr -signkey $INPUT -out "$TARGET_BASE_PATH".crt

#Convert the certificate to DER format: the certificate contains the public key
openssl x509 -outform der -in "$TARGET_BASE_PATH".crt -out "$TARGET_BASE_PATH".der

#Export the private key and certificate to p12 file
openssl pkcs12 -export -out "$TARGET_BASE_PATH"_identity.p12 -inkey $INPUT -in "$TARGET_BASE_PATH".crt

#export public key as pem
openssl ec -in $INPUT -pubout -out "$NAME"_public.pem

#delete signing request
rm "$TARGET_BASE_PATH".csr

#delete self-signed certificate
rm "$TARGET_BASE_PATH".crt

#rename to der to cer
mv "$TARGET_BASE_PATH".der "$TARGET_BASE_PATH"_public.cer