#https://github.com/jpadilla/pyjwt
#pip3 install PyJWT

import jwt
import sys
import os.path

sampleDirectory = os.path.split(sys.argv[0])[0]

def writeToSampleDirectory(content,name):
    f = open(sampleDirectory+'/'+name, 'w')
    f.write(content)
    f.close()

cryptoPayload = { 'sub': '1234567890','name': 'John Doe' }
cryptoSymSecret = 'secret'


publicKeyFile = open(sampleDirectory+'/rsa1_public.pem', 'r')
cryptoPublicKey = publicKeyFile.read()
publicKeyFile.close()

privateKeyFile = open(sampleDirectory+'/rsa1_private.pem', 'r')
cryptoPrivateKey = privateKeyFile.read()
privateKeyFile.close()

publicKeyFile2 = open(sampleDirectory+'/rsa2_public.pem', 'r')
cryptoPublicKey2 = publicKeyFile2.read()
publicKeyFile2.close()

privateKeyFile2 = open(sampleDirectory+'/rsa2_private.pem', 'r')
cryptoPrivateKey2 = privateKeyFile2.read()
privateKeyFile2.close()

ECpublicKeyFile = open(sampleDirectory+'/ec1_public.pem', 'r')
ECcryptoPublicKey = ECpublicKeyFile.read()
ECpublicKeyFile.close()

ECprivateKeyFile = open(sampleDirectory+'/ec1_private.pem', 'r')
ECcryptoPrivateKey = ECprivateKeyFile.read()
ECprivateKeyFile.close()

writeToSampleDirectory(jwt.encode(cryptoPayload, 'secret', algorithm='HS256'),'HS256.jwt')
writeToSampleDirectory(jwt.encode(cryptoPayload, 'secret', algorithm='HS384'),'HS384.jwt')
writeToSampleDirectory(jwt.encode(cryptoPayload, 'secret', algorithm='HS512'),'HS512.jwt')

writeToSampleDirectory(jwt.encode(cryptoPayload, cryptoPrivateKey, algorithm='RS256'),'RS256.jwt')
writeToSampleDirectory(jwt.encode(cryptoPayload, cryptoPrivateKey, algorithm='RS384'),'RS384.jwt')
writeToSampleDirectory(jwt.encode(cryptoPayload, cryptoPrivateKey, algorithm='RS512'),'RS512.jwt')

writeToSampleDirectory(jwt.encode(cryptoPayload, cryptoPrivateKey, algorithm='PS256'),'PS256.jwt')
writeToSampleDirectory(jwt.encode(cryptoPayload, cryptoPrivateKey, algorithm='PS384'),'PS384.jwt')
writeToSampleDirectory(jwt.encode(cryptoPayload, cryptoPrivateKey, algorithm='PS512'),'PS512.jwt')

writeToSampleDirectory(jwt.encode(cryptoPayload, ECcryptoPrivateKey, algorithm='ES256'),'ES256.jwt')
writeToSampleDirectory(jwt.encode(cryptoPayload, ECcryptoPrivateKey, algorithm='ES384'),'ES384.jwt')
writeToSampleDirectory(jwt.encode(cryptoPayload, ECcryptoPrivateKey, algorithm='ES512'),'ES512.jwt')

writeToSampleDirectory(jwt.encode(cryptoPayload, cryptoPrivateKey2, algorithm='RS256'),'RS256_2.jwt')
writeToSampleDirectory(jwt.encode(cryptoPayload, cryptoPrivateKey2, algorithm='RS384'),'RS384_2.jwt')
writeToSampleDirectory(jwt.encode(cryptoPayload, cryptoPrivateKey2, algorithm='RS512'),'RS512_2.jwt')


all_claim_valid_1 = {
    'iss' : 'alphacoders.io',
    'sub' : 'antoine',
    'aud' : 'test-app',
    'exp' : 1735689600,
    'nbf' : 0,
    'iat' : 1448371704,
    'jti' : '123456789'
}
writeToSampleDirectory(jwt.encode(all_claim_valid_1, None,algorithm='none'),'all_claim_valid_1.jwt')

all_claim_valid_2 = {
    'iss' : 'alphacoders.io',
    'sub' : 'antoine',
    'aud' : ['test-app','test-app2'],
    'exp' : 1735689600,
    'nbf' : 0,
    'iat' : 1448371704,
    'jti' : '123456789'
}
writeToSampleDirectory(jwt.encode(all_claim_valid_2, None,algorithm='none'),'all_claim_valid_2.jwt')


all_claim_valid_2_signed = {
    'iss' : 'alphacoders.io',
    'sub' : 'antoine',
    'aud' : ['test-app','test-app2'],
    'exp' : 1735689600,
    'nbf' : 0,
    'iat' : 1448371704,
    'jti' : '123456789'
}

writeToSampleDirectory(jwt.encode(all_claim_valid_2_signed, cryptoSymSecret ,algorithm='HS256'),'all_claim_valid_2_signed.jwt')
writeToSampleDirectory(jwt.encode({}, None ,algorithm='none'),'empty.jwt')
writeToSampleDirectory(jwt.encode({'exp' : '11/11/2025'}, None ,algorithm='none'),'invalid_exp_format.jwt')
writeToSampleDirectory(jwt.encode({'exp' : 1448465478}, None ,algorithm='none'),'invalid_expired.jwt')

writeToSampleDirectory(jwt.encode({'nbf' : '11/11/2025'}, None ,algorithm='none'),'invalid_nbf_format.jwt')
writeToSampleDirectory(jwt.encode({'nbf' : 1762819200}, None ,algorithm='none'),'invalid_nbf_immature.jwt')

writeToSampleDirectory(jwt.encode({'iat' : '11/11/2025'}, None ,algorithm='none'),'invalid_iat_format.jwt')
writeToSampleDirectory(jwt.encode({'iss' : 1762819200 }, None ,algorithm='none'),'invalid_iss_format.jwt')
writeToSampleDirectory(jwt.encode({'sub' : 1762819200 }, None ,algorithm='none'),'invalid_sub_format.jwt')
writeToSampleDirectory(jwt.encode({'aud' : 1762819200 }, None ,algorithm='none'),'invalid_aud_format.jwt')
writeToSampleDirectory(jwt.encode({'jti' : 1762819200 }, None ,algorithm='none'),'invalid_jti_format.jwt')

