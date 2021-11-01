from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
import json
from django.views.decorators.csrf import csrf_exempt
import datetime

from Crypto.PublicKey import RSA
from hashlib import sha512

global block
# block = {
#     'timestamp',
#     'signature',
#     'hash',
#     'keyPair',
# }

block = set()

validator=['3wfeevg3g','d3wg678g','cadw34as']
keyPair = RSA.generate(bits=1024)

# Create your views here.
def home(request):
    return HttpResponse("Hello, World")


def decrypt(data, original):
    hashB = int.from_bytes(sha512(original).digest(), byteorder='big')
    hashFromSignature = pow(data, keyPair.e, keyPair.n)
    checkVal = hashB == hashFromSignature
    return(checkVal)
      
def encrypt(data):
    enc_data=data.encode("utf8")
    hashA = int.from_bytes(sha512(enc_data).digest(), byteorder='big')
    signature = pow(hashA, keyPair.d, keyPair.n)
    encoded_val=validator[0].encode("utf8")
    check=decrypt(signature, encoded_val)
    # block = create_block(hashA, signature, keyPair)
    return (check)

def create_block(keyPair, data):
    enc_data=data.encode("utf8")
    hashA = int.from_bytes(sha512(enc_data).digest(), byteorder='big')
    signature = pow(hashA, keyPair.d, keyPair.n)
    block = {
        "timestamp": str(datetime.datetime.now()),
        "hash_value": hashA,
        "encoded_signature": signature,
        # "keyPair": keyPair,
    }
    return block


@csrf_exempt
def get_data(request):
    if request.method == 'POST':
        received_json = json.loads(request.body)
        frontend_data = received_json['fingerprint']
        final_answer = encrypt(frontend_data)
        final_block=create_block(keyPair, frontend_data)
        if(final_answer==True):
            return JsonResponse({"message": "Authentication Successful", 'data': json.dumps(final_block)})
        else:
            return JsonResponse({"message": "Authentication Failed",})
    return JsonResponse({"message": "error"})

