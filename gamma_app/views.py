from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
import json
from django.views.decorators.csrf import csrf_exempt

from Crypto.PublicKey import RSA
from hashlib import sha512

validator=['3wfeevg3g']
keyPair = RSA.generate(bits=1024)

# Create your views here.
def home(request):
    return HttpResponse("Hello, World")

def encrypt(data):
    enc_data=data.encode("utf8")
    hashA = int.from_bytes(sha512(enc_data).digest(), byteorder='big')
    signature = pow(hashA, keyPair.d, keyPair.n)
    encoded_val=validator[0].encode("utf8")
    check=decrypt(signature, encoded_val)
    return check

def decrypt(data, original):
    hashB = int.from_bytes(sha512(original).digest(), byteorder='big')
    hashFromSignature = pow(data, keyPair.e, keyPair.n)
    checkVal = hashB == hashFromSignature
    return(checkVal)

@csrf_exempt
def get_data(request):
    if request.method == 'POST':
        received_json = json.loads(request.body)
        frontend_data = received_json['fingerprint']
        final_answer = encrypt(frontend_data)
        if(final_answer==True):
            return JsonResponse({"message": "Authentication Successful"})
        else:
            return JsonResponse({"message": "Authentication Failed"})
    return JsonResponse({"message": "error"})

