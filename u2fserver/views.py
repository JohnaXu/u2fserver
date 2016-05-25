from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from M2Crypto import Rand,  EC, X509, EVP, RSA, ASN1
from hashlib import sha256
from base64 import urlsafe_b64decode, urlsafe_b64encode
import os
from models import User
import pdb
import json
from utils import (websafe_decode,websafe_encode,gen_challenge,sha_256,rand_bytes,pub_key_from_der)

PUBKEY_LEN = 65

def get_origin(environ):
    if environ.get('HTTP_HOST'):
        host = environ['HTTP_HOST']
    else:
        host = environ['SERVER_NAME']
        if environ['wsgi.url_scheme'] == 'https':
            if environ['SERVER_PORT'] != '443':
                host += ':' + environ['SERVER_PORT']
        else:
            if environ['SERVER_PORT'] != '80':
                host += ':' + environ['SERVER_PORT']

    return '%s://%s' % (environ['wsgi.url_scheme'], host)

def enroll(request):

	if "username" in request.GET:
		username1 = request.GET['username']
	else: 
		raise Exception("no userName!")
	
	enrollRequest = {}
	enrollRequest['type']='u2f_register_request'
	enrollRequest['SignRequest'] = []
	enrollRequest['sessionId']='123456'
	enrollRequest['timeoutSeconds'] = 1
	enrollRequest['requestId'] = 123456
	
	# Rand.rand_seed(os.urandom(1024))
	# challenge = urlsafe_b64encode(Rand.rand_bytes(32))
	challenge ="yNUlo7L60GGebyedX8LcR0ADOv71ivwa4D20NwyFAcg="

	# origin = get_origin(request.environ)
	#origin = "http://192.168.38.132:8002"
	origin = "http://localhost:8000"
	enrollRequest['RegisterRequest'] = [{'challenge':challenge,'version': 'U2F_V2', 'appId': origin }]

	User.objects.filter(userName=username1).delete()
	user = User.objects.create(userName=username1, challenge=challenge,appId=origin)
	user.save()

	strong_enrollRequest = {}
	strong_enrollRequest['Challenge'] = enrollRequest
	strong_enrollRequest['Message'] = ''
	strong_enrollRequest['Error'] = ''

	return JsonResponse(strong_enrollRequest)

def com_register(request):

	if "username" in request.GET:
		username = request.GET['username']
	else: 
		raise Exception("no userName!")
	
	data = json.loads(request.body)
	registrationResponse = {}
	registrationResponse['Error'] = ""
	registrationResponse['Typ'] = 'u2f_register_response'
	registrationResponse['RequestId'] = 1
	registrationResponse['Response'] = ""
	error = ""

	user = User.objects.get(userName=username)

	responseData = data['response']

	client = websafe_decode(responseData['clientData'])

	client_dict = eval(client)
	if str(client_dict['typ']) != "navigator.id.finishEnrollment":
		error = error + "wrong type"
		raise ValueError("Wrong type! Was: %s, expecting: %s" % (client_dict['typ'], registrationType))
	if client_dict['challenge'] != user.challenge:
	#if client_dict['challenge'] != 'yNUlo7L60GGebyedX8LcR0ADOv71ivwa4D20NwyFAcg=':
		# print "wrong challenge"
		error = error + "wrong challenge"
		raise ValueError("Wrong challenge! Was: %s, expecting: %s" % (client_dict['challenge'],user.challenge))
	
		#error = error + "wrong challenge"

	registrationData = websafe_decode(responseData['registrationData'])
	if ord(registrationData[0]) != 0x05:
		error = error + "wrong reserved byte"

	registrationData = registrationData[1:]
	pub_key = registrationData[:PUBKEY_LEN]
	user.public_key=pub_key.encode('hex')
	user.save()

	registrationData = registrationData[PUBKEY_LEN:]
	kh_len = ord(registrationData[0])
	registrationData = registrationData[1:]
	key_handle = registrationData[:kh_len]
	user.key_handle=key_handle.encode('hex')
	user.save()

	#certification
	registrationData = registrationData[kh_len:]
	certificate = X509.load_cert_der_string(registrationData)
	#pdb.set_trace()

	#signature
	signature = registrationData[len(certificate.as_der()):]

	app_param = sha_256(user.appId)
	chal_param = sha_256(str(client))
	data1 = chr(0x00) + app_param + chal_param + key_handle + pub_key

	# print "pub_key",pub_key.encode('hex')
	# print "key_handle",key_handle.encode('hex')
	
	pubkey = certificate.get_pubkey()
	pubkey.reset_context('sha256')
	pubkey.verify_init()
	pubkey.verify_update(data1)
	if not pubkey.verify_final(signature) == 1:
		error = error + "wrong signature"
		raise Exception('Attestation signature verification failed!')

	registrationResponse['Error']=error
	registrationResponse['Response'] = "Success"
	return JsonResponse(registrationResponse)


def sign(request):

	if "username" in request.GET:
		username = request.GET['username']
	else: 
		raise Exception("no userName!")

	user = User.objects.get(userName=username)

	signRequest={}
	signRequest['typ'] = "u2f_sign_request"
	signRequest['registerrequest'] = []
	signRequest['timeoutSeconds'] = 1
	signRequest['requestId'] = 123456

	# Rand.rand_seed(os.urandom(1024))
	# challenge = urlsafe_b64encode(Rand.rand_bytes(32))
	challenge = "SP1FwSgZPJG6j91c0fv83k5UJHcttbYFisqPEiQeAgA="
	user.challenge = challenge
	user.save()

	# origin = get_origin(request.environ)
	# origin = "http://192.168.38.132:8002"
	origin = "http://localhost:8000"
	#user.appId = origin
	user.save()

	keyHandle = urlsafe_b64encode((user.key_handle).decode('hex'))

	signRequest['SignRequest'] = [{'challenge':challenge,'version':'U2F_V2','appId':origin,'keyHandle':
				keyHandle,'sessionId':'123456'}]
	# signRequest['signrequests'] = {'Challenge':{'Challenge':challenge,"sessionId":"session1"}, 'version': 'U2F_V2', 'Error':'', 'appId': 'http://localhost:8000','keyHandle':user.key_handle}

	strong_signRequest = {}
	strong_signRequest['Challenge'] = signRequest
	strong_signRequest['Message'] = ''
	strong_signRequest['Error'] = ''
 
	return JsonResponse(strong_signRequest)
	#return JsonResponse(signRequest)

def com_auth(request):

	if "username" in request.GET:
		username = request.GET['username']
	else: 
		raise Exception("no userName!")

	signResponse = {}
	signResponse['Typ'] = 'u2f_sign_response'
	signResponse['RequestId'] = 1
	error =""

	user = User.objects.get(userName=username)
	SignResponse = json.loads(request.body)


	data = SignResponse['response']
	# print "SignResponse------------------", data
	keyHandle = data['keyHandle']
	# print "keyHandle------------------", keyHandle
	signatureData = data['signatureData']
	# print "signatureData------------------", signatureData
	clientData = data['clientData']
	# print "clientData------------------", clientData

	client = websafe_decode(clientData)
	# print "client------------------", client
	client_dict = eval(client)
	# print "client_dict------------------", client_dict
	
	#client = eval(urlsafe_b64decode(str(clientData)))

	# verify client data
	if (client_dict['typ']) != "navigator.id.getAssertion":
		error = error + "wrong type"
		raise ValueError("Wrong type! Was: %s, expecting: %s" % (client.typ, registrationType))
	if (client_dict['challenge']) != user.challenge:
		error = error + "wrong challenge"
		raise ValueError("Wrong challenge! Was: %s, expecting: %s" % (client.challenge.encode('hex'),challenge.encode('hex')))
	#app_param = sha_256(client['origin'])

	#app_param = sha_256(user.appId)



	AuthenticationData = websafe_decode(signatureData.encode('utf-8'))
	# print "AuthenticationData------------------",AuthenticationData.encode('hex')

	user_presence = AuthenticationData[0]
	# print "user_presence------------------",user_presence.encode('hex')

	counter = AuthenticationData[1:5]
	# print "counter------------------",counter.encode('hex')
	#counter_int = struct.unpack('>I', counter)[0]

	signature = AuthenticationData[5:]
	# print "signature------------------",signature.encode('hex')

	#app_param = sha_256('http://localhost:8000')
	app_param = sha_256(user.appId)
	#app_param = sha_256('http://192.168.38.132:8002')
	# print "user.appId ------------------",user.appId
	# print "app_param ------------------",app_param.encode('hex')


	chal_param = sha_256(client)
	# print "client------------------",client
	# print "chal_param ------------------",chal_param.encode('hex')

	# pdb.set_trace()
	
	data1 = app_param + user_presence + counter + chal_param
	# print "data1------------------",data1.encode('hex')

	#pdb.set_trace()
	#pub_key_zhq = '0471d57c414b2237dedabddf40335d518eac26f4116ae70292607f5def2630d48806850765f726de6f709d687737b92994da29b6298ad80d875248dbb9dee2df8f'
	#pubkey = pub_key_zhq.decode('hex')
	#pdb.set_trace()
	pubkey = (user.public_key).decode('hex')
	pub_key = pub_key_from_der(pubkey)
	digest = sha_256(data1)

	# pdb.set_trace()
	result1 = pub_key.verify_dsa_asn1(digest, signature)

	if not pub_key.verify_dsa_asn1(digest, signature) == 1:
		error = error + "wrong signNature"
		raise Exception('Challenge signature verification failed!')

	signResponse["Response"]="success"
	signResponse['Error'] = error
	return JsonResponse(signResponse)
