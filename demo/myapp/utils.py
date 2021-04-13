import random
from twilio.rest import Client



def otp_generator():
	otp = random.randint(999, 9999)
	return otp

def send_otp(country_code, phone):

	if phone:
		key = otp_generator()
		phone = str(phone)
		otp_key = str(key)
		account_sid = "ACda91193706211de6d43849548a2d3293"
		auth_token  = "b7c61e721d747dfdb6d08d21c7c87916"
		client = Client(account_sid, auth_token)
		try:
			message = client.messages.create(
					to='+'+str(country_code)+str(phone), 
					from_="+12053080842",
					body= otp_key)
			return otp_key
		except Exception as e:
			return False