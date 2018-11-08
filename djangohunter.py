#!/usr/bin/env python3

# -*- coding: utf-8 -*-
import sys

try:

	import shodan
	import requests
	import argparse
	from bs4 import BeautifulSoup

	from pyfiglet import Figlet

except ImportError as e:
    print("Error: %s \n" % (e))
    print("Try this ... pip install -r /path/to/requirements.txt")

class Picker :

	def __init__(self) :

		self.endc = '\033['
		self.end  ="\033[0m"

		self.green = '92m'
		self.fail = '91m'
		self.yellow = '93m'
		self.purple = '37m'
		self.blue = '96m'

		self.normal = '0'
		self.bold = ''
		self.underline = '2'

	def color(self, text, options) :

		# \033[1;32;40m

		if options:
			for color in options :
				return "{}{}{}{}".format(self.endc, color, text, self.end)

	def status (self, text) :
		return self.color(text, [self.green])
	def error (self, text) :
		return self.color(text, [self.fail])
	def yellows (self, text) :
		return self.color(text, [self.yellow])
	def purple (self, text) :
		return self.color(text, [self.purple])
	def blues (self, text) :
		return self.color(text, [self.blue])

class Shodan() :
  
	def __init__(self, key, limit=999, offset=None, timeout=5) :

		self.key = shodan.Shodan(key)
		self.limit = limit
		self.offset = offset
		self.timeout = timeout
		self.color = Picker()

	def django(self, query):

		counter = 0;
		mapping = (
			'DB_HOST', 
			'MYSQL',
			'RDS_HOSTNAME', 
			'ADMIN_USER', 
			'RABBITMQ_HOST', 
			'WALLET_RW_HOST', 
			'POSTGRES_PASSWORD', 
			'KYC_API_KEY', 
			'DATABASE_URL',
			'AUTO_RECRAW_HOST',
			'BONANZA_API_KEY',
			'CELERY',
			'MWS_ACCESS_KEY',
			'PROXY_SECRET',
			'KEEPA_API',
			'MONGODB_PASSWORD',
			'SCRAPYMONGO_PASSWORD',
			'FACE_ID_DB_PASSWORD',
			'AWS_SECRET_ACCESS_KEY',
			'GOOGLE_OAUTH2_CLIENT_SECRET',
			'POSTGRES_PASSWORD',
			'DJANGO_SECRET_KEY',
			'FIREBASE_SERVER_KEY',
			'GOOGLE_API_KEY',
			'SSH_PASSWORD',
			'SSH_AUTH',
			'RABBITMQ_DEFAULT_PASS',
			'AWS_SECRET_KEY',
			'AWS_S3_BUCKET',
			'EMAIL_HOST_PASSWORD',
			'SENDGRID_PASSWORD',
			'PAYU_KEY',
			'DHL_API_CLIENT_SECRET',
			'LIGHT_PASSWORD',
			'DB_PASSWORD',
			'ATEL_AUTH_SECRET'
		) # Interesting keywords ('DisallowedHost at /', 'DisallowedHost', 'KeyError', 'OperationalError', 'Page not found at /', '')

		try:

			results = self.key.search(query)
			matches = results['matches']
			total = results['total']

			print('{} Shodan found {} hosts with debug mode enabled'.format(self.color.status("[+]"), total))
			print("{} Looking for secret keys wait a moment ..\n".format(self.color.yellows("[!]")))

			

			for match in matches:
				# Perform some custom manipulations or stream the results to a database
				# For this example, I'll just print out the "data" property

				ipadress = match.get('ip_str')
				port = match.get('port')
				org = match.get('org')
				hostnames = match.get('hostnames')
				domains = match.get('domains')
				city = match['location'].get('city')
				country = match['location'].get('country_name')

				# 443
				if port == 443 :
					continue

	 			# Retrieving HTML data
				try:
					
					request = requests.get('http://{}:{}'.format(ipadress, port), timeout=self.timeout)
					
					# Beautiful Soup to parser the content
					html = BeautifulSoup(request.text, 'html.parser')

					keys = []

					for key in mapping:
						if key in html.prettify():
							keys.append(key)
				except requests.exceptions.RequestException as error:
					continue

				if len(keys) != 0:

					keys = ', '.join(str(key) for key in keys) # Keywords found
					hostnames = ', '.join(str(hostname) for hostname in hostnames)
					domains = ', '.join(str(domain) for domain in domains)

					print("[+] Possible exposed credentials on {}".format(request.url))
					print('[+] Secret keys found {}\n'.format(self.color.error(keys)))

					# some information about the host
					print("\tOrganization: {}\n\tHostnames: {}\n\tDomains: {}\n\tCity: {}\n\tCountry: {}\n".format(org, hostnames, domains, city, country))

				# Keep track of how many results have been downloaded so we don't use up all our query credits
				counter += 1
				if counter >= self.limit:
					break
		except shodan.APIError as error:
			print("error: {}".format(error))

if __name__ == '__main__':

	graph = Figlet(font='slant').renderText('djangoHunter')
	print(graph)

	print("""
  Tool designed to help identify incorrectly configured 
  Django applications that are exposing sensitive information.\n
""")

	parser = argparse.ArgumentParser(description='Django Hunter', usage=None)
	parser.add_argument('--dork', '-s', required=False, metavar='dork', default='title:"DisallowedHost"', help='Search for dork shodan i.e DisallowedHost at /')
	parser.add_argument('--key', '-k', required=True, metavar='API key', help='Shodan API key')
	parser.add_argument( '--limit','-l', type=int, default=999, required=False, metavar='limit', help='Limit results returned by shodan')
	parser.add_argument( '--timeout','-t', type=float, required=False, default=5, metavar='timeout', help='Timeout default: 5')
	args = parser.parse_args()

	if len(sys.argv) <= 2:
		parser.print_help()

	Shodan(args.key, limit=args.limit, timeout=args.timeout).django(args.dork)