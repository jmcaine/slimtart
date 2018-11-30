
from slimta.relay.smtp.mx import MxSmtpRelay
from slimta.policy.split import RecipientDomainSplit
from slimta.edge.smtp import SmtpEdge, SmtpValidators
from slimta.relay.pipe import DovecotLdaRelay
#from slimta.queue.dict import DictStorage
from slimta.queue import Queue, QueueError
from slimta.policy import QueuePolicy
from slimta.policy.headers import *
from slimta.policy.spamassassin import SpamAssassin
from slimta.util import system

from slimta.diskstorage import DiskStorage

from ssl import SSLContext, PROTOCOL_SSLv23
from pysasl import AuthenticationCredentials
from email.parser import BytesHeaderParser

import copy
import shelve
import gevent
import logging
import smtplib
import json
import urllib.request

import configparser

config = configparser.ConfigParser()
logging.basicConfig(level=logging.DEBUG)

#--------------------------------------
class MTA:
	def kill(self):
		self.edge.kill()
		self.queue.kill()


#--------------------------------------
""" right now, we just only open port 587 to internal network; any internal sender is welcome to use the MSA.  In the future, the following could be used to authenticate a sender....
WE NEED THIS!!! Need to support using mail clients (e.g., on pastors' phones) to check and send ecc email?!!!

class MSA_Validators(SmtpValidators):
	def handle_auth(self, reply, credentials):
		# 'credentials' is a pysasl.AuthenticationCredentials object
		if credentials.authcid == 'jmcaine2': #!!!! Temporaray handler!
			print('!!!!! ', credentials.secret)
			if credentials.check_secret('password'):
				return
		# if no successes:
		reply.code = '421'
		reply.message = '5.7.1 <{0}> Invalid login'

	def handle_mail(self, reply, sender, params):
		if not self.session.auth:
			reply.code = '550'
			reply.message = '5.7.1 <{0}> Not authenticated'
"""


#--------------------------------------
class MSA(MTA):

	def __init__(self):

		# Relay:
		ssl = SSLContext(PROTOCOL_SSLv23)
		ssl.load_cert_chain(config['SSL']['certificate_path'], config['SSL']['key_path'])
		self.relay = MxSmtpRelay(context=ssl, connect_timeout=20, command_timeout=10, data_timeout=20, idle_timeout=30)

		# Queue:
		#env_db = shelve.open('msa_envelope')
		#meta_db = shelve.open('msa_meta')
		#storage = DictStorage(env_db, meta_db) # !!! replace with DiskStorage!  (installed via pip install python-slimta-diskstorage)
		storage = DiskStorage(config['MSA']['ds_env'], config['MSA']['ds_meta'])

		def retry_backoff(envelope, attempts):
			if attempts < 10:
				return 60 * attempts * attempts # try again at increasingly long intervals; give up after 10 tries (100 minutes)
			return None

		self.queue = Queue(storage, self.relay, backoff = retry_backoff)
		self.queue.start()

		# Headers:
		self.queue.add_policy(AddDateHeader())
		self.queue.add_policy(AddMessageIdHeader())
		self.queue.add_policy(AddReceivedHeader())
		self.queue.add_policy(RecipientDomainSplit())
		# !!! Add Forward policy here, to manage general forwarding (but not list distribution - do that in mda!)


		# Edge:
		self.edge = SmtpEdge(('localhost', 587), self.queue, auth=False) #, auth=True, validator_class=MSA_Validators) # ?!!! context=ssl, tls_immediately=True,
		self.edge.start()


#--------------------------------------

# Mailing-list:
class MailingListDistribution(QueuePolicy):
	def __init__(self, msa, mail_list_url, mda_domain, subject_prefix = None):
		super()
		self.msa = msa
		self.mail_list_url = mail_list_url
		self.mda_domain = mda_domain
		self.subject_prefix = subject_prefix


	def apply(self, envelope):
		log = logging.getLogger('mailing-list')
		log.debug('MailingListDistribution original envelope.recipients: %s', envelope.recipients)

		local_recipients = set(envelope.recipients) # default, "original"
		external_recipients = set()
		try:
			data = json.dumps({'addresses': envelope.recipients, 'sender': envelope.sender, 'domain': self.mda_domain}).encode('utf8')
			req = urllib.request.Request(self.mail_list_url, data, {'content-type': 'application/json'})
			response = urllib.request.urlopen(req)
			result = json.loads(response.read().decode('utf8'))
			#log.debug('MailingListDistribution list recipients: %s', result['list_recipients'])
			# Distribute to list recipients:
			local_recipients = set(result['original_recipients'])
			if result['list_recipients']:
				local_recipients.add('lists@' + self.mda_domain)
				for recipient in result['list_recipients']:
					localpart, domain = recipient.rsplit('@', 1)
					if domain.lower() != self.mda_domain.lower():
						external_recipients.add(recipient)
					else:
						local_recipients.add(recipient)
			# Distribute to auto-aliases:
			for local_address, original_address in result['aliases'].items():
				external_recipients.add(original_address) # Assumes all original_addresses are 'external' (they originally came from another domain, not our own; thus the reason for the alias in the first place)
			# set envelope.recipients to (possibly) new local_recipients:
			envelope.recipients = list(local_recipients)
			log.debug('MailingListDistribution final envelope.recipients: %s', envelope.recipients)
			# Queue stack will continue processing these envelope.recipients, delivering them to their final destination.

		except:
			log.exception('Unable to fetch mailing-list recipients!')
			# And just move on with original recipient list.  Group pseudo-addresses will bounce, so sender will know something is up!

		if external_recipients:
			cpy = envelope.copy(list(external_recipients))
			headers = cpy.headers
			# Set 'sender' to the alias provided in 'result' (in order to avoid suspicion of relayed emails (me@x.com -> y.com -> destination))
			cpy.sender = result['sender'] # altered ("localized") sender
			del headers['from'] # MUST delete, first - cannot 'over-write', by design (of python email.message)
			headers['from'] = result['sender']

			# Modify the subject with a prefix if provided:
			subject = headers['subject']
			if self.subject_prefix and not subject.startswith('Re:'):
				del headers['subject'] # MUST delete, first, by (python email.message) design
				headers['subject'] = self.subject_prefix + ' ' + subject

			# Hand off the message!
			for envelope, result in self.msa.edge.handoff(cpy):
				if isinstance(result, QueueError):
					log.error(result)
				else:
					log.debug('Handed message %s off to MSA' % result)


# Validators:
class MDA_Validators(SmtpValidators):
	def handle_rcpt(self, reply, recipient, params):
		try:
			localpart, domain = recipient.rsplit('@', 1)
		except ValueError:
			reply.code = '550'
			reply.message = '5.7.1 <{0}> Not a valid email address format'
			return
		if domain.lower() != _mda_domain.lower():
			reply.code = '550'
			reply.message = '5.7.1 <{0}> Not a domain for which we accept email'
			return


#--------------------------------------
class MDA(MTA):

	def __init__(self, msa, mail_list_url, mda_domain, list_subject_prefix = None):

		self.msa = msa

		# Relay:
		relay = DovecotLdaRelay(config['LDA']['dovecot_path'], timeout=10.0)

		# Queue:
		#env_db = shelve.open('envelope')
		#meta_db = shelve.open('meta')
		#storage = DictStorage(env_db, meta_db) # !!! replace with DiskStorage!  (installed via pip install python-slimta-diskstorage)
		storage = DiskStorage(config['MDA']['ds_env'], config['MDA']['ds_meta'])

		self.queue = Queue(storage, relay) # no backoff - just fail local delivery immediately
		self.queue.start()

		# Headers:
		self.queue.add_policy(AddDateHeader())
		self.queue.add_policy(AddMessageIdHeader())
		self.queue.add_policy(AddReceivedHeader())
		# Mailing List:
		self.queue.add_policy(MailingListDistribution(self.msa, mail_list_url, mda_domain, list_subject_prefix))
		# SpamAssassin:
		#self.queue.add_policy(SpamAssassin())

		# Edge:
		#tls_args = {'keyfile': '/home/jmcaine/dev/temp/slimta/tls/key.pem', 'certfile': '/home/jmcaine/dev/temp/slimta/tls/certificate.pem'} -- gone, see https://docs.slimta.org/en/latest/blog/2016-11-14.html
		ssl = SSLContext(PROTOCOL_SSLv23)
		ssl.load_cert_chain(config['SSL']['certificate_path'], config['SSL']['key_path'])
		self.edge = SmtpEdge(('0.0.0.0', 25), self.queue, validator_class = MDA_Validators, hostname = mda_domain, context = ssl)
		self.edge.start()


#--------------------------------------
# Other: DKIM?  SPF? !!!!


if __name__ == "__main__":
	import argparse

	k_default_config_path = '/etc/slimtart/slimtart.conf'
	
	parser = argparse.ArgumentParser()
	parser.add_argument('-c', '--config', help = 'path to config file; default is %s' % k_default_config_path, default = k_default_config_path)
	args = parser.parse_args()

	config.read(args.config)

	# Run:
	try:
		
		_mda_domain = config['MDA']['domain'] # I wish I didn't have to have this global, but I see no other way to get mda_domain into the SMTP_Validators subclass: MDA_Validators

		msa = MSA()
		mda = MDA(msa, config['MDA']['mail_list_url'], config['MDA']['domain'], config['MDA']['mail_list_subject_prefix'])

		# System:
		gevent.sleep(0.5) # sometimes gevent will not have opened the ports by the time you drop privileges and then it will fail, so calling a short sleep will make sure everything is ready.
		system.drop_privileges('vmail', 'vmail') # see "Note 1" below!
		#system.redirect_stdio()  # Redirects all streams to /dev/null by default.

		# daemonize after debugging:
		#system.daemonize() # NO!: we're managing the edges via joinall() below!

		gevent.joinall((msa.edge, mda.edge))
	except KeyboardInterrupt:
		msa.kill()
		mda.kill()
		pass

"""
Note 1:
In dovecot, we made a special user vmail, as suggested/best-practice, for dovecot-lda mail delivery.  But note, this
must also be the user slimta downgrades to when running as MDA.  It's not good enough to set file group permissions that seem sufficient
(e.g., by putting a slimta downgrade user and the vmail user both in an "mta" group, or whatever) - the socket dovecot creates is owned
by user/group specified in "service auth { unix_listener auth-userdb {" in /etc/dovecot/conf.d/10-master.conf, and you can specify the
group parameter that dovecot uses to open the userdb socket in "userdb {" (e.g., with "args = uid=vmail gid=mta home=/home/vmail/%n" (notice
the gid=mta), but you'll then get an error that says:

	lda(tester@blah.org): Fatal: setuid(5000(vmail) from userdb lookup) failed with euid=121(slimta): Operation not permitted (This binary should probably be called with process user set to 5000(vmail) instead of 121(slimta))

You don't get that if you don't set up the groups as above, so the group setup *does* seem to have an effect, but not the ultimate effect you might want.

Bottom line: I demote the slimta user to 'vmail' so that it matches.


"""
