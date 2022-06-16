# -*- coding: utf-8 -*-

import os, sys
import json, logging, time

import cfg_mgr

from connectors.crowdstrike_api import oauth_api as csapi
from connectors.crowdstrike_api import threat_graph_api as tgapi
from monkey_tools.utils import time_util

_CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
_CONF_DIR = _CURR_DIR + "/config"
_TOKEN_DIR  = _CURR_DIR+"/token"

logger = logging.getLogger()

def dec_api_access(func):
	def _cs_api(self, *args):
		for i in range(0, 3):
			try:
				if self._is_expired():
					self._refresh_token()
				return func(self, *args)
			except IOError as e:
				if hasattr(e, "getcode") and e.getcode() == 404:
					raise e
				time.sleep(2)
				token = self._get_existing_token()
				if token["expire"] == self.expired:
					self._refresh_token()
				else:
					self._set_token(token)
		raise e
	return _cs_api

class CSOAuthApiHelperBase(object):
	_API_TYPE_KEY_ = None
	#_CONFIG_FILE = _CONF_DIR + "/oauth.json"

	def __init__(self, customer_name):
		self.customer_name = customer_name
		self.token_dir = _TOKEN_DIR+"/"+self.customer_name
		if not os.path.exists(self.token_dir):
			try:
				os.mkdir(self.token_dir)
				os.chmod(self.token_dir, 0777)
			except OSError as e:
				logger.warning("cannot make directory msg:{}".format(e.message))
		self.client_id, self.secret = self._get_credential(customer_name)
		self.api_host = self._get_api_host(customer_name)
		self.api = csapi.CSApi(
				customer_name, self.client_id, self.secret, host=self.api_host)
		self.token_file = "{}/{}.json".format(self.token_dir, self._API_TYPE_KEY_)
		if os.path.exists(self.token_file):
			token = self._get_existing_token()
			self._set_token(token)
		else:
			self._refresh_token()
	
	# private

	def _refresh_token(self):
		token = self._get_new_token()
		self._set_token(token)

	def _set_token(self, token):
		if isinstance(token, basestring):
			token = json.loads(token)
		if "token" in token:
			json_token = json.dumps(token["token"])
			self.expired = token["expire"]
		else:
			json_token = json.dumps(token)
		self.api.set_token(json_token)

	def _get_new_token(self):
		token = self.api.get_new_token()
		self._store_new_token(token)
		return token

	def _store_new_token(self, token):
		with open(self.token_file, "w") as wf:
			json.dump(token, wf, indent=4)
		try:
			os.chmod(self.token_file, 0666)
		except OSError as e:
			pass

	def _get_existing_token(self):
		with open(self.token_file) as f:
			token = json.load(f)
		return token

	def _is_expired(self, buf=1):
		now = time_util.get_unix()+buf
		return now>self.expired

	def _get_credential(self, customer_name):
		creds = self._get_config(customer_name)
		return creds["client_id"], creds["secret"]

	def _get_api_host(self, customer_name):
		cfg = cfg_mgr.get_oauth_conf()
		if customer_name in cfg:
			return cfg[customer_name].get("host")
		else:
			raise ValueError("has no config for {}".format(customer_name))

	def _get_config(self, customer_name):
		cfg = cfg_mgr.get_oauth_conf()
		if customer_name in cfg:
			return cfg[customer_name][self._API_TYPE_KEY_]
		else:
			raise ValueError("has no config for {}".format(customer_name))

