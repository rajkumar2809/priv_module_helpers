# -*- encoding:utf-8

import os, sys
import json, time, logging
from monkey_tools.utils import rest_util as rest
from monkey_tools.utils import time_util as _time

from connectors.sophos_api import xdr_api

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
CONF_DIR = CURR_DIR+"/config"
CFG_FILE = CONF_DIR+"/config.json"
QUERY_DIR = CURR_DIR+"/query"

logger = logging.getLogger("xdr_api_helper")

class SophosXdrAPIHelper(object):
	DEFALUT_QUERY = {
			"INDICATOR" : "indicator.txt"
	}

	def __init__(self, customer_name):
		self.customer_name = customer_name
		with open(CFG_FILE) as f:
			self.config = json.load(f)
		client_id, secret = self._get_credentials()
		self.api = xdr_api.SophosXdrAPI(client_id, secret)

	def search_indicator(self, diff=600):
		query = self._get_query(self.DEFALUT_QUERY["INDICATOR"])
		now = _time.get_unix()
		prev_time = _time.get_time_from_unix(now-diff, _time.UNIX)
		query = query.format(prev_time)
		logger.debug("query is {}".format(query))
		return self.search(query)

	def search(self, query):
		result = self.api.run_query(query)
		return result

	def quarantine(self, ids, enabled=True, comments=None):
		try:
			result = self.api.quarantine(ids, enabled, comments)
			return True
		except Exception as e:
			logger.exception(e)
			return False

	# private

	def _get_credentials(self):
		creds = self.config["credentials"][self.customer_name]
		return creds["client_id"], creds["client_secret"]

	def _get_query(self, query_fname):
		data = ""
		with open("{}/{}".format(QUERY_DIR, query_fname)) as f:
			data = f.read()
		return data

def __test__quarantine():
	customer_name= 'DGH1'
	#device_id = "735eda5d-01fc-45b5-9eb1-89b1babc4a16"
	device_id = "c1933c37-ee1f-e4bc-28ec-b6af825bb2b7"
	api = SophosXdrAPIHelper(customer_name)
	print api.quarantine(device_id)

def __test__query():
	customer_name= 'DGH1'
	api = SophosXdrAPIHelper(customer_name)
	print api.search_indicator()

if __name__ == '__main__':
	_format="%(asctime)s [%(filename)s:%(lineno)d] %(levelname)-8s %(message)s"
	logging.basicConfig(level=logging.DEBUG, format=_format)
	__test__query()

