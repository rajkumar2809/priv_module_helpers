# -*- coding: utf-8 -*-

import os, sys
import json, re, glob
import logging

dirpath = os.path.dirname( os.path.abspath(__file__) )+"/"
apppath = dirpath+"../../"

logger = logging.getLogger()

from priv_module_helpers.splunk_helpers import splunk_searcher as _splunk
from priv_module_helpers.splunk_helpers import splunk_post_helper as _splunk_post
from priv_module_helpers.cbapi_helpers import cb_api_helper as _api

def get_api_customers():
	return _api.get_customers()

import base

class CbdefenseIocSearcher(base.IocSearcher):
	_PRODUCT = "cbdefense"

	def check_ioc(self, iocs):
		logger.info("targe customer:{}".format(self.customer_name))
		api = _api.init_by_cfg_file(self.customer_name)
		results = []
		for each_type in [ "sha256" ]:
			for each_value in iocs[each_type]:
				logger.info("check IOC by {}:{}".format(each_type, each_value))
				_raw = api.get_events(hash_sha256=each_value, search_window="2w")
				devices = []
				for each in _raw:
					each_dev = each["device"]
					hostname = each_dev["deviceName"]
					if not hostname in devices:
						devices.append(hostname)
				message = "undetected" if len(devices) is 0 else "detected on {} device".format(len(device))
				each_result = { "type"    : each_type,
								"value"   : each_value,
								"devices" : devices,
								"product" : self._PRODUCT,
								"message" : message,
								"customer_name" : self.customer_name }
				self._post_to_splunk(each_result)
				results.append( each_result )
		return results

	# private

def __main__():
	logging.basicConfig(level=logging.DEBUG)

if __name__ == '__main__':
	__main__()

