# -*- coding: utf-8 -*-

import os, sys
import json, re, glob
import logging

dirpath = os.path.dirname( os.path.abspath(__file__) )+"/"
apppath = dirpath+"../../"

logger = logging.getLogger()

from priv_module_helpers.splunk_helpers import splunk_searcher as _splunk
from priv_module_helpers.splunk_helpers import splunk_post_helper as _splunk_post
from priv_module_helpers.csapi_helpers import cs_api_helper as _api

def get_api_customers():
	return _api.get_customers()

import base

class CrowdstrikeIocSearcher(base.IocSearcher):
	_PRODUCT = "crowdstrike"

	def check_ioc(self, iocs):
		logger.info("targe customer:{}".format(self.customer_name))
		api = _api.CSApiHelper(self.customer_name)
		results = []
		for each_type in [ "sha256", "domain", "ip" ]:
			for each_value in iocs[each_type]:
				ioc_type = each_type+"v4" if each_type=="ip" else each_type
				logger.info("check IOC by {}:{}".format(ioc_type, each_value))
				devices = api.search_devices_by_ioc(ioc_type, each_value)
				message = "undetected" if len(devices) is 0 else "detected on {} device".format(len(device))
				each_result = { "type"    : ioc_type,
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

