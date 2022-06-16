# -*- coding: utf-8 -*-

import os, sys
import json, re, glob
import logging

dirpath = os.path.dirname( os.path.abspath(__file__) )+"/"
apppath = dirpath+"../../"

logger = logging.getLogger()

from priv_module_helpers.splunk_helpers import splunk_searcher as _splunk
from priv_module_helpers.splunk_helpers import splunk_post_helper as _splunk_post
from priv_module_helpers.hxapi_helpers import hx_api_helper as _hxapi

_MAX_SEARCH = 4

class IocSearcher(object):
	_PRODUCT = None
	_DATA_TYPE = "ioc_search"

	def __init__(self, customer_name, splunk_server, cfg, max_num=_MAX_SEARCH):
		self.splunk_server = splunk_server
		self.splunk = _splunk.MySearcher
		self.config = cfg["splunk"]["post"]
		self.max_num = max_num
		self.customer_name = customer_name
		if "." in splunk_server:
			cfg_name = splunk_server.split(".")[0]
		else:
			cfg_name = splunk_server
		self.splunk.init_splunk_by_cfg_file(cfg_name)
		self.post_server = _splunk_post.SplunkLogSender.init_splunk_by_cfg_file(
				cfg_name, by_local=False)
		self.index = self.config["index"]
		self.source_type = self.config["source_type"]
		self.source = self._PRODUCT
		self.post_server.init_params(self._DATA_TYPE,
				self.index, self.source, self.source_type)

	def check_ioc(self, iocs):
		assert False, "You must overload this function"

	# private

	def _post_to_splunk(self, _raw):
		assert self.source, "source(or product) is not set"
		logger.info("post search log to splunk.")
		post_data = json.dumps(_raw)
		self.post_server.post_data(self._DATA_TYPE, post_data)

