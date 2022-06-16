# -*- encoding:utf-8

import os, sys
import json
import argparse
from logging import getLogger

from monkey_tools.utils import file_util
from monkey_tools.utils import time_util

from priv_module_helpers.cyfirma_helpers import main as _cyfirma
from priv_module_helpers.splunk_helpers.splunk_post_helper import SplunkLogSender

CURR_DIR  = os.path.dirname( os.path.abspath(__file__) )
CONF_DIR  = CURR_DIR+"/config"
CONF_FILE = CONF_DIR+"/config.json"

logger = getLogger("cyfirma_sync")

class CyfirmaSync(object):

	def __init__(self, by_local=True):
		with open(CONF_FILE) as f:
			cfg = json.load(f)
		self.index = cfg["index"]
		self.source = cfg["source"]
		self.splunk_name = cfg["splunk_name"]
		self.by_local = by_local
		self.splunk = SplunkLogSender.init_splunk_by_cfg_file(
				self.splunk_name, by_local=self.by_local)
		self.splunk.init_params( self.source,
				index=self.index, source=self.source)

	def sync2splunk(self, by_diff=True, by_all=True):
		iocs = get_ioc(by_diff, by_all)
		for each in iocs:
			post2splunk(each)

	def get_ioc(self, by_diff=True, by_all=True):
		result =  _cyfirma.get_ioc_by_json(by_diff=by_diff, by_all=by_all)
		return result
	
	def post2splunk(self, ioc):
		data = json.dumps(ioc)
		self.splunk.post_data(self.source, data)

