# -*- encoding:utf-8

import sys, os, json, glob
import unittest

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )

PJ_TOP = CURR_DIR+"/../../../soc_operations/auto_response"
sys.path.append(PJ_TOP)

from monkey_tools.mymocks.mymodule import mock_rm_helpers as rm_util
from connectors.micky_app_api import micky_api_ex as _api_orig

import bin.auto_response as target

_USE_MOCK = True

class mock_argparse(object):
	_CSV_GZ = None
	_PRODUCT = None
	class ArgumentParser(object):
		def __init__(self, description=None):
			self.description = description
			self.args = {}
			self.api_type = mock_argparse._PRODUCT
			self.alerts_csv_gz = mock_argparse._CSV_GZ

		def add_argument(self, name, **kwargs):
			self.args[name] = kwargs

		def parse_args(self):
			return self

class mock_mickyapp_api(object):
	_RESULT_URL = None
	_RESULT_PAGE = ""
	class MickyAppAPI(object):
		def __init__(self, customer_name, splunk_name, api_type):
			self.customer_name = customer_name
			self.host = splunk_name
			self.api_type = api_type
			self.api = _api_orig.MickyAppAPI(customer_name, splunk_name, api_type)
			self.uri = self.api.uri

		def autorun(self, wait_time=None, **kwargs):
			self.wait_time = wait_time
			self.autorun_kwargs = kwargs

		def autorun_with_qstring(self, qstr, with_close=True, wait_time=0):
			mock_mickyapp_api._RESULT_URL = 'https://{}{}?{}'.format(self.host, self.uri, qstr)
			return mock_mickyapp_api._RESULT_PAGE

class mock_selenium_webdriver(object):
	class Chrome(object):
		def __init__(self, *args, **kwargs):
			self.args = args
			self.kwargs = kwargs
		
		def set_page_load_timeout(self, sec):
			self.timeout_sec = sec

if _USE_MOCK:
	target.argparse = mock_argparse
	target._api = mock_mickyapp_api
	_api_orig.webdriver = mock_selenium_webdriver

_CONF_PATH = CURR_DIR+"/config"
_GEN_CONF = _CONF_PATH+"/config.json"
_LOG_CONF = _CONF_PATH+"/auto_response.conf"
_RM_CONF  = _CONF_PATH+"/redmine.json"

target.logger_util.init_conf(_LOG_CONF)
target.logger = target.logger_util.get_standard_logger("auto run tier1 app")

target.RM_FILE = _RM_CONF

class TestModule(unittest.TestCase):
	"""test class of auto_response.py in bin of auto_response
	"""

	def setUp(self):
		self.csv_gz_list = glob.glob(CURR_DIR+"/testdata/use/*.csv.gz")
		print self.csv_gz_list

	def tearDown(self):
		pass

	def test_main(self):
		mock_argparse._CSV_GZ = self.csv_gz_list[0]
		mock_argparse._PRODUCT = "cbdefense"
		target.main()

if __name__ =="__main__":
	unittest.main()

