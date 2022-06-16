# -*- encoding:utf-8

import sys, os, json
import unittest

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )

PJ_TOP = CURR_DIR+"/../../../risk_checker/cbdefense"
sys.path.append(PJ_TOP)

from monkey_tools.mymocks.mymodule import mock_get_threat_info as intel
from monkey_tools.mymocks.mymodule import mock_rm_helpers as rm_util
from monkey_tools.mymocks.mymodule.mock_splunk_post_helper import SplunkLogSender
from priv_module_helpers.splunk_helpers import splunk_alert_searcher as _splunk
_splunk._CONF = "test.json"
intel.set_data_dir(CURR_DIR+"/searchdata")

import main as target
import cfg_util

_USE_MOCK = False

if _USE_MOCK:
	target.intel = intel

target.SplunkLogSender = SplunkLogSender
target.rm_helper.rm_util = rm_util
target.logger_util.init_conf(cfg_util.get_log_conf())

_CONF_PATH = CURR_DIR+"/config"
_CONF = _CONF_PATH+"/config.json"
cfg_util._GEN_CONF = _CONF
cfg_util.CURR_DIR = CURR_DIR

class TestFpCheckerMainModule(unittest.TestCase):
	"""test class of main.py in fp_checker
	"""

	def setUp(self):
		pass

	def tearDown(self):
		pass

	def test_main(self):
		target.main()

if __name__ =="__main__":
	unittest.main()

