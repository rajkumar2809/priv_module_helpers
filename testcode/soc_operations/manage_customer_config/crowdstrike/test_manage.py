# -*- encoding:utf-8

import sys, os, json
import unittest
import logging



CURR_DIR = os.path.dirname( os.path.abspath(__file__) )

PJ_TOP = CURR_DIR+"/../../../../soc_operations/manage_customer_config/crowdstrike"
sys.path.append(PJ_TOP)

import manage as target

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
streamHandler = logging.StreamHandler()
streamHandler.setFormatter(formatter)
logger.addHandler(streamHandler)
target.logger = logger

_RET_VAULE = None

def _diff_csapi(api_type, work_dir, config):
	return _RET_VALUE

class TestMgrCustomerConfig(unittest.TestCase):
	"""test class of manage.py in manage_customer_config of crowdstrike
	"""

	def setUp(self):
		pass

	def tearDown(self):
		pass

	def test_for_csapi(self):
		target.procedure_for_csapi("falcon.crowdstrike.com", "falcon_dhsoc", "DGH1", "oauthID", "oauthPassword", "ThreatGraphID", "ThreatGraphPassword")
		target.procedure_for_csapi("falcon.us-2.crowdstrike.com", "falcon_dhsoc", "DGH1", "oauthID", "oauthPassword", "ThreatGraphID", "ThreatGraphPassword")

	def test_check_api_add_csapi(self):
		origin = target._diff_csapi
		target._diff_csapi = _diff_csapi
		global _RET_VALUE

		_RET_VALUE = {
				"add" : [ { "customer_name" : "DGH1" } ], "del" : []
		}
		result = target._check_api_add("oauth", "DGH1", "falcon_dhsoc", {}, "")
		print result

		_RET_VALUE = {
				"add" : [ { "customer_name" : "XXX1" } ], "del" : []
		}
		result = target._check_api_add("oauth", "DGH1", "falcon_dhsoc", {}, "")
		print result
		target._diff_csapi = origin

if __name__ =="__main__":
	unittest.main()

