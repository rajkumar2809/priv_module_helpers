# -*- coding: utf-8 -*-

import sys, os, json, time
import unittest

PJ_TOP = os.path.dirname( os.path.abspath(__file__) )+"/../../"
sys.path.append(PJ_TOP)

from priv_module_helpers.hxapi_helpers import hx_api_helper as target

class TestApi(object):
	def __init__(self, appliance, username, password):
		self.appliance = appliance
		self.username = username
		self.password = password

	def get_hostsets(self):
		pass

USE_MOCK = False

if USE_MOCK:
	target.api.FireeyeHxApi = TestApi

class TestModule(unittest.TestCase):
	"""test class of main.py hx_api_helper 
	"""

	def setUp(self):
		pass

	def tearDown(self):
		pass

	def test_hostset(self):
		host = "hx09"
		res = target.get_hostset("DGH2", host, with_case=True)
		print "{} -> {}".format(host, res)
		host = "HX09"
		res = target.get_hostset("DGH2", host, with_case=True)
		print "{} -> {}".format(host, res)

	def test_epsearch(self):
		_id = self._test_add_epsearch()
		print _id
		time.sleep(5)
		res = self._test_get_epsearch(_id)
		print json.dumps(res, indent=4)
		time.sleep(5)
		flag = self._test_delete_epsearch(_id)
		print flag

	def _test_get_epsearch(self, _id):
		res = get_result_enterprise_search("DGH2", _id)
		return res

	def _test_delete_epsearch(self, _id):
		flag = delete_enterprise_search("DGH2", _id)
		return flag

	def _test_add_epsearch(self):
		values = [
				"ed5f36137d09e1cfc0ccf2675fb5d460e7eed135ba36d3259d2c510592047f25",
				"ed5f36137d09e1cfc0ccf2675fb5d460e7eed135ba36d3259d2c510592047f26",
				"ed5f36137d09e1cfc0ccf2675fb5d460e7eed135ba36d3259d2c510592047f27",
				"ed5f36137d09e1cfc0ccf2675fb5d460e7eed135ba36d3259d2c510592047f28",
				"ed5f36137d09e1cfc0ccf2675fb5d460e7eed135ba36d3259d2c510592047f29",
				"ed5f36137d09e1cfc0ccf2675fb5d460e7eed135ba36d3259d2c510592047f2a"
		]
		queries = make_queries_by_sha256(values)
		res = set_new_enterprise_search("DGH2", queries)
		return res

if __name__ =="__main__":
	unittest.main()

