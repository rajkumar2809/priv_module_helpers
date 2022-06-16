# -*- encoding:utf-8 -*-

import sys, os, json
import random
import unittest

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/../../"
sys.path.append(PJ_TOP)

from splunk_helpers import splunk_searcher as target
from mocks import mock_splunk_search_util as sp_util

target.SplunkSearcher = sp_util.SplunkSearcher
conf_name = PJ_TOP+"splunk_helpers/config/splunk.json"

with open(conf_name, "r") as f:
	cfg = json.load(f)

class TestSplunkSearcherClass(unittest.TestCase):
	"""test class of splunk_searcher.py
	"""
	v, p, u, r = "testvalue", "product", "user", "type"

	def setUp(self):
		pass

	def tearDown(self):
		pass

	def test_is_init(self):
		cls = target.MySearcher
		cls.splunk_searcher = None
		self.assertFalse(cls.is_init())
		cls.init_splunk(**cfg)
		self.assertTrue(cls.is_init())

	def test_init_splunk(self):
		cls = target.MySearcher
		cls.init_splunk(**cfg)
		self.assertIsInstance(cls.splunk_searcher, sp_util.SplunkSearcher)
		self.assertTrue(cls.is_init())

	def test_init_splunk_by_cfg_file(self):
		cls = target.MySearcher
		cls.init_splunk_by_cfg_file("splunk-production00")
		cls.init_splunk_by_cfg_file("splunk-production01")
		cls.init_splunk_by_cfg_file("splunk-production02")
		cls.init_splunk_by_cfg_file("splunk")
		self.assertTrue(cls.is_init())


if __name__ =="__main__":
	unittest.main()

