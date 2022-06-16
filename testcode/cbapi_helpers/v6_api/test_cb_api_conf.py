import sys, os, json
from glob import glob
from copy import deepcopy
from datetime import datetime
import json
import unittest

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/../../.."
sys.path.append(PJ_TOP)

from priv_module_helpers.cbapi_helpers.v6_api import cb_api_conf as target

class TestDomainValidatorModule(unittest.TestCase):
	"""test class of validate_domain.py
	"""

	def setUp(self):
		target.CONF_PATH = CURR_DIR+"/config/"
		target.CONF_NAME = "test.json"

	def tearDown(self):
		pass

	def test_get_conf(self):
		cfg1 = target.get_conf("dhsoc")
		self.assertIsNotNone(cfg1)
		cfg2 = target.get_conf("DGH1")
		self.assertIsNotNone(cfg2)
		self.assertEqual(cfg1, cfg2)
		cfg1 = target.get_conf("digitalhearts")
		self.assertIsNotNone(cfg1)
		cfg2 = target.get_conf("DGH2")
		self.assertIsNotNone(cfg2)
		self.assertEqual(cfg1, cfg2)
		cfg1 = target.get_conf("XXX99")
		self.assertIsNotNone(cfg2)
		cfg2 = target.get_conf("XXX88")
		self.assertIsNotNone(cfg2)
		self.assertEqual(cfg1, cfg2)
		cfg = target.get_conf("unexist")
		self.assertIsNone(cfg)

if __name__ =="__main__":
	unittest.main()

