import sys, os, json
from glob import glob
from copy import deepcopy
from datetime import datetime
import json
import unittest

PJ_TOP = os.path.dirname( os.path.abspath(__file__) )+"/../../"
sys.path.append(PJ_TOP)

from vtapi_helpers.validator import validate_ip as target
from vtapi_helpers.validator.validate_const import VtValidatorConst as const

class TestIpAddrValidatorModule(unittest.TestCase):
	"""test class of validate_ip.py
	"""

	def setUp(self):
		test_json_files = "./testfile/ipaddr*.json"
		self.datas = []
		self.iplist = [ "8.8.8.8", "1.1.1.1", "52.194.102.242" ]
		for each in glob(test_json_files):
			with open(each, "r") as f:
				data=json.load(f)
				self.datas.append(data)

	def tearDown(self):
		pass

	def test_init_(self):
		"""test method __init__
		"""
		validator = target.IpAddrValidator()
		validator = target.IpAddrValidator(False)
		self.assertTrue(True)
	
	def test_validate(self):
		"""test method validate
		"""
		validator = target.IpAddrValidator()
		_SCORE_ = const.Result
		test_ip = None
		for each in self.datas:
			res = validator.validate(each)
			if res["value"] == "1.1.1.1":
				self.assertEqual(res["score"], 2)
				self.assertIn("detected_point", res)
				self.assertTrue(len(res["detected_point"]) > 0)
				self.assertEqual(res["reputation"], "suspicious")
			elif res["value"] == "8.8.8.8":
				self.assertEqual(res["score"], 2)
				self.assertIn("detected_point", res)
				self.assertTrue(len(res["detected_point"]) > 0)
				self.assertEqual(res["reputation"], "suspicious")
			elif res["value"] == "52.194.102.242":
				self.assertEqual(res["score"], 0)
				self.assertIn("detected_point", res)
				self.assertTrue(len(res["detected_point"]) is 0)
				self.assertEqual(res["reputation"], "benign")
				test_ip = each
		test = deepcopy(test_ip)
		urls = test["detected_urls"]
		for i in range(1, 100):
			each = {}
			each["positives"] = i
			each["total"] = 70
			each["url"] = "testurl_{}.jp".format(i)
			each["scan_date"] = "2019-1-1 09:00:00"
			urls.append(each)
		res = validator.validate(test)
		self.assertEqual(res["score"], 2)
		self.assertEqual(res["reason_code"], 2)
		self.assertEqual(res["reputation"], "suspicious")
		test = deepcopy(test_ip)
		urls = test["detected_urls"]
		for i in range(1, 101):
			each = {}
			each["positives"] = 1
			each["total"] = 70
			each["url"] = "testurl_{}.jp".format(i)
			each["scan_date"] = "2019-1-1 09:00:00"
			urls.append(each)
		res = validator.validate(test)
		self.assertEqual(res["score"], 2)
		self.assertEqual(res["reason_code"], 1)

	def test_get_condition(self):
		"""test method get_condition
		"""
		_TYPE_ = const.Result
		validator = target.IpAddrValidator()
		condition = validator.get_condition()
		self.assertIn(_TYPE_.MALICIOUS, condition)
		self.assertIn(_TYPE_.SUSPICIOUS, condition)

	def test_clear_condition(self):
		"""test method clear_condition
		"""
		_TYPE_ = const.Result
		validator = target.IpAddrValidator()
		validator.clear_condition()
		self.assertEqual(len(validator.get_condition()), 0)
		validator = target.IpAddrValidator()
		validator.clear_condition(_TYPE_.MALICIOUS)
		condition = validator.get_condition()
		self.assertIn(_TYPE_.SUSPICIOUS, condition)
		self.assertFalse(_TYPE_.MALICIOUS in condition)
		validator = target.IpAddrValidator()
		validator.clear_condition(_TYPE_.SUSPICIOUS)
		condition = validator.get_condition()
		self.assertIn(_TYPE_.MALICIOUS, condition)
		self.assertFalse(_TYPE_.SUSPICIOUS in condition)

	def test_set_condition_for_suspicious(self):
		"""test method set_condition_for_suspicious
		"""
		_KEY_ = const.KEY
		_TYPE_ = const.Result
		validator = target.IpAddrValidator()
		validator.set_condition_for_suspicious(
			_KEY_.OR,
			total_detect_url = 100,
			threshold_over_url_num = (10, 10),
		)
		condition = validator.get_condition()
		self.assertIn(_TYPE_.MALICIOUS, condition)
		self.assertIn(_TYPE_.SUSPICIOUS, condition)
		tgt = condition[_TYPE_.SUSPICIOUS]
		self.assertEqual(tgt[_KEY_.TOTAL_DETECT_URL_NUM], 100)
		self.assertEqual(tgt[_KEY_.TOTAL_OVER_URL_NUM], (10, 10))

	def test_set_condition_for_malicious(self):
		"""test method set_condition_for_suspicious
		"""
		_KEY_ = const.KEY
		_TYPE_ = const.Result
		validator = target.IpAddrValidator()
		validator.set_condition_for_malicious(
			_KEY_.OR,
			total_detect_url = 100,
			threshold_over_url_num = (10, 10),
		)
		condition = validator.get_condition()
		self.assertIn(_TYPE_.MALICIOUS, condition)
		self.assertIn(_TYPE_.SUSPICIOUS, condition)
		tgt = condition[_TYPE_.MALICIOUS]
		self.assertEqual(tgt[_KEY_.TOTAL_DETECT_URL_NUM], 100)
		self.assertEqual(tgt[_KEY_.TOTAL_OVER_URL_NUM], (10, 10))

if __name__ =="__main__":
	unittest.main()

