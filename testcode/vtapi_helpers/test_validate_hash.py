import sys, os, json
from glob import glob
from copy import deepcopy
from datetime import datetime
import json
import unittest

PJ_TOP = os.path.dirname( os.path.abspath(__file__) )+"/../../"
sys.path.append(PJ_TOP)

from vtapi_helpers.validator import validate_hash as target
from vtapi_helpers.validator.validate_const import VtValidatorConst as const

_KEY_ = const.KEY
_TYPE_ = const.Result
_DEF_ = const.Default

class TestHashValidatorModule(unittest.TestCase):
	"""test class of validate_hash.py
	"""

	def setUp(self):
		test_json_files = "./testfile/hash*.json"
		self.datas = []
		self.hashes = [
				"f26cce437bfc88769b01188e0662c4c2502f4261eca1617ee7e068d735a4843b",
				"826b28196c1d66c78a3c65d71294b281c5bbc02403d279e3cef3f6ed46e3ca67",
				"4691e3590cdf63047a668675b2d7d803879cbedf61c46245c08f891e84412154" ]
		for each in glob(test_json_files):
			with open(each, "r") as f:
				data=json.load(f)
				self.datas.append(data)

	def tearDown(self):
		pass

	def test_init_(self):
		"""test method __init__
		"""
		validator = target.HashValidator()
		validator = target.HashValidator(False)
		self.assertTrue(True)
	
	def test_init_vendors(self):
		"""test method init_vendors
		"""
		def_lv1 = list(_DEF_.LV1_VENDORS_KEYWORD)
		def_lv2 = list(_DEF_.LV2_VENDORS_KEYWORD)
		validator = target.HashValidator()
		self.assertEqual(validator.lv1_vendors, def_lv1)
		self.assertEqual(validator.lv2_vendors, def_lv2)
		test_lv1 = ["fuga", "hoge", "mof"]
		validator.init_vendors(lv1_vendors=test_lv1)
		self.assertEqual(validator.lv1_vendors, test_lv1)
		self.assertEqual(validator.lv2_vendors, def_lv2)
		test_lv2 = ["foo", "bar", "pin"]
		validator.init_vendors(lv2_vendors=test_lv2)
		self.assertEqual(validator.lv1_vendors, def_lv1)
		self.assertEqual(validator.lv2_vendors, test_lv2)
		test = [123]
		try:
			validator.init_vendors(lv1_vendors=test)
			validator = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(validator)
		try:
			validator.init_vendors(lv2_vendors=test)
			validator = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(validator)

	def test_get_condition(self):
		"""test method get_condition
		"""
		validator = target.HashValidator()
		condition = validator.get_condition()
		self.assertIn(_TYPE_.MALICIOUS, condition)
		self.assertIn(_TYPE_.SUSPICIOUS, condition)

	def test_clear_vendors(self):
		"""test method clear_vendors
		"""
		validator = target.HashValidator()
		self.assertTrue(len(validator.lv1_vendors)>0)
		self.assertTrue(len(validator.lv2_vendors)>0)
		validator.clear_vendors(_KEY_.Lv1)
		self.assertTrue(len(validator.lv1_vendors) is 0)
		self.assertTrue(len(validator.lv2_vendors)>0)
		validator.clear_vendors(_KEY_.Lv2)
		self.assertTrue(len(validator.lv1_vendors) is 0)
		self.assertTrue(len(validator.lv2_vendors) is 0)
		validator = target.HashValidator()
		validator.clear_vendors(_KEY_.Lv2)
		self.assertTrue(len(validator.lv1_vendors) > 0)
		self.assertTrue(len(validator.lv2_vendors) is 0)

	def test_add_vendors(self):
		validator = target.HashValidator()
		validator.add_vendors(_KEY_.Lv1, "fuga")
		self.assertIn("fuga", validator.lv1_vendors)
		validator.add_vendors(_KEY_.Lv2, "hoge")
		self.assertIn("hoge", validator.lv2_vendors)
		try:
			validator.add_vendors(_KEY_.Lv1, 123)
			validator = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(validator)
		try:
			validator.add_vendors(_KEY_.Lv1, ["fuga"])
			validator = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(validator)
		try:
			validator.add_vendors(_KEY_.Lv2, 123)
			validator = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(validator)
		try:
			validator.add_vendors(_KEY_.Lv2, ["fuga"])
			validator = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(validator)
		try:
			validator.add_vendors("LV1", "fuga")
			validator = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(validator)
		try:
			validator.add_vendors(123, "fuga")
			validator = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(validator)
		try:
			validator.add_vendors("fuga")
			validator = None
		except TypeError as e:
			self.assertTrue(True)
		self.assertIsNotNone(validator)
		try:
			validator.add_vendors("lv3", "fuga")
			validator = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(validator)

	def test_set_condition_for_suspicious(self):
		validator = target.HashValidator()
		data = {
					_KEY_.VALIDATE_THRESHOLD: 70,
					_KEY_.MUST_VENDORS     : 50,
					_KEY_.RELIABLE_VENDORS : 9,
					_KEY_.NORMAL_VENDORS   : 1
				}
		validator.set_condition_for_suspicious(
				_KEY_.OR, data)
		condition = validator.get_condition()
		sus = condition[_TYPE_.SUSPICIOUS]
		self.assertTrue(data, sus['detected_score'])
		self.assertTrue(_KEY_.OR, sus['base'])

	def test_set_condition_for_malicious(self):
		validator = target.HashValidator()
		data = {
					_KEY_.VALIDATE_THRESHOLD: 70,
					_KEY_.MUST_VENDORS     : 50,
					_KEY_.RELIABLE_VENDORS : 9,
					_KEY_.NORMAL_VENDORS   : 1
				}
		validator.set_condition_for_malicious(
				_KEY_.OR, data)
		condition = validator.get_condition()
		mal = condition[_TYPE_.MALICIOUS]
		self.assertTrue(data, mal['detected_score'])
		self.assertTrue(_KEY_.OR, mal['base'])

	def test_validate(self):
		validator = target.HashValidator()
		testdata = None
		testdata2 = None
		for each in self.datas:
			each_res = validator.validate(each)
			self.assertIn("value", each_res)
			self.assertIn("score", each_res)
			self.assertIn("reputation", each_res)
			self.assertIn("reason_code", each_res)
			self.assertIn("reason", each_res)
			self.assertIn("detected_point", each_res)
			if each_res["value"] == "826b28196c1d66c78a3c65d71294b281c5bbc02403d279e3cef3f6ed46e3ca67":
				self.assertEqual(each_res["reputation"], "malicious")
				self.assertEqual(each_res["reason_code"], 1)
				self.assertEqual(each_res["score"], 5)
				testdata = each
		test1 = testdata.copy()
		test1["detected_vendors"]=[]
		res = validator.validate(test1)
		self.assertEqual(res["reason_code"], 0)
		self.assertEqual(res["score"], 0)
		self.assertEqual(res["reputation"], "benign")
		self.assertEqual(len(res["detected_point"]), 0)
		validator = target.HashValidator()
		validator.init_vendors(lv1_vendors=["unexist_vendor1"], lv2_vendors=["unexist_vendor2"])
		data = {
					_KEY_.VALIDATE_THRESHOLD: 60,
					_KEY_.MUST_VENDORS     : 60,
					_KEY_.RELIABLE_VENDORS : 30,
					_KEY_.NORMAL_VENDORS   : 1
				}
		mal_data = data.copy()
		validator.set_condition_for_suspicious(
				_KEY_.OR, data)
		validator.set_condition_for_malicious(
				_KEY_.OR, mal_data)
		res = validator.validate(testdata)
		self.assertEqual(res["reason_code"], 0)
		self.assertEqual(res["score"], 0)
		self.assertEqual(res["reputation"], "benign")
		self.assertEqual(len(res["detected_point"]), 0)
		data[_KEY_.VALIDATE_THRESHOLD]=10
		validator.set_condition_for_suspicious(
				_KEY_.OR, data)
		res = validator.validate(testdata)
		self.assertEqual(res["reason_code"], 1)
		self.assertEqual(res["score"], 2)
		self.assertEqual(res["reputation"], "suspicious")
		self.assertTrue(len(res["detected_point"]) > 0)
		test1 = testdata.copy()
		test1["detected_vendors"]=["unexist_vendor1"]
		res = validator.validate(test1)
		self.assertEqual(res["reason_code"], 1)
		self.assertEqual(res["score"], 5)
		self.assertEqual(res["reputation"], "malicious")
		self.assertTrue(len(res["detected_point"]) > 0)
		self.assertIn("unexist_vendor1", res["detected_point"])
		test1["detected_vendors"]=["unexist_vendor2", "unexist_vendor2"]
		res = validator.validate(test1)
		self.assertEqual(res["reason_code"], 1)
		self.assertEqual(res["score"], 5)
		self.assertEqual(res["reputation"], "malicious")
		self.assertTrue(len(res["detected_point"]) > 0)
		self.assertIn("unexist_vendor2", res["detected_point"])
		test1["detected_vendors"]=["unexist_vendor2"]
		res = validator.validate(test1)
		self.assertEqual(res["reason_code"], 1)
		self.assertEqual(res["score"], 2)
		self.assertEqual(res["reputation"], "suspicious")
		self.assertTrue(len(res["detected_point"]) > 0)
		self.assertIn("unexist_vendor2", res["detected_point"])

if __name__ =="__main__":
	unittest.main()

