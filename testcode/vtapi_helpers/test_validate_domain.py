import sys, os, json
from glob import glob
from copy import deepcopy
from datetime import datetime
import json
import unittest

PJ_TOP = os.path.dirname( os.path.abspath(__file__) )+"/../.."
sys.path.append(PJ_TOP)

from vtapi_helpers.validator import validate_domain as target
from vtapi_helpers.validator.validate_const import VtValidatorConst as const

class TestDomainValidatorModule(unittest.TestCase):
	"""test class of validate_domain.py
	"""

	def setUp(self):
		test_json_files = "./testfile/domain*.json"
		self.datas = []
		self.domains = [
				"dhsoc.jp", "digitalhearts.com", "kozow.com",
				"qlql.ru", "mindspark.com" ]
		for each in glob(test_json_files):
			with open(each, "r") as f:
				data=json.load(f)
				self.datas.append(data)

	def tearDown(self):
		pass

	def test_init_(self):
		"""test method __init__
		"""
		validator = target.DomainValidator()
		validator = target.DomainValidator(False)
		self.assertTrue(True)
	
	def test_init_malicious_categories_keyword(self):
		"""test method init_malicious_categories_keyword
		"""
		default = const.Default.MAL_CATEGORY_KEYWORDS
		validator = target.DomainValidator()
		self.assertTrue(default, validator.mal_categories)
		my_categories = ["abc","def"]
		validator.init_malicious_categories(my_categories)
		self.assertTrue(my_categories, validator.mal_categories)
		try:
			validator = target.DomainValidator()
			validator.init_malicious_categories("direct")
			validator = None
		except AssertionError as e:
			self.assertTrue(True)
		except:
			self.assertTrue(False)
		self.assertIsNotNone(validator)

	def test_add_mal_category(self):
		"""test method add_mal_category
		"""
		categories = const.Default.MAL_CATEGORY_KEYWORDS
		validator = target.DomainValidator()
		word = "test"
		validator.add_mal_category(word)
		self.assertIn(word, validator.mal_categories)
		for each in categories:
			self.assertIn(each, validator.mal_categories)
		try:
			validator.add_mal_category(123)
			validator = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(validator)

	def test_validate(self):
		"""test method validate
		"""
		validator = target.DomainValidator()
		_SCORE_ = const.Result
		test_domain = None
		for each in self.datas:
			res = validator.validate(each)
			if res["value"] == "digitalhearts.com":
				self.assertEqual(res["score"], 0)
				self.assertIn("detected_point", res)
				self.assertTrue(len(res["detected_point"]) is 0)
				self.assertEqual(res["reputation"], "benign")
				test_domain = each
			elif res["value"] == "qlql.ru":
				self.assertEqual(res["score"], 5)
				self.assertIn("detected_point", res)
				self.assertTrue(len(res["detected_point"]) > 0)
				self.assertEqual(res["reputation"], "malicious")
			elif res["value"] == "mindspark.com":
				self.assertEqual(res["score"], 5)
				self.assertIn("detected_point", res)
				self.assertTrue(len(res["detected_point"]) > 0)
				self.assertEqual(res["reputation"], "malicious")
		test = deepcopy(test_domain)
		test["create_date"]="2019-5-27"
		res = validator.validate(test)
		self.assertEqual(res["score"], 2)
		self.assertEqual(res["reason_code"], 4)
		test = deepcopy(test_domain)
		test["categories"].append("phishing")
		res = validator.validate(test)
		self.assertEqual(res["score"], 5)
		self.assertEqual(res["reason_code"], 3)
		test = deepcopy(test_domain)
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
		test = deepcopy(test_domain)
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

	def test_days_from_created(self):
		data = self.datas[0]
		validator = target.DomainValidator()
		data["create_date"] = None
		days = validator.days_from_created(data)
		self.assertIsNone(days)
		data["create_date"] = "2019-01-01"
		d1 = validator.days_from_created(data)
		data["create_date"] = "2018-12-31"
		d2 = validator.days_from_created(data)
		self.assertEqual(d1+1, d2)
		data["create_date"] = "2018-12-01"
		d2 = validator.days_from_created(data)
		self.assertEqual(d1+31, d2)
		data["create_date"] = "2010-10-15"
		d2 = validator.days_from_created(data)
		self.assertEqual(d1+3000, d2)

	def test_get_condition(self):
		_TYPE_ = const.Result
		validator = target.DomainValidator()
		condition = validator.get_condition()
		self.assertIn(_TYPE_.MALICIOUS, condition)
		self.assertIn(_TYPE_.SUSPICIOUS, condition)

	def test_clear_condition(self):
		_TYPE_ = const.Result
		validator = target.DomainValidator()
		validator.clear_condition()
		self.assertEqual(len(validator.get_condition()), 0)
		validator = target.DomainValidator()
		validator.clear_condition(_TYPE_.MALICIOUS)
		condition = validator.get_condition()
		self.assertIn(_TYPE_.SUSPICIOUS, condition)
		self.assertFalse(_TYPE_.MALICIOUS in condition)
		validator = target.DomainValidator()
		validator.clear_condition(_TYPE_.SUSPICIOUS)
		condition = validator.get_condition()
		self.assertIn(_TYPE_.MALICIOUS, condition)
		self.assertFalse(_TYPE_.SUSPICIOUS in condition)

	def test_set_condition_for_suspicious(self):
		_KEY_ = const.KEY
		_TYPE_ = const.Result
		validator = target.DomainValidator()
		validator.set_condition_for_suspicious(
			_KEY_.OR,
			total_detect_url = 100,
			threshold_over_url_num = (10, 10),
			has_malicious_categories = True,
			unknown_with_nearly_creation_date = 100
		)
		condition = validator.get_condition()
		self.assertIn(_TYPE_.MALICIOUS, condition)
		self.assertIn(_TYPE_.SUSPICIOUS, condition)
		tgt = condition[_TYPE_.SUSPICIOUS]
		self.assertEqual(tgt[_KEY_.TOTAL_DETECT_URL_NUM], 100)
		self.assertEqual(tgt[_KEY_.HAS_MAL_CATEGORIES], True)
		self.assertEqual(tgt[_KEY_.UNKNOWN_NEW_HOST], 100)
		self.assertEqual(tgt[_KEY_.TOTAL_OVER_URL_NUM], (10, 10))

	def test_set_condition_for_malicious(self):
		_KEY_ = const.KEY
		_TYPE_ = const.Result
		validator = target.DomainValidator()
		validator.set_condition_for_malicious(
			_KEY_.OR,
			total_detect_url = 100,
			threshold_over_url_num = (10, 10),
			has_malicious_categories = True,
			unknown_with_nearly_creation_date = 100
		)
		condition = validator.get_condition()
		self.assertIn(_TYPE_.MALICIOUS, condition)
		self.assertIn(_TYPE_.SUSPICIOUS, condition)
		tgt = condition[_TYPE_.MALICIOUS]
		self.assertEqual(tgt[_KEY_.TOTAL_DETECT_URL_NUM], 100)
		self.assertEqual(tgt[_KEY_.HAS_MAL_CATEGORIES], True)
		self.assertEqual(tgt[_KEY_.UNKNOWN_NEW_HOST], 100)
		self.assertEqual(tgt[_KEY_.TOTAL_OVER_URL_NUM], (10, 10))

if __name__ =="__main__":
	unittest.main()

