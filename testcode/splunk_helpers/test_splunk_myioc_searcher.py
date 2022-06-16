# -*- encoding:utf-8 -*-

import sys, os, json
import random
import unittest

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/../../"
sys.path.append(PJ_TOP)

from splunk_helpers import splunk_myioc_searcher as target
from mocks import mock_splunk_search_util as sp_util

target.SplunkSearcher = sp_util.SplunkSearcher
conf_name = PJ_TOP+"splunk_helpers/config/splunk.json"

with open(conf_name, "r") as f:
	cfg = json.load(f)

class TestMyIntelSearcherClass(unittest.TestCase):
	"""test class of splunk_myioc_searcher.py
	"""
	v, p, u, r = "testvalue", "product", "user", "type"

	def setUp(self):
		cls = target.MyIntelSearcher
		cls.records.clear()
		del sp_util.SplunkSearcher._RETURN_DATA[:]

	def tearDown(self):
		pass

	def test_is_init(self):
		cls = target.MyIntelSearcher
		cls.splunk_searcher = None
		self.assertFalse(cls.is_init())
		cls.init_splunk(**cfg)
		self.assertTrue(cls.is_init())

	def test_init_splunk(self):
		cls = target.MyIntelSearcher
		cls.init_splunk(**cfg)
		self.assertIsInstance(cls.splunk_searcher, sp_util.SplunkSearcher)

	def test_add(self):
		cls = target.MyIntelSearcher
		cls.init_splunk(**cfg)
		v, p, u, r = "testvalue", "product", "user", "type"
		record = {  "value" : v, "product" : p,
					"user"  : u, "type" : r,
					"info" : "fugahoge" }
		cls.add(record, v, p, u, r)
		self.assertIn(v, cls.records)
		datas = cls.records[v]
		self.assertIsInstance(datas, list)
		self.assertEqual(1, len(datas))
		self.assertEqual(p, datas[0]["product"])

		v, p, u, r = "testvalue2", "product", "user", "type"
		record = {  "value" : v, "product" : p,
					"user"  : u, "type" : r,
					"info" : "fugahoge" }
		cls.add(record, v, p, u, r)
		self.assertIn(v, cls.records)
		datas = cls.records[v]
		self.assertIsInstance(datas, list)
		self.assertEqual(1, len(datas))
		self.assertEqual(p, datas[0]["product"])
		self.assertEqual(u, datas[0]["user"])
		self.assertEqual(r, datas[0]["type"])
		self.assertEqual(record, datas[0]["data"])

		record = {  "value" : v, "product" : p,
					"user"  : u, "type" : "all",
					"info" : "fugahoge" }
		cls.add(record, v, p, u)
		self.assertIn(v, cls.records)
		datas = cls.records[v]
		self.assertEqual(2, len(datas))
		each = datas[1]
		self.assertEqual(p, each["product"])
		self.assertEqual(u, each["user"])
		self.assertEqual("all", each["type"])
		self.assertEqual(record, each["data"])

		record = {  "value" : v, "product" : p,
					"user"  : "all", "type" : "all",
					"info" : "fugahoge" }
		cls.add(record, v, p)
		self.assertIn(v, cls.records)
		datas = cls.records[v]
		each = datas[2]
		self.assertEqual(p, each["product"])
		self.assertEqual("all", each["user"])
		self.assertEqual("all", each["type"])
		self.assertEqual(record, each["data"])

		record = {  "value" : v, "product" : "all",
					"user"  : "all", "type" : "all",
					"info" : "fugahoge" }
		cls.add(record, v)
		self.assertIn(v, cls.records)
		datas = cls.records[v]
		each = datas[3]
		self.assertEqual("all", each["product"])
		self.assertEqual("all", each["user"])
		self.assertEqual("all", each["type"])
		self.assertEqual(record, each["data"])

	def test_add_all_by_records(self):
		cls = target.MyIntelSearcher
		cls.init_splunk(**cfg)
		records = self._make_test_records()
		cls.add_all_by_records(records)
		self.assertEqual(10, len(cls.records))
		for k, each_records in cls.records.items():
			self.assertEqual(100, len(each_records))
			for i in range(0, len(each_records)):
				strnum = str(i)
				each = each_records[i]
				self.assertIn(strnum, each["product"])
				self.assertIn(strnum, each["user"])
				self.assertIn(strnum, each["type"])


	def test_search_cache(self):
		v, p, u, r = "testvalue", "product", "user", "type"
		cls = target.MyIntelSearcher
		cls.init_splunk(**cfg)
		records = self._make_random_test_records()
		cls.add_all_by_records(records)
		records = self._make_random_test_records()
		cls.add_all_by_records(records)
		records = self._make_random_test_records()
		cls.add_all_by_records(records)
		records = self._make_test_records()
		cls.add_all_by_records(records)
		records = self._make_test_records()
		cls.add_all_by_records(records)
		testv1 = u"ほげ".encode("utf-8")
		records = self._make_test_records(v=testv1)
		cls.add_all_by_records(records)
		testv2 = u"ふが".encode("utf-8")
		records = self._make_test_records(v=testv2)
		cls.add_all_by_records(records)
		for each_value in cls.records.keys():
			results = cls.search_cache(each_value)
			if testv1 in each_value:
				self.assertEqual(100, len(results))
				continue
			elif testv2 in each_value:
				self.assertEqual(100, len(results))
				continue
			else:
				self.assertEqual(500, len(results))
			for i in range(0, 100):
				each_p = "{}:{}".format(p, i)
				each_u = "{}:{}".format(u, i)
				each_r = "{}:{}".format(r, i)
				results = cls.search_cache(
						each_value, product=each_p)
				self.assertEqual(5, len(results))
				results = cls.search_cache(
						each_value, user=each_u)
				self.assertEqual(5, len(results))
				results = cls.search_cache(
						each_value, rec_type=each_r)
				self.assertEqual(5, len(results))
				results = cls.search_cache(
						each_value,
						product=each_p,
						rec_type=each_r)
				results = cls.search_cache(
						each_value,
						product=each_p,
						user=each_u)
				results = cls.search_cache(
						each_value,
						user=each_u,
						rec_type=each_r)
				results = cls.search_cache(
						each_value,
						product=each_p,
						user=each_u,
						rec_type=each_r)
				self.assertTrue(1<len(results))

	def test_clone_records(self):
		cls = target.MyIntelSearcher
		res = cls.clone_records()
		self.assertEqual(res, cls.records)
		self.assertEqual(0, len(res))
		cls.init_splunk(**cfg)
		records = self._make_test_records()
		cls.add_all_by_records(records)
		res = cls.clone_records()
		self.assertEqual(res, cls.records)
		self.assertEqual(10, len(res))
		for each in res.values():
			self.assertEqual(100, len(each))
	
	def test_get_all(self):
		cls = target.MyIntelSearcher
		records = cls.get_all()
		self.assertEqual(0, len(records))
		self.assertIsInstance(records, list)
		cls.init_splunk(**cfg)
		records = self._make_test_records()
		cls.add_all_by_records(records)
		records = cls.get_all()
		self.assertEqual(1000, len(records))
		for values in cls.records.values():
			for each in values:
				self.assertIn(each, records)

	def test_get(self):
		""" get method is like a alias of search_cache now.
		"""
		pass

	def test_has(self):
		""" has method is almost alias of search_cache now.
		"""
		cls = target.MyIntelSearcher
		cls.init_splunk(**cfg)
		records = self._make_test_records()
		cls.add_all_by_records(records)
		testkey = "{}:{}".format(self.v, 1)
		testkey_p = "{}:{}".format(self.p, 4)
		testkey_u = "{}:{}".format(self.u, 4)
		testkey_r = "{}:{}".format(self.r, 4)
		res=cls.has(testkey, product=testkey_p, user=testkey_u, rec_type=testkey_r)
		self.assertTrue(res)
		testkey_p = "{}:{}".format(self.p, 4)
		testkey_u = "{}:{}".format(self.u, 5)
		testkey_r = "{}:{}".format(self.r, 5)
		res=cls.has(testkey, product=testkey_p, user=testkey_u, rec_type=testkey_r)
		self.assertFalse(res)

	def test_del_records(self):
		cls = target.MyIntelSearcher
		cls.init_splunk(**cfg)
		records = self._make_test_records()
		cls.add_all_by_records(records)
		testkey = "{}:{}".format(self.v, 1)
		self.assertEqual(10, len(cls.records))
		cls.del_records(testkey)
		self.assertEqual(9, len(cls.records))
		testkey = "{}:{}".format(self.v, 2)
		testkey_p = "{}:{}".format(self.p, 1)
		cls.del_records(testkey, product=testkey_p)
		self.assertEqual(99, len(cls.records[testkey]))
		testkey_u = "{}:{}".format(self.u, 2)
		cls.del_records(testkey, user=testkey_u)
		self.assertEqual(98, len(cls.records[testkey]))
		testkey_r = "{}:{}".format(self.r, 3)
		cls.del_records(testkey, rec_type=testkey_r)
		self.assertEqual(97, len(cls.records[testkey]))
		testkey_p = "{}:{}".format(self.p, 4)
		testkey_u = "{}:{}".format(self.u, 4)
		testkey_r = "{}:{}".format(self.r, 4)
		cls.del_records(testkey, product=testkey_p, user=testkey_u, rec_type=testkey_r)
		self.assertEqual(96, len(cls.records[testkey]))
		testkey_p = "{}:{}".format(self.p, 4)
		testkey_u = "{}:{}".format(self.u, 5)
		testkey_r = "{}:{}".format(self.r, 6)
		cls.del_records(testkey, product=testkey_p, user=testkey_u, rec_type=testkey_r)
		self.assertEqual(96, len(cls.records[testkey]))

	def test_clear(self):
		cls = target.MyIntelSearcher
		cls.init_splunk(**cfg)
		self.assertEqual(0, len(cls.records))
		cls.clear()
		self.assertEqual(0, len(cls.records))
		records = self._make_test_records()
		cls.add_all_by_records(records)
		cls.clear()
		self.assertEqual(0, len(cls.records))

	def _make_test_records(self, vmax=10, other_max=100, **data):
		v = data["v"] if data.has_key("v") else self.v
		p = data["p"] if data.has_key("p") else self.p
		u = data["u"] if data.has_key("u") else self.u
		r = data["r"] if data.has_key("r") else self.r
		results = []
		for i in range(0, vmax):
			each_value = "{}:{}".format(v, i)
			for j in range(0, other_max):
				each_p = "{}:{}".format(p, j)
				each_u = "{}:{}".format(u, j)
				each_r = "{}:{}".format(r, j)
				results.append({"value"   : each_value,
								"product" : each_p,
								"user"    : each_u,
								"type" : each_r,
								"info" : "fugahoge" })
		return results

	def _make_random_test_records(self, vmax=10, other_max=100, **data):
		v = data["v"] if data.has_key("v") else self.v
		p = data["p"] if data.has_key("p") else self.p
		u = data["u"] if data.has_key("u") else self.u
		r = data["r"] if data.has_key("r") else self.r
		results = []
		list1 = random.sample(range(0, other_max), other_max)
		list2 = random.sample(range(0, other_max), other_max)
		list3 = random.sample(range(0, other_max), other_max)
		for i in range(0, vmax):
			each_value = "{}:{}".format(v, i)
			for j in range(0, other_max):
				each_p = "{}:{}".format(p, list1[j])
				each_u = "{}:{}".format(u, list2[j])
				each_r = "{}:{}".format(r, list3[j])
				results.append({"value"   : each_value,
								"product" : each_p,
								"user"    : each_u,
								"type" : each_r,
								"info" : "fugahoge" })
		return results

	def test_make_query(self):
		cls = target.MyIntelSearcher
		cls.init_splunk(**cfg)
		testvalue="fuga"
		query=cls.make_query(testvalue)

		query_top = u'| savedsearch search_valid_threat_info'
		self.assertTrue(query.startswith(query_top))
		self.assertIn('| search', query)
		self.assertIn('value=\"{}\"'.format(testvalue), query)
		testuser="hoge"
		query=cls.make_query(testvalue, user=testuser)
		self.assertIn('user=\"{}\"'.format(testuser), query)
		self.assertIn('OR user=ALL', query)
		testproduct="ping"
		query=cls.make_query(testvalue, user=testuser, product=testproduct)
		self.assertIn('product=\"{}\"'.format(testproduct), query)
		self.assertIn('OR product=ALL', query)
		testtype="pong"
		query=cls.make_query(testvalue, user=testuser, product=testproduct, rec_type=testtype)
		self.assertIn('type=\"{}\"'.format(testtype), query)
		self.assertIn('value=\"{}\"'.format(testvalue), query)
		self.assertIn('user=\"{}\"'.format(testuser), query)
		self.assertIn('OR user=ALL', query)
		self.assertIn('product=\"{}\"'.format(testproduct), query)
		self.assertIn('OR product=ALL', query)

class TestSplunkIocSearcherModule(unittest.TestCase):
	"""test class of splunk_myioc_searcher.py
	"""
	_DATA = sp_util.SplunkSearcher._default

	def test_search(self):
		v, p, u, r = self._DATA["value"], self._DATA["product"], self._DATA["user"], self._DATA["type"]
		cls = target.MyIntelSearcher
		cls.init_splunk(**cfg)
		res=target.search(v, p, u, r)
		self.assertEqual(1, len(res))
		self.assertEqual(v, res[0]["value"]   )
		self.assertEqual(p, res[0]["product"] )
		self.assertEqual(u, res[0]["user"]    )
		self.assertEqual(r, res[0]["type"]    )
		_call = sp_util._COM_[-1]
		self.assertEqual("search", _call["method"])
		self.assertEqual("blocking", _call["args"]["exec_mode"])
		self.assertEqual(100, _call["args"]["max_count"])
		_ng = sp_util.SplunkSearcher._NG_VALUE
		res=target.search(_ng["value"], p, u, r )
		self.assertEqual(0, len(res))
		res=target.search(v, _ng["product"], u, r)
		self.assertEqual(0, len(res))
		res=target.search(v, p, _ng["user"], r)
		self.assertEqual(0, len(res))
		res=target.search(v, p, u, _ng["type"])
		self.assertEqual(0, len(res))
		res=target.search(v, p, u, _ng["type"], exec_mode="normal", max_count=0)
		_call = sp_util._COM_[-1]
		self.assertEqual("search", _call["method"])
		self.assertEqual("normal", _call["args"]["exec_mode"])
		self.assertEqual(0, _call["args"]["max_count"])

if __name__ =="__main__":
	unittest.main()

