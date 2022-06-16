import sys, os, json
from glob import glob
from copy import deepcopy
from datetime import datetime
import json
import unittest

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/../../"
sys.path.append(PJ_TOP)

from vtapi_helpers import vtapi_helper as target
from vtapi_helpers.validator.validate_const import VtValidatorConst as const

class testobj(object):
	class VtApi(object):
		def __init__(self, keys):
			self.keys = keys

		def search_hashes(self, hashes, with_parse=True):
			return ( hashes, with_parse )

		def search_ipaddrs(self, iplist, with_parse=True):
			return ( iplist, with_parse )

		def search_domains(self, domains, with_parse=True):
			return ( domains, with_parse )

target.vtapi = testobj

class TestVtApiHelperModule(unittest.TestCase):
	"""test class of vtapi_helper.py
	"""

	def setUp(self):
		test_json_domain = CURR_DIR+"/testfile/domain*.json"
		test_json_ip = CURR_DIR+"/testfile/ipaddr*.json"
		test_json_hash = CURR_DIR+"/testfile/hash*.json"
		self.domain_list = []
		self.hash_list = []
		self.ip_list = []
		for each in glob(test_json_domain):
			with open(each, "r") as f:
				data=json.load(f)
				self.domain_list.append(data)
		for each in glob(test_json_hash):
			with open(each, "r") as f:
				data=json.load(f)
				self.hash_list.append(data)
		for each in glob(test_json_ip):
			with open(each, "r") as f:
				data=json.load(f)
				self.ip_list.append(data)

	def tearDown(self):
		pass

	def test_get_vtapi(self):
		vtapi = target.get_vtapi()
		self.assertIsInstance( vtapi, testobj.VtApi )
	
	def test_parse_config(self):
		cfg = target.parse_config(target._CONF_NAME)
		self.assertIsInstance( cfg, list )
		self.assertTrue( len(cfg) is not 0 )
	
	def test_search_hashes(self):
		values = [ "1"*64, "2"*64 ]
		result = target.search_hashes( values )
		self.assertEqual( values, result[0] )
		self.assertTrue( result[1] )
		result = target.search_hashes( values, False )
		self.assertFalse( result[1] )

	def test_search_iplist(self):
		values = [ "1.1.1.1", "2.2.2.2" ]
		result = target.search_iplist( values )
		self.assertEqual( values, result[0] )
		self.assertTrue( result[1] )
		result = target.search_iplist( values, False )
		self.assertFalse( result[1] )

	def test_search_domains(self):
		values = [ "test.com", "hoge.fuga" ]
		result = target.search_domains( values )
		self.assertEqual( values, result[0] )
		self.assertTrue( result[1] )
		result = target.search_domains( values, False )
		self.assertFalse( result[1] )
	
	def test_sammarize_hash(self):
		h1 = self.hash_list[0]
		result = target.sammarize_hash(h1)
		self.assertTrue(result["exist"])
		self.assertEqual("benign", result["reputation"])
		h2 = self.hash_list[1]
		result = target.sammarize_hash(h2)
		self.assertTrue(result["exist"])
		self.assertEqual("benign", result["reputation"])
		h3 = self.hash_list[2]
		result = target.sammarize_hash(h3)
		self.assertTrue(result["exist"])
		self.assertEqual("malicious", result["reputation"])
		for each in self.hash_list:
			result = target.sammarize_hash(each)
			for each in result["detected_detail"]:
				self.assertIsInstance(each, str)

	def test_sammarize_ip(self):
		ip1 = self.ip_list[0]
		result = target.sammarize_ip(ip1)
		self.assertTrue(result["exist"])
		self.assertEqual("suspicious", result["reputation"])
		ip2 = self.ip_list[1]
		result = target.sammarize_ip(ip2)
		self.assertTrue(result["exist"])
		self.assertEqual("benign", result["reputation"])
		ip3 = self.ip_list[2]
		result = target.sammarize_ip(ip3)
		self.assertTrue(result["exist"])
		self.assertEqual("suspicious", result["reputation"])
		for each in self.ip_list:
			result = target.sammarize_ip(each)
			for each in result["detected_urls"]:
				self.assertIsInstance(each, str)

	def test_sammarize_domain(self):
		d1 = self.domain_list[0]
		result = target.sammarize_domain(d1)
		self.assertTrue(result["exist"])
		self.assertEqual("malicious", result["reputation"])
		d2 = self.domain_list[1]
		result = target.sammarize_domain(d2)
		self.assertTrue(result["exist"])
		self.assertEqual("malicious", result["reputation"])
		d3 = self.domain_list[2]
		result = target.sammarize_domain(d3)
		self.assertTrue(result["exist"])
		self.assertEqual("benign", result["reputation"])
		d4 = self.domain_list[3]
		result = target.sammarize_domain(d4)
		self.assertTrue(result["exist"])
		self.assertEqual("benign", result["reputation"])
		d5 = self.domain_list[4]
		result = target.sammarize_domain(d5)
		self.assertTrue(result["exist"])
		self.assertEqual("malicious", result["reputation"])
		for each in self.domain_list:
			result = target.sammarize_domain(each)
			for each in result["detected_urls"]:
				self.assertIsInstance(each, str)

	def test_sammarize(self):
		result = target.sammarize("hash", self.hash_list[0])
		self.assertEqual("benign", result["reputation"])
		result = target.sammarize("ip", self.ip_list[0])
		self.assertEqual("suspicious", result["reputation"])
		result = target.sammarize("domain", self.domain_list[0])
		self.assertEqual("malicious", result["reputation"])
	
	def test_search(self):
		value = "1"*64
		result = target.search("hash", value)
		self.assertEqual(value, result[0])
		value = "1.1.1.1"
		result = target.search("ip", value)
		self.assertEqual(value, result[0])
		value = "test.com"
		result = target.search("domain", value)
		self.assertEqual(value, result[0])

if __name__ =="__main__":
	unittest.main()

