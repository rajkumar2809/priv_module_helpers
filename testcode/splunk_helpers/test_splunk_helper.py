import sys, os, json
import unittest

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/../../"
sys.path.append(PJ_TOP)

from splunk_helpers import splunk_post_helper as target
from mocks import mock_rest_util
target.rest_util = mock_rest_util

class TestSplunkLogSenderModule(unittest.TestCase):
	"""test class of SplunkLogSender in splunk_post_helper.py
	"""

	def setUp(self):
		pass

	def tearDown(self):
		pass

	def test_init__(self):
		"""test method of __init__
		"""
		hostname = "testhost.com"
		username = "testuser"
		password = "password"
		obj = target.SplunkLogSender(hostname, username, password)
		self.assertEqual(hostname, obj.hostname)
		self.assertEqual(username, obj.username)
		self.assertEqual(password, obj.password)
		self.assertEqual(obj._URI, obj.resource)
		self.assertEqual(0, len(obj.params))
		resource = "/fuga/hoge"
		obj2 = target.SplunkLogSender(hostname, username, password, resource)
		self.assertEqual(resource, obj2.resource)
		self.assertEqual(obj._URI, obj.resource)
		port = 10000
		obj3 = target.SplunkLogSender(hostname, username, password, resource, port=port)
		self.assertEqual(port, obj3.port)
		obj4 = target.SplunkLogSender(hostname, username, password, port=port, resource=resource )
		self.assertEqual(resource, obj4.resource)
		self.assertEqual(port, obj4.port)
		try:
			obj = target.SplunkLogSender(123, username, password)
			obj = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(obj)
		try:
			obj = target.SplunkLogSender(123, username, password)
			obj = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(obj)
		try:
			obj = target.SplunkLogSender(hostname, username, 123)
			obj = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(obj)
		try:
			obj = target.SplunkLogSender(hostname, username, password, 123)
			obj = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(obj)
		try:
			obj = target.SplunkLogSender(hostname, username, password, resource, "abc")
			obj = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(obj)

	def test_make_param_dict(self):
		"""test method of _make_param_dict
		"""
		hostname = "testhost.com"
		username = "testuser"
		password = "password"
		tgt = target.SplunkLogSender(hostname, username, password)
		a = tgt.make_param_dict( "a", "b", "c" )
		self.assertEqual(a["index"], "a")
		self.assertEqual(a["source"], "b")
		self.assertEqual(a["sourcetype"], "c")
		a = tgt.make_param_dict( "a", "b" )
		self.assertEqual(a["index"], "a")
		self.assertEqual(a["source"], "b")
		self.assertTrue(not "sourcetype" in a)
		try:
			tgt.make_param_dict( 1, "b", "c" )
			tgt = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(tgt)
		try:
			tgt.make_param_dict( "", "b", "c" )
			tgt = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(tgt)
		try:
			tgt.make_param_dict( "a", 1, "c" )
			tgt = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(tgt)
		try:
			tgt.make_param_dict( "a", "", "c" )
			tgt = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(tgt)
		try:
			tgt.make_param_dict( "a", "b", 1 )
			tgt = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(tgt)
		try:
			tgt.make_param_dict( "a", "b", "" )
			tgt = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(tgt)

	def test_init_params(self):
		"""test method of init_params
		"""
		hostname = "testhost.com"
		username = "testuser"
		password = "password"
		tgt = target.SplunkLogSender(hostname, username, password)
		data_type = "testtype"
		data = {
				"index" : "index",
				"source" : "source",
				"sourcetype" : "sourcetype" }
		tgt.init_params(data_type, data["index"], data["source"], data["sourcetype"])
		self.assertEqual(data, tgt.params[data_type])
		tgt.init_params(data_type, data["index"], data["source"])
		self.assertTrue(not("sourcetype" in tgt.params[data_type]))
		try:
			tgt.init_params(123, data["index"], data["source"])
			tgt = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(tgt)
		try:
			tgt.init_params("", data["index"], data["source"])
			tgt = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(tgt)

	def test_build_url_for_splunk_post(self):
		"""test method of build_url_for_splunk_post
		"""
		hostname = "testhost.com"
		username = "testuser"
		password = "password"
		tgt = target.SplunkLogSender(hostname, username, password)
		data_type = "testtype"
		data = {
				"index" : "index",
				"source" : "source",
				"sourcetype" : "sourcetype" }
		tgt.init_params(data_type, data["index"], data["source"], data["sourcetype"])
		result = tgt.build_url_for_splunk_post(data_type)
		self.assertEqual(result[0], hostname)
		self.assertEqual(result[1], tgt._URI)
		self.assertEqual(result[2], tgt.params[data_type])
		self.assertEqual(result[3], "https")
		self.assertEqual(result[4], tgt._PORT)
		try:
			result = tgt.build_url_for_splunk_post("no_key")
			result = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(result)

	def test_has_params(self):
		"""test method of has_params
		"""
		hostname = "testhost.com"
		username = "testuser"
		password = "password"
		tgt = target.SplunkLogSender(hostname, username, password)
		data_type = "testtype"
		self.assertFalse(tgt.has_params(data_type))
		data = {
				"index" : "index",
				"source" : "source",
				"sourcetype" : "sourcetype" }
		tgt.init_params(data_type, data["index"], data["source"], data["sourcetype"])
		self.assertTrue(tgt.has_params(data_type))
		self.assertFalse(tgt.has_params("no_key"))

	def test_get_params(self):
		"""test method of get_params
		"""
		hostname = "testhost.com"
		username = "testuser"
		password = "password"
		tgt = target.SplunkLogSender(hostname, username, password)
		data_type = "testtype"
		self.assertIsNone(tgt.get_params(data_type))
		data = {
				"index" : "index",
				"source" : "source",
				"sourcetype" : "sourcetype" }
		tgt.init_params(data_type, data["index"], data["source"], data["sourcetype"])
		params = tgt.get_params(data_type)
		self.assertEqual(data, params)
		self.assertIsNone(tgt.get_params("no_key"))

	def test_post_data(self):
		"""test method of post_data
		"""
		hostname = "testhost.com"
		username = "testuser"
		password = "password"
		tgt = target.SplunkLogSender(hostname, username, password)
		data_type = "testtype"
		data = {
				"index" : "index",
				"source" : "source",
				"sourcetype" : "sourcetype" }
		tgt.init_params(data_type, data["index"], data["source"], data["sourcetype"])
		_data_dict = {"fuga" : "hoge", "pin" : "pon"}
		post_data = json.dumps(_data_dict)
		res = tgt.post_data( data_type, post_data)
		url = tgt.build_url_for_splunk_post(data_type)
		self.assertEqual( url, res[0] )
		self.assertEqual( post_data, res[1] )
		self.assertEqual( username, res[2] )
		self.assertEqual( password, res[3] )
		self.assertIsNone( res[4] )
		headers = {"hdr1":"content"}
		res = tgt.post_data( data_type, post_data, headers)
		url = tgt.build_url_for_splunk_post(data_type)
		self.assertEqual( url, res[0] )
		self.assertEqual( post_data, res[1] )
		self.assertEqual( username, res[2] )
		self.assertEqual( password, res[3] )
		self.assertEqual( headers, res[4] )
		try:
			res = tgt.post_data( data_type, "", headers)
			res = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(res)
		try:
			res = tgt.post_data( data_type, 123, headers)
			res = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(res)

if __name__ =="__main__":
	unittest.main()

