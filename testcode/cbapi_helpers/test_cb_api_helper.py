import sys, os, json
import unittest
from glob import glob
import json

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/../.."
sys.path.append(PJ_TOP)

_TESTDATA_  = CURR_DIR+"/testfile/testdata.json"
_TESTALERT_ = CURR_DIR+"/testfile/cbapi_alert.json"
_TESTEVENT_ = CURR_DIR+"/testfile/event_api.json"

from priv_module_helpers.cbapi_helpers import cb_api_helper as target

class TestCbApiHelperModule(unittest.TestCase):
	"""test class of cbapi_helper.py
	"""

	def setUp(self):
		with open(_TESTDATA_) as f:
			self.testdata_events = json.load(f)
		with open(_TESTALERT_) as f:
			self.test_alert = json.load(f)

	def tearDown(self):
		pass

	def test_parse_app_detail(self):
		result = target._parse_app_detail(self.testdata_events["events"])
		for each in result:
			for ev in each["events"]:
				self.assertIn("event_id", ev)
				self.assertIsInstance(ev["event_id"], list)
				self.assertIn("occurred", ev)
				self.assertIsInstance(ev["occurred"], list)
				self.assertIn("runuser", ev)
		try:
			res = json.dumps(result[0], indent=4)
		except Exception as e:
			print e.message
			self.assertTrue(False, "unexpected Exception")
		self.assertIsNotNone(res)

	def test_get_device_list(self):
		api = target.init_by_cfg_file("DGH1")
		result = api.get_device_list()
		self.assertIsInstance( result, list )
		self.assertTrue( len(result) > 0 )
		each = result[0]
		self.assertIn( "ip",        each)
		self.assertIn( "hostname",  each)
		self.assertIn( "policy",    each)
		self.assertIn( "device_id", each)
		self.assertIn( "username",  each)
		self.assertIn( "priority",  each)
		ip = each["ip"]
		hostname = each["hostname"]
		result = api.get_device_list(ip_addr=ip)
		self.assertTrue( len(result) > 0 )
		result = api.get_device_list(host_name=hostname)
		self.assertTrue( len(result) > 0 )

	def test_parse_alert(self):
		raw_alert = target._parse_alert(self.test_alert)
		threat = self.test_alert["threatInfo"]
		self.assertEqual(raw_alert["incident_id"], threat["incidentId"])

	def test_sammarize_alert(self):
		raw_alert = target._parse_alert(self.test_alert)
		alert = target.sammarize_alert(raw_alert)
		self.assertEqual(1, alert["event_num"])

	def test_sammarize_events_process_list(self):
		raw_alert = target._parse_alert(self.test_alert)
		pslist = target.sammarize_events_process_list(raw_alert["events"])
		self.assertIn("233", pslist)
		self.assertEqual(1, len(pslist))

	def test_sammarize_each_process(self):
		raw_alert = target._parse_alert(self.test_alert)
		for each in raw_alert["events"]:
			ps = target.sammarize_each_process(each)
			self.assertIsInstance(ps, dict)

	def test_sammarize_events(self):
		raw_alert = target._parse_alert(self.test_alert)
		events = target.sammarize_events(raw_alert["events"])
		self.assertEqual(1, len(events))

	def test_sammarize_each_event(self):
		raw_alert = target._parse_alert(self.test_alert)
		for each in raw_alert["events"]:
			ev = target.sammarize_each_event(each)
			self.assertIsInstance(ev, dict)
	
	def test_sammarize_event_detail(self):
		with open(_TESTEVENT_) as f:
			data = json.load(f)
		res = target.sammarize_event_detail(data)
		for k, v in res.items():
			self.assertIsInstance(v, list)
			for each in v:
				self.assertIsInstance(each, basestring)
			self.assertIsInstance(k, basestring)

	def test_quarantine(self):
		api = target.init_by_cfg_file("DGH1", api_type="ex")
		try:
			api.quarantine("99999999")
		except IOError as e:
			self.assertTrue(True)
		try:
			api.quarantine("0")
		except IOError as e:
			self.assertTrue(True)
		self.assertTrue(True)

if __name__ =="__main__":
	unittest.main()

