import sys, os, json
import unittest
from glob import glob
import json

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/../../.."
sys.path.append(PJ_TOP)

#_TESTDATA_  = CURR_DIR+"/testfile/testdata.json"
_TESTALERT_  = CURR_DIR+"/testfile/cbapi_alert.json"
_TESTALERT_2  = CURR_DIR+"/testfile/cbapi_alert_blacklist.json"
_TESTALERT_3  = CURR_DIR+"/testfile/cbapi_alert_blacklist2.json"
_TESTEVENT_SIMPLE_ = CURR_DIR+"/testfile/raw-event-simple.json"
_TESTEVENT_ = CURR_DIR+"/testfile/event_api.json"

from priv_module_helpers.cbapi_helpers.v6_api import cb_api_helper as target

class TestCbApiHelperModule(unittest.TestCase):
	"""test class of cbapi_helper.py
	"""

	def setUp(self):
		with open(_TESTALERT_) as f:
			self.test_alert = json.load(f)
		with open(_TESTALERT_2) as f:
			self.test_alert2 = json.load(f)
		with open(_TESTALERT_3) as f:
			self.test_alert3 = json.load(f)
		with open(_TESTEVENT_SIMPLE_) as f:
			self.test_events = json.load(f)

	def tearDown(self):
		pass

	def test_parse_alert(self):
		alert = target._parse_alert(self.test_alert)
		self._check_each_alert(alert)
		alert = target._parse_alert(self.test_alert2)
		self._check_each_alert(alert)
		alert = target._parse_alert(self.test_alert3)
		self._check_each_alert(alert)
#		with open("cbapi-blacklist2.json", "w") as wf:
#			json.dump(alert, wf, indent=4)

	def _check_each_alert(self, alert):
		self.assertIn("alerted_process", alert)
		self.assertIn("incident_id", alert)
		self.assertIn("threat_cause_actor_name", alert)
		self.assertIn("threat_cause_vector", alert)
		self.assertIn("attack_phase", alert)
		self.assertIn("threat_cause_reputation", alert)
		self.assertIn("threat_cause_event_id", alert)
		self.assertIn("occurred", alert)
		self.assertIn("summary", alert)
		self.assertIn("score", alert)
		self.assertIn("malicious_activity", alert)
		self.assertIn("network_access", alert)
		self.assertIn("threat_cause_category", alert)
		self.assertIn("threat_cause_actor_sha256", alert)
		self.assertIn("malware_info", alert)
		self.assertIn("category", alert)
		self.assertIn("events", alert)
		self.assertIn("categories", alert)

		self.assertTrue(isinstance(alert["malicious_activity"], list))
		self.assertTrue(isinstance(alert["network_access"], list))
		self.assertTrue(isinstance(alert["threat_cause_category"], basestring))
		self.assertTrue(isinstance(alert["threat_cause_actor_sha256"], basestring))
		self.assertTrue(isinstance(alert["malware_info"], list))
		self.assertTrue(isinstance(alert["category"], basestring))
		self.assertTrue(isinstance(alert["events"], list))
		self.assertTrue(isinstance(alert["categories"], list))

	def test_parse_app_detail(self):
		alert = target._parse_alert(self.test_alert)
		result = target._parse_app_detail(alert["events"])
		for each in result:
			for ev in each["events"]:
				self.assertIn("event_id", ev)
				self.assertIsInstance(ev["event_id"], list)
				self.assertIn("occurred", ev)
				self.assertIsInstance(ev["occurred"], list)
				self.assertIn("runuser", ev)
				self.assertIn("event_summary", ev)
				self.assertIn("event_detail", ev)
				self.assertIn("description", ev)
				self.assertIn("raw_ev_type", ev)
				self.assertIn("ev_type", ev)
				self.assertIn("attack_phase", ev)
			ps = each["process_info"]
			self.assertIn("parent_name", ps)
			self.assertIn("parent_hash", ps)
			self.assertIn("parent_command_line", ps)
			self.assertIn("parent_pid", ps)
			self.assertIn("hash", ps)
			self.assertIn("path", ps)
			self.assertIn("command_line", ps)
			self.assertIn("pid", ps)
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

	def test_sammarize_alert(self):
		raw_alert = target._parse_alert(self.test_alert)
		alert = target.sammarize_alert(raw_alert)
		self.assertEqual(5, alert["event_num"])

	def test_sammarize_events_process_list(self):
		events = [ target.parser.CbApiMapToEvent(each).to_dict() for each in self.test_events["results"] ]
		pslist = target.sammarize_events_process_list(events)
		self.assertEqual(35, len(pslist))
		self.assertIsInstance(pslist, dict)
		for pspid, info in pslist.items():
			self.assertTrue(len(pspid)>68)
			self.assertIn("process", info)
			self.assertIn("parent_process", info)
			self.assertIn("runuser", info)
			self.assertIn("categories", info)
			self.assertIn("ev_type", info)

	def test_sammarize_each_process(self):
		events = [ target.parser.CbApiMapToEvent(each).to_dict() for each in self.test_events["results"] ]
		for each in events:
			ps = target.sammarize_each_process(each)
			self.assertIsInstance(ps, dict)

	def test_sammarize_events(self):
		events = [ target.parser.CbApiMapToEvent(each).to_dict() for each in self.test_events["results"] ]
		self.assertEqual(100, len(events))

	def test_sammarize_each_event(self):
		events = [ target.parser.CbApiMapToEvent(each).to_dict() for each in self.test_events["results"] ]
		for each in events:
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

