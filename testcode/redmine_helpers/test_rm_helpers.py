# -*- encoding: utf-8 -*-

import sys, os, json
import unittest

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/../../"
sys.path.append(PJ_TOP)

_CONF_DIR = CURR_DIR+"/config"
_CONF = _CONF_DIR+"/test.json"

from redmine_helpers import rm_helpers as target
import mock_rm_util as rm_util
from monkey_tools.utils import rm_util as correct_rm_util
target.rm_util = rm_util

test_with_redmine_access=True
_CLOSED_TICKET_ = "PWZLAMQB"
_OPENED_TICKET_ = "E2QKDIAC"
_NX_OPENED_TICKET_ = "71326"

class TestRmHelperModule(unittest.TestCase):
	"""test class of rm_helpers.py
	"""

	def setUp(self):
		rm_util.clear_call_history()
		target.rm_util = rm_util

	def tearDown(self):
		pass

	def test_set_cfg_file(self):
		rm = target.RmHelper
		rm.set_cfg_file(_CONF)
		self.assertEqual(rm._CONF, _CONF)
		try:
			rm.set_cfg_file("unexist.json")
			rm = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(rm)

	def test_init_by_cfg_file(self):
		with open(_CONF, "r") as f:
			cfg = json.load(f)
		rm = target.RmHelper.init_by_cfg_file(_CONF)
		con = rm.connector
		self.assertEqual(cfg["url"], con.url)
		self.assertEqual(cfg["username"], con.username)
		self.assertEqual(cfg["password"], con.password)
		self.assertEqual(cfg["project_name"], con.project_name)
		self.assertEqual(cfg["custom_fields"], rm.custom_fields_id)
		self.assertEqual(cfg["project"], rm.project_info)
		self.assertEqual(cfg["description"], rm.description_column)

	def test___init__(self):
		with open(_CONF, "r") as f:
			cfg = json.load(f)
		rm = target.RmHelper(**cfg)
		con = rm.connector
		self.assertEqual(cfg["url"], con.url)
		self.assertEqual(cfg["username"], con.username)
		self.assertEqual(cfg["password"], con.password)
		self.assertEqual(cfg["project_name"], con.project_name)
		self.assertEqual(cfg["custom_fields"], rm.custom_fields_id)
		self.assertEqual(cfg["project"], rm.project_info)
		self.assertEqual(cfg["description"], rm.description_column)
		url, user, pswd, pjname = cfg["url"], cfg["username"], cfg["password"], cfg["project_name"]
		rm = target.RmHelper(url, user, pswd, pjname, project={}, custom_fields={}, description={})
		self.assertEqual(0, len(rm.project_info))
		self.assertEqual(0, len(rm.custom_fields_id))
		self.assertEqual(0, len(rm.description_column))
		rm = target.RmHelper(url, user, pswd, pjname, project={"subject" : "testdata" }, custom_fields={1 : "hoge"}, description={u"テスト" : "fuga"})
		self.assertEqual(1, len(rm.project_info))
		self.assertEqual(1, len(rm.custom_fields_id))
		self.assertEqual(1, len(rm.description_column))

		try:
			rm = target.RmHelper(url, user, pswd, pjname, custom_fields={}, description={})
			rm = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(rm)
		try:
			rm = target.RmHelper(url, user, pswd, pjname, project={}, description={})
			rm = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(rm)
		try:
			rm = target.RmHelper(url, user, pswd, pjname, project={}, custom_fields={})
			rm = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(rm)

	def test_add_project_info(self):
		with open(_CONF, "r") as f:
			cfg = json.load(f)
		url, user, pswd, pjname = cfg["url"], cfg["username"], cfg["password"], cfg["project_name"]
		rm = target.RmHelper(url, user, pswd, pjname, project={}, custom_fields={}, description={})
		rm.add_project_info("fuga", "hoge")
		self.assertEqual(1, len(rm.project_info))
		rm.add_project_info("hoge", "hogehoge")
		self.assertEqual(2, len(rm.project_info))
		rm.add_project_info("hoge", "2nd")
		self.assertEqual(2, len(rm.project_info))
		rm.add_project_info(1, "1 no value")
		self.assertEqual(3, len(rm.project_info))
		rm.add_project_info("1", "1 no value")
		self.assertEqual(3, len(rm.project_info))
		rm.add_project_info((1,2,3), "tuple value")
		self.assertEqual(4, len(rm.project_info))
		rm.add_project_info((1,3,2), "tuple value")
		self.assertEqual(5, len(rm.project_info))
		for i in range(0, 100):
			rm.add_project_info("No:{}".format(i), i)
		self.assertEqual(105, len(rm.project_info))

	def test_add_custom_field(self):
		with open(_CONF, "r") as f:
			cfg = json.load(f)
		url, user, pswd, pjname = cfg["url"], cfg["username"], cfg["password"], cfg["project_name"]
		rm = target.RmHelper(url, user, pswd, pjname, project={}, custom_fields={}, description={})
		name, value, _id = "name", "value", 99
		rm.custom_fields_id[name] = _id
		rm.add_custom_field(name, value)
		self.assertIn(name, rm.custom_fields)
		self.assertEqual(rm.custom_fields[name]["value"], value)
		self.assertEqual(rm.custom_fields[name]["id"], _id)
		name, value, _id = "name2", "value2", 1000
		rm.add_custom_field(name, value, _id)
		self.assertIn(name, rm.custom_fields)
		self.assertEqual(rm.custom_fields[name]["value"], value)
		self.assertEqual(rm.custom_fields[name]["id"], _id)
		try:
			rm.add_custom_field("unexist", "value")
			rm = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(rm)

	def test_add_description(self):
		with open(_CONF, "r") as f:
			cfg = json.load(f)
		url, user, pswd, pjname = cfg["url"], cfg["username"], cfg["password"], cfg["project_name"]
		rm = target.RmHelper(url, user, pswd, pjname, project={}, custom_fields={}, description={})
		name, value, column = "name", "value", "column"
		rm.description_column[name] = column
		rm.add_description(name, value)
		each = rm.description[0]
		self.assertEqual(each["name"], column)
		self.assertEqual(each["value"], value)
		name, value, column = "name", "value", "column"
		rm.description_column[name] = column
		rm.add_description(name, value)
		each = rm.description[1]
		self.assertEqual(each["name"], column)
		self.assertEqual(each["value"], value)
		name, value, column = "name2", "value2", "column2"
		rm.add_description(name, value, column)
		each = rm.description[2]
		self.assertEqual(each["name"], column)
		self.assertEqual(each["value"], value)
		try:
			rm.add_description("unexist", "fuga")
			rm = None
		except AssertionError as e:
			self.assertTrue(True)
		self.assertIsNotNone(rm)

	def test_issue_ticket(self):
		with open(_CONF, "r") as f:
			cfg = json.load(f)
		rm = target.RmHelper(**cfg)
		rm.issue_ticket()
		res = rm_util._COM_[0]
		self.assertEqual(res["method"], "save")
		self.assertEqual(18, res["tracker_id"])
		self.assertEqual("CbDefense Threat Alert", res["subject"])
		self.assertEqual(0, len(res["custom_fields"]))
		self.assertEqual(0, len(res["description"]))
		self.assertEqual(1, len(res["project_info"]))

		rm.add_description("fuga", "hoge", "column")
		rm.add_project_info("fuga", "hoge")
		rm.add_custom_field("fuga", "hoge", 100)
		rm.issue_ticket()
		res = rm_util._COM_[1]
		self.assertEqual(1, len(res["custom_fields"]))
		self.assertEqual(1, len(res["description"]))
		self.assertEqual(2, len(res["project_info"]))

	def test_search_ticket(self):
		with open(_CONF, "r") as f:
			cfg = json.load(f)
		rm = target.RmHelper(**cfg)
		con = rm_util.RedmineConnector
		_cfid, _value = con._CFID_, con._CFVALUE_
		_ticket_id = rm.search_ticket(_value, _cfid)
		self.assertTrue(_ticket_id, con._TICKETID_)
		_ticket_id  = rm.search_ticket("unexist", 123)
		self.assertIsNone(_ticket_id)

	def test_init_for(self):
		if test_with_redmine_access:
			target.rm_util = correct_rm_util
			rm = target.FireeyeNxRmHelper.init_for("splunk-test.dhsoc.jp", "fireeye_nx")
			result = rm.get_ticket_idlist(_NX_OPENED_TICKET_, 5, status="closed")
			self.assertTrue( len(result) is 1)
			rm = target.FireeyeNxRmHelper.init_for("splunk-test.dhsoc.jp", "fireeye_nx")
			result = rm.get_ticket_idlist(_NX_OPENED_TICKET_, 5)
			self.assertTrue( len(result) is 0)
			rm = target.FireeyeNxRmHelper.init_for("splunk-test.dhsoc.jp", "fireeye_nx")
			result = rm.get_ticket_idlist(_NX_OPENED_TICKET_, status="*")
			self.assertTrue( len(result) is 1)
			rm = target.FireeyeNxRmHelper.init_for("splunk-test.dhsoc.jp")
			result = rm.get_ticket_idlist(_NX_OPENED_TICKET_)
			self.assertTrue( len(result) is 0)
			target.rm_util = rm_util

	def test_search_ticket_cbdefense1(self):
		if test_with_redmine_access:
			target.rm_util = correct_rm_util
			rm = target.init_for_cbdefense("splunk-test.dhsoc.jp")
			result = rm.get_ticket_idlist(_OPENED_TICKET_, status="closed")
			self.assertTrue( len(result) is 0)
			target.rm_util = rm_util

	def test_search_ticket_cbdefense2(self):
		if test_with_redmine_access:
			target.rm_util = correct_rm_util
			rm = target.init_for_cbdefense("splunk-test.dhsoc.jp")
			result = rm.get_ticket_idlist(_OPENED_TICKET_)
			self.assertTrue( len(result) is 1)
			rm = target.init_for_cbdefense("splunk-test.dhsoc.jp")
			result = rm.get_ticket_idlist(_CLOSED_TICKET_, status="*")
			self.assertTrue( len(result) is 1)
			rm = target.init_for_cbdefense("splunk-test.dhsoc.jp")
			result = rm.get_ticket_idlist(_CLOSED_TICKET_)
			self.assertTrue( len(result) is 0)
			rm = target.init_for_cbdefense("splunk-test.dhsoc.jp")
			result = rm.get_ticket_idlist(_CLOSED_TICKET_, status="1")
			self.assertTrue( len(result) is 0)
			target.rm_util = rm_util

	def test_update_ticket(self):
		with open(_CONF, "r") as f:
			cfg = json.load(f)
		rm = target.RmHelper(**cfg)
		_id, notes = 123, "update_note"
		rm.update_ticket(_id, notes)
		res = rm_util._COM_[0]
		self.assertEqual(res["method"], "update")
		self.assertEqual(res["ticket_id"], _id)
		self.assertEqual(res["update_notes"], notes)
		self.assertEqual(0, len(res["custom_fields"]))
		self.assertEqual(0, len(res["description"]))
		self.assertEqual(1, len(res["project_info"]))
		rm.add_custom_field("fuga", "hoge", 100)
		rm.update_ticket(_id, notes)
		res = rm_util._COM_[1]
		self.assertEqual(1, len(res["custom_fields"]))
		rm.update_ticket(_id, notes, 3)
		res = rm_util._COM_[2]
		pjinfo = res["project_info"]
		self.assertEqual(pjinfo["status_id"], 3)

if __name__ =="__main__":
	unittest.main()

