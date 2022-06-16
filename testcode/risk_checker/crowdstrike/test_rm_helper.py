# -*- encoding:utf-8

import sys, os, json, glob
import unittest, logging

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )

PJ_TOP = CURR_DIR+"/../../../risk_checker/cbdefense"
sys.path.append(PJ_TOP)

import rm_helper as target

_CONF_PATH = CURR_DIR+"/config"
_CONF = _CONF_PATH+"/test_rm_helper.json"

_TEST_DIR = CURR_DIR+"/testdata/rm_helper"
_TEST_FILEs = _TEST_DIR+"/*.json"

class TestRmHelperModule(unittest.TestCase):

	def setUp(self):
		with open(_CONF) as f:
			self.config = json.load(f)["redmine"]
		self.testdata = []
		for each in glob.glob(_TEST_FILEs):
			with open(each) as f:
				self.testdata.append( (each, json.load(f)) )

	def tearDown(self):
		pass

	def test_get_ticket_idlist(self):
		testdata = self.testdata[0][1]
		alert_id = testdata["alert_summary"]["alert_id"]
		idlist = target.get_ticket_idlist(self.config, alert_id)
		self.assertTrue(len(idlist) is not 0)

	def test_update_redmine_ticket(self):
		for each in self.testdata:
			testdata = each[1]
			alert_id = testdata["alert_summary"]["alert_id"]
			idlist = target.get_ticket_idlist(self.config, alert_id)
			self.assertTrue(len(idlist) is not 0, "ticket not exist")
			if testdata["alert_summary"]["alert_type"] == "malware":
				result = self._make_result(flag=True, is_gray=False)
			else:
				result = self._make_result()
			res = target.update_redmine_ticket( self.config,
				idlist, testdata, result, "http://testfuagfuga" )
	
	def test_issue_redmine_ticket(self):
		for each in self.testdata:
			testdata = each[1]
			target._issue_redmine_ticket(self.config, testdata)

	# private

	def _make_result(self, flag=False, is_gray=True,
			correct_severity=None, message="test_message"):
		if isinstance(message, basestring):
			message = [ message ]
		return {"flag"    : flag,
				"is_gray" : is_gray,
				"message" : message,
				"correct_severity" : correct_severity }


if __name__ =="__main__":
	logging.basicConfig(level=logging.DEBUG)
	unittest.main()

