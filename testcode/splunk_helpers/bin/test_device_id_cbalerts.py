import sys, os, json
import unittest
from glob import glob
import json
import subprocess

from priv_module_helpers.splunk_helpers import splunk_alert_searcher as _splunk
_splunk._CONF = "test.json"

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/../../.."
sys.path.append(PJ_TOP)
COM_DIR = PJ_TOP+"/splunk_helpers/bin"

#from priv_module_helpers.cbapi_helpers.bin import search_device as target

class TestSearchDeviceModule(unittest.TestCase):
	"""test class of device_id_cbalerts.py
	"""

	def setUp(self):
		self.customer_name = "YSN1"
		self.device_id = "12951938"
		self.timerange = 600
		com = "{}/device_id_cbalerts.py".format(COM_DIR)
		self.com = '{} {} {}'.format(sys.executable, com, self.customer_name)

	def tearDown(self):
		pass

	def test_com_wDevId1(self):
		com = '{} {} -cfg_name=test'.format(self.com, self.device_id)
		res = subprocess.check_output(com.split())
		self.assertIsInstance(res, str)
		info = json.loads(res)
		self.assertIsInstance(info, list)

	def test_com_wDevId2(self):
		com = '{} {} -cfg_name=test'.format(self.com, "00000000")
		res = subprocess.check_output(com.split())
		self.assertIsInstance(res, str)
		info = json.loads(res)
		self.assertIsInstance(info, list)
		self.assertEqual(len(info), 0)

	def test_com_wMulti1(self):
		com = '{} {} -timerange={} -cfg_name=test'.format(
			self.com, self.device_id, self.timerange)
		res = subprocess.check_output(com.split())
		self.assertIsInstance(res, str)
		info = json.loads(res)
		self.assertIsInstance(info, list)

	def test_com_NG(self):
		com = '{} {} -timerange={}'.format(
			self.com, self.device_id, self.timerange)
		res = subprocess.check_output(com.split())
		self.assertIsInstance(res, str)
		self.assertEqual(res.strip(), "1")

if __name__ =="__main__":
	unittest.main()

