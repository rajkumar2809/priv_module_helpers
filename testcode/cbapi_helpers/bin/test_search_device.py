import sys, os, json
import unittest
from glob import glob
import json
import subprocess

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/../../.."
sys.path.append(PJ_TOP)
COM_DIR = PJ_TOP+"/cbapi_helpers/bin"

#from priv_module_helpers.cbapi_helpers.bin import search_device as target

class TestSearchDeviceModule(unittest.TestCase):
	"""test class of search_device.py
	"""

	def setUp(self):
		self.customer_name = "DGH1"
		self.ipaddr = "192.168.129.154"
		self.hostname = "yokoNoMacBook"
		com = "{}/search_device.py".format(COM_DIR)
		self.com = '{} {} {}'.format(sys.executable, com, self.customer_name)

	def tearDown(self):
		pass

	def test_com_nonArg(self):
		com = '{}'.format(self.com)
		res = subprocess.check_output(com.split())
		self.assertIsInstance(res, str)
		info = json.loads(res)
		for each in info:
			self.assertIn("policy",      each)
			self.assertIn("device_id",   each)
			self.assertIn("device_name", each)
		self.assertIsInstance(info, list)

	def test_com_wIp(self):
		com = '{} -ipaddr={}'.format(self.com, self.ipaddr)
		res = subprocess.check_output(com.split())
		self.assertIsInstance(res, str)
		info = json.loads(res)
		self.assertIsInstance(info, list)

	def test_com_wName(self):
		com = '{} -hostname={}'.format(self.com, self.hostname)
		res = subprocess.check_output(com.split())
		self.assertIsInstance(res, str)
		info = json.loads(res)
		self.assertIsInstance(info, list)

	def test_com_wName2(self):
		com = '{} -hostname={}'.format(self.com, "KonnaYatsu-Ha-Inai")
		res = subprocess.check_output(com.split())
		self.assertIsInstance(res, str)
		info = json.loads(res)
		self.assertIsInstance(info, list)
		self.assertEqual(len(info), 0)

if __name__ =="__main__":
	unittest.main()

