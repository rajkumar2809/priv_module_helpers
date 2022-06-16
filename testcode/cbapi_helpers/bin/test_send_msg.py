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
		self.device_id     = "10463299"
		com = "{}/send_msg.py".format(COM_DIR)
		self.com = '{} {} {}'.format(sys.executable, com, self.customer_name)

	def tearDown(self):
		pass

	def test_com_nonMsg(self):
		com = '{} {}'.format(self.com, self.device_id)
		res = subprocess.check_output(com.split())
		self.assertIsInstance(res, str)
		self.assertTrue(int(res) < 2)

	def test_com_wMsg(self):
		com = '{} {} -message={}'.format(self.com, self.device_id, "testmsg")
		res = subprocess.check_output(com.split())
		self.assertIsInstance(res, str)
		self.assertTrue(int(res) < 2)

if __name__ =="__main__":
	unittest.main()

