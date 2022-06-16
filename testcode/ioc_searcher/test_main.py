import sys, os, json, logging
import unittest
from glob import glob
import json

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
PJ_TOP = CURR_DIR+"/../.."
sys.path.append(PJ_TOP)

from priv_module_helpers.ioc_searcher import main as target

_TEST_HASH = [
	"0000000000000000000000000000000000000000000000000000000000000000",
	"90b2d35cd5e08370ed20db81197dd9da1a4dbb421f71293fd5733ea49eb7b3e1",
	"222a65557214bb435a3cacc0956fbe233533b935fbb51d6bdad2b314859cda4a"
]

_TEST_ADDR = [
	"1.1.1.1",
	"52.218.106.116",
	"52.218.108.44"
]

_TEST_DOMAIN = [
	"hmamail.com", 
	"droptop6.com"
]

class TestCyfirmaSeacherModule(unittest.TestCase):
	"""test class of cyfirma_searcher.py
	"""

	def setUp(self):
		self.cyfirma = target.IocChecker()

	def tearDown(self):
		pass

	def test_check_hashes(self):
		results = self.cyfirma.check_hashes(_TEST_HASH)
		results = self.cyfirma.check_hashes(_TEST_HASH)

	def test_check_ipv4(self):
		results = self.cyfirma.check_ipv4(_TEST_ADDR)
		results = self.cyfirma.check_ipv4(_TEST_ADDR)

	def test_check_domains(self):
		results = self.cyfirma.check_domains(_TEST_DOMAIN)
		results = self.cyfirma.check_domains(_TEST_DOMAIN)

if __name__ =="__main__":
	logging.basicConfig(level=logging.DEBUG)
	unittest.main()

