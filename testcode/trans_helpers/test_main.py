# -*- coding: utf-8 -*-

import sys, os, json
import unittest

PJ_TOP = os.path.dirname( os.path.abspath(__file__) )+"/../../"
sys.path.append(PJ_TOP)

from priv_module_helpers.trans_helpers import main as target

class TestTransHelpersModule(unittest.TestCase):
	"""test class of main.py trans_helpers 
	"""

	def setUp(self):
		pass

	def tearDown(self):
		pass

	def test_trans(self):
		result = target.trans_en2ja("this is test. love is over")
		print result
		self.assertIsInstance(result, unicode)
		self.assertIn(u"テスト", result)
		self.assertIn(u"愛は終わった", result)

if __name__ =="__main__":
	unittest.main()

