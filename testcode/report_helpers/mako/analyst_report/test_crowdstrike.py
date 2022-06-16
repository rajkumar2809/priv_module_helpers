# -*- encoding: utf-8

import sys, os
import json, re, glob
import unittest

from monkey_tools.utils import file_util

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
_TESTDIR_ = CURR_DIR+"/../testfile"
_OUTPUT_DIR = CURR_DIR+"/output"
PJ_TOP = CURR_DIR+"/../../.."
sys.path.append(PJ_TOP)

_files = glob.glob(_OUTPUT_DIR+"/*")
_report_search_files = glob.glob(_TESTDIR_+"/csalert*.csv")

for each in _files:
	os.remove(each)

from priv_module_helpers.report_helpers.mako.analyst_report import crowdstrike as target

class TestReportMaker(unittest.TestCase):
	"""test class of ReportMaker in crowdstrike.py
	"""

	def setUp(self):
		testfile = _TESTDIR_+"/csalert{}.json"
		with open(testfile.format("1")) as f:
			self.reportdata1 = json.load(f)

	def tearDown(self):
		pass

	def test_render(self):
		doc = target.ReportMaker.to_html(self.reportdata1)
		self.assertIsInstance(doc, basestring)
	
	def test_write(self):
		target.ReportMaker.OUTPUT_DIR = _OUTPUT_DIR
		target.ReportMaker.SPLITER = "\n"
		code = target.ReportMaker.write(self.reportdata1, _OUTPUT_DIR+"/output1.html")
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata1, _OUTPUT_DIR+"/output2.html", with_pdf=True)
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata1, _OUTPUT_DIR+"/output3.html", with_pdf=True, sender_name="nvc")
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata1, _OUTPUT_DIR+"/output4.html", with_pdf=True, sender_name="nvc", language="en") #TODO change to en
		self.assertEqual(code, 0)
		htmls = glob.glob(_OUTPUT_DIR+"/*.html")
		self.assertTrue(len(htmls) >= 3)
		pdfs = glob.glob(_OUTPUT_DIR+"/*.pdf")
		self.assertEqual(len(pdfs), 3)
		try:
			code = target.ReportMaker.write(self.reportdata1, _OUTPUT_DIR+"/nodir/error/output0.html")
			code = 100
		except IOError as e:
			self.assertTrue(True)
		self.assertNotEqual(code, 100)

class TestEditorMaker(unittest.TestCase):
	"""test class of EditorMaker in crowdstrike.py
	"""

	def setUp(self):
		testfile = _TESTDIR_+"/csalert{}.json"
		with open(testfile.format("1")) as f:
			self.reportdata1 = json.load(f)

	def tearDown(self):
		pass

	def test_render(self):
		doc = target.EditorMaker.to_html(self.reportdata1)
		self.write_file(doc, _OUTPUT_DIR+"/editor1.html")
		self.assertIsInstance(doc, basestring)
	
	def write_file(self, doc, filename):
		self.assertIsInstance(doc, basestring)
		with open(filename, "w") as f:
			f.write(doc)

if __name__ =="__main__":
	unittest.main()

