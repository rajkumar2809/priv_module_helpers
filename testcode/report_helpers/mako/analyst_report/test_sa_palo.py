# -*- encoding: utf-8

import sys, os
import json, re, glob
import unittest

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
_TESTDIR_ = CURR_DIR+"/../testfile"
_OUTPUT_DIR = CURR_DIR+"/output"
PJ_TOP = CURR_DIR+"/../../.."
sys.path.append(PJ_TOP)

_files = glob.glob(_OUTPUT_DIR+"/*")

for each in _files:
	os.remove(each)

from priv_module_helpers.report_helpers.mako.analyst_report import paloalto_csv as target

class TestPaloaltoReportModule(unittest.TestCase):
	"""test class of ReportMaker in paloalto_csv.py
	"""

	def setUp(self):
		testfile = _TESTDIR_+"/sa_palo.json"
		with open(testfile) as f:
			self.reportdata = json.load(f)

	def tearDown(self):
		pass

	def test_render(self):
		doc = target.ReportMaker.to_html(self.reportdata)
		self.assertIsInstance(doc, basestring)
	
	def test_write(self):
		target.ReportMaker.OUTPUT_DIR = _OUTPUT_DIR
		code = target.ReportMaker.write(self.reportdata, _OUTPUT_DIR+"/output1.html")
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata, _OUTPUT_DIR+"/output2.html", with_pdf=True)
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata, _OUTPUT_DIR+"/output3.html", with_pdf=True, language="en")
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata, _OUTPUT_DIR+"/output4.html", with_pdf=True, sender_name="nvc")
		self.assertEqual(code, 0)
		htmls = glob.glob(_OUTPUT_DIR+"/*.html")
		self.assertTrue(len(htmls) >= 2)
		pdfs = glob.glob(_OUTPUT_DIR+"/*.pdf")
		self.assertEqual(len(pdfs), 3)
		try:
			code = target.ReportMaker.write(self.reportdata, _OUTPUT_DIR+"/nodir/error/output1.html")
			code = 100
		except IOError as e:
			self.assertTrue(True)
		self.assertNotEqual(code, 100)

class TestPaloaltoEditorModule(unittest.TestCase):
	"""test class of ReportMaker in paloalto_csv.py
	"""

	def setUp(self):
		testfile = _TESTDIR_+"/sa_palo.json"
		with open(testfile) as f:
			self.reportdata = json.load(f)

	def tearDown(self):
		pass

	def test_to_html(self):
		doc = target.EditorMaker.to_html(self.reportdata)
		self.assertIsInstance(doc, basestring)
		_fname = _OUTPUT_DIR+"/editor1.html"
		with open(_fname, "w") as f:
			f.write(doc)

	def test_render(self):
		maker = target.EditorMaker(self.reportdata)
		doc = maker.render()
		self.assertIsInstance(doc, basestring)
		_fname = _OUTPUT_DIR+"/editor2.html"
		with open(_fname, "w") as f:
			f.write(doc)
		maker = target.EditorMaker(self.reportdata, language="en")
		doc = maker.render()
		self.assertIsInstance(doc, basestring)
		_fname = _OUTPUT_DIR+"/editor3.html"
		with open(_fname, "w") as f:
			f.write(doc)

if __name__ =="__main__":
	unittest.main()

