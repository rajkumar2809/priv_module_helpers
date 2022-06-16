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
_report_search_files = glob.glob(_TESTDIR_+"/cbreport*.csv")

for each in _files:
	os.remove(each)

from priv_module_helpers.report_helpers.mako.analyst_report import cbdefense as target

class TestReportMaker(unittest.TestCase):
	"""test class of ReportMaker in cbdefense.py
	"""

	def setUp(self):
		testfile = _TESTDIR_+"/cb-alerts.json"
		testfile2 = _TESTDIR_+"/cb-alerts2rep.json"
		testfile3 = _TESTDIR_+"/cbalerts3.json"
		testfile4 = _TESTDIR_+"/cbalerts3rep.json"
		with open(testfile) as f:
			self.reportdata = json.load(f)
		with open(testfile2) as f:
			self.reportdata2 = json.load(f)
		with open(testfile3) as f:
			self.reportdata3 = json.load(f)
		with open(testfile4) as f:
			self.reportdata4 = json.load(f)

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
		code = target.ReportMaker.write(self.reportdata, _OUTPUT_DIR+"/output3.html", with_pdf=True, sender_name="nvc")
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata, _OUTPUT_DIR+"/output4.html", with_pdf=True, sender_name="nvc", language="en") #TODO change to en
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata2, _OUTPUT_DIR+"/output5.html", with_pdf=True)
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata3, _OUTPUT_DIR+"/output6.html", with_pdf=True, sender_name="dh")
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata4, _OUTPUT_DIR+"/output7.html", with_pdf=True, sender_name="dh")
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata, _OUTPUT_DIR+"/output-nos1.html", with_pdf=True, sender_name="nos")
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata, _OUTPUT_DIR+"/output-kop1.html", with_pdf=True, sender_name="kop")
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata, _OUTPUT_DIR+"/output-kop2.html", with_pdf=True, sender_name="kop", language="en")
		self.assertEqual(code, 0)
		htmls = glob.glob(_OUTPUT_DIR+"/*.html")
		self.assertTrue(len(htmls) >= 6)
		pdfs = glob.glob(_OUTPUT_DIR+"/*.pdf")
		self.assertTrue(len(pdfs) >= 9)
		try:
			code = target.ReportMaker.write(self.reportdata, _OUTPUT_DIR+"/nodir/error/output0.html")
			code = 100
		except IOError as e:
			self.assertTrue(True)
		self.assertNotEqual(code, 100)

class TestEditorMaker(unittest.TestCase):
	"""test class of EditorMaker in cbdefense.py
	"""

	def setUp(self):
		testfile1 = _TESTDIR_+"/cb-alerts.json"
		with open(testfile1) as f:
			self.reportdata1 = json.load(f)
		testfile2 = _TESTDIR_+"/cb-alerts2edt.json"
		with open(testfile2) as f:
			self.reportdata2 = json.load(f)
		with open(testfile2) as f:
			self.reportdata3 = json.load(f)
		rawdata = _TESTDIR_+"/cbalerts_raw.json"
		with open(rawdata) as f:
			self.reportdata3["_raw"]=f.read().strip()

	def tearDown(self):
		pass

	def test_render(self):
		doc = target.EditorMaker.to_html(self.reportdata1)
		self.assertIsInstance(doc, basestring)
		_fname = _OUTPUT_DIR+"/editor1.html"
		with open(_fname, "w") as f:
			f.write(doc)
		maker = target.EditorMaker(self.reportdata2)
		doc = maker.render()
		self.assertIsInstance(doc, basestring)
		_fname = _OUTPUT_DIR+"/editor2.html"
		with open(_fname, "w") as f:
			f.write(doc)
		doc = target.EditorMaker.to_html(self.reportdata3, language="en")
		self.assertIsInstance(doc, basestring)
		_fname = _OUTPUT_DIR+"/editor3.html"
		with open(_fname, "w") as f:
			f.write(doc)

if __name__ =="__main__":
	unittest.main()

