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

from priv_module_helpers.report_helpers.mako.analyst_report import stellar as target

class TestReportMakerModule(unittest.TestCase):
	"""test class of ReportMaker in stellar.py
	"""

	def setUp(self):
		testfile = _TESTDIR_+"/stellar.json"
		with open(testfile) as f:
			self.reportdata = json.load(f)
		testfile2 = _TESTDIR_+"/stellar2.json"
		with open(testfile2) as f:
			self.reportdata2 = json.load(f)
		testfile3 = _TESTDIR_+"/stellar_meta1.json"
		with open(testfile3) as f:
			self.reportdata3 = json.load(f)
		testfile4 = _TESTDIR_+"/stellar_meta2.json"
		with open(testfile4) as f:
			self.reportdata4 = json.load(f)
		testfile5 = _TESTDIR_+"/stellar_meta3.json"
		with open(testfile5) as f:
			self.reportdata5 = json.load(f)
		testfile6 = _TESTDIR_+"/stellar_meta4.json"
		with open(testfile6) as f:
			self.reportdata6 = json.load(f)

	def tearDown(self):
		pass

	def test_render(self):
		doc = target.ReportMaker.to_html(self.reportdata)
		self.assertIsInstance(doc, basestring)
		self.reportdata["traffic_type"] = "priv2pub"
		self.reportdata["incident_category"] = "malware-object"
		doc = target.ReportMaker.to_html(self.reportdata)
		self.assertIsInstance(doc, basestring)
		self.reportdata["incident_category"] = "phishing"
		doc = target.ReportMaker.to_html(self.reportdata)
		self.assertIsInstance(doc, basestring)
		self.reportdata["incident_category"] = "ids"
		doc = target.ReportMaker.to_html(self.reportdata)
		self.assertIsInstance(doc, basestring)
		self.reportdata["incident_category"] = "mal_access"
		doc = target.ReportMaker.to_html(self.reportdata)
		self.assertIsInstance(doc, basestring)
		self.reportdata["incident_category"] = "mal_anomaly"
		doc = target.ReportMaker.to_html(self.reportdata)
		self.assertIsInstance(doc, basestring)
		self.reportdata["incident_category"] = "callback"
		doc = target.ReportMaker.to_html(self.reportdata)
		self.assertIsInstance(doc, basestring)
		self.reportdata["traffic_type"] = "not_traffic"
		self.reportdata["incident_category"] = "callback"
		doc = target.ReportMaker.to_html(self.reportdata)
		self.assertIsInstance(doc, basestring)
	
	def test_write(self):
		target.ReportMaker.OUTPUT_DIR = _OUTPUT_DIR
		code = target.ReportMaker.write(self.reportdata, _OUTPUT_DIR+"/output1.html")
		self.assertEqual(code, 0)
		self.reportdata["incident_category"] = "malware-object"
		code = target.ReportMaker.write(self.reportdata, _OUTPUT_DIR+"/output2.html", with_pdf=True)
		self.assertEqual(code, 0)
		htmls = glob.glob(_OUTPUT_DIR+"/*.html")
		self.assertTrue(len(htmls) > 2)
		pdfs = glob.glob(_OUTPUT_DIR+"/*.pdf")
		self.assertEqual(len(pdfs), 1)
		try:
			code = target.ReportMaker.write(self.reportdata, _OUTPUT_DIR+"/nodir/error/output1.html")
			code = 100
		except IOError as e:
			self.assertTrue(True)
		self.assertNotEqual(code, 100)

	def test_write2(self):
		target.ReportMaker.OUTPUT_DIR = _OUTPUT_DIR
		code = target.ReportMaker.write(self.reportdata2, _OUTPUT_DIR+"/output2-1.html", with_pdf=True)
		self.assertEqual(code, 0)

	def test_write3(self):
		target.ReportMaker.OUTPUT_DIR = _OUTPUT_DIR
		code = target.ReportMaker.write(self.reportdata3, _OUTPUT_DIR+"/output3-1.html", with_pdf=True)
		self.assertEqual(code, 0)

	def test_write4(self):
		target.ReportMaker.OUTPUT_DIR = _OUTPUT_DIR
		code = target.ReportMaker.write(self.reportdata4, _OUTPUT_DIR+"/output4-1.html", with_pdf=True)
		self.assertEqual(code, 0)

	def test_write5(self):
		target.ReportMaker.OUTPUT_DIR = _OUTPUT_DIR
		code = target.ReportMaker.write(self.reportdata5, _OUTPUT_DIR+"/output5-1.html", with_pdf=True)
		self.assertEqual(code, 0)

	def test_write6(self):
		target.ReportMaker.OUTPUT_DIR = _OUTPUT_DIR
		code = target.ReportMaker.write(self.reportdata6, _OUTPUT_DIR+"/output6-1.html", with_pdf=True)
		self.assertEqual(code, 0)

class TestEditorMakerModule(unittest.TestCase):
	"""test class of EditorMaker in stellar.py
	"""

	def setUp(self):
		testfile = _TESTDIR_+"/stellar.json"
		with open(testfile) as f:
			self.reportdata = json.load(f)
		testfile = _TESTDIR_+"/stellar2.json"
		with open(testfile) as f:
			self.reportdata2 = json.load(f)

	def tearDown(self):
		pass

	def test_to_html(self):
		doc = target.EditorMaker.to_html(self.reportdata)
		self.assertIsInstance(doc, basestring)
		_fname = _OUTPUT_DIR+"/editor1.html"
		with open(_fname, "w") as f:
			f.write(doc)
		doc = target.EditorMaker.to_html(self.reportdata2)
		self.assertIsInstance(doc, basestring)
		_fname = _OUTPUT_DIR+"/editor2.html"
		with open(_fname, "w") as f:
			f.write(doc)
	
	def test_render(self):
		maker = target.EditorMaker(self.reportdata)
		doc = maker.render()
		self.assertIsInstance(doc, basestring)

if __name__ =="__main__":
	unittest.main()

