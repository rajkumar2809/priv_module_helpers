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
_report_search_files = glob.glob(_TESTDIR_+"/cb_v6/*.csv")

for each in _files:
	os.remove(each)

from priv_module_helpers.report_helpers.mako.analyst_report import cbdefense as target

class TestReportMaker(unittest.TestCase):
	"""test class of ReportMaker in cbdefense.py
	"""

	def setUp(self):
		self.reportdata = []
		for fname in _report_search_files:
			reports = file_util.parse_csv(fname)
			for each in reports:
				self.reportdata.append(each)
		print len(self.reportdata)

	def tearDown(self):
		pass

	def test_render(self):
		each = self.reportdata[0]
		doc = target.ReportMaker.to_html(each)
		self.assertIsInstance(doc, basestring)
	
	def test_write(self):
		target.ReportMaker.OUTPUT_DIR = _OUTPUT_DIR
		for each in self.reportdata:
			alert_id = each["incident_id"]
			print "test at {}".format(alert_id)
			code = target.ReportMaker.write(each, _OUTPUT_DIR+"/{}.html".format(alert_id))
			self.assertEqual(code, 0)
			code = target.ReportMaker.write(each, _OUTPUT_DIR+"/{}.html".format(alert_id), with_pdf=True)
			self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata[0], _OUTPUT_DIR+"/output1.html")
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata[0], _OUTPUT_DIR+"/output2.html", with_pdf=True)
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata[0], _OUTPUT_DIR+"/output3.html", with_pdf=True, sender_name="nvc")
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata[0], _OUTPUT_DIR+"/output4.html", with_pdf=True, sender_name="nvc", language="en") #TODO change to en
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata[1], _OUTPUT_DIR+"/output5.html", with_pdf=True)
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata[2], _OUTPUT_DIR+"/output6.html", with_pdf=True, sender_name="dh")
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata[3], _OUTPUT_DIR+"/output7.html", with_pdf=True, sender_name="dh")
		self.assertEqual(code, 0)
		code = target.ReportMaker.write(self.reportdata[3], _OUTPUT_DIR+"/output8.html", with_pdf=True, sender_name="his")
		self.assertEqual(code, 0)
		htmls = glob.glob(_OUTPUT_DIR+"/*.html")
		self.assertTrue(len(htmls) >= 6)
		pdfs = glob.glob(_OUTPUT_DIR+"/*.pdf")
		self.assertTrue(len(pdfs) >= 6)
		try:
			code = target.ReportMaker.write(self.reportdata[0], _OUTPUT_DIR+"/nodir/error/output0.html")
			code = 100
		except IOError as e:
			self.assertTrue(True)
		self.assertNotEqual(code, 100)

class TestEditorMaker(unittest.TestCase):
	"""test class of EditorMaker in cbdefense.py
	"""

	def setUp(self):
		self.reportdata = []
		for fname in _report_search_files:
			reports = file_util.parse_csv(fname)
			for each in reports:
				self.reportdata.append(each)
		print len(self.reportdata)

	def tearDown(self):
		pass

	def test_render(self):
		for each in self.reportdata:
			doc = target.EditorMaker.to_html(each)
			self.assertIsInstance(doc, basestring)
			_fname = _OUTPUT_DIR+"/editor1_{}.html".format(each["incident_id"])
			with open(_fname, "w") as f:
				f.write(doc)
			maker = target.EditorMaker(each)
			doc = maker.render()
			self.assertIsInstance(doc, basestring)
			_fname = _OUTPUT_DIR+"/editor2_{}.html".format(each["incident_id"])
			with open(_fname, "w") as f:
				f.write(doc)
			doc = target.EditorMaker.to_html(each, language="en")
			self.assertIsInstance(doc, basestring)
			_fname = _OUTPUT_DIR+"/editor3_{}.html".format(each["incident_id"])
			with open(_fname, "w") as f:
				f.write(doc)

if __name__ =="__main__":
	unittest.main()

