# -*- encoding:utf-8 -*-

import os, sys
import json

from monkey_tools.product.fireeye_hx import convert2reportdata as _convert

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
MODULE_TOP = CURR_DIR+"/.."
sys.path.append(MODULE_TOP)

import base.analyst as base

_TABLE_FIELDS  = (
	"summary_info",
	"hidden_fields",
	"nw_contain"
)

def _to_reportdata(origin):
	if "with_eng" in origin:
		with_eng = origin["with_eng"]
	else:
		with_eng = "0"
	if "_raw" in origin:
		reportdata = _convert.convert2reportdata(origin,
				origin["summary"], origin["remediation"], with_eng)
		return reportdata
	else:
		return origin

class ReportMaker(base.AnalystReportBase):
	_BASE_NAME     = __file__
	_CURR_DIR      = CURR_DIR
	_TABLE_FIELDS  = _TABLE_FIELDS
	
	def _make_reportdata(self, origin, fields, sender_name=None):
		origin = _to_reportdata(origin)
		reportdata = super(ReportMaker, self)._make_reportdata(
				origin, fields, sender_name)
		severity = origin["severity"]
		if not severity in [ "high", "高" ]:
			del(reportdata["nw_contain"])
		return reportdata

class EditorMaker(base.AnalystEditorBase):
	_BASE_NAME     = __file__
	_CURR_DIR      = CURR_DIR
	_TABLE_FIELDS  = _TABLE_FIELDS

	def _make_reportdata(self, origin, fields, sender_name=None):
		origin = _to_reportdata(origin)
		malwares = json.loads(origin["malware_info"])
		reportdata = super(EditorMaker, self)._make_reportdata(
				origin, fields, sender_name)
		severity = origin["severity"]
		if not severity in [ "high", "高" ]:
			del(reportdata["nw_contain"])
			reportdata["hidden_fields"].append(
				{"src":"contain_host", "content":""})
			reportdata["hidden_fields"].append(
				{"src":"need_contain", "content":""})
		return reportdata

