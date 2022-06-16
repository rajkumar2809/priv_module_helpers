# -*- encoding:utf-8 -*-

import os, sys, re
import json

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
MODULE_TOP = CURR_DIR+"/.."
sys.path.append(MODULE_TOP)

import base.analyst as base

_TABLE_FIELDS  = (
	"summary_info",
	"hidden_fields",
	"nw_contain"
)

class ReportMaker(base.AnalystReportBase):
	_BASE_NAME     = __file__
	_CURR_DIR      = CURR_DIR
	_TABLE_FIELDS  = _TABLE_FIELDS
	
	def _make_reportdata(self, origin, fields, sender_name=None):
		if "_raw" in origin:
			self.SPLITER = "\n"
		reportdata = super(ReportMaker, self)._make_reportdata(
				origin, fields, sender_name)
		reportdata["process_info"]["content"]=origin["process_info"].replace(" ", '&nbsp')
		if not origin["severity"] == "高":
			del(reportdata["nw_contain"])
		return reportdata

class EditorMaker(base.AnalystEditorBase):
	_BASE_NAME     = __file__
	_CURR_DIR      = CURR_DIR
	_TABLE_FIELDS  = _TABLE_FIELDS

	def _make_reportdata(self, origin, fields, sender_name=None):
		origin = self._add_field4crowdstrike(origin)
		reportdata = super(EditorMaker, self)._make_reportdata(
				origin, fields, sender_name)
		reportdata["process_info"]["content"]=origin["process_info"]
		if not origin["severity"] == "高":
			del(reportdata["nw_contain"])
			reportdata["hidden_fields"].append(
				{"src":"contain_host", "content":""})
		return reportdata

	def _add_field4crowdstrike(self, _origin):
		origin = {}
		for k, v in _origin.items():
			if not k == "_raw" and isinstance(v, basestring):
				v = v.replace('"', '\\"')
				v = v.replace(',', ' ')
			origin[k] = v
		return origin

