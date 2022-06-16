# -*- encoding:utf-8 -*-

import os, sys
import json

from monkey_tools.product.cbdefense.alert import append_info

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
MODULE_TOP = CURR_DIR+"/.."
sys.path.append(MODULE_TOP)

_COMMON_TABLE_FIELDS  = (
	"summary_info",
	"outbound",
	"detail",
	"hidden_fields",
	"cause_event",
	"nw_contain"
)

_SELECTED_TABLE_FILEDS = {
}

import base.analyst as base

def _get_taginfo(_rawdata, language="ja"):
	try:
		data = json.loads(_rawdata)
		tags = _rawdata["alert_summary"]["threat_tags"]
		return append_info.get_detail_of_tags(tags)
	except:
		return []


class ReportMaker(base.AnalystReportBase):
	_BASE_NAME     = __file__
	_CURR_DIR      = CURR_DIR
	_TABLE_FIELDS  = _COMMON_TABLE_FIELDS

	def _make_reportdata(self, origin, fields, sender_name=None):
		if origin.has_key("_raw"):
			origin["taginfo"] = json.dumps(
				{ "tags" : _get_taginfo(origin["_raw"], self.language) })
		reportdata = super(ReportMaker, self)._make_reportdata(
				origin, fields, sender_name)
		if "vtinfo" in origin:
			reportdata["vtinfo"] = origin["vtinfo"]
		del(reportdata["appendix"]) #TODO
		if not origin["severity"] == "high":
			del(reportdata["nw_contain"])
		return reportdata

class EditorMaker(base.AnalystEditorBase):
	_BASE_NAME     = __file__
	_CURR_DIR      = CURR_DIR
	_TABLE_FIELDS  = _COMMON_TABLE_FIELDS

	def _make_reportdata(self, origin, fields, sender_name=None):
		if origin.has_key("_raw"):
			origin["taginfo"] = json.dumps(
				{ "tags" : _get_taginfo(origin["_raw"], self.language) })
		reportdata = super(EditorMaker, self)._make_reportdata(
				origin, fields, sender_name)
		del(reportdata["appendix"]) #TODO
		if not origin["severity"] == "high":
			del(reportdata["nw_contain"])
			reportdata["hidden_fields"].append(
				{"src":"contain_host", "content":""})
		return reportdata

