# -*- encoding:utf-8 -*-

import os, sys
import json

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
MODULE_TOP = CURR_DIR+"/.."
sys.path.append(MODULE_TOP)

_COMMON_TABLE_FIELDS  = (
	"summary_info",
	"detail_score",
	"detail_network_comm_src",
	"detail_network_comm_dst",
	"detail_network_content",
	"hidden_fields",
	"remediation_append"
)

_SELECTED_TABLE_FILEDS = {
	"anomaly"  : "detail_alert_mal_anomaly",
	"callback" : "detail_alert_callback",
	"ids"      : "detail_alert_ids",
	"malware-object" : "detail_alert_sandbox",
	"mal_access"     : "detail_alert_mal_access",
	"phishing"       : "detail_alert_phishing"
}

import base.analyst as base

class ReportMaker(base.AnalystReportBase):
	_BASE_NAME     = __file__
	_CURR_DIR      = CURR_DIR
	_TABLE_FIELDS  = _COMMON_TABLE_FIELDS

	def _make_reportdata(self, origin, fields, sender_name=None):
		reportdata = super(ReportMaker, self)._make_reportdata(origin, fields, sender_name)
		for k, field in _SELECTED_TABLE_FILEDS.items():
			if k == origin["incident_category"]:
				reportdata["detail_alert"] = reportdata[field]
				self._set_content_all(reportdata["detail_alert"], origin)
			else:
				del(reportdata[field][:])
		traffic_type = origin.get("traffic_type")
		if traffic_type and "," in traffic_type:
			origin["traffic_type"] = traffic_type.split(",")[0]
		if "traffic_type" in origin and not origin["traffic_type"] in( "not_traffic", "correlation" ):
			reportdata["is_traffic_base"] = True
		else:
			reportdata["is_traffic_base"] = False
		if "appendix_metadata" in origin:
			reportdata["appendix"] = True
			reportdata["appendix_metadata"] = origin["appendix_metadata"]
		if "vtinfo" in origin:
			reportdata["appendix"] = True
			reportdata["vtinfo"] = origin["vtinfo"]
		if "total" in origin:
			reportdata["appendix"] = True
			reportdata["total"] = origin["total"]
		if "appendix_correlation_info" in origin:
			reportdata["appendix"] = True
			reportdata["appendix_correlation_info"] = origin["appendix_correlation_info"]
		if "appendix_event_data" in origin:
			reportdata["appendix"] = True
			reportdata["appendix_event_data"] = origin["appendix_event_data"]
		if "appendix_ids" in origin:
			reportdata["appendix"] = True
			reportdata["appendix_ids"] = origin["appendix_ids"]
		self._masking_url(reportdata)
		return reportdata

	def _masking_url(self, reportdata):
		def _mask_each(url):
			url = url.replace("http://", "hxxp://")
			url = url.replace("https://", "hxxps://")
			return url.replace(".", "[x]")

		if "url" in reportdata and len(reportdata["url"]) is not 0:
			reportdata["url"] = _mask_each(reportdata["url"])

class EditorMaker(base.AnalystEditorBase):
	_BASE_NAME     = __file__
	_CURR_DIR      = CURR_DIR
	_TABLE_FIELDS  = _COMMON_TABLE_FIELDS

	def _make_reportdata(self, origin, fields, sender_name=None):
		reportdata = super(EditorMaker, self)._make_reportdata(origin, fields, sender_name)
		for k, field in _SELECTED_TABLE_FILEDS.items():
			if k == origin["incident_category"]:
				reportdata["detail_alert"] = reportdata[field]
				self._set_content_all(reportdata["detail_alert"], origin)
			else:
				del(reportdata[field][:])
		if "traffic_type" in origin and origin["traffic_type"] == "not_traffic":
			reportdata["is_traffic_base"] = True
		else:
			reportdata["is_traffic_base"] = False
		return reportdata

