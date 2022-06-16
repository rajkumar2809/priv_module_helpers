# -*- encoding:utf-8 -*-

import os, sys
import json

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
MODULE_TOP = CURR_DIR+"/.."
sys.path.append(MODULE_TOP)

import base.analyst as base

_TABLE_FIELDS  = (
	"summary_info",
	"hidden_fields"
)

class ReportMaker(base.AnalystReportBase):
	_BASE_NAME     = __file__
	_CURR_DIR      = CURR_DIR
	_TABLE_FIELDS  = _TABLE_FIELDS
	
	def _make_reportdata(self, origin, fields, sender_name=None):
		reportdata = super(ReportMaker, self)._make_reportdata(origin, fields, sender_name)
		self._set_content(reportdata["outbound"], origin)
		if self._is_malware_object_alert(origin):
			malobj = reportdata["malware_object"]
			self._set_content_all(malobj["malware_file"], origin)
			self._set_content(malobj["known_callback"], origin)
		else:
			del(reportdata["malware_object"])
		if self._has_endpoint_av_info(origin):
			avobj = reportdata["ref_av_detection"]
			self._set_content_all(avobj["endpointav"], origin)
		else:
			del(reportdata["ref_av_detection"])
		return reportdata

	def _has_endpoint_av_info(self, origin):
		return(
			("end_host"   in origin and len(origin["end_host"])   is not 0) and
			("end_action" in origin and len(origin["end_action"]) is not 0)
		)

	def _is_malware_object_alert(self, origin):
		return(
			("fname" in origin and len(origin["fname"]) is not 0) and
			("fhash" in origin and len(origin["fhash"]) is not 0)
		)

class EditorMaker(base.AnalystEditorBase):
	_BASE_NAME     = __file__
	_CURR_DIR      = CURR_DIR
	_TABLE_FIELDS  = _TABLE_FIELDS

	def _make_reportdata(self, origin, fields, sender_name=None):
		reportdata = super(EditorMaker, self)._make_reportdata(origin, fields, sender_name)
		self._set_content(reportdata["outbound"], origin)
		malobj = reportdata["malware_object"]
		self._set_malware_object_info(malobj, origin)
		avobj = reportdata["ref_av_detection"]
		self._set_endpointav_info(avobj, origin)
		return reportdata

	def _set_malware_object_info(self, malobj, origin):
		if not "fname" in malobj:
			malobj["fname"] = ""
		if not "fhash" in malobj:
			malobj["fhash"] = ""
		if not "known_callback" in malobj:
			malobj["known_callback"] = ""
		self._set_content_all(malobj["malware_file"], origin)
		self._set_content(malobj["known_callback"], origin)

	def _set_endpointav_info(self, avobj, origin):
		if not "end_host" in avobj:
			avobj["end_host"] = ""
		if not "end_target" in avobj:
			avobj["end_target"] = ""
		if not "end_action" in avobj:
			avobj["end_action"] = ""
		self._set_content_all(avobj["endpointav"], origin)

