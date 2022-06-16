# -*- encoding:utf-8 -*-

import os, sys
import json

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
MODULE_TOP = CURR_DIR+"/.."
sys.path.append(MODULE_TOP)

import base.analyst as base

_TABLE_FIELDS  = (
	"summary_info",
)

class ReportMaker(base.AnalystReportBase):
	_BASE_NAME     = __file__
	_CURR_DIR      = CURR_DIR
	_TABLE_FIELDS  = _TABLE_FIELDS
	
	def _make_reportdata(self, origin, fields, sender_name=None):
		reportdata = super(ReportMaker, self)._make_reportdata(origin, fields, sender_name)
		self._set_content(reportdata["outbound"], origin)
		self._set_content(reportdata["endpointav"], origin)
		if self._is_malware_object_alert(origin):
			malobj = reportdata["malware_object"]
			self._set_content_all(malobj["malware_file"], origin)
			self._set_content(malobj["known_callback"], origin)
		else:
			del(reportdata["malware_object"])
		return reportdata

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
		self._set_content(reportdata["endpointav"], origin)
		malobj = reportdata["malware_object"]
		if not "fname" in malobj:
			malobj["fname"] = ""
		if not "fhash" in malobj:
			malobj["fhash"] = ""
		if not "known_callback" in malobj:
			malobj["known_callback"] = ""
		self._set_content_all(malobj["malware_file"], origin)
		self._set_content(malobj["known_callback"], origin)
		return reportdata

