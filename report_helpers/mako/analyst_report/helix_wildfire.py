# -*- encoding:utf-8 -*-

import os, sys
import json

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
MODULE_TOP = CURR_DIR+"/.."
sys.path.append(MODULE_TOP)

import base.analyst as base

_COMMON_TABLE_FIELDS  = (
	"summary_info",
	"detail_network",
	"hidden_fields"
)

class ReportMaker(base.AnalystReportBase):
	_BASE_NAME     = __file__
	_CURR_DIR      = CURR_DIR
	_TABLE_FIELDS  = _COMMON_TABLE_FIELDS

class EditorMaker(base.AnalystEditorBase):
	_BASE_NAME     = __file__
	_CURR_DIR      = CURR_DIR
	_TABLE_FIELDS  = _COMMON_TABLE_FIELDS

