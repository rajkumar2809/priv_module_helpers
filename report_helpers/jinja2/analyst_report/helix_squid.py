# -*- encoding:utf-8 -*-

import os, sys
import json, argparse, copy
from monkey_tools.utils import template_util as j2util

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
MODULE_TOP = CURR_DIR+"/.."
sys.path.append(MODULE_TOP)

import base.analyst as base

class ReportMaker(base.AnalystReportBase):
	_BASE_NAME     = __file__
	_CURR_DIR      = CURR_DIR
	_TABLE_FIELDS  = (
		"summary_info",
		"detail_alert",
		"detail_network",
		"detail_history"
	)

