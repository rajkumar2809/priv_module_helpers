# -*- coding: utf-8 -*-

import os, sys
import json, re, glob
import logging

reload(sys)
sys.setdefaultencoding("utf-8")

logger = logging.getLogger()

from monkey_tools.utils import str_util, rest_util
from priv_module_helpers.redmine_helpers import rm_helpers as rm_util

def _init_redmine(rm_conf):
	return rm_util.CbDefenseRmHelper(
		rm_conf["url"],      rm_conf["username"],
		rm_conf["password"], rm_conf["pj_name"],
		project={}, custom_fields={}, description={} )

def status_is_new(rm_conf, ticket_id):
	rm = _init_redmine(rm_conf)
	try:
		status = rm.get_ticket_status(ticket_id)
		if status:
			return status["id"] == 1
		else:
			return False
	except Exception as e:
		logger.error("failed to get redmine ticket :{}.".format(ticket_id))
		logger.exception(e)
		return False

def get_ticket_idlist(rm_conf, alert_id):
	logger.info("get ticket_id list by alert_id:{}".format(alert_id))
	try:
		rm = _init_redmine(rm_conf)
		return rm.get_ticket_idlist(alert_id)
	except Exception as e:
		logger.error("failed to get redmine ticket idlist for ID:{}.".format(alert_id))
		logger.exception(e)
		return []

def update_redmine_ticket( rm_conf, id_list, severity, msg,
		_response_by_other=False, _need_tier1=False ):
	try:
		logger.info( "update Redmine ticket at incident of ID:{}".format(str(id_list)) )
		rm = _init_redmine(rm_conf)
		cfid_severity = rm_conf["custom_fields"]["alert_summary.severity"]
		logger.info("custom fields ID is {}".format(cfid_severity))
		for each in id_list:
			logger.info("severity: -> {}".format(severity))
			rm.add_custom_field("severity", severity, cfid_severity)
			cfid = rm_conf["for_tier1_app"]
			logger.info("change Tier1Work:[CFID:{} Value:{}]".format(
				cfid, _need_tier1))
			_tier1 = "必要" if _need_tier1 else "不要"
			rm.add_custom_field("tier1", _tier1, cfid)
			rm.update_ticket(each, msg)
	except Exception as e:
		logger.error("failed to update redmine tickets for ID:{}.".format(str(id_list)))
		logger.exception(e)


