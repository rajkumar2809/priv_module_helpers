# -*- coding: utf-8 -*-

import os, sys
import json, re, glob
import logging

reload(sys)
sys.setdefaultencoding("utf-8")

logger = logging.getLogger()

from monkey_tools.utils import str_util, rest_util
from priv_module_helpers.redmine_helpers import rm_helpers as rm_util

CONF = None

def get_info_by_hash_from_past_ticket(ps_hash, customer, past_days=30):
	def _get_analyse_comment(notes):
		for each in notes:
			if each.startswith("*result*"):
				return each
		return None
	rm_conf = CONF
	rm = rm_util.CbDefenseRmHelper(
		rm_conf["url"],      rm_conf["username"],
		rm_conf["password"], rm_conf["pj_name"],
		project={}, custom_fields={}, description={} )
	result = rm.filter_redmine_ticket(status="close", limit=10,
			description="~u'{}'".format(ps_hash),
			created_on="><t-{}".format(past_days))
	info = None
	for each in result["tickets"]:
		if each[u"参考利用可"] == 'Yes': #「参考利用可」フラグがYESになっているチケットのみ参考する
			msg = _get_analyse_comment(each["notes"])
			if msg is None:
				continue
			msg = msg.replace("*result*", "過去の以下チケットにならいます。\n#{}\n".format(each["id"]))
			if msg:
				if info is None:
					info = {"ticket_id" : int(each["id"]),
							"severity"  : each[u"危険度"],
							"message"   : msg }
				elif info["ticket_id"]<int(each["id"]):
					info = {"ticket_id" : int(each["id"]),
							"severity"  : each[u"危険度"],
							"message"   : msg }
	return info

def get_ticket_idlist(rm_conf, alert_id):
	try:
		logger.info("get ticket_id list by alert_id:{}".format(alert_id))
		rm = rm_util.CbDefenseRmHelper(
			rm_conf["url"],      rm_conf["username"],
			rm_conf["password"], rm_conf["pj_name"],
			project={}, custom_fields={}, description={} )
		return rm.get_ticket_idlist(alert_id)
	except StandardError as e:
		logger.exception("failed to get redmine ticket idlist for ID:{}.".format(alert_id))
		return []

def update_redmine_ticket( rm_conf, id_list, alert, result,
		instruction_url=None, _need_tier1=None ):
	try:
		logger.info( "update Redmine ticket at incident of ID:{}".format(str(id_list)) )
		rm = rm_util.CbDefenseRmHelper(
			rm_conf["url"],      rm_conf["username"],
			rm_conf["password"], rm_conf["pj_name"],
			project={}, custom_fields={}, description={} )
		msg = get_fpcheck_message(result["flag"], result["message"], u"過検知判定")
		msg = msg.encode('utf-8').decode('utf-8')
		if "severity" in rm_conf["custom_fields"]:
			cfid_severity = rm_conf["custom_fields"]["severity"]
		else:
			cfid_severity = rm_conf["custom_fields"]["alert_summary.severity"]
		logger.info("custom fields ID is {}".format(cfid_severity))
		for each in id_list:
			if result["flag"]:
				if result["is_gray"]:
					rm.add_custom_field("severity", "未", cfid_severity)
				elif result["correct_severity"]:
					correct_severity = result["correct_severity"]
					logger.info("changed severity:[{} -> {}]".format(
						alert["alert_summary"]["severity"], correct_severity))
					rm.add_custom_field("severity", correct_severity, cfid_severity)
				if _need_tier1:
					cfid = rm_conf["for_tier1_app"]
					logger.info("change Tier1Work:[{}]".format(cfid))
					rm.add_custom_field("tier1", "必要", cfid)
			else:
				rm.add_custom_field("severity", "-", cfid_severity)
			#rm.update_ticket(each, msg)
			msg = msg+"\n\n"+instruction_url
			if not result["flag"]:
				logger.info("change status to ID:10")
				rm.update_ticket(each, msg, status_id=10)
			else:
				rm.update_ticket(each, msg)
	except StandardError as e:
		logger.exception("failed to update redmine tickets for ID:{}.".format(str(id_list)))

def get_fpcheck_message(is_positive, messages, fieldname=None):
	msg = ""
	res = u"正検知" if is_positive else u"過検知"
	if fieldname:
		msg += str_util.combine(fieldname, res)+"\n"
	else:
		msg += res+"\n"
	for each in messages:
		if isinstance(each, dict):
			msg += str_util.combine(each["ppid"], each["message"])+"\n"
		elif isinstance(each, basestring):
			msg += each+"\n"
		elif isinstance(each, list):
			for l in each:
				if isinstance(l, dict):
					if "message" in l:
						msg += str(l["message"])+"\n"
					else:
						msg += str(l)+"\n"
				else:
					msg += str(l)+"\n"
		else:
			msg += "\n"
	return msg

def _issue_redmine_ticket(rm_conf, alert):
	logger.info("make new ticket at ID:{}".format(
		alert["alert_summary"]["alert_id"]))
	rm = rm_util.CbDefenseRmHelper(
		rm_conf["url"],      rm_conf["username"],
		rm_conf["password"], rm_conf["pj_name"],
		project={}, custom_fields={}, description={} )
	custom_fields = rm_conf["custom_fields"]
	description   = rm_conf["description"]
	project_info  = rm_conf["project"]
	for _key, _id in custom_fields.items():
		section_name, name = _key.split(".")
		if section_name in alert:
			section = alert[section_name]
			if name in section:
				rm.add_custom_field(name, section[name], _id)
	for each in description:
		section_name, name = each["field"].split(".")
		if section_name in alert:
			section = alert[section_name]
			if name in section:
				rm.add_description(name, section[name], each["name"])
			elif name.endswith("*"):
				prefix = name.replace("*", "")
				for k,v in section.items():
					if k.startswith(prefix):
						rm.add_description(k, v, k)
	for name, value in project_info.items():
		if value is None:
			if name == "subject":
				alert_id = alert["alert_summary"]["alert_id"]
				value = "{}:{}".format( APP_NAME, alert_id )
			else:
				value = ""
		rm.add_project_info(name, value)
	rm.issue_ticket()

