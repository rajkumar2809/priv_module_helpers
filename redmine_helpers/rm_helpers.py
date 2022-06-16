# -*- coding: utf-8 -*-

import os, sys
import json, re
import copy
from monkey_tools.utils import rm_util
from monkey_tools.utils.str_util import _DEFAULT_ENCODE

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
_CONF_DIR = CURR_DIR+"/config"
_DEF_CONF = _CONF_DIR+"/cbdefense.json"

def init_for_cbdefense(splunk_name, by_local=True):
	return RmHelper.init_for(splunk_name, "cbdefense", by_local)

def init_for_stellar(splunk_name, by_local=True):
	return RmHelper.init_for(splunk_name, "stellar", by_local)

class RmHelper(object):
	_CONF = None
	_CFID_ALERTID = 9
	_PRODUCT_ = None
	_LOCAL_ = "https://127.0.0.1:10443/redmine"

	@classmethod
	def set_cfg_file(cls, cfg_file, in_cfg_dir=False):
		# [str] cfg_file -> None
		assert os.path.exists(cfg_file), "file not exist:{}".format(cfg_file)
		assert isinstance(cfg_file, str) or isinstance(cfg_file, unicode), "cfg_file must be str type."
		cls._CONF = cfg_file

	@classmethod
	def init_by_cfg_file(cls, cfg_file=None, cfg_name=None):
		# [str] cfg_file(None) -> instance of me
		if cfg_file:
			cls.set_cfg_file(cfg_file)
		elif cfg_name:
			if cfg_name.endswith(".json"):
				cls.set_cfg_file(cfg_name, True)
			else:
				cls.set_cfg_file("{}.json".format(cfg_name), True)
		with open(cls._CONF, "r") as f:
			cfg = json.load(f)
		return cls(**cfg)

	@classmethod
	def init_for(cls, splunk_name, product_name=None, by_local=True):
		assert product_name or cls._PRODUCT_, "you must set product_name"
		if product_name is None:
			product_name = cls._PRODUCT_
		if "." in splunk_name:
			cfg_name = splunk_name.split(".", 1)[0]
		else:
			cfg_name = splunk_name
		with open("{}/{}.json".format(_CONF_DIR, cfg_name), "r") as f:
			cfg = json.load(f)
		if product_name in cfg:
			cfg["project"] = cfg[product_name]
		else:
			assert False, "unrecognize product:{}".format(product_name)
		cfg["description"] = {}
		if by_local:
			cfg["url"] = cls._LOCAL_
		return cls(**cfg)

	def __init__(self, url, username, password, project_name, **cfg):
		self.connector = rm_util.RedmineConnector(
				url, username, password, project_name)
		self.custom_fields = {}
		self.description = []
		self._parse_config(cfg)

	def add_project_info(self, name, value):
		if not isinstance(name, unicode):
			name = str(name)
		self.project_info[name]=value

	def get_cfid(self, name=None):
		if name is None:
			return copy.copy(self.custom_fields_id)

		elif name in self.custom_fields_id:
			return self.custom_fields_id[name]
		else:
			return None

	def add_custom_field(self, name, value, _id=None):
		if _id is None:
			assert name in self.custom_fields_id, "id information is needed."
			_id = self.custom_fields_id[name]
		self.custom_fields[name]={"id" : _id, "value" : value}

	def add_description(self, name, value, column_name=None):
		if column_name is None:
			assert name in self.description_column, "column_name information is needed."
			column_name = self.description_column[name]
		self.description.append({"name":column_name, "value":value})
	
	def issue_ticket(self):
		subject = self.project_info["subject"]
		tracker_id = self.project_info["tracker_id"]
		ticket = self.connector.make_new_ticket(subject, tracker_id)
		for k, v in self.project_info.items():
			if not( k == "subject" or k == "tracker_id" ):
				ticket.add_project_info(k, v)
		for each in self.description:
			ticket.add_description(each["name"], each["value"])
		for each in self.custom_fields.values():
			ticket.add_custom_field(each["id"], each["value"])
		ticket.save()
	
	def filter_redmine_ticket(self, status="open", limit=10, **filteroption):
		if status == "open":
			status = "o"
		else:
			status = "c"
		if not "created_on" in filteroption:
			filteroption["created_on"] = "><t-1"
		results = self.connector.raw_ticket_search(
				status_id=status, limit=limit, **filteroption)
		return results

	def search_ticket(self, alert_id, cfid_alert_id=9, status=None):
		id_list = self.connector.get_ticket_numbers(
				cfid_alert_id, alert_id, status)
		if len(id_list) is 0:
			return None
		else:
			return id_list[0]

	def get_ticket_list(self, custom_fields, status=None):
		tickets = self.connector.get_tickets_by_multi_filter(
				custom_fields, status)
		results = []
		for each in tickets:
			results.append(rm_util.ticket_to_dict(each))
		return results

	def get_ticket_idlist(self, value, cfid=None, status=None):
		if cfid is None:
			cfid = self._CFID_ALERTID
		id_list = self.connector.get_ticket_numbers(
				cfid, value, status)
		return id_list

	def update_ticket(self, _id, notes, status_id=None):
		if status_id:
			assert isinstance(status_id, int), "status_id must be int"
		else:
			status_id = 1
		ticket = self.connector.make_update_ticket(_id, notes, status_id)
		for each in self.custom_fields.values():
			ticket.add_custom_field(each["id"], each["value"])
		ticket.update()

	def get_ticket_status(self, ticket_id):
		ticket = self.connector.get(ticket_id)
		if ticket and ticket.status:
			return { "id": ticket.status.id, "name": ticket.status.name }
		else:
			return None

	def get_ticket(self, ticket_id, with_format=True):
		ticket = self.connector.get(ticket_id)
		if ticket and with_format:
			if ticket.status:
				status = ticket.status.name
			else:
				status = "N/A"
			notes = []
			for each in ticket.journals:
				if hasattr(each, "notes"):
					note = each.notes
					if isinstance(note, basestring):
						notes.append(each.notes)
			severity = "N/A"
			alert_id = "N/A"
			for each in ticket.custom_fields:
				if each.name == u"危険度":
					severity = each.value
				elif each.name == u"アラートID":
					alert_id = each.value
			return {"ticket_id" : ticket_id, "alert_id" : alert_id,
					"severity"  : severity,  "notes"    : notes,
					"status"    : status }
		else:
			return ticket

	def clear(self):
		self.custom_fields.clear()
		self.project_info.clear()
		del self.description[:]

	# private

	def _parse_config(self, cfg):
		assert "project" in cfg, "key of project must be needed."
		assert "custom_fields" in cfg, "key of custom_fields must be needed."
		assert "description" in cfg, "key of description must be needed."
		self.project_info = cfg["project"].copy()
		self.custom_fields_id = cfg["custom_fields"].copy()
		self.description_column = cfg["description"].copy()
	

class CbDefenseRmHelper(RmHelper):
	_CFID_ALERTID = 9
	_PRODUCT_ = "cbdefense"

class StellarRmHelper(RmHelper):
	_CFID_ALERTID = 9
	_PRODUCT_ = "stellar"

class FireeyeNxRmHelper(RmHelper):
	_CFID_ALERTID = 5
	_PRODUCT_ = "fireeye_nx"

class FireeyeHxRmHelper(RmHelper):
	_CFID_ALERTID = 9
	_PRODUCT_ = "fireeye_hx"

PRODUCTS = {
	CbDefenseRmHelper._PRODUCT_ : CbDefenseRmHelper,
	FireeyeNxRmHelper._PRODUCT_ : FireeyeNxRmHelper,
	FireeyeHxRmHelper._PRODUCT_ : FireeyeHxRmHelper
}
