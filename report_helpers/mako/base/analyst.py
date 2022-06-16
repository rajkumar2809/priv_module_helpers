# -*- encoding:utf-8 -*-

import os, sys
import json, argparse, copy, base64, re, copy
from monkey_tools.utils import logger_util
from monkey_tools.utils import file_util
from monkey_tools.utils import time_util as _tu

from mako.template import Template
from mako.lookup import TemplateLookup

logger = logger_util.get_standard_logger("reportbase")

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
_DEFAULT_TEMP_DIR = CURR_DIR+"/../templates"
_SENDER_FILE = "sender_name.json"

def get_template(_file, _dirs=None):
	if _dirs is None:
		_dirs = [_DEFAULT_TEMP_DIR]
	elif not _DEFAULT_TEMP_DIR in _dirs:
		_dirs.append(_DEFAULT_TEMP_DIR)
	myLookup = TemplateLookup( directories=_dirs,
				input_encoding="utf-8",
				output_encoding="utf-8")
	return myLookup.get_template(_file)

class AnalystBase(object):
	_DEFAULT_FIELD_ = "default.json"
	_CURR_DIR       = CURR_DIR
	_OUTPUT_DIR     = "../output"
	_TEMPLATE_DIR   = "../templates"
	_FIELD_DATA_DIR = "../fields"
	_FOOTER_DIR     = "../footers"
	#_FOOTER_FILE    = "dhsoc.html"
	_FOOTER_FILE    = "default.html"
	_TABLE_FIELDS   = ()
	_BASE_NAME      = None
	_OUTPUT_FILE    = None
	_TEMPLATE_FILE  = None
	_FIELD_DATA     = None

	@classmethod
	def to_base64(cls, reportinfo, language="ja", sender_name=None):
		return cls.to_html(reportinfo, True, language, sender_name)

	@classmethod
	def to_html(cls, reportinfo, to_base64=False, language="ja", sender_name=None):
		instance = cls(reportinfo, language, sender_name)
		data = instance.render()
		if to_base64:
			return base64.b64encode(data)
		else:
			return data

	def __init__(self, reportinfo, language="ja", sender_name=None):
		if self._FIELD_DATA is None:
			self._FIELD_DATA = self._replace_ext("json")
		if self._TEMPLATE_FILE is None:
			self._TEMPLATE_FILE = self._replace_ext("mk.tmpl")

		self.template_dir = "{}/{}".format(self._CURR_DIR, self._TEMPLATE_DIR)
		_field_dir = "{}/{}".format(self._CURR_DIR, self._FIELD_DATA_DIR)
		self.language = language
		if language == "ja":
			self.field_dir = _field_dir
		elif language == "en":
			self.field_dir = _field_dir+"/en"
		else:
			assert False, "cannot support language type:{}".format(language)
		logger.debug("get field information file:{}".format(self._FIELD_DATA))
		fields = self._get_fieldinfo()
		logger.debug("make report data")
		self.reportdata = self._make_reportdata(reportinfo, fields, sender_name)

	def render(self):
		_template = get_template(self._TEMPLATE_FILE,[self.template_dir])
		return _template.render(**self.reportdata)

	# private

	def _replace_ext(self, ext):
		assert self._BASE_NAME, "field data is not define"
		basename = os.path.basename(self._BASE_NAME)
		return re.sub(r".pyc?$", ".{}".format(ext), basename)
	
	#TODO dont merge default
	def _get_fieldinfo(self):
		def _for_this_report():
			field_file = "{}/{}".format(self.field_dir, self._FIELD_DATA)
			with open(field_file, "r") as f:
				data = json.load(f)
			return data
		logger.debug("get for this report")
		data = _for_this_report()
		logger.debug("Note:dont use default config now.")
		return data

	def _make_reportdata(self, origin, fields, sender_name=None):
		reportdata = copy.deepcopy(fields)
		logger.debug("set generic report information")
		self._set_content(reportdata["summary"],     origin)
		self._set_content(reportdata["remediation"], origin)
		if "metadata" in origin:
			reportdata["metadata"] = origin["metadata"]
		if reportdata["date"]["src"] == "UNIX":
			reportdata["date"]["content"] = _tu.get_date(_tu.UNIX)
		else:
			reportdata["date"]["content"] = _tu.get_date()
		logger.debug("set table report data")
		for each in self._TABLE_FIELDS:
			self._set_content_all(reportdata[each], origin)
		if "mltables" in reportdata:
			self._set_multiline_tables(reportdata, origin)
		if "matrix_tables" in reportdata:
			self._set_matrix_tables(reportdata, origin)
		_sender_file = "{}/{}".format(self.field_dir, _SENDER_FILE)
		with open(_sender_file) as f:
			sender_info=json.load(f)
		if sender_name and sender_name in sender_info:
			reportdata["company"]=sender_info[sender_name]
			self.sender_name = sender_name
		else:
			reportdata["company"]=sender_info["default"]
			self.sender_name = None
		return reportdata

	def _set_content_all(self, fields, reportdata):
		for each in fields:
			self._set_content(each, reportdata)

	def _set_content(self, field, reportdata, name=None):
		if name is None:
			name = field["src"]
		if name in reportdata:
			field["content"]=reportdata[name]
		else:
			field["content"]=""
	
	def _set_matrix_tables(self, reportdata, origin, spliter=","):
		matrix_tables = reportdata["matrix_tables"]
		for _type, data in matrix_tables.items():
			if data["from"]:
				try:
					self._set_data_by_fieldinfo(data, origin, spliter)
					self._replace_char_fieldinfo(data)
				except ValueError as e:
					pass
				except KeyError as e:
					pass
			fields = data["fields"]
			headers = data["headers"]
			maskchar = data.get("maskchar")
			tmp = {}
			is_exist = False
			tmp = { "header" : headers, "fields" : [] }
			for i in range(0, len(fields)):
				field = fields[i]
				row = [ { "src" : "name", "content" : field["name"] } ]
				for each in headers:
					if each["prefix"]:
						key = each["prefix"]+"_"+field["src"]
						if key in origin:
							is_exist = True
							value = origin[key]
							if maskchar:
								for c in maskchar:
									value = value.replace(c, " ")
							if not spliter == ",":
								value = value.replace(",", " ").split(spliter)
							row.append( { "src" : key, "content" : value } )
						else:
							row.append( { "src" : key, "content" : "" } )
				tmp["fields"].append(row)
			if is_exist:
				reportdata[_type] = tmp
			else:
				fields = []
				for each in tmp["fields"]:
					fields.extend(each)
				self._add_hidden_fields(reportdata, fields, "")


	def _set_multiline_tables(self, reportdata, origin, spliter=","):
		mltables = reportdata["mltables"]
		for _type, data in mltables.items():
			if data["from"]:
				try:
					self._set_data_by_fieldinfo(data, origin, spliter)
					self._replace_char_fieldinfo(data)
				except ValueError as e:
					pass
				except KeyError as e:
					pass
			prefix = data["prefix"]+"_"
			fields = data["fields"]
			maskchar = data.get("maskchar")
			tmp = {}
			max_line = 0
			for k, v in origin.items():
				if k.startswith(prefix):
					key = re.sub(r"^{}".format(prefix), "", k)
					if len(v) > 0:
						if not spliter == ",":
							v = v.replace(",", " ")
						tmp[key] = v.split(spliter)
						if len(tmp[key]) > max_line:
							max_line = len(tmp[key])
			if max_line > 0:
				reportdata[_type] = []
				for i in range(0, max_line):
					eachfields = copy.deepcopy(fields)
					for each in eachfields:
						for name, values in tmp.items():
							if name == each["src"]:
								each["prefix"]=prefix
								if i < len(values):
									if "limit" in each:
										limit = each["limit"]
										s = values[i]
										if len(s) > limit:
											s=s[:each["limit"]]+"(以下略)"
										each["content"]=s
									else:
										each["content"]=values[i]
								else:
									each["content"]=""
								break
						if not "prefix" in each:
							each["prefix"]=prefix
							each["content"]=""
						if maskchar:
							for c in maskchar:
								each["content"] = each["content"].replace(c, " ")
					reportdata[_type].append(eachfields)
			else:
				self._add_hidden_fields(reportdata, fields, prefix)
	
	def _add_hidden_fields(self, reportdata, fields, prefix=""):
		if not "hidden_fields" in reportdata:
			reportdata["hidden_fields"] = []
		for each in fields:
			if each["src"]:
				key = prefix+each["src"]
				reportdata["hidden_fields"].append({"src" : key, "content" : ""})
	
	def _set_data_by_fieldinfo(self, data, origin, spliter):
		def _get_by_list(each_target, _path):
			tmp = []
			for _t in each_target:
				if _path in _t:
					target = _t[_path]
					if isinstance(target, list):
						tmp.extend(target)
					elif target:
						tmp.append(target)
					else:
						tmp.append("")
			if len(tmp) > 0:
				return True, tmp
			else:
				return False, tmp

		if not data["from"] in origin:
			return
		else:
			if data["datatype"] == "json":
				info = json.loads(origin[data["from"]])
			else:
				info = origin[data["from"]]
			paths = data["prefix"].split(".")
			target = info
			for each in paths:
				target = target[each]
			prefix = self._replace_each_field(data["prefix"])
			for each in data["fields"]:
				paths = each["src"].split(".")
				values = []
				for each_target in target:
					flag = True
					for _path in paths:
						if isinstance(each_target, list):
							flag, each_target = _get_by_list(each_target, _path)
						elif _path in each_target:
							each_target = each_target[_path]
						else:
							flag = False
					if flag:
						if isinstance(each_target, list):
							each_target = " | ".join(set(each_target))
						values.append(str(each_target))
				key = "{}_{}".format( prefix,
						self._replace_each_field(each["src"]))
				origin[key] = "\n".join(values)

	def _replace_char_fieldinfo(self, data):
		prefix = data["prefix"]
		data["prefix"] = self._replace_each_field(prefix)
		for each in data["fields"]:
			src = each["src"]
			each["src"] = self._replace_each_field(src)
	
	def _replace_each_field(self, field):
		return field.replace(".", "_")

class AnalystReportBase(AnalystBase):
	SPLITER = ","

	def __init__(self, reportinfo, language="ja", sender_name=None):
		super(AnalystReportBase, self).__init__(reportinfo, language, sender_name)
		self.output_dir = "{}/{}".format(self._CURR_DIR, self._OUTPUT_DIR)
		self.footer_dir = "{}/{}".format(self._CURR_DIR, self._FOOTER_DIR)
		self._TEMPLATE_FILE = "reports/"+self._TEMPLATE_FILE
	
	@classmethod
	def write(cls, reportinfo, file_name=None, with_pdf=False, footer=None, language="ja", sender_name=None):
		instance = cls(reportinfo, language, sender_name)
		return instance.write2file(file_name, with_pdf, footer)

	def write2file(self, file_name=None, with_pdf=False, footer=None):
		if file_name is None:
			assert self._OUTPUT_FILE, "file name is not define yet"
			file_name = self._OUTPUT_FILE
			if not file_name.endswith(".html"):
				file_name += file_name +".html"
		doc = self.render()
		with open(file_name, "w") as f:
			f.write(doc)
		if with_pdf:
			pdf_name = re.sub(r"\.html$", ".pdf", file_name)
			if footer:
				footer = "{}/{}".format(self.footer_dir, footer)
			elif self.sender_name:
				footer = "{}/{}.html".format(self.footer_dir, self.sender_name)
			elif self._FOOTER_FILE:
				footer = "{}/{}".format(self.footer_dir, self._FOOTER_FILE)
			else:
				footer = None
			return file_util.convert2pdf( file_name, pdf_name, footer )
		return 0

	def _set_multiline_tables(self, reportdata, origin, spliter=None):
		if spliter is None:
			spliter = self.SPLITER
		super(AnalystReportBase, self)._set_multiline_tables(reportdata, origin, spliter)

class AnalystEditorBase(AnalystBase):
	SPLITER = "\n"
	def __init__(self, reportinfo, language="ja", sender_name=None):
		super(AnalystEditorBase, self).__init__(reportinfo, language)
		self._TEMPLATE_FILE = "editors/"+self._TEMPLATE_FILE
	
	def _set_multiline_tables(self, reportdata, origin, spliter=None):
		if spliter is None:
			spliter = self.SPLITER
		super(AnalystEditorBase, self)._set_multiline_tables(reportdata, origin, spliter)

