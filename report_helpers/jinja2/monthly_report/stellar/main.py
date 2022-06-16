#!/usr/bin/python
# -*- coding: utf-8 -*-

import os, sys
import json, urllib, re, copy
import argparse

import matplotlib
matplotlib.use('Agg')
 
reload(sys)
sys.setdefaultencoding("utf-8")

from monkey_tools.utils import splunk_search_util as _splunk
from monkey_tools.utils import time_util as _tu
from monkey_tools.utils import logger_util
from monkey_tools.utils import file_util
from monkey_tools.utils import mail_util

from monkey_tools.utils import template_util as report
from monkey_tools.utils import graph_util as graph
from monkey_tools.constant.color_code import Bright as _clr

CURR_DIR = os.path.dirname( os.path.abspath(__file__) )
CONF_DIR = CURR_DIR+"/config"
TEMP_DIR = CURR_DIR+"/templates"
SRC_DIR  = CURR_DIR+"/srcfiles"

_SP_CONF_    = CONF_DIR+"/splunk.json"
_MAIL_CONF_  = CONF_DIR+"/mail.json"
_NAMEDATA_   = CONF_DIR+"/fieldname.json"
_OUTPUT_DIR_ = CURR_DIR+"/reports"
_TEMPLATE_   = TEMP_DIR+'/template.txt.j2'
_TEMPLATE2_  = TEMP_DIR+'/include_low_template.txt.j2'
#_TEMPLATE_   = TEMP_DIR+'/2m.txt.j2' #TODO
_LOGO_DIR    = CURR_DIR+"/logos/dh"
_LOGODATA_   = _LOGO_DIR+'/logo2_b64.txt'

_MAIL_TEMPLATE_1 = TEMP_DIR+'/mail-body.txt.j2'
_MAIL_TEMPLATE_2 = TEMP_DIR+'/mail-password.txt.j2'
_TEST_MAIL_ADDR_ = "soc-all@dhsoc.jp"

_6MONTH_STATS = file_util.parse_csv_gzip(SRC_DIR+"/stats6month.csv.gz")

_SEND_DATA_ = _OUTPUT_DIR_+"/"+_tu.get_month(-1, "UNIX")+".json"

_HIGH_   = u"高"
_MEDIUM_ = u"中"
_LOW_    = u"低"

_MAGIC_WORD_ = "konna word wa nai"*2

logger_util.init_conf(CURR_DIR+"/config/log.conf")
logger = logger_util.get_standard_logger("monthly_report")

class Recorder:
	alerts = {}

	@classmethod
	def add(cls, customer, provider, alert):
		cls.alerts[cls._make_key(customer, provider)]=alert

	@classmethod
	def has(cls, customer, provider, alert_id):
		return cls.alerts.has_key(cls._make_key(customer, provider, alert_id))

	@classmethod
	def get(cls, customer, provider, alert_id):
		if cls.has(customer, provider, alert_id):
			return cls.alerts[cls._make_key(customer, provider, alert_id)]
		else:
			return None

	@classmethod
	def _make_key(cls, customer, provider, alert_id):
		return customer+"-"+provider+"-"+alert_id

class Cfg:
	includeLow   = False
	useMagic     = False
	checkMail    = True
	sendMail     = False
	remakeReport = False
	template = _TEMPLATE_

with open(_SP_CONF_, "r") as f:
	sp_cfg = json.load(f)

with open(_MAIL_CONF_, "r") as f:
	mail_cfg = json.load(f)

def get_base_obj(provider):
	cfg_file = CONF_DIR+"/{}.json".format(provider)
	with open(cfg_file, "r") as f:
		cfg=json.load(f)
	return cfg

sp=_splunk.SplunkSearcher(**sp_cfg)

def search(query):
	return sp.search(query)

def get_customer_list(provider = None, customer_name = None, excludes = None):
	lastmonth = _tu.get_month(-1, "UNIX")
	limitdate = lastmonth+"-01"
	q = '| savedsearch aella_list_mss_users'
	if provider:
		q+= '| where provider == "{}"'.format(provider)
	if customer_name:
		if "," in customer_name:
			q+= '| search customer_name IN ({})'.format(customer_name)
		else:
			q+= '| where customer_name == "{}"'.format(customer_name)
	q+= '| eval pastsec = strptime(install_date,"%Y-%m-%d") - strptime("{}","%Y-%m-%d")'.format(limitdate)
	q+= '| search install_date="unknown" OR pastsec<=0'

	result = search(q)
	customers = []
	exists = []
	for each in result:
		if not each.has_key("customer_name"):
			continue
		if customer_name and not each["customer_name"] in customer_name:
			continue
		if excludes and each["customer_name"] in excludes:
			continue

		if not each["customer_name"] in exists:
			exists.append(each["customer_name"])
			each_info = {
				"customer_name"  :each["customer_name"],
				"customer_fname" :each["customer_formal_name"],
				"provider_fname" :each["provider_formal_name"],
				"provider"       :each["provider"],
				"install_date"   :each["install_date"],
				"mail_addr"      :each["mail_addr"]
			}
			customers.append(each_info)
	return customers

def get_description_of_alert_type():
	q = '| inputlookup aella_categorize'
	q+= '| where isnotnull(incident_category) AND isnotnull(description) '
	q+= '| table incident_category,description'
	return search(q)

def get_description_of_killchain():
	q = '| inputlookup killchain_description'
	q+= '| where isnotnull(aella) AND isnotnull(description)'
	q+= '| table aella,phase,description'
	return search(q)

def get_alert_by_type(customer_name, provider, risk_score=2):
	q = '| savedsearch aella_lastmonth_alert'
	q+= '| search customer_name="{}"'.format(customer_name)
	if provider:
		q+= ' AND provider="{}"'.format(provider)
	if customer_name.lower() == "all":
		q+= '| search NOT customer_name=OCS1'
	q+= '| search risk_score>="{}"'.format(risk_score)
	if Cfg.useMagic:
		logger.debug( "use magic comment." )
		q+= '| search "{}"'.format(_MAGIC_WORD_)
	q+= '| stats count by incident_category'
	return search(q)

def _query_base_for_traffic_summary(index, customer_name):
	q = '| search index="{}" earliest=-1mon@mon latest=@mon-1'.format(index)
	q+= '| regex tenant_name != "(?i)(root|all|unknown)\s+tenants?"'
	q+= '| eval count = if(isnull(count), data_ingest, count)'
	q+= '| eval count = if(isnull(count), Count, count)'
	q+= '| rex field=count mode=sed "s/(\s*^|\s*$|,)//g"'
	q+= '| rex field=tenant_name mode=sed "s/(\s*^|\s*$)//g"'
	q+= '| join type=left tenant_name ['
	q+= '  | inputlookup aella_devices'
	q+= '  | rename tenant as tenant_name'
	q+= '  | fields customer_name, tenant_name'
	q+= ']'
	q+= '| where isnotnull(customer_name)'
	q+= '| search customer_name="{}"'.format(customer_name)
	return q

def _get_traffic_summary_by_ingest(customer_name, provider):
	q = _query_base_for_traffic_summary("aella_traffic_data_ingest", customer_name)
	q+= '| stats sum(count) by tenant_name'
	q+= '| rename sum(count) as count'
	q+= '| sort by count desc'
	return search(q)

def _get_traffic_summary_by_country(customer_name, provider):
	q = _query_base_for_traffic_summary("aella_traffic_country", customer_name)
	q+= '| rex field=dst_country_name mode=sed "s/(\s*^|\s*$|,)//g"'
	q+= '| rex field=app_name mode=sed "s/(\s*^|\s*$|,)//g"'
	q+= '| table tenant_name,dst_country_name,count'
	q+= '| eval dst_country_name=lower(dst_country_name)'
	q+= '| stats sum(count) by dst_country_name'
	q+= '| rename sum(count) as count'
	q+= '| sort by count desc'
	#q+= '| timechart span=1mon sum(count) by dst_country_name limit=0'
	return search(q)

def _get_traffic_summary_by_application(customer_name, provider):
	q = _query_base_for_traffic_summary("aella_traffic_app", customer_name)
	q+= '| rex field=app_name mode=sed "s/(\s*^|\s*$|,)//g"'
	q+= '| table tenant_name,app_name,count'
	q+= '| eval app_name=lower(app_name)'
	q+= '| stats sum(count) by app_name'
	q+= '| rename sum(count) as count'
	q+= '| sort by count desc'
	return search(q)

def get_alert_by_killchain(customer_name, provider, risk_score=2):
	q = '| savedsearch aella_lastmonth_alert'
	q+= '| search customer_name="{}"'.format(customer_name)
	if provider:
		q+= ' AND provider="{}"'.format(provider)
	if customer_name.lower() == "all":
		q+= '| search NOT customer_name=OCS1'
	if Cfg.useMagic:
		logger.debug( "use magic comment." )
		q+= '| search "{}"'.format(_MAGIC_WORD_)
	q+= '| search risk_score>="{}"'.format(risk_score)
	q+= '| stats count by event_type'
	return search(q)

def get_risklevel_table(customer_name, provider):
	q = '| savedsearch aella_lastmonth_alert'
	q+= '| search customer_name="{}"'.format(customer_name)
	if provider:
		q+= ' AND provider="{}"'.format(provider)
	if customer_name.lower() == "all":
		q+= '| search NOT customer_name=OCS1'
	if Cfg.useMagic:
		logger.debug( "use magic comment." )
		q+= '| search "{}"'.format(_MAGIC_WORD_)
	q+= '| stats count by risklevel,risk_score'
	q+= '| sort risk_score desc | fields - risk_score'
	return search(q)

#TODO this method is not work well. will be deleted.
def _back_get_6month_timechart(customer_name, provider, risk_score=None):
	result = []
	key = provider+":"+customer_name
	for each in _6MONTH_STATS:
		print raw
		exit(0)

def get_6month_timechart(customer_name, provider, risk_score=None):
	if risk_score:
		risk_score = risk_score
	elif Cfg.includeLow:
		risk_score = 0
	else:
		risk_score = 2
	q = '| savedsearch aella_last6month_alert'
	q+= '| search customer_name="{}"'.format(customer_name)
	if provider:
		q+= ' AND provider="{}"'.format(provider)
	q+= '| search risk_score>="{}"'.format(risk_score)
	if customer_name.lower() == "all":
		q+= '| search NOT customer_name=OCS1'
	if Cfg.useMagic:
		logger.debug( "use magic comment." )
		q+= '| search "{}"'.format(_MAGIC_WORD_)
	q+= '| timechart span=1mon count(tenantid) by risklevel'
	q+= '| eval high   = if(isnull(high),   0, high)'
	q+= '| eval middle = if(isnull(middle), 0, middle)'
	q+= '| eval low    = if(isnull(low),    0, low)'
	return search(q)

def get_1month_alerts(customer_name, provider, risk_score=None):
	if risk_score:
		risk_score = risk_score
	elif Cfg.includeLow:
		risk_score = 0
	else:
		risk_score = 2
	q = '| savedsearch aella_lastmonth_alert'
	q+= '| search customer_name="{}"'.format(customer_name)
	if provider:
		q+= ' AND provider="{}"'.format(provider)
	q+= '| search risk_score>="{}"'.format(risk_score)
	if customer_name.lower() == "all":
		q+= '| search NOT customer_name=OCS1'
	return search(q)

def get_1month_timechart(customer_name, provider, risk_score=None):
	if risk_score:
		risk_score = risk_score
	elif Cfg.includeLow:
		risk_score = 0
	else:
		risk_score = 2
	q = '| savedsearch aella_lastmonth_alert'
	q+= '| search customer_name="{}"'.format(customer_name)
	if provider:
		q+= ' AND provider="{}"'.format(provider)
	q+= '| search risk_score>="{}"'.format(risk_score)
	if customer_name.lower() == "all":
		q+= '| search NOT customer_name=OCS1' #TODO 
	if Cfg.useMagic:
		logger.debug( "use magic comment." )
		q+= '| search "{}"'.format(_MAGIC_WORD_)
	q+= '| timechart span=1day count(tenantid) by risklevel'
	q+= '| eval high   = if(isnull(high),   0, high)'
	q+= '| eval middle = if(isnull(middle), 0, middle)'
	q+= '| eval low    = if(isnull(low),    0, low)'
	return search(q)

def get_topnum_by(customer_name, provider, count_target, _num):
	if Cfg.includeLow:
		risk_score = 0
	else:
		risk_score = 2
	q = '| savedsearch aella_lastmonth_alert'
	q+= '| search srcip_type="private" customer_name="{}"'.format(customer_name)
	if provider:
		q+= ' AND provider="{}"'.format(provider)
	if Cfg.useMagic:
		logger.debug( "use magic comment." )
		q+= '| search "{}"'.format(_MAGIC_WORD_)
	q+= '| search risk_score>="{}"'.format(risk_score)
	q+= '| top limit={} {}'.format(_num, count_target)
	q+= '| sort by count desc'
	return search(q)

def to_html_img_tag(base64_img):
	data = urllib.quote(base64_img)
	return "<img src = {}{} />".format('data:image/png;base64,', data)

def get_detail(customer_name, provider):
	result = {}
	logger.info("make by alert_type with high risk alert")
	result["alert_type"] = _alert_by_type(customer_name, provider)
	logger.info("make by killchain with high risk alert")
	result["killchain"] = _alert_by_killchain(customer_name, provider)
	return result

def get_traffic_summary(customer_name, provider):
	def _traffic_by_ingest(customer_name, provider, report_dir):
		data={}
		data["name"]=u"分析対象のログデータ量"
		data["comment"]=u"分析対象となったログデータ量は以下の通りです。本データ量は、通信データ量を元に必要な情報にフィルタリングした後のデータ量となります。"
		fname = "{}/{}.json".format(report_dir,  "traffic_by_injest")
		if os.path.exists(fname):
			_raw = load_jsondata(fname)
		else:
			_raw = _get_traffic_summary_by_ingest(customer_name, provider)
			write_to_json(fname, _raw)
		_keyname = "tenant_name"
		values, labels = _each_alert_traffic(_raw, len(_raw), label= _keyname, is_float=True)
		img = graph.get_barchart_h(values, labels, size=(3, 3))
		#data["img"] = img
		data["table"] = []
		data["table_head"]=[u"対象ユーザ", u"バイト数[GB]"]
		values = [ "-" if each is 0 else each for each in values ]
		for i in reversed(range(0, len(values))):
			each = [labels[i], values[i]]
			data["table"].append(each)
		return data

	def _traffic_by_country(customer_name, provider, report_dir):
		data={}
		data["name"]=u"通信先(国家)ベースでのセッション数"
		data["comment"]=u"通信の多い国家は以下の通りです。"
		fname = "{}/{}.json".format(report_dir,  "traffic_by_country")
		if os.path.exists(fname):
			_raw = load_jsondata(fname)
		else:
			_raw = _get_traffic_summary_by_country(customer_name, provider)
			write_to_json(fname, _raw)
		del(_raw[10:])
		_keyname = "dst_country_name"
		values, labels = _each_alert_traffic(_raw, len(_raw), label= _keyname)
		img = graph.get_barchart_h(values, labels, size=(5, 6))
		data["img"] = img
		data["table"] = []
		data["table_head"]=[u"通信先国家", u"セッション数"]
		values = [ "-" if each is 0 else each for each in values ]
		for i in reversed(range(0, len(values))):
			each = [labels[i], values[i]]
			data["table"].append(each)
		return data

	def _traffic_by_application(customer_name, provider, report_dir):
		data={}
		data["name"]=u"通信プロトコル（アプリ）ベースでのセッション数"
		data["comment"]=u"通信の多いプロトコル/アプリケーションは以下の通りです。"
		fname = "{}/{}.json".format(report_dir,  "traffic_by_application")
		if os.path.exists(fname):
			_raw = load_jsondata(fname)
		else:
			_raw = _get_traffic_summary_by_application(customer_name, provider)
			write_to_json(fname, _raw)
		del(_raw[10:])
		_keyname = "app_name"
		values, labels = _each_alert_traffic(_raw, len(_raw), label= _keyname)
		img = graph.get_barchart_h(values, labels, size=(5, 6))
		data["img"] = img
		data["table"] = []
		data["table_head"]=[u"アプリケーション", u"セッション数"]
		values = [ "-" if each is 0 else each for each in values ]
		for i in reversed(range(0, len(values))):
			each = [labels[i], values[i]]
			data["table"].append(each)
		return data

	result = []
	logger.info("make traffic info by data_ingest")
	report_dir = get_report_dir(customer_name)
	result.append( _traffic_by_ingest(customer_name, provider, report_dir))
	logger.info("make traffic info by country")
	result.append( _traffic_by_country(customer_name, provider, report_dir))
	logger.info("make traffic info by application")
	result.append( _traffic_by_application(customer_name, provider, report_dir))
	return result

#TODO maybe needless
def check_alert_severity_over_middle(customer_name, provider):
	alerts = get_1month_alerts(customer_name, provider, 2)
	results = []
	for each in alerts:
		alert = dict(each)
		_id = alert["alert_id"]
		if Recorder.has(customer_name, provider, _id):
			results.append(Recorder.get(customer_name, provider, _id))
		else:
			#analyze_result = a 
			pass
	return results

def get_summary(customer_name, provider):
	summary = {}
	summary["risklevel_data"] = _risklevel_summary(customer_name, provider)
	summary["risklevel_data"]['header']=[u'危険度', u'アラート数']
	summary["alert_sum"]={"total":0, "middle_over":0}
	for each in summary["risklevel_data"]["table"]:
		label, num = each[0], each[1]
		summary["alert_sum"]["total"] += num
		if label != u"低":
			summary["alert_sum"]["middle_over"] += num
	report_dir = get_report_dir(customer_name)
	summary["timechart_1month"] = _timechart_1month(customer_name, provider, report_dir)
	summary["timechart_6month"] = _timechart_6month(customer_name, provider, report_dir)
	if summary["timechart_1month"]: #TODO false positive check is needed.
		#alerts = check_alert_severity_over_middle(customer_name, provider)
		summary["alert_sum"]["total_wo_fp"] = len(summary["timechart_1month"]["table"])-1
	else:
		summary["alert_sum"]["total_wo_fp"] = 0
	return summary

def _timechart_1month(customer_name, provider, report_dir):
	logger.info("get alert history of {} from splunk.".format(customer_name))
	fname = "{}/{}.json".format(report_dir,  "1month_timechart")
	if os.path.exists(fname):
		_raw = load_jsondata(fname)
	else:
		_raw = get_1month_timechart(customer_name, provider)
		write_to_json(fname, _raw)
	result = _raw
	if len(result) is 0:
		logger.info( "no alert at 1 months" )
		return None
	else:
		logger.info( "make graph of timechart Term:1month" )
		return _make_timechart_byrisklevel(result, _type="day", label_interval=3, size=(8, 3), fsize=8)

def _timechart_6month(customer_name, provider, report_dir):
	logger.info("get alert history of {} from splunk.".format(customer_name))
	fname = "{}/{}.json".format(report_dir,  "6month_timechart")
	if os.path.exists(fname):
		_raw = load_jsondata(fname)
	else:
		_raw = get_6month_timechart(customer_name, provider)
		write_to_json(fname, _raw)
	result = _raw
	if len(result) is 0:
		logger.info( "no alert at 6 months" )
		return None
	else:
		logger.info( "make graph of timechart Term:6month" )
		return _make_timechart_byrisklevel(result, _type="month", fsize=16)

def _make_timechart_byrisklevel(_raw, _type="day", label_interval=None, size=None, fsize=12):
	values, labels = _parse_risklevel_timechart(_raw, _type)
	if Cfg.includeLow:
		legend = [_LOW_, _MEDIUM_, _HIGH_]
	else:
		legend = [_MEDIUM_, _HIGH_]
	data = {}
	data["table"]=[]
	data["table_head"] = [ u"年月" if _type == "month" else u"日付"]
	data["table_head"].extend(legend)
	data['table'] = []
	for i in range(0, len(labels)):
		each = [labels[i]]
		for each_level in values:
			each.append(each_level[i])
		data['table'].append(each)
	color = [ _clr.YELLOW, _clr.RED ]
	img = graph.get_stack_barchart(values, labels, legend, label_interval, size, fsize, color=color)
	data["img"] = img
	return data


def _each_alert_traffic(_raw, _num, label, is_float=False):
	values, labels =[], []
	datas = {}
	for each in _raw:
		labels.append(each[label])
		if is_float:
			values.append(float(each["count"]))
		else:
			values.append(int(each["count"]))
	if _num > len(labels):
		#labels.append(u"その他の項目なし")
		#values.append(0)
		pass
	values.reverse()
	labels.reverse()
	return values, labels

def get_alert_traffic(customer_name, provider, _num=5):
	def _alert_traffic_app_base(customer_name, provider, _num=5):
		data={}
		data["name"]=u"アプリケーション(プロトコル)TOP{}".format(_num)
		data["comment"]=u"アラートが発生した通信について利用されたプロトコルのTOP{}は以下の通りです".format(_num)
		_keyname = "appid_name"
		report_dir = get_report_dir(customer_name)
		fname = "{}/{}.json".format(report_dir,  "alert_traffic_by_app")
		if os.path.exists(fname):
			_raw = load_jsondata(fname)
		else:
			_raw = get_topnum_by(customer_name, provider, _keyname, _num)
			write_to_json(fname, _raw)
		values, labels = _each_alert_traffic(_raw, _num, label= _keyname)
		data["table_head"]=[u"アプリケーション", u"アラート数"]
		img = graph.get_barchart_h(values, labels, size=(3, 3))
		data["img"] = img
		data["table"] = []
		values = [ "-" if each is 0 else each for each in values ]
		for i in reversed(range(0, len(values))):
			each = [labels[i], values[i]]
			if not each in data["table"]:
				data["table"].append(each)
		return data

	def _alert_traffic_srcip_base(customer_name, provider, _num=5):
		data={}
		data["name"]=u"通信元(IPアドレス)TOP{}".format(_num)
		data["comment"]=u"アラートの発生が多い通信元ホストのTOP{}は以下の通りです。".format(_num)
		_keyname = "srcip"
		report_dir = get_report_dir(customer_name)
		fname = "{}/{}.json".format(report_dir,  "alert_traffic_by_srcip")
		if os.path.exists(fname):
			_raw = load_jsondata(fname)
		else:
			_raw = get_topnum_by(customer_name, provider, _keyname, _num)
			write_to_json(fname, _raw)
		values, labels = _each_alert_traffic(_raw, _num, label= _keyname)
		data["table_head"]=["srcip", u"アラート数"]
		img = graph.get_barchart_h(values, labels, size=(3, 3))
		data["img"] = img
		data["table"] = []
		values = [ "-" if each is 0 else each for each in values ]
		for i in reversed(range(0, len(values))):
			each = [labels[i], values[i]]
			data["table"].append(each)
		return data

	def _alert_traffic_dstip_base(customer_name, provider, _num=5):
		data={}
		data["name"]=u"通信先(IPアドレス)TOP{}".format(_num)
		data["comment"]=u"アラート発生時の通信先について、IPアドレスベースのTOP{}は以下の通りです。".format(_num)
		_keyname = "dstip"
		report_dir = get_report_dir(customer_name)
		fname = "{}/{}.json".format(report_dir,  "alert_traffic_by_dstip")
		if os.path.exists(fname):
			_raw = load_jsondata(fname)
		else:
			_raw = get_topnum_by(customer_name, provider, _keyname, _num)
			write_to_json(fname, _raw)
		values, labels = _each_alert_traffic(_raw, _num, label= _keyname)
		data["table_head"]=["dstip", u"アラート数"]
		img = graph.get_barchart_h(values, labels, size=(3, 3))
		data["img"] = img
		data["table"] = []
		values = [ "-" if each is 0 else each for each in values ]
		for i in reversed(range(0, len(values))):
			each = [labels[i], values[i]]
			data["table"].append(each)
		return data

	def _alert_traffic_dstip_country_base(customer_name, provider, _num=5):
		data={}
		data["name"]=u"通信先(国家)TOP{}".format(_num)
		data["comment"]=u"アラート発生時の通信先について、国家ベースのTOP{}は以下の通りです。".format(_num)
		_keyname = "dstip_geo_countryName"
		report_dir = get_report_dir(customer_name)
		fname = "{}/{}.json".format(report_dir,  "alert_traffic_by_dst_country")
		if os.path.exists(fname):
			_raw = load_jsondata(fname)
		else:
			_raw = get_topnum_by(customer_name, provider, _keyname, _num)
			write_to_json(fname, _raw)
		values, labels = _each_alert_traffic(_raw, _num, label= _keyname)
		data["table_head"]=[u"通信先国家", u"アラート数"]
		img = graph.get_barchart_h(values, labels, size=(3, 3))
		data["img"] = img
		data["table"] = []
		values = [ "-" if each is 0 else each for each in values ]
		for i in reversed(range(0, len(values))):
			each = [labels[i], values[i]]
			data["table"].append(each)
		return data

	result = []
	logger.info( "make graph by application" )
	result.append( _alert_traffic_app_base(customer_name, provider, _num) )
	logger.info( "make graph by srcip" )
	result.append( _alert_traffic_srcip_base(customer_name, provider, _num) )
	logger.info( "make graph by dstip" )
	result.append( _alert_traffic_dstip_base(customer_name, provider, _num) )
	logger.info( "make graph by countryName of dstip" )
	result.append( _alert_traffic_dstip_country_base(customer_name, provider, _num) )
	return result

def _alert_by_type(customer_name, provider):
	data = {}
	keys = ["malware-object", "ids", "bad_reps", "mal_anomaly", "suspicious", "noise"]
	report_dir = get_report_dir(customer_name)
	fname = "{}/{}.json".format(report_dir,  "alert_type_desc")
	if os.path.exists(fname):
		_raw_desc = load_jsondata(fname)
	else:
		_raw_desc = get_description_of_alert_type()
		write_to_json(fname, _raw_desc)
	descs = {}
	for each in _raw_desc:
		category = "noise" if each["incident_category"]=="monthly" else each["incident_category"]
		descs[category] = [ category, each["description"] ]
	data["desc_head"] = [ u"タイプ", u"説明" ]
	data["description"] = []
	for _key in keys:
		data["description"].append(descs[_key])
	keys.reverse()
	report_dir = get_report_dir(customer_name)
	fname = "{}/{}.json".format(report_dir,  "alert_type")
	if os.path.exists(fname):
		_raw = load_jsondata(fname)
	else:
		_raw = get_alert_by_type(customer_name, provider)
		write_to_json(fname, _raw)
	tmp = {}
	for each in _raw:
		category = each["incident_category"].lower()
		if category == "monthly":
			tmp["noise"] = int(each["count"])
		else:
			tmp[category] = int(each["count"])
	values = []
	for each in keys:
		tmp[each] = tmp[each] if tmp.has_key(each) else 0
		values.append(tmp[each])
	data["table_head"] = [ u"タイプ", u"アラート数" ]
	data["total_num"] = 0
	data["table"] = []
	for i in reversed(range(0, len(values))):
		data["table"].append([keys[i], values[i]])
		data["total_num"] += values[i]
	data["img"] = graph.get_barchart_h(values, keys, size=(3, 3))
	return data

def _alert_by_killchain(customer_name, provider):
	data = {}
	keys = ["reconn", "delivery", "exploit", "install", "cnc", "action"]
	report_dir = get_report_dir(customer_name)
	fname = "{}/{}.json".format(report_dir,  "alert_killchain_desc")
	if os.path.exists(fname):
		_raw_desc = load_jsondata(fname)
	else:
		_raw_desc = get_description_of_killchain()
		write_to_json(fname, _raw_desc)
	descs = {}
	for each in _raw_desc:
		descs[each["aella"]] = [ each["aella"], each["phase"], each["description"] ]
	data["desc_head"] = [ u"表記", u"フェーズ", u"説明" ]
	data["description"] = []
	for _key in keys:
		data["description"].append(descs[_key])
	keys.reverse()
	report_dir = get_report_dir(customer_name)
	fname = "{}/{}.json".format(report_dir,  "alert_killchain")
	if os.path.exists(fname):
		_raw = load_jsondata(fname)
	else:
		_raw=get_alert_by_killchain(customer_name, provider)
		write_to_json(fname, _raw)
	for each in _raw:
		ev_type = each["event_type"].lower()
		if ev_type in keys:
			data[ev_type] = int(each["count"])
		elif data.has_key("nw_anomary"):
			data["nw_anomary"] += int(each["count"])
		else:
			data["nw_anomary"] = int(each["count"])
	values = []
	for each in keys:
		data[each] = data[each] if data.has_key(each) else 0
		values.append(data[each])
	data["nw_anomary"] = data["nw_anomary"] if data.has_key("nw_anomary") else 0
	data["table_head"] = [ u"フェーズ", u"アラート数" ]
	data["total_num"] = 0
	data["table"] = []
	for i in reversed(range(0, len(values))):
		data["table"].append([keys[i], values[i]])
		data["total_num"] += values[i]
	data["img"] = graph.get_barchart_h(values, keys, size=(3, 3))
	return data

def _risklevel_summary(customer_name, provider):
	report_dir = get_report_dir(customer_name)
	fname = "{}/{}.json".format(report_dir,  "risklevel_table")
	if os.path.exists(fname):
		_raw = load_jsondata(fname)
	else:
		_raw = get_risklevel_table(customer_name, provider)
		write_to_json(fname, _raw)
	result = _raw
	values, labels = _parse_risklevel_data(result)
	data = {}
	data["table"]=[]
	for i in range(0, len(values)):
		each = [labels[i], values[i]]
		data["table"].append(each)
	img = graph.get_circle(values, legend=labels)
	data["img"] = img
	return data

def _parse_risklevel_timechart(_raw, _type):
	high_list, middle_list, low_list, labels = [], [], [], []
	datas = {}
	for each in _raw:
		if not each.has_key("_time"):
			continue
		if _type == "month":
			_date = re.sub(r'^(\d{4})-(\d{1,2}).*$', r'\1/\2', each['_time'])
		elif _type == "day":
			_date = re.sub(r'^(\d{4})-(\d{1,2})-(\d{1,2}).*$', r'\1/\2/\3', each['_time'])
		else:
			_date = re.sub(r'^(\d{4})-(\d{1,2})-(\d{1,2})T([\d|:]+).*$',
					r'\1/\2/\3 \4', each['_time'])
		labels.append(_date)
		low_list.append( int(each["low"]) if each.has_key("low") else 0 )
		middle_list.append( int(each["middle"]) if each.has_key("middle") else 0 )
		high_list.append( int(each["high"]) if each.has_key("high") else 0 )
	if Cfg.includeLow:
		values = [low_list, middle_list, high_list]
	else:
		values = [middle_list, high_list]
	return values, labels

def _parse_risklevel_data(result):
	values, labels=[], []
	datas = {}
	for each in result:
		if each.has_key("risklevel"):
			risk = each["risklevel"].lower()
			datas[risk]=int(each["count"])
	if not datas.has_key("high"):
		datas["high"] = 0
	if not datas.has_key("middle"):
		datas["middle"] = 0
	if not datas.has_key("low"):
		datas["low"] = 0
	labels.append(_HIGH_)
	values.append(datas["high"])
	labels.append(_MEDIUM_)
	values.append(datas["middle"])
	if Cfg.includeLow:
		labels.append(u"低")
		values.append(datas["low"])
	return values, labels

def get_report_target(data):
	report_target = data["report_target"]
	names=data["report_target"]["table_item_name"]
	report_target["table_item"] = []
	report_target["table_item"].append(
		{ "name": names["product"], "content" : "Stellar Cyber社製 Starlight" } )
	month = _tu.get_month(-1)
	report_target["month"]=month
	first = month+"1日"
	last = _tu.get_last_day(month)
	report_target["table_item"].append(
		{ "name": names["term"], "content" : u"{} 〜 {}".format(first, last)} )
	return report_target

def load_logo():
	with open(_LOGODATA_) as f:
		res = f.read()
	return res

def make_each_report(customer, provider, customer_info, base_obj, with_traffic=False):
	data = copy.deepcopy(base_obj)

	data["headers"]["customer_name"]=u"{} 御中".format(customer_info["customer_fname"])
	if data["headers"]["date"] == "JPN":
		data["headers"]["date"] = _tu.get_date()
	else:
		data["headers"]["date"] = _tu.get_date(_tu.UNIX)
	
	data["headers"]["company"]=customer_info["provider_fname"]
	data["headers"]["sub_title"] += "{}版".format(_tu.get_month(-1))
	#data["headers"]["logo"] = load_logo()
	data["report_target"] = get_report_target(data)
	logger.info("make summary")
	if customer == "ALL":
		customer = "*"

	if with_traffic:
		data["traffic_summary"] = get_traffic_summary(customer, provider)
	data["summary"] = get_summary(customer, provider)
	total = data["summary"]["alert_sum"]["total"]
	total_wo_fp = data["summary"]["alert_sum"]["total_wo_fp"]
	middle_over = data["summary"]["alert_sum"]["middle_over"]
	logger.info("alert num is {}/{}".format(middle_over, total))

	logger.info("make alert_traffic")
	data["alert_traffic"] = None if total_wo_fp is 0 else get_alert_traffic(customer, provider)
	logger.info("make detail")
	data["detail"] = get_detail(customer, provider)
	return data

def get_report_dir(customer):
	month = _tu.get_month(-1, _tu.UNIX)
	return _OUTPUT_DIR_+"/{}/{}".format(customer, month)

def load_jsondata(file_name):
	logger.info("load json file of {}".format(file_name))
	with open(file_name) as f:
		data = json.load(f)
	return data

def write_to_json(fname, _raw):
	logger.info("write json file of {}".format(fname))
	data = [ dict(each) for each in _raw ]
	with open(fname, "w") as wf:
		json.dump(data, wf, indent=4)

def write_file(data, customer, template, password=None):
	month_ja = data["report_target"]["month"]
	month = _tu.get_month(-1, _tu.UNIX)
	#report_dir = _OUTPUT_DIR_+"/{}/{}".format(customer, month)
	report_dir = get_report_dir(customer)

	html_file = report_dir+"/{}.html".format(customer)
	if os.path.exists(html_file):
		os.remove(html_file)
	logger.info("write report file of {}".format(html_file))
	report.write(data, html_file, template)
	pdf_file = report_dir+"/monthly_report_{}.pdf".format(month)
	if os.path.exists(pdf_file):
		os.remove(pdf_file)
	logger.info("write pdf Name:{}".format(pdf_file))
	file_util.convert2pdf(html_file, pdf_file)
	zip_name = "{}.zip".format(
			data["headers"]["filename"].replace('{replace}', month_ja))
	zip_file = report_dir+"/"+zip_name
	if os.path.exists(zip_file):
		os.remove(zip_file)
	logger.info("write zip Name:{}".format(zip_file))
	res = file_util.file_to_zip(pdf_file, zip_file, random=True)
	password = res[1]
	return zip_name, zip_file, password

def send_mail(zip_name, zip_file, password, customer_info):
	def send_to_customer(taddr, subject, mail_template, rawbody, attach_file=None, attach_name=None, ccaddrs=None):
		faddr  = mail_cfg["from"]
		server = mail_cfg["server"]
		port   = mail_cfg["port"]
		is_ssl = mail_cfg["ssl"]
		if is_ssl:
			account = mail_cfg["account"]["user"]
			password = mail_cfg["account"]["password"]
		body = report.render(rawbody, mail_template)
		msg = mail_util.set_msg(
				faddr, taddr, subject, body, attach_file, attach_name, ccaddrs=ccaddrs)
		if isinstance(taddr, basestring):
			send_to = [taddr]
		else:
			send_to = copy.copy(taddr)
		if ccaddrs:
			send_to.extend(ccaddrs)

		if is_ssl:
			mail_util.ssend( server, faddr, send_to, msg, account, password, port )
		else:
			mail_util.send( server, faddr, send_to, msg )
	customer_fname = customer_info["customer_fname"]
	customer_name  = customer_info["customer_name"] 
	mail_addr      = customer_info["mail_addr"].split(",")
	body_data = { "customer_name" : customer_fname,
					"month" : _tu.get_month(-1),
					"password" : password }
	month = _tu.get_month(-1, _tu.UNIX)
	subject = mail_cfg["subject"]
	if Cfg.checkMail:
		body_data["mail_to"] = "\n".join(mail_addr)
		body_data["is_check"] = True
		mail_addr = _TEST_MAIL_ADDR_.split(",")
		send_to_customer(mail_addr, subject, _MAIL_TEMPLATE_1, body_data, zip_file, zip_name)
	else:
		ccaddrs = [ mail_cfg["from"] ]
		send_to_customer(mail_addr, subject, _MAIL_TEMPLATE_1, body_data, zip_file, zip_name, ccaddrs)
		subject = u"[パスワードのご連絡] "+subject
		send_to_customer(mail_addr, subject, _MAIL_TEMPLATE_2, body_data, ccaddrs=ccaddrs)

def write_send_data(customer_name, zip_name, zip_fullname, password):
	if os.path.exists(_SEND_DATA_):
		try:
			with open(_SEND_DATA_) as f:
				data = json.load(f)
		except ValueError as e:
			logger.error("corrupt send data json. recreate new one")
			data = {}
	else:
		data = {}
	if not customer_name in data:
		data[customer_name] = {}
	data[customer_name]["zip_name"] = zip_name
	data[customer_name]["zip_fullname"] = zip_fullname
	data[customer_name]["password"] = password

	with open(_SEND_DATA_, "w") as wf:
		json.dump(data, wf, indent=4)

def exists_data(customer_name):
	if os.path.exists(_SEND_DATA_):
		try:
			with open(_SEND_DATA_) as f:
				data = json.load(f)
			return customer_name in data
		except ValueError as e:
			return False
	else:
		return False

def get_send_data(customer_name):
	with open(_SEND_DATA_, "r") as f:
		data = json.load(f)
	if not customer_name in data:
		assert False, "cannot make report yet for {}".format(customer_name)
	else:
		return data[customer_name]

def main():
	logger.info("start")
	parser = argparse.ArgumentParser(description="make monthly report for args user and provider")
	parser.add_argument('provider', help="monthly report target provider")
	parser.add_argument('-customer', default=None, help="monthly report target customer")
	parser.add_argument('-with_traffic', default=None, help="monthly report target customer")
	parser.add_argument('-with_lowlevel', default=None, help="monthly report target customer")
	parser.add_argument('-with_magic', default=None, help="monthly report target customer")
	parser.add_argument('-excludes', default=None, help="excludes customer name for sending")
	parser.add_argument('-to_customer', nargs="?", const=True, help="BE CAREFULL!! if you set this, you send mail to customer.")
	parser.add_argument('-r', '--remake_report', nargs="?", const=True, help="recreate pdf if already make pdf for this customer.")
	parser.add_argument('-m', '--send_mail', nargs="?", const=True, help="send mail to customers")
	args = parser.parse_args()
	customer = args.customer
	provider = args.provider
	with_traffic = args.with_traffic
	with_lowlevel = args.with_lowlevel
	with_magic = args.with_magic
	to_customer = args.to_customer
	is_remake_report = args.remake_report
	excludes = args.excludes
	is_send_mail = args.send_mail
	if with_lowlevel:
		Cfg.includeLow = True
		Cfg.template   = _TEMPLATE2_
	if with_magic:
		Cfg.useMagic = True
	if to_customer:
		Cfg.checkMail = False
	if is_remake_report is True:
		Cfg.remakeReport = True
	if is_send_mail is True:
		Cfg.sendMail = True

	logger.info("check monthly report for {} and {}".format(customer, provider))
	customers = get_customer_list(provider, customer, excludes)
	base_obj = get_base_obj(provider)
	for each in customers:
		try:
			customer = each["customer_name"]
			logger.info( "start to make report for {}".format(customer) )
			if exists_data(customer) and not Cfg.remakeReport:
				logger.info("already exists report files")
			else:
				report_dir = get_report_dir(customer)
				if not os.path.exists(report_dir):
					os.makedirs(report_dir)
				data = make_each_report(customer, provider, each, base_obj, with_traffic)
				zip_name, zip_fullname, password = write_file(data, customer, Cfg.template)
				write_send_data(customer, zip_name, zip_fullname, password)
		except AssertionError as e:
			logger.exception(e)
	if Cfg.sendMail:
		logger.info("start to send email")
		for each in customers:
			try:
				customer = each["customer_name"]
				logger.info("send log to {} for {}".format(each["mail_addr"], customer))
				senddata = get_send_data(customer)
				send_mail(  senddata["zip_name"].encode("utf-8"),
							senddata["zip_fullname"],
							senddata["password"],
							each)
			except AssertionError as e:
				logger.exception(e)
	logger.info("end")

if __name__ == '__main__':
	try:
		main()
	except Exception as e:
		logger.exception(e)

