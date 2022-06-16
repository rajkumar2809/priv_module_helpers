import os, sys

_COM_ = []

def clear_call_history():
	del _COM_[:]

class issue(object):
	pass

class RedmineTicket(object):
	def __init__(self, issue, pjid, subject="", tracker_id="", **data):
		if data.has_key("description"):
			desc = data["description"]
			self.description = [desc] if desc else []
			del data["description"]
		else:
			self.description = []
		if data.has_key("custom_fields"):
			del data["custom_fields"]
		self.issue = issue
		self.project_id = pjid
		self.subject = subject
		self.tracker_id = tracker_id
		self.project_info = data.copy()
		self.custom_fields = {}
		self.ticket_id = None
		self.update_notes = None

	def set_updateinfo(self, _id, notes):
		self.ticket_id = _id
		self.update_notes = notes

	def add_project_info(self, name, value):
		self.project_info[name]=value

	def add_description(self, msg1, msg2=None):
		self.description.append((msg1, msg2))

	def add_custom_field(self, _id, value):
		self.custom_fields[_id]=value

	def save(self):
		_COM_.append(
			{   "method" : "save",
				"subject" : self.subject,
				"tracker_id" : self.tracker_id,
				"project_info" : self.project_info,
				"description" : self.description,
				"custom_fields" : self.custom_fields
			}
		)

	def update(self):
		_COM_.append( {
				"method" : "update",
				"ticket_id" : self.ticket_id,
				"update_notes" : self.update_notes,
				"project_info" : self.project_info,
				"description" : self.description,
				"custom_fields" : self.custom_fields
		} )

class RedmineConnector(object):
	_CFID_ = 9
	_CFVALUE_ = "ABCDEFG"
	_TICKETID_ = "1234"
	_TICKETID_CLOSED_ = "4321"
	_PJID_ = 9999

	def __init__(self, url = None,
				username = None,
				password = None,
				project_name=None,
				**others ):
		self.url = url
		self.username = username
		self.password = password
		self.project_name = project_name
		self.project_id = self._PJID_
		self.infos = others

	def make_new_ticket(self, subject=None, tracker_id=None, due_date=None, description=None):
		return RedmineTicket(
				issue=issue, pjid=self.project_id,
				subject=subject, tracker_id=tracker_id,
				due_date=due_date, description=description )

	def get_ticket_numbers(self, cfid, value, status=None):
		if cfid == self._CFID_ and self._CFVALUE_ == value:
			if str(status) != "*":
				result = [ self._TICKETID_, self._TICKETID_CLOSED_ ]
			else:
				result = [ self._TICKETID_ ]
		else:
			result = []
		return result

	def make_update_ticket(self, _id, notes, status_id=None, custom_fields=None):
		ticket = RedmineTicket( issue=issue, pjid=self.project_id, status_id=status_id )
		ticket.set_updateinfo( _id, notes )
		if custom_fields:
			assert isinstance(custom_fields, dict), "custom_fields is must be dict type."
			for k, v in custom_fields.items():
				ticket.add_custom_field(k, v)
		return ticket


