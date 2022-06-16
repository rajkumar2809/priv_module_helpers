_CALL = []

def _get_callinfo():
	call = _CALL
	for each in range(0, _CALL):
		_CALL.pop()
	return call

def build_url(hostname, resource=None, params=None, protocol="https", port=None):
	assert not('?' in hostname), 'you cannot put params in hostname please use params with dict'
	assert not('#' in hostname), 'url fragment is not support.'
	args = ( hostname, resource, params, protocol, port )
	_CALL.append({"send_post": args})
	return args

def get_opener(url, username=None, password=None, ssl_flag=True):
	args = (url, username, password, ssl_flag)
	_CALL.append({"send_post": args})
	return args

def send_post(url, data, username=None, password=None, headers=None):
	args = (url, data, username, password, headers)
	_CALL.append({"send_post": args})
	return args

def send_get(url, username=None, password=None, headers=None):
	args = (url, username, password, headers)
	_CALL.append({"send_post": args})
	return args

