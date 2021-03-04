#!/bin/env python
#-*- coding: utf-8 -*-

from flask import Flask, Response, render_template, request
from pathlib import Path
import os
import time
import json
import uuid
import MySQLdb
import httplib
from tinydb import TinyDB, Query
import copy
import requests
from urlparse import urlparse

app = Flask(__name__)

server_ip = 'localhost'
server_port = 5000
site_name = 'Seocho Lab.'

db_server = 'localhost'
db_user = 'vnfm'
db_pw = 'telco1234'
db_name = 'vnfm'

vnfm_ip = 'localhost'
vnfm_port = 8080


@app.route('/v2.1/vnf/instances/<uuid:vnfi_id>/servers/<uuid:vnfci_id>/action', methods=['POST'])
def move_volume(vnfi_id, vnfci_id):
	job_id = str(uuid.uuid4())
	Path('./jobs/'+job_id).touch()
	res_body = {
			"job": {
				"id": job_id,
				"links": [
					{
						"href": "http://"+server_ip+":"+str(server_port)+"/v2/jobs/"+job_id,
						"rel": "self"
						}
					]
				}
			}
	return Response(json.dumps(res_body), status=202, mimetype='application/json; charset=utf-8')


@app.route('/v2/jobs/<uuid:job_id>', methods=['GET'])
def get_job_status(job_id):
	try:
		stat = os.stat('./jobs/{}'.format(job_id))

		cur_time = time.time()

		if (cur_time - stat.st_mtime < 60):
			progress = 50
			status = 'Running'
			status_code = '200'
		else:
			progress = 100
			status = 'Completed'
			status_code = '303'
		
		res_body = {
				"job": {
					"job_id": str(job_id),
					"job_name": "move volume",
					"error_code": "0",
					"error_descr": "No errors",
					"progress": progress,
					"status": status,
					"status_code": status_code,
					"links": [
						{
							"href": "http://"+server_ip+":"+str(server_port)+"/v2/jobs/"+str(job_id),
							"rel": "self"
						}
						]
					}
				}

	except OSError:
		res_body = { "fail_detail": { "code": 404, "message":"job not found" } }
		return Response(json.dumps(res_body), status=404, mimetype='application/json; charset=utf-8')

	return Response(json.dumps(res_body), status=200, mimetype='application/json; charset=utf-8')


@app.route('/resources/status_check.jsp', methods=['GET'])
def heartbeat():
	return Response(status=200)


def db_select_one(query):
	result = None
	db = MySQLdb.connect(db_server, db_user, db_pw, db_name)
	cursor = db.cursor()

	try:
		cursor.execute(query)
		result = cursor.fetchone()

	except MySQLdb.Error, e:
		try:
			print("MySQL Error [{}]: {}".format(e.args[0], e.args[1]))
		except IndexError:
			print("MySQL Error: {}".format(str(e)))
		finally:
			raise e

	finally:
		db.close()

	data = {}

	for i,d in enumerate(cursor.description):
		data[d[0]] = result[i]

	return data
	

def http_send_to_vnfm(method, uri, body, db):

	conn = httplib.HTTPConnection(vnfm_ip, vnfm_port)

	try:
		token = get_cms_token(db)
		if token == None:
			return None, None, None
	except:
		return None, None, None

	headers = {"X-Auth-Token": token }

	conn.request(method, uri, body, headers)
	reqlog = "VNFM < Request\n  * URI   : {} {}\n  * Token : {}\n".format(method, uri, token)
	if(len(body) > 0):
		reqlog = reqlog + "  * Body  : \n{}\n".format(body)

	r1 = conn.getresponse()
	data1 = r1.read()
	reslog = "\n\nVNFM > Response\n  * Status: {} {}\n  * Result: {}\n  * Body  : \n{}".format(r1.status, r1.reason, r1.status/100==2 and "Success" or "Fail", data1)

	return r1.status, data1, reqlog+reslog


@app.route('/vnf/instances/<vnfi_id>', methods=['GET'])
def vnf_instance(vnfi_id):
	vnfi_uri = '/manager/v2/vnf/instances/'+vnfi_id+'/details'
	status, res_body, msglog = http_send_to_vnfm("GET", vnfi_uri, "", "vnfm")
	if status == 200:
		vnfi = json.loads(res_body)

		vnfci_uri = vnfi['vnf']['components']['links'][0]['href']
		vnfci_uri = vnfci_uri[vnfci_uri.find('/',8):]
		status, res_body, msglog = http_send_to_vnfm("GET", vnfci_uri, "", "vnfm")
		if status == 200:
			vnfcis = json.loads(res_body)

		updpkg_uri = '/manager/v2/vnf/packages?updatefor=' + vnfi_id
		status, res_body, msglog = http_send_to_vnfm("GET", updpkg_uri, "", "vnfm")
		if status == 200:
			updpkgs = json.loads(res_body)

		set_vdus_settings_from_vnfr(vnfi_id, vnfi['vnf']['vnfi_name'])

	return render_template('vnf-instance.html', vnfi=vnfi, vnfcis=vnfcis, updpkgs=updpkgs, site_name=site_name)


@app.route('/vnf/instances/', methods=['GET'])
@app.route('/', methods=['GET'])
def vnf_instances():
	uri = "/manager/v2/vnf/instances/list"
	status, res_body, msglog = http_send_to_vnfm('GET', uri, "", "vnfm")

	if status == 200:
		res_json=json.loads(res_body)

	return render_template('vnf-instances.html', vnfis=res_json, site_name=site_name)


@app.route('/vnf/eventLogs/', methods=['GET'])
@app.route('/vnf/eventLogs/page/<page>', methods=['GET'])
def vnf_eventlogs(page="1"):
	perpage = 15
	uri = "/manager/v2/vnf/events?perpage="+ str(perpage) +"&page="+ page
	status, res_body, msglog = http_send_to_vnfm('GET', uri, "", "vnfm")

	if status == 200:
		res_json=json.loads(res_body)

	return render_template('vnf-eventlogs.html', site_name=site_name, events=res_json, curpage=int(page), perpage=perpage)


@app.route('/vnf/eventLogs/<job_id>', methods=['GET'])
def vnf_eventlog(job_id):
	uri = "/manager/v2/vnf/lc-details/" + job_id
	status, res_body, msglog = http_send_to_vnfm('GET', uri, "", "vnfm")

	if status == 200:
		res_json=json.loads(res_body)

	return render_template('vnf-eventlog.html', site_name=site_name, log=res_json)


def get_cms_token(db):
	sql = "select token from {}.AUTH_PRODUCER_TBL where name='{}'".format(db, db=="vnfm" and "CMS" or "PORTAL")
	db = MySQLdb.connect(db_server, db_user, db_pw, db_name)
	cursor = db.cursor()
	try:
		cursor.execute(sql)
		data = cursor.fetchone()
		if data == None:
			print "Data Not Exist: %s" % sql
			return
		return data[0]
	except MySQLdb.Error, e:
		try:
			print "MySQL Error [%d]: %s" % (e.args[0], e.args[1])
		except IndexError:
			print "MySQL Error: %s" % str(e)
		finally:
			raise e

	finally:
		db.close()


@app.route('/lcop/moveVolume', methods=['GET', 'POST'])
def op_move_volume():
	mvreq = request.get_json(force=True)

	uri = "/manager/v2/vnf/instances/" + mvreq['vnfi_id']
	body = "{ \"action_type\": \"move volume\", \"volume_attach\": { \"source_server\": \""+mvreq['source_vnfci_name']+"\", \"target_server\": \""+mvreq['target_vnfci_name']+"\" } }"
	status, res_body, msglog = http_send_to_vnfm('PATCH', uri, body, "vnfm")

	job_url = ''
	if status == 202:
		res_json=json.loads(res_body)
		job_url = res_json['job']['id']

	return Response(msglog, status=200, headers={'X-Job-ID': job_url})



@app.route('/<system>/jobs/<job_id>', methods=['GET'])
def op_job_status(system, job_id):

	if system == 'cms':
		uri = '/v2/jobs/' + job_id
		status, res_body, msglog = http_send_to_vnfm('GET', uri, '', "nfvo")
	else:
		uri = '/manager/v2/jobs/' + job_id
		status, res_body, msglog = http_send_to_vnfm('GET', uri, '', "vnfm")

	return Response(msglog, status=200)



@app.route('/vnf/packages/', methods=['GET'])
def vnf_packages():

	uri = '/manager/v2/vnf/packages?perpage=100'
	status, res_body, msglog = http_send_to_vnfm('GET', uri, '', "vnfm")

	pkgs = []
	if status == 200:
		res_json = json.loads(res_body)
		if int(res_json['total_count']) > 0:
			pkgs = res_json['packages']
			for pkg in pkgs:
				pkg['page_uri'] = '/vnf/packages/' + pkg['vnfd_id']

	return render_template('vnf-packages.html', pkgs=pkgs, site_name=site_name)


@app.route('/vnf/packages/<vnfd_id>', methods=['GET'])
def vnf_package(vnfd_id):
	uri = '/manager/v2/vnf/packages/' + vnfd_id
	status, res_body, msglog = http_send_to_vnfm('GET', uri, '', "vnfm")
	if status == 200:
		pkginfo = json.loads(res_body)
		vnfis = pkginfo['vnfd']['servers']['links']
		if len(vnfis) > 0:
			status, res_body, msglog = http_send_to_vnfm('GET', vnfis[0]['href'], '', "vnfm")
			if status == 200:
				vnfiinfo = json.loads(res_body)
				pkginfo['vnfi'] = vnfiinfo

	return render_template('vnf-package.html', pkg=pkginfo, site_name=site_name)


@app.route('/vnf/records/', methods=['GET'])
def pre_instances():
	db = TinyDB('data/preins.json')
	nstbl = db.table('ns_table')
	nss = nstbl.all()
	return render_template('vnf-records.html', site_name=site_name, nss=nss)


@app.route('/nss/<ns_id>/', methods=['GET'])
def network_service(ns_id):
	db = TinyDB('data/preins.json')
	vnfrtbl = db.table('vnfr_table')
	q = Query()
	docs = vnfrtbl.search(q.ns_instance_id == ns_id)

	vnfrs = []
	for doc in docs:
		del doc['content']

	return Response(json.dumps(docs), status=200, mimetype='application/json; charset=utf-8')


@app.route('/nss/', methods=['POST', 'DELETE'])
def network_services():
	tdb = TinyDB('data/preins.json')
	nstbl = tdb.table('ns_table')

	mdb = MySQLdb.connect(db_server, db_user, db_pw, db_name)
	cursor = mdb.cursor()

	if request.method == 'POST':
		ns_name = request.form['ns_name']

		uri = '/v2/ns/instances/'
		body= { "network_service": { "name": ns_name, "description": "Auto Generated by UI tool" } }
		status, res_body, msglog = http_send_to_vnfm('POST', uri, json.dumps(body), "nfvo")
		if(status != 200):
			return Response(msglog, status=status)

		info = json.loads(res_body)
		ns_id = info['network_service']['id']
		nsinfo = { 'ns_name': ns_name, 'ns_id': ns_id }
		nstbl.insert(nsinfo)

		return Response(json.dumps(nsinfo), status=200, mimetype='application/json; charset=utf-8')

	else:
		ns_id = request.form['ns_id']

		uri = '/v2/ns/instances/' + ns_id
		status, res_body, msglog = http_send_to_vnfm('DELETE', uri, "", "nfvo")
		if(status != 200):
			return Response(msglog, status=status)

		nstbl.remove(Query().ns_id == ns_id)

		return ('', 204)


@app.route('/nss/<ns_id>/vnfrs/', methods=['POST'])
def vnf_records(ns_id):
	db = TinyDB('data/preins.json')
	vnfrtbl = db.table('vnfr_table')

	if request.method == 'POST':
		vnfr_name = request.form['vnfr_name']
		vnfr = {
				'vnfr_name': vnfr_name,
				'vnfr_id': str(uuid.uuid4()),
				'ns_instance_id': ns_id,
				'content': {
					'vnf': {
						'name': '',
						'vnf_descriptor_id': '',
						'flavor_id': '',
						'vl_maps': [{'ivl': '', 'cidr':'', 'physical_network_id':''}],
						'vnfcs': [{'host_id':'', 'vdu_id':'', 'sequence':'', 'static_ips':[{'ni_name':'', 'ip':''}], }],
						'config_params': [{'type': '', 'name':'', 'value':''}]
						}
					}
				}
		vnfrtbl.insert(vnfr)
		return Response(json.dumps(vnfr), status=201, mimetype='application/json; charset=utf-8')


@app.route('/nss/<ns_id>/vnfrs/<vnfr_id>', methods=['DELETE', 'GET', 'PUT'])
def vnf_record(ns_id, vnfr_id):
	db = TinyDB('data/preins.json')
	vnfrtbl = db.table('vnfr_table')
	q = Query()

	if request.method == 'DELETE':
		vnfrtbl.remove(q.vnfr_id == vnfr_id)
		docs = vnfrtbl.search(q.ns_instance_id == ns_id)
		vnfrs = []
		for doc in docs:
			del doc['content']
		return Response(json.dumps(docs), status=200, mimetype='application/json; charset=utf-8')

	elif request.method == 'GET':
		docs = vnfrtbl.search(q.vnfr_id == vnfr_id)
		return Response(json.dumps(docs[0]), status=200, mimetype='application/json; charset=utf-8')

	else: # case 'PUT'
		vnfr = request.get_json(force=True)
		vnfrtbl.update(vnfr, q.vnfr_id == vnfr['vnfr_id'])
		return Response('', status=200)


@app.route('/lcop/instantiateVnf', methods=['POST'])
def instantiate():
	uri = "/v2/vnf/instances"
	reqbody = request.get_json()

	ns_id = reqbody['ns_id']
	vnfr_id = reqbody['vnfr_id']
	flavor_id = reqbody['flavor_id']

	db = TinyDB('data/preins.json')
	vnfrtbl = db.table('vnfr_table')
	q = Query()
	docs = vnfrtbl.search(q.vnfr_id == vnfr_id)
	doc = docs[0]

	vnfr = copy.deepcopy(doc['content'])
	vnfr['vnf']['ns_instance_id'] = doc['ns_instance_id']
	vnfr['vnf']['flavor_id'] = flavor_id

	status, res_body, msglog = http_send_to_vnfm('POST', uri, json.dumps(vnfr), "nfvo")

	if status == 202:
		doc['inst_time'] = time.time()
		vnfrtbl.update(doc, q.vnfr_id == vnfr_id)

		res_json=json.loads(res_body)
		job_url = res_json['job']['id']

	return Response(msglog, status=200, headers={'X-Job-ID': job_url})


@app.route('/lcop/terminateVnf/<vnfi_id>', methods=['POST'])
def terminate(vnfi_id):
	delete_vnfcis_settings(vnfi_id)

	uri = "/v2/vnf/instances/" + vnfi_id
	status, res_body, msglog = http_send_to_vnfm('DELETE', uri, "", "nfvo")

	job_url = ''
	if status == 202:
		res_json=json.loads(res_body)
		job_url = res_json['job']['id']

		del_vdus_settings_from_vnfr(vnfi_id)

	return Response(msglog, status=200, headers={'X-Job-ID': job_url})


@app.route('/lcop/cleanVnf/<vnfi_id>', methods=['POST'])
def clean(vnfi_id):
	delete_vnfcis_settings(vnfi_id)

	uri = "/v2/vnf/instances/eliminate/" + vnfi_id
	status, res_body, msglog = http_send_to_vnfm('DELETE', uri, "", "nfvo")

	job_url = ''
	if status == 202:
		res_json=json.loads(res_body)
		job_url = res_json['job']['id']

		del_vdus_settings_from_vnfr(vnfi_id)

	return Response(msglog, status=200, headers={'X-Job-ID': job_url})


@app.route('/lcop/scaleVnf/<vnfi_id>', methods=['POST'])
def scale(vnfi_id):
	req = request.get_json(force=True)
	cur_flv_id = req['cur_flavor_id']
	dst_flv_id = req['flavor_id']
	vnfi_name = req['vnfi_name']
	vnfd_id = req['vnfd_id']

	# Get VNFCI settings
	db = TinyDB('data/preins.json')
	tbl = db.table('settings_vdus_table')
	q = Query()
	docs = tbl.search(q.vnfi_id == vnfi_id)
	if len(docs) <= 0:
		return Response('', status=403)
	vnfcis = docs[0]['settings']['vnfcs']

	# Get VNFD info
	uri = '/manager/v2/vnf/packages/' + vnfd_id
	status, res_body, msglog = http_send_to_vnfm('GET', uri, '', "vnfm")
	if status == 200:
		pkginfo = json.loads(res_body)

	vnfd_flv = pkginfo['vnfd']['flavors']

	for flv in vnfd_flv:
		if flv['flavor_id'] == cur_flv_id:
			cur_flv_info = flv
		elif flv['flavor_id'] == dst_flv_id:
			dst_flv_info = flv
			

	scale_body = {
			"vnf": {
				"ns_instance_id": vnfi_id,
				"vnf_descriptor_id": pkginfo['vnfd']['vnfd_id'],
				"name": vnfi_name,
				"flavor_id": dst_flv_id
				}
			}

	if int(cur_flv_info['grade']) > int(dst_flv_info['grade']): # case scale-out 
		vnfcs = []
		for c_vdu in cur_flv_info['vdus']:
			for d_vdu in dst_flv_info['vdus']:
				if c_vdu['vdu_id'] == d_vdu['vdu_id']:
					if int(c_vdu['num_instances']) != int(d_vdu['num_instances']):
						vdu_id = c_vdu['vdu_id']
						begin = int(c_vdu['num_instances'])
						end = int(d_vdu['num_instances'])
						for vnfci in vnfcis:
							if vnfci['vdu_id'] == vdu_id :
								if int(vnfci['sequence']) > begin : 
									if int(vnfci['sequence']) <= end:
										vnfci['sequence'] = str(int(vnfci['sequence']) - begin)
										vnfcs.append(vnfci)
		scale_body['vnf']['vnfcs'] = vnfcs

	uri = '/v2/vnf/instances/'+ vnfi_id +'/scale'
	status, res_body, msglog = http_send_to_vnfm('POST', uri, json.dumps(scale_body), "nfvo")

	job_url = ''
	if status == 202:
		res_json=json.loads(res_body)
		job_url = res_json['job']['id']

	return Response(msglog, status=200, headers={'X-Job-ID': job_url})


@app.route('/relayOperation/', methods=['POST'])
def relay_operation():
	req = request.get_json(force=True)
	status, res_body, msglog = http_send_to_vnfm(req['method'], req['uri'], req['body'], req['system'])

	if status == 202:
		res_json=json.loads(res_body)
		job_url = res_json['job']['id']

	return Response(msglog, status=200, headers={'X-Job-ID': job_url})

@app.route('/relayRead/', methods=['POST'])
def relay_read():
	req = request.get_json(force=True)
	status, res_body, msglog = http_send_to_vnfm(req['method'], req['uri'], "", req['system'])

	if res_body == None:
		res_body = ''

	return Response(res_body, status=status)


def del_vdus_settings_from_vnfr(vnfi_id):
	db = TinyDB('data/preins.json')
	settbl = db.table('settings_vdus_table')
	q = Query()
	settbl.remove(q.vnfi_id == vnfi_id)
	return


def set_vdus_settings_from_vnfr(vnfi_id, vnfi_name):
	db = TinyDB('data/preins.json')
	settbl = db.table('settings_vdus_table')
	vnfrtbl = db.table('vnfr_table')
	q = Query()

	vnfrs = vnfrtbl.search((q.content.vnf.name == vnfi_name) & q.inst_time.exists())

	if len(vnfrs) <= 0 :
		return

	def sortInstTime(item):
		return item['inst_time']
	vnfrs.sort(key=sortInstTime)
	vnfr = vnfrs[0]

	data = {
			'vnfi_id': vnfi_id,
			'settings': {
				'vnfcs': vnfr['content']['vnf']['vnfcs']
				}
			}

	docs = settbl.search(q.vnfi_id == vnfi_id)
	if(len(docs) == 0):
		settbl.insert(data)

	return


def delete_vnfcis_settings(vnfi_id):
	db = TinyDB('data/preins.json')
	tbl = db.table('settings_vdus_table')
	q = Query()
	tbl.remove(q.vnfi_id == vnfi_id)

@app.route('/vnf/instances/<vnfi_id>/settings/vnfcis/', methods=['PUT', 'GET'])
def settings_vnfc_instances(vnfi_id):
	db = TinyDB('data/preins.json')
	tbl = db.table('settings_vdus_table')
	q = Query()

	if request.method == 'PUT':
		data = request.get_json(force=True)

		docs = tbl.search(q.vnfi_id == vnfi_id)
		if(len(docs) > 0):
			tbl.update(data, q.vnfi_id == vnfi_id)
		else:
			tbl.insert(data)

		return Response('', status=200)

	else: # case 'GET'
		docs = tbl.search(q.vnfi_id == vnfi_id)
		if len(docs) <= 0:
			return Response('', status=204)
		else:
			#doc = docs[0]
			return Response(json.dumps(docs[0]), status=200, mimetype='application/json; charset=utf-8')


@app.route('/lcop/abort/<job_id>', methods=['POST'])
def abort(job_id):
	uri = '/manager/v2/jobs/'+job_id+'/action'
	body = '{ "abort": null }'

	status, res_body, msglog = http_send_to_vnfm('POST', uri, body, 'vnfm')

	return Response(msglog, status=200, headers={'X-Job-ID': job_id})


@app.route('/vnf/lastLCevent/<vnfi_id>', methods=['GET'])
def vnf_last_lc_event(vnfi_id):
	sql = 'SELECT vnfi_name, event, date_format(start_time,"%Y-%m-%d %T") start_time, job_id FROM VNF_EVENT_LOG_TBL WHERE vnfi_id = "' + vnfi_id + \
			'" AND end_time = "0000-00-00 00:00:00" AND result = "" ORDER BY start_time DESC LIMIT 1'
	job_info = db_select_one(sql)
	if job_info == None:
		return Response('', status=400)

	res_body = { 'vnfi_name': job_info['vnfi_name'], 'event': job_info['event'], 'start_time': job_info['start_time'], 'job_id': job_info['job_id'] }
	return Response(json.dumps(res_body), status=200, mimetype='application/json; charset=utf-8')


def os_auth_token_n_nova_ep(osc_name):
	sql = "SELECT * FROM OSC_AUTH_TBL WHERE name = '"+osc_name+"'"
	osc_info = db_select_one(sql)

	o = urlparse(osc_info['keystone_ep'])
	keystone_ip = o.hostname
	keystone_port = o.port

	uri = o.path + '/auth/tokens/'
	body = {
			"auth" : {
				"identity" : {
					"password" : {
						"user" : {
							"domain" : { "name" : osc_info['user_domain_name'] },
							"name" : osc_info['user_name'],
							"password" : osc_info['user_password']
						}
					},
					"methods" : [ "password" ]
				},
				"scope" : {
					"project" : {
						"domain" : { "id" : osc_info['project_domain_id'] },
						"name" : osc_info['project_name']
					}
				}
			}
		}

	mimetype = 'application/json; charset=UTF-8'
	hdrs = { 'Content-type': mimetype }

	conn = httplib.HTTPSConnection(keystone_ip, keystone_port)
	conn.request('POST', uri, json.dumps(body), hdrs)

	res = conn.getresponse()
	if res.status/100 != 2:
		print('Status code: {}'.format(res.status))
		return None, None

	res_body = json.loads(res.read())
	for catalog in res_body['token']['catalog']:
		if catalog['name'] != 'nova': 
			continue
		for ep in catalog['endpoints']:
			if ep['interface'] != 'public':
				continue
			nova_ep = ep['url']

	token = res.getheader('X-Subject-Token')

	return token, nova_ep


@app.route('/oscs/<osc_name>/console/<vm_id>', methods=['GET'])
def get_console(osc_name, vm_id):

	token, nova_ep = os_auth_token_n_nova_ep(osc_name)
	if token == None:
		return Response('', status=500)

	nova = urlparse(nova_ep)

	mimetype = 'application/json; charset=UTF-8'
	hdrs = { 'X-Auth-Token': token, 'Content-type': mimetype }
	body = { 'os-getVNCConsole': { 'type': 'novnc' } }
	uri = nova.path+'/servers/'+vm_id+'/action'

	conn = httplib.HTTPSConnection(nova.hostname, nova.port)
	conn.request('POST', uri, json.dumps(body), hdrs)
	res = conn.getresponse()
	res_body = res.read()

	return Response(res_body, status=res.status, mimetype=mimetype)



if __name__ == '__main__':
	app.debug = True
	app.run(host='0.0.0.0', port=server_port)


