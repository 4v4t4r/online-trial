#!/usr/bin/env python
#
# Copyright 2014 Ravello Systems, Inc.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import re
import shutil
import tempfile
import socket
import time
import textwrap

from uuid import uuid4
from subprocess import check_call, Popen, PIPE
from datetime import datetime, timedelta

import rq
import pytz
import psycopg2

from redis import Redis
from ravello_sdk import RavelloClient, RavelloError, application_state
from flask import (Flask, render_template, request, g, url_for, redirect,
                   abort, jsonify, make_response)


app = Flask(__name__)
cfgname = os.environ.get('TRIAL_CONFIG', 'config.py')
app.config.from_pyfile(cfgname)

re_name = re.compile('^[^ ]+ [^ ]')
re_email = re.compile(r'^[a-z0-9._+-]+@([a-z0-9-]+\.)+[a-z]{2,6}$', re.I)
re_uuid = re.compile('^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-'
                     '[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)

# Utility functions

def cfgdict(config, section=None):
    """Utility function to convert a Flask style config object to a dict used
    for keyword arguments."""
    kwargs = {}
    prefix = section.upper() + '_' if section else ''
    for key in config:
        if key.startswith(prefix):
            kwargs[key[len(prefix):].lower()] = config[key]
    return kwargs


def qcols(*names):
    """Given a dict, return 'key1, key2, ...'."""
    if len(names) == 1 and isinstance(names[0], dict):
        names = sorted(names[0])
    return ', '.join(names)

def qargs(*names):
    """Given a dict, return '%(key1)s, %(key2)s, ...'."""
    if len(names) == 1 and isinstance(names[0], dict):
        names = sorted(names[0])
    result = []
    for name in names:
        result.append('%({})s'.format(name))
    return ', '.join(result)

def qset(*names):
    """Given a dict, reutrn 'key1=%(key1)s, key2=%(key2)s, ...'."""
    if len(names) == 1 and isinstance(names[0], dict):
        names = sorted(names[0])
    result = []
    for name in names:
        result.append('{}=%({})s'.format(name, name))
    return ', '.join(result)


def rowdict(row, description):
    """Return a dictionary mapping the field names for a row."""
    return dict(zip((col.name for col in description), row))


def set_g(name, obj, cleanup=None):
    if getattr(g, 'exports', None) is None:
        g.exports = []
    if getattr(g, 'cleanup', None) is None:
        g.cleanup = []
    g.exports.append(name)
    if cleanup:
        g.cleanup.append(cleanup)
    setattr(g, name, obj)


# Connections

def connect_database():
    """Return a connection for the database."""
    kwargs = cfgdict(app.config, 'postgres')
    return psycopg2.connect(**kwargs)


def get_cursor():
    """Return a cursor for the database."""
    cursor = getattr(g, 'cursor', None)
    if cursor is None:
        conn = connect_database()
        set_g('database', conn, conn.commit)
        cursor = conn.cursor()
        def close_db():
            cursor.close()
            conn.close()
        set_g('cursor', cursor, close_db)
    return g.cursor


def get_job_queue():
    """Return the job queue."""
    redis = Redis(**cfgdict(app.config, 'redis'))
    set_g('redis', redis, redis.connection_pool.disconnect)
    queue = rq.Queue(connection=redis)
    set_g('queue', queue)
    return g.queue


def connect_ravello():
    """Return a new Ravello connection."""
    client = RavelloClient()
    client.connect()
    client.login(**cfgdict(app.config, 'ravello'))
    return client


def get_ravello_client():
    """Return a Ravello client."""
    client = getattr(g, 'ravello', None)
    if client is None:
        client = connect_ravello()
        set_g('ravello', client, client.close)
    return g.ravello


def get_service_addr(app, name):
    """Return the (ip, port, fqdn, vmid) for a public service."""
    deploy = app.get('deployment', {})
    port = None
    for vm in deploy.get('vms', []):
        for svc in vm.get('suppliedServices', []):
            if svc.get('external') and svc.get('name') == name:
                luid = svc['ipConfigLuid']
                port = svc.get('externalPort')
                break
        if port is None:
            continue
        # This VM has a public SSH service
        for conn in vm.get('networkConnections', []):
            config = conn.get('ipConfig', {})
            if config.get('id') == luid and config.get('publicIp'):
                return (config['publicIp'], int(port), config.get('fqdn'), vm['id'])
        # Could not resolve, try again
        port = None


def get_remote_addr():
    """Return the address of the remote client."""
    addr = request.headers.get('X-Forwarded-For')
    if addr is None:
        addr = request.environ['REMOTE_ADDR']
    return addr


def generate_keypair():
    """Create a new OpenSSH keypair. Return as (private, public)."""
    tempdir = tempfile.mkdtemp()
    keyfile = os.path.join(tempdir, 'id_rsa')
    try:
        check_call(['ssh-keygen', '-q', '-b', '1024', '-N', '', '-f', keyfile])
        with open(keyfile) as fin:
            private = fin.read()
        with open(keyfile + '.pub') as fin:
            public = fin.read()
    finally:
        shutil.rmtree(tempdir)
    return (private, public)


def wait_for_service(addr, timeout):
    """Wait until a TCP/IP service becomes available."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        time.sleep(10)
        sock = socket.socket()
        sock.settimeout(10)
        try:
            sock.connect(addr)
        except socket.error:
            continue
        finally:
            sock.close()
        return True
    return False


def connect_ssh(addr, privkey, user):
    """Return a ssh instance to a remote server."""
    return Popen(['ssh', '-i', privkey, '-o', 'StrictHostKeyChecking=no',
                  '-o', 'UserKnownHostsFile=/dev/null', '-T', '-l', user,
                  '-p', str(addr[1]), addr[0]], stdin=PIPE, stdout=PIPE, stderr=PIPE)


def complete_create_trial(uuid):
    """Complete the creation of a trial."""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM trials WHERE id = %s', (uuid,))
    row = cursor.fetchone()
    if row is None:
        raise ValueError('trial {!r} does not exist'.format(uuid))
    trial = rowdict(row, cursor.description)
    trial['ssh_private_key'], trial['ssh_public_key'] = generate_keypair()
    ravello = connect_ravello()
    blueprint_id = app.config['BLUEPRINT_ID']
    application = {'name': 'trial-{}'.format(uuid),
                   'description': 'Online trial',
                   'baseBlueprintId': blueprint_id}
    application = ravello.create_application(application)
    trial['application_id'] = application['id']
    # If cloudinit is available, we can use that to deploy the ssh key.
    cloudinit = app.config['CLOUDINIT']
    if cloudinit:
        pubkey = {'name': 'trial-{}'.format(uuid),
                  'publicKey': trial['ssh_public_key']}
        pubkey = ravello.create_keypair(pubkey)
        for vm in application.get('design', {}).get('vms', []):
            vm['keypairId'] = pubkey['id']
        application = ravello.update_application(application)
    publish_cfg = cfgdict(app.config, 'publish')
    publish_req = {'preferredCloud': publish_cfg.get('cloud'),
                   'preferredRegion': publish_cfg.get('region'),
                   'optimizationLevel':  publish_cfg.get('optimization'),
                   'startAllVms': True}
    publish_req = dict(((k,v) for k,v in publish_req.items() if v is not None))
    ravello.publish_application(application['id'], publish_req)
    trial['status'] = 'BUILDING'
    fields = qset('ssh_private_key', 'ssh_public_key', 'application_id', 'status')
    cursor.execute('UPDATE trials set {} WHERE id = %(id)s'.format(fields), trial)
    conn.commit()
    # Wait for the application to come up
    ravello.wait_for(application, lambda app: application_state(app) == 'STARTED', 600)
    # Wait for ssh to come up.
    application = ravello.reload(application)
    ssh_addr = get_service_addr(application, 'ssh')
    if not wait_for_service(ssh_addr[:2], 300):
        raise RuntimeError('ssh did not come up within 900 seconds')
    if not cloudinit:
        privkey = app.config['SSH_KEY']
        ssh = connect_ssh(ssh_addr[:2], privkey, 'root')
        pubkey = trial['ssh_public_key'].rstrip()
        ssh.communicate(textwrap.dedent("""\
                cat >> .ssh/authorized_keys << EOM 
                {}
                EOM
                chmod 600 .ssh/authorized_keys
                """).format(pubkey).encode('ascii'))
        ssh.wait()
        if ssh.returncode != 0:
            raise RuntimeError('error deploying ssh key through ssh')
    # Optionally wait for another service
    waitfor = app.config.get('WAITFOR')
    if waitfor:
        service, timeout = waitfor.split(':')
        timeout = int(timeout)
        svc_addr = get_service_addr(application, service)
        if not wait_for_service(svc_addr[:2], timeout):
            raise RuntimeError('error waiting for {!r} service'.format(service))
    # Do we need to reboot?
    reboot = app.config.get('REBOOT')
    if reboot:
        time.sleep(reboot)
        ssh = connect_ssh(ssh_addr[:2], privkey, 'root')
        ssh.communicate('shutdown -r now'.encode('ascii'))
        ssh.wait()
        time.sleep(30)
        if not wait_for_service(ssh_addr[:2], 600):
            raise RuntimeError('ssh did not come up after reboot')
        # Wait again..
        if waitfor and not wait_for_service(svc_addr[:2], timeout):
            raise RuntimeError('error waiting for {!r} service'.format(service))
    # Mark as READY!
    trial['status'] = 'READY'
    fields = qset('status')
    cursor.execute('UPDATE trials set {} WHERE id = %(id)s'.format(fields), trial)
    conn.commit()
    cursor.close()
    conn.close()


# Request handlers

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/trials', methods=['POST'])
def create_trial():
    """Create a new trial."""
    name = request.form.get('fname')
    if not isinstance(name, str) or not re_name.match(name) or len(name) > 120:
        abort(400)
    email = request.form.get('femail')
    if not isinstance(email, str) or not re_email.match(email) or len(email) > 120:
        abort(400)
    cursor = get_cursor()
    trial = {'id': str(uuid4()),
             'name': name,
             'email': email,
             'status': 'QUEUED'}
    trial['created_at'] = datetime.utcnow().replace(tzinfo=pytz.UTC)
    days = app.config.get('TRIAL_DURATION', 14)
    trial['expires_at'] = trial['created_at'] + timedelta(days=days)
    query = 'INSERT INTO trials ({}) VALUES ({})'.format(qcols(trial), qargs(trial))
    cursor.execute(query, trial)
    queue = get_job_queue()
    queue.enqueue_call(complete_create_trial, (trial['id'],), timeout=2000)
    return redirect(url_for('get_trial', uuid=trial['id']))


@app.route('/trials/<uuid>')
def get_trial(uuid):
    """Show the status of a trial."""
    if not re_uuid.match(uuid):
        abort(400)
    cursor = get_cursor()
    cursor.execute('SELECT * FROM trials WHERE id = %s', (uuid,))
    row = cursor.fetchone()
    if not row:
        abort(404)
    trial = rowdict(row, cursor.description)
    trial['expires_in'] = trial['expires_at'] - datetime.utcnow().replace(tzinfo=pytz.UTC)
    return render_template('trial.html', **trial)


@app.route('/trials/<uuid>/key')
def get_trial_key(uuid):
    """Download a private key for a trial."""
    if not re_uuid.match(uuid):
        abort(400)
    cursor = get_cursor()
    cursor.execute('SELECT * FROM trials WHERE id = %s', (uuid,))
    row = cursor.fetchone()
    if not row:
        abort(404)
    trial = rowdict(row, cursor.description)
    response = make_response(trial['ssh_private_key'])
    response.headers['Content-Type'] = 'text/plain'
    return response


@app.route('/trials/<uuid>/vnc')
def get_trial_vnc(uuid):
    """Get VNC URL for a trial."""
    if not re_uuid.match(uuid):
        abort(400)
    cursor = get_cursor()
    cursor.execute('SELECT * FROM trials WHERE id = %s', (uuid,))
    row = cursor.fetchone()
    if not row:
        abort(404)
    trial = rowdict(row, cursor.description)
    client = get_ravello_client()
    app = client.get_application(trial['application_id'])
    addr = get_service_addr(app, 'ssh')
    if not addr:
        abort(404)
    vnc_url = client.get_vnc_url(app['id'], addr[3])
    return redirect(vnc_url)


@app.route('/trials/<uuid>/dyn')
def get_trial_dyn(uuid):
    """Get trial dynamic metadata."""
    if not re_uuid.match(uuid):
        abort(400)
    cursor = get_cursor()
    cursor.execute('SELECT * FROM trials WHERE id = %s', (uuid,))
    row = cursor.fetchone()
    if not row:
        abort(404)
    trial = rowdict(row, cursor.description)
    meta = {'id': trial['id'], 'status': trial['status']}
    if trial['status'] != 'READY':
        return jsonify(meta)
    client = get_ravello_client()
    app = client.get_application(trial['application_id'])
    deploy = app.get('deployment', {})
    meta['cloud'] = deploy.get('cloud')
    meta['region'] = deploy.get('regionName')
    meta['status'] = 'READY' if application_state(app) == 'STARTED' else 'STARTING'
    addr = get_service_addr(app, 'ssh')
    if addr:
        meta['ssh_addr'] = addr[0]
    addr = get_service_addr(app, 'http')
    if addr:
        meta['http_url'] = 'http://{2}:{1}/'.format(*addr)
    return jsonify(meta)


@app.template_filter('date')
def format_date(d):
    return d.strftime('%a, %d %b %Y %H:%M')


@app.template_filter('interval')
def format_date(d):
    return '{} days, {} hours'.format(d.days, d.seconds // 3600)


# Intialization / finalization

@app.teardown_request
def teardown_request(exc):
    """Finalize a request."""
    cleanup = getattr(g, 'cleanup', None)
    if cleanup:
        for func in cleanup:
            func()
    exports = getattr(g, 'exports', None)
    if exports:
        for name in exports:
            setattr(g, name, None)
    g.cleanup = None
    g.exports = None
