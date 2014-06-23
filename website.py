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
import base64
import six

import urllib

from uuid import uuid4
from subprocess import check_call, Popen, PIPE
from datetime import datetime, timedelta
from six.moves.http_client import HTTPSConnection
from six.moves.urllib_parse import urlencode

import rq
import pytz
import psycopg2
import jinja2

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

topdir = os.path.split(__file__)[0]

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


def b64enc(s):
    """Base-64 encode a string *s*."""
    if isinstance(s, six.text_type):
        s = s.encode('ascii')
    return base64.b64encode(s).decode('ascii')


def parse_email(message):
    """Parse an email with embedded headers."""
    pos = message.find('\n\n')
    if pos != -1:
        header, message = message[:pos], message[pos+2:]
        fields = [field.split(':') for field in header.splitlines()]
        headers = dict(((k.lower(), v.strip()) for (k,v) in fields))
    else:
        headers = {}
    return headers, message


def send_email(email, template, kwargs):
    """Send an email via the mailgun service."""
    maildir = os.path.join(topdir, 'emails')
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(maildir))
    template = env.get_template(template)
    rendered = template.render(**kwargs)
    headers, message = parse_email(rendered)
    mailargs = {'to': email,
                'from': app.config['MAIL_FROM'],
                'bcc': app.config.get('MAIL_BCC'),
                'text': message}
    mailargs.update(headers)
    conn = HTTPSConnection('api.mailgun.net', 443)
    conn.connect()
    auth = b64enc('api:{0[MAILGUN_KEY]}'.format(app.config))
    headers = {'Authorization': 'Basic {0}'.format(auth),
               'Accept': 'application/json',
               'Content-type': 'application/x-www-form-urlencoded'}
    url = '/v2/{0[MAILGUN_DOMAIN]}/messages'.format(app.config)
    body = urlencode(mailargs)
    conn.request('POST', url, body, headers)
    resp = conn.getresponse()
    if resp.status != 200:
        raise RuntimeError('could not send email')
    conn.close()


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
    trial_cfg = cfgdict(app.config, trial['trial_name'])
    trial['ssh_private_key'], trial['ssh_public_key'] = generate_keypair()
    ravello = connect_ravello()
    blueprint_id = trial_cfg['blueprint']
    application = {'name': 'trial-{}'.format(uuid),
                   'description': 'Trial ({0})'.format(trial['trial_name']),
                   'baseBlueprintId': blueprint_id}
    application = ravello.create_application(application)
    trial['application_id'] = application['id']
    # If cloudinit is available, we can use that to deploy the ssh key.
    cloudinit = trial_cfg['cloudinit']
    if cloudinit:
        pubkey = {'name': 'trial-{}'.format(uuid),
                  'publicKey': trial['ssh_public_key']}
        pubkey = ravello.create_keypair(pubkey)
        for vm in application.get('design', {}).get('vms', []):
            vm['keypairId'] = pubkey['id']
        application = ravello.update_application(application)
    autostop = trial_cfg.get('autostop')
    if autostop:
        exp_req = {'expirationFromNowSeconds': autostop*3600}
        ravello.set_application_expiration(application, exp_req)
        nowutc = datetime.utcnow().replace(tzinfo=pytz.UTC)
        trial['autostop_at'] = nowutc + timedelta(seconds=autostop*3600)
    else:
        trial['autostop_at'] = None
    publish_cfg = cfgdict(app.config, 'publish')
    publish_req = {'preferredCloud': publish_cfg.get('cloud'),
                   'preferredRegion': publish_cfg.get('region'),
                   'optimizationLevel':  publish_cfg.get('optimization'),
                   'startAllVms': True}
    publish_req = dict(((k,v) for k,v in publish_req.items() if v is not None))
    ravello.publish_application(application['id'], publish_req)
    trial['status'] = 'BUILDING'
    fields = qset('ssh_private_key', 'ssh_public_key', 'application_id',
                  'status', 'autostop_at')
    cursor.execute('UPDATE trials set {} WHERE id = %(id)s'.format(fields), trial)
    conn.commit()
    # At this point send the email.
    send_email(trial['email'], 'registered.txt', trial)
    # Wait for the application to come up
    ravello.wait_for(application, lambda app: application_state(app) == 'STARTED', 600)
    # Wait for ssh to come up.
    application = ravello.reload(application)
    ssh_addr = get_service_addr(application, 'ssh')
    ssh_timeout = trial_cfg.get('ssh_timeout', 300)
    if not wait_for_service(ssh_addr[:2], ssh_timeout):
        raise RuntimeError('error waiting for ssh service')
    if not cloudinit:
        privkey = trial_cfg['ssh_key']
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
    service = trial_cfg.get('service')
    if service:
        svc_addr = get_service_addr(application, service)
        svc_timeout = trial_cfg.get('service_timeout', 300)
        if not wait_for_service(svc_addr[:2], svc_timeout):
            raise RuntimeError('error waiting for {!r} service'.format(service))
    # Do we need to reboot?
    reboot = trial_cfg.get('reboot')
    if reboot:
        time.sleep(trial_cfg.get('reboot_delay', 60))
        ssh = connect_ssh(ssh_addr[:2], privkey, 'root')
        ssh.communicate('shutdown -r now'.encode('ascii'))
        ssh.wait()
        time.sleep(trial_cfg.get('reboot_timeout', 30))
        if not wait_for_service(ssh_addr[:2], ssh_timeout):
            raise RuntimeError('ssh did not come up after reboot')
        # Wait again for the service..
        if service and not wait_for_service(svc_addr[:2], svc_timeout):
            raise RuntimeError('error waiting for {!r} service'.format(service))
    # Mark as READY!
    time.sleep(trial_cfg.get('final_delay', 0))
    trial['status'] = 'READY'
    fields = qset('status')
    cursor.execute('UPDATE trials set {} WHERE id = %(id)s'.format(fields), trial)
    conn.commit()
    cursor.close()
    conn.close()


# Request handlers

@app.route('/<trial_name>')
def index(trial_name):
    if trial_name not in app.config.get('TRIALS', []):
        abort(404)
    trial_cfg = cfgdict(app.config, trial_name)
    trial_cfg['trial_name'] = trial_name
    return render_template('index.html', **trial_cfg)


@app.route('/trials/_/checkemail', methods=['POST'])
def check_email():
    """Check if email address exists."""
    email = request.form.get('email')
    if not isinstance(email, str):
        abort(400)
    cursor = get_cursor()
    cursor.execute('SELECT id FROM trials WHERE email = %s', (email,))
    row = cursor.fetchone()
    return jsonify({'valid': row is None})


@app.route('/trials/_/remind', methods=['POST'])
def send_reminder():
    """Send an email reminder of the trial ID."""
    email = request.form.get('email')
    if not isinstance(email, str):
        abort(400)
    cursor = get_cursor()
    cursor.execute('SELECT * FROM trials WHERE email = %s', (email,))
    row = cursor.fetchone()
    if not row:
        abort(400)
    trial = rowdict(row, cursor.description)
    queue = get_job_queue()
    queue.enqueue_call(send_email, (trial['email'], 'reminder.txt', trial))
    response = make_response()
    response.status_code = 204  # No content
    return response


@app.route('/trials/<trial_name>', methods=['POST'])
def create_trial(trial_name):
    """Create a new trial."""
    if trial_name not in app.config.get('TRIALS', []):
        abort(404)
    trial_cfg = cfgdict(app.config, trial_name)
    trial_cfg['trial_name'] = trial_name
    name = request.form.get('name')
    if not isinstance(name, str) or not re_name.match(name) or len(name) > 120:
        abort(400)
    email = request.form.get('email')
    if not isinstance(email, str) or not re_email.match(email) or len(email) > 120:
        abort(400)
    cursor = get_cursor()
    cursor.execute('SELECT id FROM trials WHERE email = %s', (email,))
    row = cursor.fetchone()
    if row is not None:
        abort(400)
    trial = {'id': str(uuid4()),
             'name': name,
             'trial_name': trial_name,
             'email': email,
             'status': 'QUEUED'}
    trial['created_at'] = datetime.utcnow().replace(tzinfo=pytz.UTC)
    days = trial_cfg.get('duration', 14)
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
    trial.update(cfgdict(app.config, trial['trial_name']))
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
    utcnow = datetime.utcnow().replace(tzinfo=pytz.UTC)
    meta['expires_in'] = format_interval(trial['expires_at'] - utcnow)
    if trial['autostop_at']:
        meta['autostop_in'] = format_interval(trial['autostop_at'] - utcnow)
    if trial['status'] != 'READY':
        return jsonify(meta)
    client = get_ravello_client()
    app = client.get_application(trial['application_id'])
    deploy = app.get('deployment', {})
    meta['cloud'] = deploy.get('cloud')
    meta['region'] = deploy.get('regionName')
    state = application_state(app)
    if isinstance(state, list):
        if 'STARTING' in state:
            state = 'STARTING'
        elif 'STOPPING' in state:
            state = 'STOPPING'
        else:
            state = 'UNKNOWN'
    meta['status'] = state
    addr = get_service_addr(app, 'ssh')
    if addr:
        meta['ssh_addr'] = addr[0]
    addr = get_service_addr(app, 'http')
    if addr:
        meta['http_url'] = 'http://{2}:{1}/'.format(*addr)
    return jsonify(meta)


@app.route('/trials/<uuid>/extend')
def extend_autostop(uuid):
    """Extend the autostop timer."""
    if not re_uuid.match(uuid):
        abort(400)
    cursor = get_cursor()
    cursor.execute('SELECT * FROM trials WHERE id = %s', (uuid,))
    row = cursor.fetchone()
    if not row:
        abort(404)
    trial = rowdict(row, cursor.description)
    trial_cfg = cfgdict(app.config, trial['trial_name'])
    autostop = trial_cfg.get('autostop')
    if not autostop:
        abort(400)
    client = get_ravello_client()
    application = client.get_application(trial['application_id'])
    exp_req = {'expirationFromNowSeconds': autostop*3600}
    client.set_application_expiration(application, exp_req)
    state = application_state(application)
    if state == 'STOPPED':
        client.start_application(application)
    elif state not in ('STARTING', 'STARTED'):
        abort(400)
    utcnow = datetime.utcnow().replace(tzinfo=pytz.UTC)
    trial['autostop_at'] = utcnow + timedelta(seconds=autostop*3600)
    fields = qset('autostop_at')
    cursor.execute('UPDATE trials set {} WHERE id = %(id)s'.format(fields), trial)
    response = make_response()
    response.status_code = 204  # No content
    return response


@app.template_filter('date')
def format_date(d):
    return d.strftime('%a, %d %b %Y %H:%M')


@app.template_filter('interval')
def format_interval(d):
    r = d + timedelta(seconds=30)  # for rounding
    if d.days:
        return '{} days, {} hours'.format(r.days, r.seconds // 3600)
    else:
        return '{} hours, {} minutes'.format(r.seconds // 3600, (r.seconds // 60) % 60)


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
