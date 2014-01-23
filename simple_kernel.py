# simple_kernel.py
# by Doug Blank <doug.blank@gmail.com>
#
# This sample kernel is meant to be able to demonstrate using zmq for
# implementing a language backend (called a kernel) for IPython. It is
# written in the most straightforward manner so that it can be easily
# translated into other programming languages. It doesn't use any code
# from IPython, but only standard Python libraries and zmq.
#
# It is also designed to be able to run, showing the details of the
# message handling system.
#
# To adjust debug output, set debug_level to:
#  0 - show no debugging information
#  1 - shows basic running information
#  2 - also shows loop details
#  3 - also shows message details
#
# Start with a command, such as:
# ipython console --KernelManager.kernel_cmd="['python', 'simple_kernel.py', 
#                                              '{connection_file}']"

from __future__ import print_function

## General Python imports:
import sys
import zmq
import json
import hmac
import uuid
import errno
import hashlib
import datetime
import threading
from pprint import pformat

# zmq specific imports:
from zmq.eventloop import ioloop, zmqstream
from zmq.error import ZMQError

#Globals:
decode = json.JSONDecoder().decode
encode = json.JSONEncoder().encode
debug_level = 3 # 0 (none) to 3 (all) for various levels of detail
exiting = False

# Utility functions:
def dprint(level, *args, **kwargs):
    """ Show debug information """
    if level <= debug_level:
        print("DEBUG:", *args, **kwargs)
        sys.stdout.flush()

def msg_id():
    """ Return a new uuid for message id """
    return str(uuid.uuid4())

def sign(msg_lst):
    """
    Sign a message with a secure signature.
    """
    h = auth.copy()
    for m in msg_lst:
        h.update(m)
    return h.hexdigest()

def send(stream, header, parent_header, metadata, content):
    msg_lst = [
        bytes(encode(header)), 
        bytes(encode(parent_header)), 
        bytes(encode(metadata)), 
        bytes(encode(content)),
    ]
    signature = sign(msg_lst)
    parts = ["<IDS|MSG>", 
             signature, 
             msg_lst[0],
             msg_lst[1],
             msg_lst[2],
             msg_lst[3]]
    dprint(3, "send parts:", parts)
    stream.send_multipart(parts)
    stream.flush()

def run_thread(loop, name):
    dprint(2, "Starting loop for '%s'..." % name)
    while True:
        dprint(2, "%s Loop!" % name)
        try:
            loop.start()
        except ZMQError as e:
            dprint(2, "%s ZMQError!" % name)
            if e.errno == errno.EINTR:
                continue
            else:
                raise
        except Exception:
            dprint(2, "%s Exception!" % name)
            if exiting:
                break
            else:
                raise
        else:
            dprint(2, "%s Break!" % name)
            break

def heartbeat_loop():
    dprint(2, "Starting loop for 'Heartbeat'...")
    while not exiting:
        dprint(3, ".", end="")
        try:
            zmq.device(zmq.FORWARDER, heartbeat_socket, heartbeat_socket)
        except zmq.ZMQError as e:
            if e.errno == errno.EINTR:
                continue
            else:
                raise
        else:
            break

# Socket Handlers:
def shell_handler(msg):
    global execution_count
    dprint(1, "shell received:", msg)
    position = 0
    while (msg[position] != "<IDS|MSG>"):
        position += 1
    m_delim         = msg[position]
    m_signature     = msg[position + 1]
    m_header        = decode(msg[position + 2])
    m_parent_header = decode(msg[position + 3])
    m_metadata      = decode(msg[position + 4])
    m_content       = decode(msg[position + 5])

    check_sig = sign(msg[position + 2:position + 6])
    if check_sig != m_signature:
        raise ValueError("Signatures do not match")
    # process request:

    if m_header["msg_type"] == "execute_request":
        dprint(1, "simple_kernel Executing:", pformat(m_content["code"]))
        header = {
            "date": datetime.datetime.now().isoformat(),
            "msg_id": msg_id(),
            "username": "kernel",
            "session": m_header["session"],
            "msg_type": "status",
        }
        metadata = {}
        content = {
            'execution_state': "busy",
        }
        send(iopub_stream, header, m_header, metadata, content)
        #######################################################################
        header = {
            "date": datetime.datetime.now().isoformat(),
            "msg_id": msg_id(),
            "username": "kernel",
            "session": m_header["session"],
            "msg_type": "pyin",
        }
        metadata = {}
        content = {
            'execution_count': execution_count,
            'code': m_content["code"],
        }
        send(iopub_stream, header, m_header, metadata, content)
        #######################################################################
        header = {
            "date": datetime.datetime.now().isoformat(),
            "msg_id": msg_id(),
            "username": "kernel",
            "session": m_header["session"],
            "msg_type": "pyout",
        }
        metadata = {}
        content = {
            'execution_count': execution_count,
            'data': {"text/plain": "result!"},
            'metadata': {}
        }
        send(iopub_stream, header, m_header, metadata, content)
        #######################################################################
        header = {
            "date": datetime.datetime.now().isoformat(),
            "msg_id": msg_id(),
            "username": "kernel",
            "session": m_header["session"],
            "msg_type": "status",
        }
        metadata = {}
        content = {
            'execution_state': "idle",
        }
        send(iopub_stream, header, m_header, metadata, content)
        #######################################################################
        header = {
            "date": datetime.datetime.now().isoformat(),
            "msg_id": msg_id(),
            "username": "kernel",
            "session": m_header["session"],
            "msg_type": "execute_reply",
        }
        metadata = {
            "dependencies_met": True,
            "engine": "459cfb86-2298-417c-8ebc-438f1af52be2",
            "status": "ok",
            "started": datetime.datetime.now().isoformat(),
        }
        content = {
            "status": "ok",
            "execution_count": execution_count,
            "user_variables": {},
            "payload": [],
            "user_expressions": {},
        }
        send(shell_stream, header, m_header, metadata, content)
        execution_count += 1
    elif m_header["msg_type"] == "kernel_info_request":
        header = {
            "date": datetime.datetime.now().isoformat(),
            "msg_id": msg_id(),
            "username": "kernel",
            "session": m_header["session"],
            "msg_type": "kernel_info_reply",
        } 
        content = {
            "protocol_version": [4, 0],
            "ipython_version": [1, 1, 0, ""],
            "language_version": [0, 0, 1],
            "language": "simple_kernel",
        }
        metadata = {}
        send(shell_stream, header, m_header, metadata, content) # ok
    elif m_header["msg_type"] == "history_request":
        header = {
            "date": datetime.datetime.now().isoformat(),
            "msg_id": msg_id(),
            "username": m_header["username"],
            "session": m_header["session"],
            "msg_type": "kernel_info_reply",
        } 
        content = {
            'output' : False,
        }
        send(shell_stream, header, m_header, m_metadata, content)
    else:
        dprint("unknown msg_type:", m_header["msg_type"])

def control_handler(msg):
    global exiting
    dprint(1, "control received:", msg)
    position = 0
    while (msg[position] != "<IDS|MSG>"):
        position += 1
    m_delim         = msg[position]
    m_signature     = msg[position + 1]
    m_header        = decode(msg[position + 2])
    m_parent_header = decode(msg[position + 3])
    m_metadata      = decode(msg[position + 4])
    m_content       = decode(msg[position + 5])
    # Control message handler:
    if m_header["msg_type"] == "shutdown_request":
        exiting = True

def iopub_handler(msg):
    dprint(1, "iopub received:", msg)

def stdin_handler(msg):
    dprint(1, "stdin received:", msg)

def bind(socket, connection, port):
    if port <= 0:
        return socket.bind_to_random_port(connection)
    else:
        socket.bind("%s:%s" % (connection, port))
    return port

## Initialize:
ioloop.install()

if len(sys.argv) > 1:
    dprint(1, "Loading simple_kernel with args:", sys.argv)
    dprint(1, "Reading config file '%s'..." % sys.argv[1])
    config = decode("".join(open(sys.argv[1]).readlines()))
else:
    dprint(1, "Starting simple_kernel with default args...")
    config = {
        'control_port'      : 0,
        'hb_port'           : 0,
        'iopub_port'        : 0,
        'ip'                : '127.0.0.1',
        'key'               : uuid.uuid4(),
        'shell_port'        : 0,
        'signature_scheme'  : 'hmac-sha256',
        'stdin_port'        : 0,
        'transport'         : 'tcp'
    }

connection     = config["transport"] + "://" + config["ip"]
session_id = unicode(uuid.uuid4()).encode('ascii')
secure_key = unicode(config["key"]).encode("ascii")
signature_schemes = {"hmac-sha256": hashlib.sha256}
auth = hmac.HMAC(
    secure_key, 
    digestmod=signature_schemes[config["signature_scheme"]])
execution_count = 1

##########################################
# Heartbeat:
ctx = zmq.Context()
heartbeat_socket = ctx.socket(zmq.REP)
config["hb_port"] = bind(heartbeat_socket, connection, config["hb_port"])

##########################################
# IOPub/Sub:
# aslo called SubSocketChannel in IPython sources
iopub_socket = ctx.socket(zmq.PUB)
config["iopub_port"] = bind(iopub_socket, connection, config["iopub_port"])
iopub_loop = ioloop.IOLoop()
iopub_stream = zmqstream.ZMQStream(iopub_socket, iopub_loop)
iopub_stream.on_recv(iopub_handler)

##########################################
# Control:
control_socket = ctx.socket(zmq.DEALER)
config["control_port"] = bind(control_socket, connection, config["control_port"])
control_loop = ioloop.IOLoop()
control_stream = zmqstream.ZMQStream(control_socket, control_loop)
control_stream.on_recv(control_handler)

##########################################
# Stdin:
stdin_socket = ctx.socket(zmq.DEALER)
config["stdin_port"] = bind(stdin_socket, connection, config["stdin_port"])
stdin_loop = ioloop.IOLoop()
stdin_stream = zmqstream.ZMQStream(stdin_socket, stdin_loop)
stdin_stream.on_recv(stdin_handler)

##########################################
# Shell:
shell_socket = ctx.socket(zmq.DEALER)
config["shell_port"] = bind(shell_socket, connection, config["shell_port"])
shell_loop = ioloop.IOLoop()
shell_stream = zmqstream.ZMQStream(shell_socket, shell_loop)
shell_stream.on_recv(shell_handler)

dprint(1, "Config:", encode(config))
dprint(1, "Starting loops...")
# Which threads to run is determined by the frontend
# For example, the notebook frontend does not use heartbeat
threads = [
    threading.Thread(target=lambda: run_thread(shell_loop, "Shell")),
    threading.Thread(target=lambda: run_thread(iopub_loop, "IOPub")),
    threading.Thread(target=lambda: run_thread(control_loop, "Control")),
    threading.Thread(target=lambda: run_thread(stdin_loop, "StdIn")),
    threading.Thread(target=heartbeat_loop),
]
for thread in threads:
    thread.start()
dprint(1, "Ready! Listening...")
