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
        print(*args, **kwargs)

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
    msg_lst = [bytes(encode(header)), 
               bytes(encode(parent_header)), 
               bytes(encode(metadata)), 
               bytes(encode(content))]
    signature = sign(msg_lst)
    dprint(3, "send: msg_list:", msg_lst) 
    dprint(3, "send: signature:", signature)
    stream.send_multipart([
        "<IDS|MSG>", 
        signature, 
        msg_lst[0],
        msg_lst[1],
        msg_lst[2],
        msg_lst[3]])

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
    while not exiting:
        dprint(2, "Ping!")
        heartbeat_socket.send(b'ping')
        ready = poll()
        if ready:
            heartbeat_socket.recv()
        else:
            dprint(1, "heartbeat_loop fail!")

def poll():
    events = []
    dprint(2, "Start poll...")
    while not exiting:
        try:
            dprint(2, ".", end="")
            sys.stdout.flush()
            events = poller.poll(1000)
        except ZMQError as e:
            if e.errno == errno.EINTR:
                continue
            else:
                raise
        except Exception:
            dprint(2, "Exception!")
            raise
        else:
            break
    dprint(2, "Return:", events)
    return events

# Socket Handlers:
def shell_handler(msg):
    global execution_count
    dprint(1, "shell received:", msg)
    position = 0
    while (msg[position] != "<IDS|MSG>"):
        position += 1
    delim         = msg[position]
    signature     = msg[position + 1]
    shell_header  = decode(msg[position + 2])
    parent_header = decode(msg[position + 3])
    metadata      = decode(msg[position + 4])
    content       = decode(msg[position + 5])

    dprint(3, "Checking signature:", signature)
    # TODO: check signature
    check_sig = sign(msg[position + 2:position + 6])
    print("Computed signature    :", check_sig)

    # process request:
    if shell_header["msg_type"] == "execute_request":
        dprint(1, "simple_kernel Executing:", pformat(content["code"]))
        pub_header = {
            "msg_id": msg_id(),
            "username": shell_header["username"],
            "session": shell_header["session"],
            "msg_type": "pyout",
        }
        pub_content = {
            'execution_count': execution_count,
            'data' : {"text/plain": "result!"},
            'metadata' : {},
        }
        send(iopub_stream, pub_header, shell_header, metadata, pub_content)
        header = {
            "msg_id": msg_id(),
            "username": shell_header["username"],
            "session": shell_header["session"],
            "msg_type": "execute_reply",
        } 
        content = {
            "status": "ok",
            "execution_count": execution_count,
            "playload": [],
            "user_variables": {},
            "user_expressions": {},
        }
        send(shell_stream, header, shell_header, metadata, content)
    elif shell_header["msg_type"] == "kernel_info_request":
        header = {
            "msg_id": msg_id(),
            "username": shell_header["username"],
            "session": shell_header["session"],
            "msg_type": "kernel_info_reply",
        } 
        content = {
            "protocol_version": [1, 1],
            "ipython_version": [1, 1, 0, ""],
            "language_version": [0, 0, 1],
            "language": "simple",
        }
        send(shell_stream, header, shell_header, metadata, content)
    elif shell_header["msg_type"] == "history_request":
        header = {
            "msg_id": msg_id(),
            "username": shell_header["username"],
            "session": shell_header["session"],
            "msg_type": "kernel_info_reply",
        } 
        content = {
            'output' : False,
        }
        send(shell_stream, header, shell_header, metadata, content)
    else:
        dprint("unknown msg_type:", shell_header["msg_type"])
        header = {
            "msg_id": msg_id(),
            "username": shell_header["username"],
            "session": shell_header["session"],
            "msg_type": "execute_reply",
        } 
        content = {
            "status": "error",
            "execution_count": execution_count,
        }
        send(shell_stream, header, shell_header, metadata, content)
    execution_count += 1

def control_handler(msg):
    global exiting
    dprint(1, "control received:", msg)
    # Need to handle: "shutdown_request"
    # exiting = True

# Control message to handle:
# ['\x00\xe4<\x98i', 
#  '<IDS|MSG>', 
#  '47917158f71daf34e9565516a11ea9632aa8a7cd1cfee29fff1c25b9049f373a', 
#  '{"date":"2014-01-18T13:11:04.544653","username":"dblank",
#    "session":"d63aaffb-f40d-492c-ade1-01432181ee3e",
#    "msg_id":"dcc9c54a-d5fb-4570-95a9-4845ad28ebc3",
#    "msg_type":"shutdown_request"}', 
#  '{}', '{}', '{"restart":false}']

def iopub_handler(msg):
    dprint(1, "iopub received:", msg)

def stdin_handler(msg):
    dprint(1, "stdin received:", msg)

## Initialize:
ioloop.install()

dprint(1, "Loading simple_kernel with args:", sys.argv)
dprint(1, "Reading config file '%s'..." % sys.argv[1])
config = decode("".join(open(sys.argv[1]).readlines()))
dprint(1, "Config:", pformat(config))

connection     = "tcp://" + config["ip"] + ":"
heartbeat_conn = connection + str(config["hb_port"])
iopub_conn     = connection + str(config["iopub_port"])
shell_conn     = connection + str(config["shell_port"])
control_conn   = connection + str(config["control_port"])
stdin_conn     = connection + str(config["stdin_port"])

session_id = unicode(uuid.uuid4()).encode('ascii')
secure_key = unicode(config["key"]).encode("ascii")
auth = hmac.HMAC(secure_key)
execution_count = 1

##########################################
# Heartbeat:
ctx = zmq.Context()
heartbeat_socket = ctx.socket(zmq.REQ)
heartbeat_socket.setsockopt(zmq.LINGER, 0)
heartbeat_socket.connect(heartbeat_conn)
poller = zmq.Poller()
poller.register(heartbeat_socket, zmq.POLLIN)

##########################################
# IOPub/Sub:
# aslo called SubSocketChannel in IPython sources
iopub_socket = ctx.socket(zmq.SUB)
iopub_socket.setsockopt(zmq.SUBSCRIBE,b'')
iopub_socket.setsockopt(zmq.IDENTITY, session_id)
iopub_socket.connect(iopub_conn)
iopub_loop = ioloop.IOLoop()
iopub_stream = zmqstream.ZMQStream(iopub_socket, iopub_loop)
iopub_stream.on_recv(iopub_handler)

##########################################
# Control:
control_socket = ctx.socket(zmq.DEALER)
control_socket.setsockopt(zmq.IDENTITY, session_id)
control_socket.connect(control_conn)
control_loop = ioloop.IOLoop()
control_stream = zmqstream.ZMQStream(control_socket, control_loop)
control_stream.on_recv(control_handler)

##########################################
# Stdin:
stdin_socket = ctx.socket(zmq.DEALER)
stdin_socket.setsockopt(zmq.IDENTITY, session_id)
stdin_socket.connect(stdin_conn)
stdin_loop = ioloop.IOLoop()
stdin_stream = zmqstream.ZMQStream(stdin_socket, stdin_loop)
stdin_stream.on_recv(stdin_handler)

##########################################
# Shell:
shell_socket = ctx.socket(zmq.DEALER)
shell_socket.setsockopt(zmq.IDENTITY, session_id)
shell_socket.connect(shell_conn)
shell_loop = ioloop.IOLoop()
shell_stream = zmqstream.ZMQStream(shell_socket, shell_loop)
shell_stream.on_recv(shell_handler)

dprint(1, "Starting loops...")
# Which threads to run is determined by the frontend
# For example, the notebook frontend does not use heartbeat
threads = [
    threading.Thread(target=lambda: run_thread(shell_loop, "Shell")),
    threading.Thread(target=lambda: run_thread(iopub_loop, "IOPub")),
#    threading.Thread(target=lambda: run_thread(control_loop, "Control")),
    threading.Thread(target=lambda: run_thread(stdin_loop, "StdIn")),
#    threading.Thread(target=heartbeat_loop),
]
for thread in threads:
    thread.start()
dprint(1, "Ready! Listening...")
