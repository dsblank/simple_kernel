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

## Imports:
import sys
import zmq
import json
import hmac
import uuid
import threading
from pprint import pformat
from zmq.eventloop import ioloop, zmqstream
from zmq.error import ZMQError

decode = json.JSONDecoder().decode
encode = json.JSONEncoder().encode
debug_level = 3 # 0 (none) to 3 (all) for various levels of detail

def dprint(level, *args, **kwargs):
    """ Show debug information """
    if level <= debug_level:
        print(*args, **kwargs)

## Initialize:
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

def iopub_handler(msg):
    dprint(1, "iopub received:", msg)

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

def shell_handler(msg):
    global execution_count
    dprint(1, "shell received:", msg)
    # Shell message to handle:
    # ['90711B188AEF41E19FE80A2A788E75A4', 
    #  '<IDS|MSG>', 
    #  '5973981c454337cba7959cc375a375bf721aebc0f07bda054a92da9c733feac1', 
    #  '{"username":"username","msg_id":"A96BBFE315DC4BE989FB1E2087D30EA5","msg_type":"execute_request","session":"90711B188AEF41E19FE80A2A788E75A4"}', 
    #  '{}', 
    #  '{}', 
    #  '{"store_history":true,"silent":false,"user_variables":[],"code":"1","user_expressions":{},"allow_stdin":true}']

    ident         = msg[0]
    delim         = msg[1]
    signature     = msg[2]
    parent_header = decode(msg[3])
    header        = msg[4]
    metadata      = msg[5]
    content       = decode(msg[6])

    # process request:
    if parent_header["msg_type"] == "execute_request":
        dprint(1, "Executing:", content["code"])
        header_reply = {
            "msg_id": msg_id(),
            "username": parent_header["username"],
            "session": parent_header["session"],
            "msg_type": "execute_reply",
        } 
        content = {
            "status": "ok",
            "execution_count": execution_count,
            "playload": [],
            "user_variables": {},
            "user_expressions": {},
        }
    elif parent_header["msg_type"] == "kernel_info_request":
        header_reply = {
            "msg_id": msg_id(),
            "username": parent_header["username"],
            "session": parent_header["session"],
            "msg_type": "kernel_info_reply",
        } 
        content = {
            "protocol_version": [1, 1],
            "ipython_version": [1, 1, 0, ""],
            "language_version": [0, 0, 1],
            "language": "simple",
        }
    else:
        dprint("unknown msg_type:", parent_header["msg_type"])
        content = {}

    header_pub = {
        "msg_id": msg_id(),
        "username": parent_header["username"],
        "session": parent_header["session"],
        "msg_type": "pyout",
    }

    ### respond:
    msg_lst = [bytes(encode(header_pub)), # header_pub
               msg[3],
               msg[5],
               bytes(encode(content))]
    signature = sign(msg_lst)
    dprint(3, "msg_list:", msg_lst) # list of serialized objects
    dprint(3, "signature:", signature)
    # Send to pub:
    iopub_stream.send_multipart([
        "<IDS|MSG>", # delim
        signature, # HMAC sig
        bytes(encode(header_pub)), # header_pub
        msg[3], # parent
        msg[5], # parent_header
        bytes(encode(content))])
    # Send to shell:
    msg_lst = [bytes(encode(header_reply)), # header_pub
               msg[3],
               msg[5],
               bytes(encode(content))]
    signature = sign(msg_lst)
    dprint(3, "msg_list:", msg_lst) # list of serialized objects
    dprint(3, "signature:", signature)
    shell_stream.send_multipart([
        "<IDS|MSG>", # delim
        signature, # sig
        bytes(encode(header_reply)),
        msg[3],
        msg[5],
        bytes(encode(content))])
    execution_count += 1

def control_handler(msg):
    dprint(1, "control received:", msg)

def stdin_handler(msg):
    dprint(1, "stdin received:", msg)

exiting = False
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
        #else:
        #    break
    dprint(2, "Return:", events)
    return events

ioloop.install()

# Control message to handle:
# ['\x00\xe4<\x98i', 
#  '<IDS|MSG>', 
#  '47917158f71daf34e9565516a11ea9632aa8a7cd1cfee29fff1c25b9049f373a', 
#  '{"date":"2014-01-18T13:11:04.544653","username":"dblank",
#    "session":"d63aaffb-f40d-492c-ade1-01432181ee3e",
#    "msg_id":"dcc9c54a-d5fb-4570-95a9-4845ad28ebc3",
#    "msg_type":"shutdown_request"}', 
#  '{}', '{}', '{"restart":false}']


def shell_thread():
    name = "Shell"
    dprint(2, "Starting loop for '%s'..." % name)
    while True:
        dprint(2, "%s Loop!" % name)
        try:
            shell_loop.start()
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

def control_thread():
    name = "Control"
    dprint(2, "Starting loop for '%s'..." % name)
    while True:
        dprint(2, "%s Loop!" % name)
        try:
            control_loop.start()
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

def iopub_thread():
    name = "IOPub"
    dprint(2, "Starting loop for '%s'..." % name)
    while True:
        dprint(2, "%s Loop!" % name)
        try:
            iopub_loop.start()
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

def stdin_thread():
    name = "StdIn"
    dprint(2, "Starting loop for '%s'..." % name)
    while True:
        dprint(2, "%s Loop!" % name)
        try:
            stdin_loop.start()
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
iopub_socket.bind(iopub_conn)
iopub_loop = ioloop.IOLoop()
iopub_stream = zmqstream.ZMQStream(iopub_socket, iopub_loop)
iopub_stream.on_recv(iopub_handler)

##########################################
# Control:
control_socket = ctx.socket(zmq.ROUTER)
control_socket.setsockopt(zmq.IDENTITY, session_id)
control_socket.bind(control_conn)
control_loop = ioloop.IOLoop()
control_stream = zmqstream.ZMQStream(control_socket, control_loop)
control_stream.on_recv(control_handler)

##########################################
# Stdin:
stdin_socket = ctx.socket(zmq.ROUTER)
stdin_socket.setsockopt(zmq.IDENTITY, session_id)
stdin_socket.bind(stdin_conn)
stdin_loop = ioloop.IOLoop()
stdin_stream = zmqstream.ZMQStream(stdin_socket, stdin_loop)
stdin_stream.on_recv(stdin_handler)

##########################################
# Shell:
shell_socket = ctx.socket(zmq.ROUTER)
shell_socket.setsockopt(zmq.IDENTITY, session_id)
shell_socket.bind(shell_conn)
shell_loop = ioloop.IOLoop()
shell_stream = zmqstream.ZMQStream(shell_socket, shell_loop)
shell_stream.on_recv(shell_handler)

dprint(1, "Starting loops...")
threads = [threading.Thread(target=shell_thread),
           threading.Thread(target=iopub_thread),
           threading.Thread(target=control_thread),
           threading.Thread(target=stdin_thread),
           threading.Thread(target=heartbeat_loop)]
for thread in threads:
    thread.start()
dprint(1, "Ready! Listening...")
