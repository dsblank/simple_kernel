simple_kernel
=============

A small, simple kernel example for Jupyter, specification version: 5.0

## Run

Download and run:

`ipython console --KernelManager.kernel_cmd="['python', 'simple_kernel.py', '{connection_file}']"`

`ipython notebook --KernelManager.kernel_cmd="['python', 'simple_kernel.py', '{connection_file}']"`

`ipython qtconsole --KernelManager.kernel_cmd="['python', 'simple_kernel.py', '{connection_file}']"`

### Alternative way

Install Jupyter

```Bash
$ git clone https://github.com/jupyter/notebook.git
$ cd notebook
$ mkvirtualenv jupyter-env
$ workon jupyter-env
(jupyter-env) $ pip install --pre -e .
(jupyter-env) $ pip install jupyter-console
```

Download project to the different directory, install (prepare kernel.json file with `install_script.sh` script) and run:

```Bash
(jupyter-env) $ git clone https://github.com/dsblank/simple_kernel.git
(jupyter-env) $ ./install_script.sh
(jupyter-env) $ jupyter console --kernel simple_kernel
```

### Testing kernel

You can test your project using [jupyter_kernel_test](https://github.com/jupyter/jupyter_kernel_test) project.

Clone this project:

```Bash
(jupyter-env) $ git clone https://github.com/jupyter/jupyter_kernel_test
(jupyter_env) $ cd jupyter_kernel_test
```

Modify `test_ipython.py` file to look like this:

```Python
import unittest
import jupyter_kernel_test as jkt

class IRkernelTests(jkt.KernelTests):
    kernel_name = "simple_kernel"
    language_name = "simple_kernel"

    code_hello_world = "print('hello, world')"

if __name__ == '__main__':
    unittest.main()
```

and run this project with following command:

```Bash
(jupyter-env) $ python test_ipython.py
```

Output should be similar to this:

```Bash
### some debug information
----------------------------------------------------------------------
Ran 5 tests in 1.034s

OK (skipped=3)
```

Current status
----------

Features:

* shell, heartbeat, and iopub channels working
* signatures are correct
* need to test control and stdin channels
* need to handle "magics"

Bugs:

1. when running a console, doesn't stop python when exiting

References
----------

These references may be helpful in understanding the big picture of IPython and zmq.

1. http://ipython.org/ipython-doc/dev/development/messaging.html - Messaging documentation
2. http://andrew.gibiansky.com/blog/ipython/ipython-kernels/ - Useful document in making a kernel
3. http://zeromq.github.io/pyzmq/api/index.html - 0MQ Documentation for low-level socket functionality

Other Kernel Examples
---------------------

Here is a list of all of the standalone kernels (backends) that I know about. I don't think I got a single one to run, however.

* https://github.com/gibiansky/IHaskell - Written in Haskell
* https://github.com/takluyver/igo - Written in Go
  * fails to build, needs Go 1.2?
* https://github.com/mattpap/IScala - Written in Scala
* https://github.com/mattpap/IAldor - Written C
  * fails to build
* https://github.com/mattpap/ipykernel - Written in C
  *  needs "sudo ln -s /usr/lib/x86_64-linux-gnu/libjansson.so.4 /usr/lib/libjansson.so"
  *  needs "sudo apt-get install uuid-dev"
  *  echo fails, needs M_UUID defined
* http://nbviewer.ipython.org/gist/Carreau/4279371/node-kernel.ipynb - Written in JavaScript
  * needs "sudo apt-get install libzmq-dev"
  * ImportError: The IPython Notebook requires tornado >= 3.1.0, but you have 2.4.1
  * After upgrading "sudo pip install tornado": ImportError: No module named zmq.subprocesskernel
  * Matthias Bussonnier says "The node example pre-date the ability to configure kernelmanager. Just forget about subpricesskernelmanager."
* https://github.com/minrk/profile_jskernel - In-browser JavaScript kernel
  * doesn't work as far as I can tell
* https://bitbucket.org/ipre/calico/src/master/Source/Calico/ZMQServer.cs?at=master - Written in C#, but serves a variety of languages (Java, Python, Scheme, and others)

