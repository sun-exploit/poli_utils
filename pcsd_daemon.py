# This file is part of Fork of crcnetd - CRCnet Configuration System Daemon
#
# Copyright (c) 2012 sun-exploit <a1@sun-exploit.com>
#
#  Fork of crcnetd is free software: you may copy, redistribute
#  and/or modify it under the terms of the GNU General Public License as
#  published by the Free Software Foundation, either version 2 of the
#  License, or (at your option) any later version.
#
#  This file is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# This file incorporates work covered by the following copyright and
# permission notice:
#
#   Copyright (C) 2006  The University of Waikato
#
#   This file is part of the CRCnet Configuration System
#
#   Helper functions for creating servers
#
#   Author:       Matt Brown <matt@crc.net.nz>
#   Version:      $Id$
#
#   crcnetd is free software; you can redistribute it and/or modify it under the
#   terms of the GNU General Public License version 2 as published by the Free
#   Software Foundation.
#
#   crcnetd is distributed in the hope that it will be useful, but WITHOUT ANY
#   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
#   FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
#   details.
#
#   You should have received a copy of the GNU General Public License along with
#   crcnetd; if not, write to the Free Software Foundation, Inc.,
#   51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
import sys
import os, os.path
import getopt
import pwd

from pcsd_common import *
from pcsd_log import *
from pcsd_config import config_get, config_init
from pcsd_events import registerEvent, triggerEvent

pcs_utils_type = PCSD_CORE

#####################################################################
# Server / Daemonisation Helper Functions
#####################################################################
@registerEvent("shutdown")
def shutdownHandler():
    """Closes down the daemon nicely"""

    log_info("Shutting down...")

    # Trigger shutdown event
    triggerEvent(-1, "shutdown")

    log_info("Shutdown completed successfully")

def putpid(location):
    """Writes to the specified location the pid of the current process"""

    try:
        f = open(location, "w")
        f.write("%d" % os.getpid())
        f.close()
    except:
        log_fatal("Could not write pidfile!", sys.exc_info())

def daemonise():
    """Detach a process from the controlling terminal and run it in the
    background as a daemon.

    http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/278731
    """

    # Get pidfile location
    pidfile = config_get(None, "pidfile", DEFAULT_PIDFILE)

    # Check pidfile is writable
    if os.access(os.path.dirname(pidfile), os.W_OK) != 1:
        log_fatal("Unable to write to pid file (%s)" % pidfile)

    try:
        pid = os.fork()
    except OSError, e:
        raise Exception, "%s [%d]" % (e.strerror, e.errno)

    if (pid == 0):	# The first child.
        os.setsid()

        try:
            pid = os.fork()	# Fork a second child.
        except OSError, e:
            raise Exception, "%s [%d]" % (e.strerror, e.errno)

        if (pid == 0):	# The second child.
            os.chdir("/")
            for name in os.environ.keys():
                if name not in ALLOWED_ENV_VARS:
                    del os.environ[name]
                if name == "PWD":
                    os.environ["PWD"] = "/"
                elif name == "HOME":
                    os.environ["HOME"] = pwd.getpwuid(os.getuid())[5]
            os.umask(0)
        else:
            os._exit(0)	# Exit parent (the first child) of the second child.
    else:
        os._exit(0)	# Exit parent of the first child.

    try:
        import resource
        maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
        if (maxfd == resource.RLIM_INFINITY):
            maxfd = 1024
    except ImportError:
        maxfd = 1024

    # Try and grab the twisted waker file descriptors (this will fail on client
    # devices). Twisted starts the reactor as soon as the module is imported,
    # which means by this point it already has a pipe setup to use for waking
    # its event loop. If we close the file descriptors here we run into
    # problems later...
    try:
        twistedi = reactor.waker.i.fileno()
        twistedo = reactor.waker.o.fileno()
    except NameError:
        # Probably a client device, without twisted
        twistedi = twistedo = -1

    # Work around a broken urandom implementation in Python
    # < 2.4.3. Python opens _urandomfd the first time urandom
    # is called and expects it to stay open forever... See:
    # http://sf.net/tracker/?func=detail&atid=105470&aid=1177468&
    # group_id=5470
    urandomfd = -1
    if hasattr(os, "_urandomfd"):
        if os._urandomfd is not None:
            urandomfd = os._urandomfd

    # Iterate through and close all file descriptors.
    for fd in range(0, maxfd):
        try:
            # Skip closing this FD if it matches either twisted, or urandomfd
            # file descriptors that we found above
            if fd == urandomfd:
                continue
            if fd == twistedi or fd == twistedo:
                continue
            # Close!
            os.close(fd)
        except OSError:	# ERROR, fd wasn't open to begin with (ignored)
            pass

    # This call to open is guaranteed to return the lowest file descriptor,
    # which will be 0 (stdin), since it was closed above.
    if (hasattr(os, "devnull")):
        os.open(os.devnull, os.O_RDWR)
    else:
        os.open("/dev/null", os.O_RDWR)

    # Duplicate standard input to standard output and standard error.
    os.dup2(0, 1)			# standard output (1)
    os.dup2(0, 2)           # standard error (2)

    # Write pidfile
    putpid(pidfile)

    return 1

def sighndlr(signum, frame):
    """Handle signals"""

    log_notice("Caught signal (%d)!" % signum)
    shutdownHandler()

def handleDaemonise():

    # Read command line options
    is_daemon = 0
    optlist, args = getopt.gnu_getopt(sys.argv[1:], OPTION_LIST)
    for (arg, val) in optlist:
        if arg == "-d":
            is_daemon = daemonise()

    # Make sure logger knows our status
    setDaemonStatus(is_daemon)
    setTracebackLog(config_get(None, "traceback_log", None))

def loadModules(opmode):
    """Loads modules appropriate for the current server"""

    # Initialise modules
    mDir = "%s/modules" % os.path.dirname(os.path.dirname(__file__))
    print "%s" % mDir
    dMods = config_get(None, "modules", None)
    if dMods is None:
        log_debug("%s::%s : Modules dict is empty" % (__name__,'loadModules'))
        return []
    modules = []

    if opmode == PCSD_SERVER:
        prefix = "pcs"
    else:
        prefix = "pcs_monitor"

    # Scan through the list and load valid modules
    for module in dMods.split(","):
        module = module.strip()
        if module == "":
            continue
        mname = "%s_%s" % (prefix, module)
        mfile = "%s/%s.py" % (mDir, mname)
        # Check module exists
        if not os.path.exists(mfile):
            log_fatal("Cannot load requested module '%s'. File not found!" % \
                    module)
        # Load the modules code
        fd = open(mfile, "r")
        data = fd.read()
        fd.close()
        # Look for a line containing pcsd_mod_type
        idx = data.find("pcs_mod_type")
        if idx == -1:
            log_fatal("Module '%s' has no pcs_mod_type property!" % module)
        try:
            log_debug("%s::loadModules module =%s\n" % (__name__, mfile))
            code = compile(data[idx:data.find("\n",idx)], "%s.py" % mname, \
                    'single')
            eval(code)
            if pcs_mod_type is None:
                log_fatal("Could not determine type of module '%s'!" % module)
            if type(pcs_mod_type)==type([]):
                if opmode not in pcs_mod_type:
                    log_fatal("Module '%s' cannot be used with this mode!" % \
                            module)
                    continue
            else:
                if opmode != pcs_mod_type:
                    log_fatal("Module '%s' cannot be used with this mode!" % \
                            module)
                    continue
        except:
            log_fatal("Could not determine type of module '%s'!" % module, \
                    sys.exc_info())
        # Load the module
        try:
            log_debug("pcsd_daemon try to load {0} module".format(mname))
            exec "import crcnetd.modules.%s" % mname
            m = eval("crcnetd.modules.%s" % mname)
        except:
            log_fatal("Module '%s' failed to load!" % module, sys.exc_info())
        modules.append(m)
        log_info("Loaded Module: %s" % module)

    return modules

