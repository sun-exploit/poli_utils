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
#   This file is part of crcnetd - CRCnet Configuration System Daemon
#
#   Web and RPC Server - Provides the server that forms the primary interface
#   to the CRCnet Configuration System Daemon.
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
import os
import sys
import types
import gc
import xmlrpclib
import inspect
import hotshot
import time
import threading
import thread

from twisted.web      import xmlrpc, server, resource
from twisted.internet import reactor, defer, threads
from twisted.python   import context, threadable, threadpool, log as twisted_log

from OpenSSL import SSL

from pcsd_common import *
from pcsd_log    import *
from pcsd_daemon import shutdownHandler
from pcsd_config import config_get, config_getboolean, config_getint
from pcsd_events import registerEvent, triggerEvent

class pcsd_server_error(pcsd_error):
    pass

_http_root = None
_https_root = None

pcs_utils_type = PCSD_CORE

#####################################################################
# Webserver Initialisation
#####################################################################
def registerDailyAt(*args):
    """
    Decorator function to set up a daily call back. Accepts three arguments
    (hr, min, sec) or a single tuple containing those three arguments
    """
    try:
        if len(args) == 1:
            inHr, inMin, inSec = args[0]
        elif len(args) == 3:
            inHr, inMin, inSec = args[0:3]
        else:
            raise TypeError("registerDailyAt expects a tuple (hr, min, sec) " \
                    "or three arguments!")
        if inHr < 0 or inHr > 23:
            raise TypeError("Invalid hour value")
        if inMin < 0 or inMin > 59:
            raise TypeError("Invalid minute value")
        if inSec < 0 or inSec > 59:
            raise TypeError("Invalid seconds value")
    except:
        (etype, value, tb) = sys.exc_info()
        raise TypeError(value)

    def decorator(func):
        def _wrapper():
            # Call back every hour until the target is within 1hr, then
            # try and call back exactly
            left = min(_wrapper._target-time.time(),3600)
            if left <= 0:
                # Time has expired, run immediately
                wfunc = _wrapper._func;
                log_info("%s is being executed now as requested" % \
                        (wfunc.__name__))
                try:
                    wfunc()
                except:
                    (etype, value, tb) = sys.exc_info()
                    log_error("Scheduled function '%s' failed!" % value, \
                            (etype, value, tb))
                # Reschedule tommorrow
                _wrapper._target += (60*60*24) # 60s * 60m * 24hr
                log_debug("%s rescheduled for %s" % \
                        (wfunc.__name__, time.ctime(_wrapper._target)))
                # Check again in an hour
                reactor.callLater(3600, _wrapper)
            else:
                reactor.callLater(left, _wrapper)

        # Store function in the wrapper function
        _wrapper._func = func

        # Calculate target time today
        (y,m,d,h,minute,s,a,b,c)=time.localtime()
        _wrapper._target = time.mktime((y, m, d, inHr, inMin, inSec, 0, 0, -1))
        if _wrapper._target < time.time():
            # Already passed today, target tommorrow
            _wrapper._target += (60*60*24) # 60s * 60m * 24hr
        log_info("%s scheduled for %s" % \
                (func.__name__, time.ctime(_wrapper._target)))
        # Call wrapper to schedule
        _wrapper()
        # Done
        return _wrapper
    return decorator

def registerHalfHourly():
    """
    Decorator function that sets up a 30 min call back that started from the
    next half hour, eg 4:00 or 4:30
    """

    def decorator(func):
        def _wrapper():
            # Work out the time left until 30 mins is up.
            left = _wrapper._target - time.time()
            if left <= 0:

                wfunc = _wrapper._func;
                wfunc()
                (y,m,d,h,min,s,a,b,c) = time.localtime(_wrapper._target)
                min = min+30
                _wrapper._target = time.mktime( (y,m,d,h,min,s,a,b,c) )
                reactor.callLater(_wrapper._target-time.time(), _wrapper)

            else:
                reactor.callLater(left, _wrapper)

        _wrapper._func = func
        (y,m,d,h,min,s,a,b,c) = time.localtime()

        #Set the minutes to the next 30min period, if needed increment hour.
        if min != 0 or min != 30:
            if min > 30:
                min = 0
                h += 1
            else:
                min = 30

        _wrapper._target = time.mktime((y,m,d,h,min,0,0,0,-1))
        _wrapper()
        return _wrapper
    return decorator

def registerResource(path, res_class, **kwargs):
    """Registers a resource for both HTTP and HTTPS access"""
    log_debug("%s::%s : path=[%s], res_class=[%s]" % (__name__, 'registerResource', path, res_class))
    registerHTTPResource(path, res_class, **kwargs)
    use_ssl = config_getboolean(None, "use_ssl", True)
    if use_ssl:
        registerHTTPSResource(path, res_class, **kwargs)

def registerHTTPResource(path, res_class, **kwargs):
    """Function to register an HTTP accessible resource at the specified path"""
    global _http_root
    _http_root = _registerResource(_http_root, "HTTP", path, res_class,
            **kwargs)

def registerHTTPSResource(path, res_class, **kwargs):
    """Function to register an HTTPS accessible resource at the specified path"""
    global _https_root
    _https_root = _registerResource(_https_root, "HTTPS", path, res_class,
            **kwargs)

def _registerResource(root, desc, path, res_class, **kwargs):
    """Helper function to register a resource at the specified path on a root

    The resource must be derived from twisted.web.resource. The resource
    must have at least one private member called resourceName that provides
    a textual description of the resource.
    """
    log_debug("%s::%s : root=[%s], desc=[%s], res_class=[%s]" % \
        (__name__, '_registerResource', root, desc, res_class))
    # Check that we have a root resource
    if root is None:
        root = resource.Resource()

    # Path should not start with /
    if path.startswith("/"):
        raise pcsd_server_error("Path must not begin with /!")

    # Check if the path is already registerd
    paths = root.listNames()
    if path in paths:
        raise pcsd_server_error("Path already registered!")

    # Create an instance of the class
    inst = res_class(**kwargs)

    # Register the resource
    log_info("Registering %s resource '%s' at /%s." % \
            (desc, res_class.resourceName, path))
    root.putChild(path, inst)
    return root

def registerRecurring(interval):
    """Decorator to register a function that is called at regular intervals

    interval should be specified in seconds
    """

    def decorator(func):
        # Store the recurrance interval as a function attribute
        func._interval = interval

        def _wrapper():
            wfunc = _wrapper._func
            # call the function
            wfunc()
            # Reschedule
            reactor.callLater(wfunc._interval, _wrapper)
        _wrapper._func = func

        # Setup initial call and return
        reactor.callLater(func._interval, _wrapper)
        return _wrapper

    return decorator

def initThread(func, *args, **kwargs):
    """Calls the specified function in a new thread"""
    log_debug("%s::%s : func=[%s] in a new thread" % (__name__, 'initThread', func))
    reactor.callInThread(func, *args, **kwargs)

def suggestThreadpoolSize(maxThreads):
    """Updates the size of the twisted threadpool

    The function must be passed a parameter specifying the maximum number of
    generation threads the user has requested.
    """
    reactor.suggestThreadPoolSize(int(maxThreads*1.5))

def stopPCSDServer():
    """Stops the PCSD Server by killing the twisted mainloop."""

    rv = reactor.stop()

def twisted_threadpool_worker(self):
    """A reimplementation of the twisted threadpool worker

    This logs the name of the function that is being executed into the thread
    name to assist with debugging.
    """
    ct = self.currentThread()
    o = self.q.get()
    while o is not threadpool.WorkerStop:
        self.working.append(ct)
        ctx, function, args, kwargs, onResult = o
        del o

        # Calculate a function name
        name = ct.getName()
        try:
            funcname = "<unknown>"
            username = "<unknown>"
            try:
                adict = args[2][0]
                if "name" in adict.keys():
                    funcname = adict["name"]
            except: pass
            try:
                adict = args[2][1]
                if "username" in adict.keys():
                    username = adict["username"]
            except: pass
            ct.setName("%s (%s:%s)" % (name, username, funcname))
            ct.started_at = time.time()
        except:
            pass
        try:
            result = context.call(ctx, function, *args, **kwargs)
            success = True
        except:
            success = False
            if onResult is None:
                context.call(ctx, log.err)
                result = None
            else:
                result = failure.Failure()
        del function, args, kwargs

        self.working.remove(ct)

        if onResult is not None:
            try:
                context.call(ctx, onResult, success, result)
            except:
                context.call(ctx, log.err)

        ct.setName(name)
        del ctx, onResult, result
        self.waiters.append(ct)
        o = self.q.get()
        self.waiters.remove(ct)

    self.threads.remove(ct)
threadpool.ThreadPool._worker = twisted_threadpool_worker

def startPCSDServer(key, cert, cacert):
    """Initialises the PCSD Server.

    This function never returns as it enters the twisted mainloop
    """
    log_debug("%s::%s : key=[%s], cert=[%s], cacert=[%s]" % \
        (__name__, 'startPCSDServer', key, cert, cacert))
    try:
        # Local networks
        localnets = config_get(None, "local_networks", "127.0.0.0/8")

        # Register standard HTTP XMLRPC handler for local requests
        registerHTTPResource("RPC2", pcsd_local_xmlrpc,
                localnets=localnets.split(","))

        # Register HTTPS XMLRPC Handler
        use_ssl = config_getboolean(None, "use_ssl", True)
        if use_ssl:
            registerHTTPSResource("RPC2", pcsd_xmlrpc)

        # Setup XMLRPC Handler configuration
        pcsd_xmlrpc.log_times = config_get(None, "log_times", None)
        pcsd_xmlrpc.profile = config_getboolean(None, "profile", False)
        pcsd_xmlrpc.prof_dir = config_get(None, "profile_dir", \
                DEFAULT_PROFILE_DIR)
        pcsd_xmlrpc.log_threads = config_get(None, "log_threads", None)
        pcsd_xmlrpc.max_threads = config_getint(None, "max_threads",
                DEFAULT_MAX_THREADS)

        # SSL Context
        class SCF:
            def __init__(self, key, cert, cacert):
                self.mKey    = key
                self.mCert   = cert
                self.mCACert = cacert

            def verify(self, conn, cert, errnum, depth, ok):
                """Checks the certificate of an incoming connection"""
                # If there is already an error bail now
                if not ok:
                    return ok

                # Only perform further verification on client certs
                if depth>0:
                    return ok

                # At this point we know the certificate is signed by a
                # trusted CA, check the issuer OU matches the incoming cert
                # OU and the incoming cert is not a server cert
                # XXX: Should look at using something like nsCertType rather
                # than the CN field for this.
                s = cert.get_subject()
                i = cert.get_issuer()
                if s.OU != i.OU:
                    log_warn("Rejected incoming connection from invalid "
                            "SSL cert (%s). OU did not match." % s)
                    return 0
                if s.CN == "server":
                    log_warn("Rejected incoming connection from server SSL "
                            "cert (%s)." % s)
                    return 0
                return 1

            def getContext(self):
                """Create an SSL context."""
                ctx = SSL.Context(SSL.SSLv3_METHOD)
                # Add the CA certificate(s)
                store = ctx.get_cert_store()
                for cert in self.mCACert:
                    store.add_cert(cert)
                # Load the private key and certificate
                ctx.use_privatekey(self.mKey)
                ctx.use_certificate(self.mCert)
                ctx.set_verify(SSL.VERIFY_PEER |
                        SSL.VERIFY_FAIL_IF_NO_PEER_CERT, self.verify)
                ctx.set_verify_depth(len(self.mCACert))
                return ctx

        # Port and logfile
        http_port = int(config_get(None, "http_port",
            DEFAULT_HTTP_SERVER_PORT))
        https_port = int(config_get(None, "https_port",
            DEFAULT_HTTPS_SERVER_PORT))
        logfile = config_get(None, "request_log", DEFAULT_REQUEST_LOG)

        # Pass off control to Twisted's mainloop
        threadable.init()
        suggestThreadpoolSize(pcsd_xmlrpc.max_threads)
        reactor.listenTCP(http_port, server.Site(_http_root, logfile))
        if use_ssl:
            reactor.listenSSL(https_port, server.Site(_https_root, logfile), \
                    SCF(key, cert, cacert))
        reactor.addSystemEventTrigger("before", "shutdown", shutdownHandler)
        log_info("Server Started. Ready to serve requests...")
    except Exception as inst:
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly
        log_fatal("Could not initialise the server!", sys.exc_info())

    reactor.run()

def get_refcounts():
    d = {}
    sys.modules
    # collect all classes
    for m in sys.modules.values():
        for sym in dir(m):
            o = getattr (m, sym)
            if type(o) is types.ClassType:
                d[o] = sys.getrefcount (o)
    # sort by refcount
    pairs = map (lambda x: (x[1],x[0]), d.items())
    pairs.sort()
    pairs.reverse()
    return pairs

@registerEvent("maintenance")
@registerRecurring(MAINT_INTERVAL)
def doMaintenance():
    """Performs regular tasks to maintain the server"""

    # Memory Debugging
    max = config_getint(None, "log_refcounts", 0)
    if max > 0:
        str = "Refcounts at %s\n" % time.ctime()
        for n, c in get_refcounts()[:max]:
            str += '%10d %s\n' % (n, c.__name__)
        log_debug(str)

    # Thread tracking
    if pcsd_xmlrpc.log_threads:
        threads = getThreadStatus()
        log_info("%d threads alive" % len(threads))
        for c, ti in threads.items():
            log_debug("thread % 2s: [%s] [%s] %s" % \
                    (c, ti["status"], ti["age_str"], ti["name"]))

    # Trigger the maintenance event, in a thread so that any blocking
    # operations don't halt the mainloop!
    initThread(triggerEvent, ADMIN_SESSION_ID, "maintenance")

#####################################################################
# RPC Server
#####################################################################

class pcsd_xmlrpc(xmlrpc.XMLRPC):
    """The PCSD XMLRPC server. Exposes methods to the world."""

    # Name for the resource
    resourceName = "XMLRPC Server"

    # List of functions that have asked to be exported
    _functions = {}

    # Flags to log more information
    profile = False
    log_times = None
    prof_dir = ""

    @staticmethod
    def exportViaXMLRPC(mode, group, classmethod=False, name="",
            clientAddress=False, asynchronous=False):
        """Decorator used by methods to export themselves via XMLRPC

        Each method should specify the security parameters mode and group
        to determine who may call the function, and under what circumstances.

        When this is called for a classmethod (classmethod=True) the function
        is only tagged in this function. Once the module containing the class
        has been completely loaded it is processed and updateClassMethod is
        called on each function that has been tagged.
        """

        log_debug("%s::exportViaXMLRPC(%s, %s, %s, %s, %s, %s)" % \
                  (__name__, mode, group, classmethod, name, \
            clientAddress, asynchronous) )
        # Create a new dictionary to hold function information
        efunc = {}
        efunc["mode"] = mode
        efunc["group"] = group
        efunc["classmethod"] = classmethod
        efunc["name"] = name
        efunc["includeClientAddress"] = clientAddress
        efunc["asynchronous"] = asynchronous

        # The real decorator function we will return
        def decorator(func):
            # Determine the functions exported name
            if efunc["name"] == "":
                efunc["name"] = func.func_name
            func.xmlrpcName = efunc["name"]
            # Check it's not already registered
            if efunc["name"] in pcsd_xmlrpc._functions.keys():
                raise pcsd_server_error("Duplicate XMLRPC function registered!")
            # Class method functions aren't registed just yet, tag it
            if classmethod:
                efunc["function"] = None
                func.exportViaXMLRPC = True
            else:
                efunc["function"] = func
            # Store it
            pcsd_xmlrpc._functions[efunc["name"]] = efunc
            log_debug("%s::%s exported via XMLRPC (%s)" % \
                    (func.__module__, efunc["name"], efunc["classmethod"]))
            # Return it
            return func

        return decorator

    @staticmethod
    def updateClassMethod(func, name=""):
        """Method to update the function list with an exported classMethod

        Called by the module loading routines to update tagged functions once
        the class has been completely loaded. We can't do this completely in
        a decorator as functions passed to decorators lack the im_class
        parameter.
        """

        # Determine functions exported name
        if name=="":
            name = func.func_name

        # Check it has been registered
        if name not in pcsd_xmlrpc._functions.keys():
            raise pcsd_server_error("Cannot update unregistered method!")
        if pcsd_xmlrpc._functions[name]["function"] is not None:
            raise pcsd_server_error("Class method already registered!")

        # Store the new function
        pcsd_xmlrpc._functions[name]["function"] = func

    def render(self, request):
        """Overrides the default render method

        * Implements auto login based on the supplied client certificate
        * Dispatches requests to the appropriate function that was earlier
          registered via exportViaXMLRPC
        """
        rstart = time.time()
        func = None
        # We import this here to avoid a circular reference
        from pcsd_session import isSessionValid, getSessionE, \
                pcsd_session_error

        # Break the request out into the function and its arguments
        request.content.seek(0, 0)
        args, functionPath = xmlrpclib.loads(request.content.read())
        # Profile if requested
        if self.profile:
            ensureDirExists(self.prof_dir)
            prof = hotshot.Profile("%s/%s.prof.%s" % \
                    (self.prof_dir, functionPath, int(time.time())))
            prof.start()

        try:
            # Find a reference to the function that has been called
            try:
                func = self._findFunction(functionPath)
            except xmlrpc.Fault, f:
                self._cbRender(f, request)
                if self.profile:
                    prof.stop()
                    prof.close()
                if self.log_times and func:
                    log_custom(self.log_times, "Rendered %s in %0.3f seconds" % \
                        (func["name"], (time.time()-rstart)))
                return server.NOT_DONE_YET

            # Throw an error now if we're out of threads
            if len(reactor.threadpool.threads) >= self.max_threads:
                if len(reactor.threadpool.waiters) < 2:
                    if not func["asynchronous"]:
                        raise pcsd_server_error("No free threads")
                elif len(reactor.threadpool.waiters) < 1:
                    raise pcsd_server_error("No free threads")

            # Handle special case function without session call
            if func["mode"] == SESSION_NONE:
                request.setHeader("content-type", "text/xml")
                reactor.callInThread(self._executeFunction, request, func, \
                        None, *args)
                if self.profile:
                    prof.stop()
                    prof.close()
                if self.log_times and func:
                    log_custom(self.log_times, "Rendered %s in %0.3f seconds" % \
                        (func["name"], (time.time()-rstart)))
                return server.NOT_DONE_YET

            # Check authentication
            needsauth=True
            try:
                if args[0]!={} and isSessionValid(args[0]):
                    needsauth=False
            except pcsd_session_error:
                (type, value, tb) = sys.exc_info()
                log_debug("Invalid session supplied - %s!" % value)

            # If there is no valid session specified try and logon using the
            # certificate
            if needsauth:
                auth = self._doCertificateLogon(request)
                if auth is None:
                    raise pcsd_server_error("Insufficient authentication " \
                            "information supplied!")
                log_info("Accepted SSL connection from %s" % auth["login_id"])
            else:
                # Use the user-supplied parameters
                auth = args[0]
            # Strip the dictionary from the real arguments
            args = args[1:]

            # If the function requested client information, prepend it
            if func["includeClientAddress"]:
                args = (request.getClientIP(), ) + args

            # Check the user has the appropriate permissions for the function
            session = getSessionE(auth["session_id"])
            perm = session.hasPerms(func["mode"], func["group"])
            if perm == SESSION_NONE:
                raise pcsd_server_error("Insufficient privileges for %s" % \
                        functionPath)

            # All OK so far
            request.setHeader("content-type", "text/xml")
            reactor.callInThread(self._executeFunction, request, func, auth, \
                    *args)
        except pcsd_server_error:
            (type, value, tb) = sys.exc_info()
            log_error("Call to %s failed! - %s" % (functionPath, value), \
                    (type, value, tb))
            self._cbRender(xmlrpclib.Fault(PCSD_CALLFAILED, value), request)
        except:
            # Unexpected error
            (type, value, tb) = sys.exc_info()
            log_error("Internal error while processing XMLRPC call (%s)" % \
                    functionPath, (type, value, tb))
            self._cbRender(xmlrpclib.Fault(PCSD_CALLFAILED, value), request)

        if self.profile:
            prof.stop()
            prof.close()
        if self.log_times and func:
            log_custom(self.log_times, "Rendered %s in %0.3f seconds" % \
                    (func["name"], (time.time()-rstart)))
        return server.NOT_DONE_YET

    def _doCertificateLogon(self, request):
        """Attempt to logon using the client certificate

        This can only succeed if:
        * the client certificate CN matches a username
        * cert_logins is not disabled in the configuration file
        """
        from pcsd_session import startSession, startBasicSession
        from crcnetd.modules.pcs_contact import getUserCache

        # Check incoming peer certificate
        cert = request.channel.transport.socket.get_peer_certificate()
        subj = cert.get_subject()
        domain = config_get('network','domain', '')
        username = "%s@%s" % (subj.CN , domain)

        allow_login = config_getboolean(None, "cert_logins", True)
        if not allow_login:
            None
            # CN matches a MAC address
            #return startBasicSession(username, SESSION_RW)

        # Does the CN match a username?
        users = getUserCache(ADMIN_SESSION_ID)
        if username in users.keys():
            if users[username]["enabled"]:
                # Make sure a session exists for the user
                return startSession(users[username]['login_id'], SESSION_RW)

        # CN matches a MAC address
        #return startBasicSession(username, SESSION_RW)
        return None

    def _executeFunction(self, request, func, auth, *args):
        """Executes the specified function and returns the result"""
        from pcsd_session import getSessionE

        if pcsd_xmlrpc.log_threads:
            exstart = time.time()
            ct = threading.currentThread()
            name = ct.getName().split()[0]
            log_debug("Executing '%s' in '%s'" % \
                    (func["function"].func_name, name))

        # Check for class method calls
        if func["classmethod"] == 1:
            # Init a class and build a class method call
            (inst, args) = _initClassMethod(auth["session_id"], func, *args)
            fstr = "inst.%s" % (func["function"].func_name)
        else:
            # Build a normal call
            fstr = "func[\"function\"]"
            if auth is not None:
                # Add session_id as first param
                args = (auth["session_id"], ) + args

        # Execute the function
        try:
            fin = time.time()
            rv = eval("%s(*args)" % fstr)
            fout = time.time()
            if self.log_times and func:
                log_custom(self.log_times, "Executed %s in %0.3f seconds" % \
                        (func["name"], (fout-fin)))
            # Shutdown the session if necessary
            try:
                if auth and "basicSession" in auth.keys():
                    sess = getSessionE(auth["sessionID"])
                    sess.close()
            except:
                log_error("Failed to close basic session!", sys.exc_info())
        except pcsd_error:
            # Expected error of some type
            (type, value, tb) = sys.exc_info()
            log_debug("Incoming XMLRPC call '%s' threw an exception" % \
                    func["name"], (type, value, tb))
            rv = xmlrpclib.Fault(PCSD_CALLFAILED, value)
        except:
            # Unexpected error
            (type, value, tb) = sys.exc_info()
            log_error("Incoming XMLRPC call failed (%s)" % func["name"], \
                    (type, value, tb))
            rv = xmlrpclib.Fault(PCSD_CALLFAILED, value)
        if pcsd_xmlrpc.log_threads:
            exend = time.time()
            log_custom(self.log_threads, "Executed %s in %0.3f seconds" % \
                    (func["name"], (exend-exstart)))

            log_debug("Finished executing '%s' in '%s'" % \
                    (func["function"].func_name, name))
        reactor.callFromThread(self._cbRender, enc(rv), request)
        return True

    def _findFunction(self, functionPath):
        """Looks for the specified function in the list of registered functions

        The function description dictionary as setup by exportViaXMLRPC is
        returned to the caller
        """

        # Strip module.funcName type paths to deal with earlier versions
        # of the daemon. module is simply thrown away
        parts = functionPath.split(".")
        if len(parts)>1:
            calledName = parts[1]
        else:
            calledName = functionPath

        if calledName not in self._functions.keys():
            raise xmlrpc.NoSuchFunction(xmlrpc.XMLRPC.NOT_FOUND, \
                    "Requested function (%s) does not exist!" % calledName)
        func = self._functions[calledName]

        return func

class pcsd_local_xmlrpc(pcsd_xmlrpc):
    """Local version of the XMLRPC server.
    Accepts HTTP connections from localhost
    """
    # Name for the resource
    resourceName = "XMLRPC Server for local requests"

    def __init__(self, localnets):
        # Validate the list of local networks we've been given
        self.localnets = []
        for net in localnets:
            try:
                validateCIDR(net)
            except:
                log_error("Invalid network in local_networks: %s" % net)
                pcsd_xmlrpc.localnets.remove(net)
                continue
            # Store valid networks for later comparisons
            log_info("Registering '%s' as a local network" % net)
            network = cidrToNetwork(net)
            netmask = cidrToNetmask(net)
            self.localnets.append((network, netmask))
        # Call the parent constructor
        pcsd_xmlrpc.__init__(self)

    def _isLocalIP(self, ip):
        """Returns true if the specified IP is in the list of local networks"""
        for (network, netmask) in self.localnets:
            ipn = ipnum(ip)
            if inNetwork(ipn, network, netmask):
                return True
        return False

    def render(self, request):
        # Check HTTP request is coming from trusted range
        if not self._isLocalIP(request.getClientIP()):
            request.setResponseCode(403,
                    "HTTP connections are not allowed from %s!" % \
                    request.getClientIP() )
            request.finish()
            return
        # Call parent
        return pcsd_xmlrpc.render(self, request)

# Bring exportViaXMLRPC,updateClassMethod into global module namespace
exportViaXMLRPC = pcsd_xmlrpc.exportViaXMLRPC
updateClassMethod = pcsd_xmlrpc.updateClassMethod

processedClasses = []
processedMethods = []
def processClassMethods(mod):
    """Handles registration for pcs_class derived classes in a module

    This function is used to finalise the XMLRPC registration of class methods
    in the classes.
    """
    global processedClasses, processedMethods
    log_debug("%s::%s mod=[%s]" % (__name__, 'processClassMethods', mod.__name__))
    syms = dir(mod)
    for sym in syms:
        # Skip objects that are not derived from pcs_class
        cls = eval("mod.%s" % sym)
        if not inspect.isclass(cls):
            continue
        if pcs_class not in inspect.getmro(cls):
            continue
        if cls in processedClasses:
            continue
        else:
            processedClasses.append(cls)
        # Look for methods tagged for export in the class
        fsyms = dir(cls)
        for func in fsyms:
            method = eval("mod.%s.%s" % (sym, func))
            msyms = dir(method)
            if "exportViaXMLRPC" not in msyms:
                continue
            if method in processedMethods:
                continue
            # Call the update function
            try:
                updateClassMethod(method, method.xmlrpcName)
                processedMethods.append(method)
            except:
                log_warn("Failed to register class method %s" % \
                        method.xmlrpcName)

def _initClassMethod(session_id, funcDetails, *args):
    """Initialises the parent class of the specified function to call it on.

    Must be passed a session_id, details of the method and a list of arguments.
    The argument list should be a tuple containing parameters to be passed to
    both the constructor and the method. Only positional parameters of the
    constructor can be given values and their must be at least as many elements
    in the args tuple as there are position parameters needing values in the
    construtor (excluding the session_id parameter).

    Once the constructor parameters have been used they are removed from the
    args tuple and the remaining components are returned so they can be passed
    to the method.

    Returns a class instance and a modified list of arguments.

    This is used as part of the wrapper for XMLRPC calls on a class method.
    """

    method = funcDetails["function"]
    classref = method.im_class

    # Get constructor parameters
    res = inspect.getargspec(getattr(classref,"__init__"))
    c_args = res[0][2:] # skip self, session_id parameters
    c_defs = res[1:]

    # Check we have enough arguments
    if len(args) < len(c_args):
        raise xmlrpc.NoSuchFunction(xmlrpc.XMLRPC.NOT_FOUND, \
                "Not enough parameters for class constructor! (%s.%s)" % \
                (classref, funcDetails["name"]))

    # Build call to constructor
    cseval = "classref(session_id, "
    idx=0
    for param in c_args:
        if c_defs[idx] is None:
            if args[idx] == "" or args[idx] is None:
                raise xmlrpc.NoSuchFunction(xmlrpc.XMLRPC.NOT_FOUND, \
                        "Empty value for %s parameter not allowed in " \
                        "class constructor! (%s.%s) " % (param, \
                        classref, funcDetails["name"]))
            cseval = "%sargs[%s], " % (cseval, idx)
            idx+=1
        else:
            # First parameter with a default marks end of pos params
            break

    # Remove class constructor args from arglist
    newargs = args[idx:]

    # Evaluate it and generate a class instance
    cseval = "%s)" % cseval
    rv =  eval(cseval)

    # Return the class instance and the new arglist
    return (rv, newargs)

@exportViaXMLRPC(SESSION_NONE, AUTH_AUTHENTICATED, asynchronous=True)
def getThreadStatus():
    """Returns a dictionary describing the state of the servers threads"""
    thread_dict = {}
    c=0

    threads = threading.enumerate()
    for ti in threads:
        if c==0: status="R" # MainThread
        elif ti in reactor.threadpool.waiters: status="S" # sleeping
        elif ti in reactor.threadpool.working: status="R" # running
        else: status=" "                                  # unknown
        started_at = getattr(ti, "started_at", -1)
        if started_at != -1 and status=="R":
            age = time.time()-started_at
            age_str = "%3.3f" % (time.time()-started_at)
        else:
            age = -1
            age_str = " "*6
        thread_dict[c] = {"name":ti.getName(), "status":status,
                "age":age, "age_str":age_str}
        c+=1
    return thread_dict
