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
#   CFengine Configuration Setup
#
#   Manages the cfengine configuration for the configuration system. The two
#   primary tasks involved in this are:
#   - Configuration file generation from templates
#   - Controling cfengine runs and collecting output on demand
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
import os
import os.path
from stat import *
import imp
import time
import threading
from Cheetah.Template import Template

from pcsd_common import *
from pcsd_log import *
from pcsd_events import *
from pcsd_config import config_get, config_get_required, \
        config_getint
from pcsd_session import getSession, getSessionE, pcsd_session
from pcsd_server import registerResource, exportViaXMLRPC, \
        initThread, registerRecurring, suggestThreadpoolSize
from pcsd_service import getServiceInstance, pcsd_service_error

class pcsd_template_error(pcsd_error):
    pass

#####################################################################
# General Cfengine Integration Helper Functions
#####################################################################
def initTemplates():
    global _templateDir, _templateModDir

    # Ensure output template module directories exist and are empty
    removeDir("%s/host" % _templateModDir)
    ensureDirExists("%s/host" % _templateModDir)
    removeDir("%s/network" % _templateModDir)
    ensureDirExists("%s/network" % _templateModDir)

    # Ensure templates are compiled
    rv = log_command("/usr/bin/cheetah compile -R --idir %s/host --odir " \
            "%s/host --nobackup 2>&1" % (_templateDir, _templateModDir))
    if rv != None:
        log_error("Unable to compile all host templates!")
    rv = log_command("/usr/bin/cheetah compile -R --idir %s/network --odir " \
            "%s/network --nobackup 2>&1" % \
            (_templateDir, _templateModDir))
    if rv != None:
        log_error("Unable to compile all network templates!")

    # Load template files
    hostTemplates = loadTemplates("%s/host" % _templateModDir)
    log_info("Loaded %s host templates for cfengine." % len(hostTemplates))
    networkTemplates = loadTemplates("%s/network" % _templateModDir)
    log_info("Loaded %s network templates for cfengine." % \
            len(networkTemplates))

    return networkTemplates, hostTemplates

def loadTemplates(moduleDir, baseStrip=""):
    """Creates a dictionary of template modules from the specified dir"""

    # Dictionary of template objects
    templates = {}

    if baseStrip == "":
        baseStrip = moduleDir

    # Get a list of possible templates
    if os.access(moduleDir, os.R_OK) != 1:
        raise pcsd_template_exception("Unable to access directory! - %s" % \
                moduleDir)
    ptempls = os.listdir(moduleDir)

    # Scan through the list and load valid modules
    for tfile in ptempls:
        # Ignore hidden files
        if tfile.startswith("."):
            continue
        tfilename = "%s/%s" % (moduleDir, tfile)
        # Recurse into directories
        if os.path.isdir(tfilename):
            templates.update(loadTemplates(tfilename, baseStrip))
            continue
        # Ignore non module files
        if not tfile.endswith(".py"):
            continue
        # Load the template module
        tname = os.path.basename(tfilename)[:-3]
        if tname == "__init__":
            # Ignore python framework stuff
            continue
        m = None
        try:
            m = imp.load_source(tname, tfilename)
            # Don't want the module in the system module list
            if tname in sys.modules.keys():
                del sys.modules[tname]
        except:
            log_debug("Module import failed for %s template" % tname, \
                    sys.exc_info())
            pass
        if not m:
            log_error("Failed to import template: %s" % tname)
            continue
        # If an explicit output filename was specified use that, otherwise
        # prepend path information and store the template filename.
        path = "%s/" % os.path.dirname(tfilename[len(baseStrip)+1:])
        if len(path) == 1:
            path = ""
        tclass = eval("m.%s" % tname)
        m.fileName = "%s%s" % (path, getattr(tclass, "fileName", tname))
        m.multiFile = getattr(tclass, "multiFile", False)
        m.templateName = tname
        # Store the template for future use, prepend path for uniqueness
        templateID = "%s%s" % (path, tname)
        if templateID in templates.keys():
            log_error("Could not import duplicate template: %s" % tname)
            continue
        templates[templateID] = m

    # Return the templates
    return templates

@registerRecurring(60*10)
def cleanTemplateStatus():
    """Runs every ten minutes to clean up expired template status info"""
    global _templateStats, _statsLock

    # If generation is not finished by this many minutes after initiation
    # there is an error, stats are removed in hope of causing a Key error
    # that will kill the errant threads
    err_time = 60*60
    # Statistics for finished generation runs are removed this many minutes
    # after the run completes
    expire_time = 60*30

    _statsLock.acquire()
    try:
        for key,stats in _templateStats.items():
            if (time.time()-stats["initiated"]) > err_time:
                # Still processing after one hour!?
                log_error("Template generation (%s) was still active after " \
                        "%d seconds!" % (key, err_time))
                del _templateStats[key]
                continue
            if stats["finished"] == 0:
                # Still in progress
                continue
            if (time.time()-stats["finished"]) > expire_time:
                log_info("Removing template generation status (%s)" % key)
                del _templateStats[key]
    finally:
        _statsLock.release()

    return True

@exportViaXMLRPC(SESSION_RO, AUTH_ADMINISTRATOR)
def getTemplateStatus(session_id, statsKey, asynchronous=True):
    """Returns the status of a specified template generation run"""
    global _templateStats, _statsLock

    stats = None

    _statsLock.acquire()
    try:
        if statsKey not in _templateStats.keys():
            raise pcs_cfengine_error("Invalid key: %s" % statsKey)
        stats = dict(_templateStats[statsKey])
    finally:
        _statsLock.release()

    return stats

@exportViaXMLRPC(SESSION_RW, AUTH_ADMINISTRATOR)
def generateTemplate(session_id, requested_templates={}):
    """Generates the specified configuration templates

    The requested_templates parameter should be a dictionary indexed by
    host_name each entry should contain a list of the template ids that
    should be generated for that host.

    If the template list for a host is empty all available templates will be
    regenerated.
    If the dictionary is completely empty then all hosts will have their
    templates regenerated.

    If an entry in the dictionary contains the key "network" it will be
    interpreted as a list of network wide templates to regenerate. If this key
    is absent then the network wide templates will be regenerated if the number
    of host templates being regenerated is greater than one.

    All template processing is shunted off to another thread and the user is
    returned a token that can be passed to future calls to getTemplateStatus
    to retrieve the current status of template generation. Generation results
    are stored for 30 minutes after the end of template generation.
    """
    global _templateStats, _statsLock
    from modules.ccs_host import getHostList

    # Load the templates
    networkTemplates, hostTemplates = initTemplates()

    # Setup the basic set of statistics about template generation
    stats = {}
    stats["planned"] = {}
    stats["generated"] = {}
    stats["skipped"] = {}
    stats["initiated"] = time.time()
    stats["setupprogress"] = 10
    stats["generating"] = 0
    stats["finished"] = 0
    stats["error"] = None

    # Work out what the user has requested us to generate
    hosts = {}
    host_names = requested_templates.keys()
    if len(host_names) == 0:
        host_names = [host["host_name"] for host in getHostList(session_id)]
    for host in host_names:
        if host == "network": continue
        templates = []
        if host in requested_templates.keys():
            templates = requested_templates[host]
        if len(templates) == 0:
            templates = hostTemplates.keys()
        hosts[host] = templates
    stats["planned"]["hosts"] = hosts
    stats["generated"]["hosts"] = {}
    stats["skipped"]["hosts"] = {}

    # Work out how many host templates we're going to be generating
    total = 0
    for tlist in hosts.values():
        total += len(tlist)
    stats["planned"]["total"] = total

    # Add network level templates if more than one host template is requested
    # or they have been explicitly specified
    if "network" in host_names:
        stats["planned"]["network"] = requested_templates["network"]
    elif total > 1:
        stats["planned"]["network"] = networkTemplates.keys()
    else:
        stats["planned"]["network"] = []
    stats["planned"]["total"] += len(stats["planned"]["network"])
    stats["generated"]["network"] = {}
    stats["skipped"]["network"] = {}

    # Aquire the lock to deal with statistics
    statsKey = token = createPassword(8)
    _statsLock.acquire()
    try:
        _templateStats[statsKey] = stats
    finally:
        _statsLock.release()

    # Fire off the new thread
    initThread(processTemplates, session_id, statsKey, networkTemplates,
            hostTemplates)

    # Return back to the user
    return statsKey

@registerEvent("revisionPrepared")
def processTemplates(session_id, statsKey, networkTemplates, hostTemplates):
    """Does the hardwork of generating templates in a thread"""
    global _templateStats, _statsLock, _threadLimit
    from modules.ccs_host import getHostList, ccs_host, \
            getDistributions
    from _utils.pcsd_service import getServiceTemplateVars
    from modules.ccs_asset import getAssetTypeTemplateVariables
    from modules.ccs_link import getLinkClassTemplateVariables, \
            getLinkTemplateVariables
    try:
        session = getSessionE(session_id)
        log_info("Entered template processing thread (%s)" % statsKey)
        ct = threading.currentThread()
        ct.setName("%s: processTemplates" % session.username)

        # Make sure we have a revision to insert files into
        # Check session to see if a revision is active
        commit=0
        if session.revision == None:
            session.begin("Updated host configuration files", initiator="cfengine")
            commit=1
        outputDir = session.revision.getConfigBase()

        # More progress
        _statsLock.acquire()
        try:
            _templateStats[statsKey]["setupProgress"] = 15
        finally:
            _statsLock.release()

        # Load all the data that we need to pass to the templates
        variables = {}
        hlist = {}
        id2name = {}
        for host in getHostList(session_id):
            host = ccs_host(session_id, host["host_id"])
            hostDetails = host.getTemplateVariables()
            hlist[host["host_name"]] =  hostDetails
            _statsLock.acquire()
            try:
                if _templateStats[statsKey]["setupProgress"] < 70:
                    _templateStats[statsKey]["setupProgress"] += 2
            finally:
                _statsLock.release()
        variables["hosts"] = hlist
        dlist = {}
        for distrib in getDistributions(session_id):
            dlist[distrib["distribution_id"]] = distrib
        variables["distributions"] = dlist
        variables["services"] = getServiceTemplateVars(session_id)
        _statsLock.acquire()
        try:
            _templateStats[statsKey]["setupProgress"] = 80
        finally:
            _statsLock.release()
        variables["date"] = time.ctime()
        variables["domain"] = config_get_required("network", "domain")
        variables["site_name"] = config_get_required("network", "site_name")
        variables["port"] = int(config_get(None, "https_port", DEFAULT_HTTPS_SERVER_PORT))
        variables["server_name"] = config_get_required("network", "server_name")
        ip = getIP(variables["server_name"])
        variables["policy_ip"] = ip
        variables["policy_ip_class"] = ip.replace(".", "_")
        variables["smtp_server"] = config_get_required("network", "smtp_server")
        variables["admin_email"] = config_get_required("network", "admin_email")
        variables["dbhost"] = pcsd_session.dhost
        variables["dbuser"] = pcsd_session.duser
        variables["dbpass"] = pcsd_session.dpass
        variables["dbname"] = pcsd_session.database
        _statsLock.acquire()
        try:
            _templateStats[statsKey]["setupProgress"] = 90
        finally:
            _statsLock.release()

        variables["asset_types"] = getAssetTypeTemplateVariables(session_id)
        variables["link_classes"] = getLinkClassTemplateVariables(session_id)
        variables["links"] = getLinkTemplateVariables(session_id)
        variables["session_id"] = session_id

        # Update the stats and get the list of hosts
        _statsLock.acquire()
        try:
            planned = _templateStats[statsKey]["planned"]
            _templateStats[statsKey]["generating"] = time.time()
            _templateStats[statsKey]["setupProgress"] = 100
        finally:
            # Release the lock before proceeding
            _statsLock.release()

        # Now generate each hosts template in a separate thread
        for host,template_ids in planned["hosts"].items():
            # See if we can start a new thread
            _threadLimit.acquire()
            try:
                # Extract the host specific data for this template
                hostData = variables["hosts"][host]
                # Fire off the thread to process this host, the thread will release
                # the semaphore as it is about to exit
                # XXX: This relies on the thread behaving nicely, need to find a
                # way to find out if it's been bad and exited without releasing
                # the semaphore
                initThread(processHostTemplates, statsKey, outputDir, \
                        hostTemplates, hostData, variables)
            except:
                log_error("Failed to start thread to process templates for " \
                        "host: %s!" % host, sys.exc_info())
                _threadLimit.release()

        # Wait until all the configuration files have been generated
        hosts = list(planned["hosts"].keys())
        hasError = False
        hasTemplateError = False
        while len(hosts) > 0:
            # Wait a bit before trying again
            time.sleep(1)
            _statsLock.acquire()
            try:
                generated = _templateStats[statsKey]["generated"]["hosts"]
                for host in hosts:
                    if not host in generated.keys():
                        continue
                    # Check if it finished successfully
                    if generated[host]["finished"] > 0:
                        # Remove from list
                        hosts.remove(host)
                        # Check if any of the templates failed to be output
                        if generated[host]["error"] == "template":
                            # Set the flag so we don't commit the revision
                            hasTemplateError = True
                    else:
                        # Check for fatal errors
                        if generated[host]["error"] != "":
                            # Set the flag and remove the host from processing
                            hosts.remove(host)
                            hasError = True
                            continue
            finally:
                _statsLock.release()

        # Hosts are done, network templates now
        for template_id in planned["network"]:
            # See if we can start a new thread
            _threadLimit.acquire()
            try:
                # Fire off the thread to process this template, the thread will
                # release the semaphore as it is about to exit
                # XXX: This relies on the thread behaving nicely, need to find a
                # way to find out if it's been bad and exited without releasing
                # the semaphore
                initThread(processNetworkTemplate, statsKey, outputDir, \
                        networkTemplates, template_id, variables)
            except:
                log_error("Failed to start thread to process network template: " \
                        "%s!" % template_id, sys.exc_info())
                _threadLimit.release()

        # Wait until all network templates are done
        network = list(planned["network"])
        while len(network) > 0:
            # Wait a bit before trying again
            time.sleep(1)
            _statsLock.acquire()
            try:
                generated = _templateStats[statsKey]["generated"]["network"]
                skipped = _templateStats[statsKey]["skipped"]["network"]
                for template in network:
                    if template in generated.keys():
                        # Check for errors
                        if generated[template]["error"] != "":
                            hasTemplateError = True
                    else:
                        if template not in skipped.keys():
                            continue
                    # Remove from the list
                    network.remove(template)
            finally:
                _statsLock.release()

        # Trigger an event to allow other modules to perform final config setup
        triggerEvent(session_id, "revisionPrepared", outputDir=outputDir)

        # Commit if neceesary and no template/host errors occured
        rv = {"revision":None}
        if commit and not (hasError or hasTemplateError):
            rv = session.commit()
        # All done
        _statsLock.acquire()
        try:
            _templateStats[statsKey]["finished"] = time.time()
            _templateStats[statsKey]["revision"] = rv["revision"]
            d = _templateStats[statsKey]["finished"] - \
                    _templateStats[statsKey]["initiated"]
            if hasError:
                _templateStats[statsKey]["error"] = "host"
            elif hasTemplateError:
                _templateStats[statsKey]["error"] = "template"
        finally:
            _statsLock.release()
            log_info("Template generation completed in %0.3f seconds for %s" % \
                (d, statsKey))
    except:
        info = sys.exc_info()
        log_error("Error processing templates", info)
        _statsLock.acquire()
        _templateStats[statsKey]["error"] = ''.join(traceback.format_exception( \
            *info)[-1:]).strip().replace('\n',': ')
        _templateStats[statsKey]["finished"] = 1
        _templateStats[statsKey]["generating"] = 0
        _statsLock.release()
        session.rollback()

    return True

def processHostTemplates(statsKey, outputDir, hostTemplates, hostData,
        networkData):
    """Runs in a thread and generates the output files for the template"""
    global _templateStats, _statsLock, _threadLimit
    host_id = -1
    host = "unknown"

    # It is imperative that we release the semaphore before returning from
    # this function or we could potentially starve the calling thread of
    # workers and we'd end up in a deadlock situation!
    try:
        # Work out the host_id and host_name of this host
        host_id = hostData["host_id"]
        host = hostData["host_name"]
        hostPath = "%s/hosts/%s" % (outputDir, host)
        start = time.time()
        log_debug("Started host generation thread for %s" % host)
        session = getSessionE(networkData["session_id"])
        ct = threading.currentThread()
        ct.setName("%s: processHostTemplates %s" % (session.username, host))

        # Retrieve the list of templates to generate and flag the start
        _statsLock.acquire()
        try:
            planned = _templateStats[statsKey]["planned"]
            generated = _templateStats[statsKey]["generated"]["hosts"]
            generated[host] = {}
            generated[host]["initiated"] = start
            generated[host]["finished"] = 0
            generated[host]["error"] = ""
        finally:
            _statsLock.release()

        # Now that we have a set of templates to use do the actual generation
        hadError = False
        for tname in planned["hosts"][host]:
            try:
                tstart = time.time()
                # Instantiate a template
                template = hostTemplates[tname]
                t = eval("template.%s()" % template.templateName)
                # Is it enabled on this host?
                if not t.enabledOnHost(networkData["session_id"], host_id):
                    continue
                # Set up the variables we want to substitute in
                t._searchList = [hostData, networkData]
                # Generate the file
                filename = "%s/%s" % (hostPath, template.fileName)
                files = t.writeTemplate(filename, template.multiFile)
                tend = time.time()
                # Set properties
                format = getattr(t, "highlightFormat", "")
                if format != "":
                    for file in files:
                        session.revision.propset(file, "pcs:format", format)
                # Record how long the file took to generate
                _statsLock.acquire()
                try:
                    info = {"time":tend-tstart, "error":""}
                    generated[host][tname] = info
                finally:
                    _statsLock.release()
            except:
                (type, value, tb) = sys.exc_info()
                # Single template errors can be skipped over, nothing will
                # get committed unless the user explicitly approves
                _statsLock.acquire()
                try:

                    info = {"time":0, "error":value}
                    generated[host][tname] = info
                finally:
                    _statsLock.release()
                hadError = True
                log_error("Failed to process template (%s) for host: %s" % \
                        (tname, host), (type, value, tb))

        # Clean up
        end = time.time()
        log_debug("Completed host generation for %s in %0.3f seconds" % \
                (host, (end-start)))
        _statsLock.acquire()
        try:
            generated[host]["finished"] = end
            # If a template failed make a note of it here
            if hadError:
                generated[host]["error"] = "template"
        finally:
            _statsLock.release()
    except:
        (type, value, tb) = sys.exc_info()
        # Record the error for display to the user
        _statsLock.acquire()
        try:
            generated = _templateStats[statsKey]["generated"]["hosts"]
            if host not in generated.keys():
                generated[host] = {}
                generated[host]["initiated"] = 0
            generated[host]["finished"] = time.time()
            generated[host]["error"] = value
        finally:
            _statsLock.release()
        # Log the error for the administrators record
        log_error("Exception while processing host templates (%s)!" % \
                host, (type, value, tb))

    # Release the semaphore
    _threadLimit.release()
    return

def processNetworkTemplate(statsKey, outputDir, networkTemplates,
        template_id, networkData):
    """Runs in a thread and generates the output files for the template"""
    global _templateStats, _statsLock, _threadLimit

    # It is imperative that we release the semaphore before returning from
    # this function or we could potentially starve the calling thread of
    # workers and we'd end up in a deadlock situation!
    try:
        log_debug("Started template generation thread for %s" % template_id)
        tstart = time.time()
        session = getSessionE(networkData["session_id"])
        ct = threading.currentThread()
        ct.setName("%s: processNetworkTemplates %s" % \
                (session.username, template_id))
        # Instantiate a template
        template = networkTemplates[template_id]
        t = eval("template.%s()" % template.templateName)
        # Is it enabled?
        if not t.enabledOnNetwork(networkData["session_id"]):
            _statsLock.acquire()
            try:
                skipped = _templateStats[statsKey]["skipped"]["network"]
                skipped[template_id] = True
            finally:
                _statsLock.release()
            _threadLimit.release()
            return
        # Set up the variables we want to substitute in
        t._searchList = [networkData]
        # Generate the file
        filename = "%s/%s" % (outputDir, template.fileName)
        files = t.writeTemplate(filename, template.multiFile)
        tend = time.time()
        # Set properties
        format = getattr(template, "highlightFormat", "")
        if format != "":
            for file in files:
                session.revision.propset(file, "pcs:format", format)
        # Record how long the file took to generate
        _statsLock.acquire()
        try:
            generated = _templateStats[statsKey]["generated"]["network"]
            info = {"time":tend-tstart, "error":""}
            generated[template_id] = info
        finally:
            _statsLock.release()
        log_debug("Completed template generation for %s in %0.3f seconds" \
                % (template_id, (tend-tstart)))
    except:
        (type, value, tb) = sys.exc_info()
        # Skip over the error, nothing will get committed unless the user
        # explicitly approves
        _statsLock.acquire()
        try:
            generated = _templateStats[statsKey]["generated"]["network"]
            info = {"time":0, "error":value}
            generated[template_id] = info
        finally:
            _statsLock.release()
        log_error("Failed to process network template (%s)" % template_id, \
                (type, value, tb))

    # Release the semaphore
    _threadLimit.release()
    return

#####################################################################
# Template Mixin
#####################################################################
class pcsd_template(Template):
    """Config System Template Processor

    All templates that expect to be processed by the configuration system
    must derive from this class. It provides helper functions that are required
    to determine where and when each template should be generated and how to
    store it to disk.
    """

    def __init__(self):
        """Initialise the class

        You must call this method from your subclass
        """
        # Call Cheetah's init
        Template.__init__(self)

    def writeTemplate(self, filename, multiFile):
        """Writes the template output to the specified file"""

        files = []

        # Ensure the output directory exists
        ensureDirExists(os.path.dirname(filename))

        # Get the template contents
        self._CHEETAH__searchList += self._searchList
        template = self.writeBody().strip()
        if not template.endswith("\n"): template += "\n"

        # Write it out to a file
        if not multiFile:
            f = open(filename, "w")
            f.write(template)
            f.close()
            files.append(filename)
        else:
            # Handle templates that generate multiple output files
            lines = template.split("\n")
            f = None
            for line in lines:
                if line.startswith(".newfile"):
                    # New file starting, close previous file
                    if f is not None: f.close()
                    # Open new file
                    parts = line.split(" ")
                    if len(parts) != 2:
                        raise pcsd_template_error("Invalid multifile template!")
                    fname = "%s%s" % (filename, parts[1])
                    f = open(fname, "w")
                    files.append(fname)
                    continue
                elif f is not None:
                    # Write the line out
                    f.write("%s\n" % line)
            # Close the file
            if f is not None: f.close()

        return files

    def __str__(self):
        return self.writeBody()

    def enabledOnHost(self, session_id, host_id):
        """Returns true if the template is applicable to the specified host

        By default this method looks to see if the template has defined a
        serviceName parameter. If it has then the function checks to see if
        that service is enabled on the specified host. If it is not the
        function returns False.

        This function may be overriden by other classes/templates if you want
        to implement more logic than the default implementation provides.
        """
        serviceName = getattr(self, "serviceName", None)
        if serviceName is None:
            return True

        from modules.ccs_host import ccs_host
        host = ccs_host(session_id, host_id)
        return host.hasServiceEnabledByName(serviceName)

    def enabledOnNetwork(self, session_id):
        """Returns true if the template is able to be processed

        By default this method looks to see if the template has defined a
        serviceName parameter. If it has then the function checks to see if
        that service is enabled. If it is not the function returns False.

        This function may be overriden by other classes/templates if you want
        to implement more logic than the default implementation provides.
        """
        serviceName = getattr(self, "serviceName", None)
        if serviceName is None:
            return True

        try:
            service = getServiceInstance(session_id, serviceName)
        except ccs_service_error:
            # Named service not known
            return False
        return service.getState()

    def getTemplateVariables(self):
        """Returns a dictionary of variables that can be used by the template

        The dictionary is passed to Cheetah's searchList so that it's entries
        can be used as placeholders in the template.

        This function retains an empty list. You should override this in your
        implementing class.
        """
        return []

