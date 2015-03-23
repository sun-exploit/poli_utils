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
from pcsd_service import getServiceInstance, pcsd_service_error

class pcsd_template_error(pcsd_error):
    pass

#####################################################################
# General Cfengine Integration Helper Functions
#####################################################################
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

        from modules.pcs_host import pcs_host
        host = pcs_host(session_id, host_id)
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
        except pcsd_service_error:
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

