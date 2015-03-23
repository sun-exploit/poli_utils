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

import svn.core as core
import svn.client as client
import svn.wc as wc
import svn.fs as fs
import svn.repos as repos

import time
import threading
from tempfile import mkdtemp

from pcsd_common import *
from pcsd_log import *
from pcsd_events import *
from pcsd_config import config_get, config_get_required, \
        config_getint

KIND_DIR = core.svn_node_dir
KIND_FILE = core.svn_node_file
KIND_NONE = core.svn_node_none
KIND_UNKNOWN = core.svn_node_unknown
KIND_MAP = {KIND_DIR:"dir", KIND_FILE:"file", KIND_NONE:"none", \
        KIND_UNKNOWN:"unknown"}

class pcsd_svn_error(pcsd_error):
    pass

pcs_utils_type = PCSD_EXT

#####################################################################
# Functions to maintain / deal with checked out configs
#####################################################################
def updateSVNDirectory(svnroot, path, revNum=-1):
    """Ensures that the specified path contains the specified revision from
    svnroot checked out in it
    """

    # Get a python memory pool and context to use
    pool = core.svn_pool_create(None)
    ctx = client.svn_client_ctx_t()
    ctx.config = core.svn_config_get_config(None, pool)

    # Work out which revision to update to
    rev = core.svn_opt_revision_t()
    if revNum == -1:
        rev.kind = core.svn_opt_revision_head
    else:
        rev.kind = core.svn_opt_revision_number
        rev.value.number = int(revNum)

    # See if there is a checked out revision
    gotrev = 0
    try:
        list = client.svn_client_ls(path, rev, False, ctx, pool)
        gotrev = 1
    except:
        log_error("Unable to access svn base checkout!")
        raise pcsd_svn_error("Cannot access svn base checkout!")

    if gotrev:
        # Update the directory
        nrev = client.svn_client_update(path, rev, True, ctx, pool)
    else:
        # Checkout the directory
        nrev = client.svn_client_checkout(svnroot, path, rev, True, ctx, pool)

    # Get rid of the pool
    core.svn_pool_destroy(pool)
    del pool
    del ctx

    return nrev

#####################################################################
# Revision Class
#####################################################################
class pcsd_svn:
    """Wrapper for a svn revision of files.

    This class wraps the generation of an entire revision of the configuration
    files managed by this system.

    It contains the methods needed to generate the files, insert them into
    version control (svn) and then update then pass the resulting revision
    identifier back to it's caller.
    """

    # Location of the svnroot
    svnroot = None

    def __init__(self, parentSession=None, changeset=None, checkout=True):
        """Creates a pcsd_svn class.

        If parentSession or changeset are not specified or None, a read-only
        revision is created. This is only useful if you want to inspect the
        repository without making any changes.
        """

        self.mParentSession = parentSession
        self.mChangeset = changeset
        self.checkout = checkout
        self.pendingProps = {}
        self.lock = threading.RLock()
        self._revinfocache = {}
        self._needsCommit = False

        # Get a python memory pool and context to use
        self.pool = core.svn_pool_create(None)
        self.ctx = client.svn_client_ctx_t()
        self.ctx.config = core.svn_config_get_config(None, self.pool)

        if self.checkout:
            # Setup a working directory for this revision
            self.rDir = mkdtemp("", "pcsd")

            # Checkout the current configuration HEAD to this directory
            rev = core.svn_opt_revision_t()
            rev.kind = core.svn_opt_revision_head
            client.svn_client_checkout(self.svnroot, self.rDir, rev, \
                    True, self.ctx, self.pool)
            self.mCurRev = rev

            # Check basic repository structure
            if self.mParentSession is not None and self.mChangeset is not None:
                self.checkRepoStructure()
        else:
            self.rDir = None
            self.mCurRev = None

        # Start with no errors
        self.mErrors = {}

    def __del__(self):

        # Nothing to check if nothing was checked out
        if self.rDir is None:
            core.svn_pool_destroy(self.pool)
            self.pool = None
            self.ctx = None
            return

        # Don't check the status of a read-only revision
        if self.mParentSession is None or self.mChangeset is None:
            removeDir(self.rDir)
            core.svn_pool_destroy(self.pool)
            self.pool = None
            self.ctx = None
            return

        # Callback function to process status information
        def status_cb(epath, entry):
            try:
                if entry.text_status == wc.svn_wc_status_ignored:
                    pass
                elif entry.text_status != wc.svn_wc_status_normal:
                    log_debug("Changes (%s) to %s in changeset %s will " \
                            "be lost" % \
                            (entry.text_status, epath, self.mChangeset))
            except:
                log_error("Failed to check status of %s" % epath, \
                        sys.exc_info())

        # Check the status
        self.flag = False
        self.lock.acquire()
        try:
            client.svn_client_status(self.rDir, self.mCurRev, status_cb, \
                    True, True, False, False, self.ctx, self.pool)
        finally:
            self.lock.release()

        # Clean up the working directory
        removeDir(self.rDir)
        core.svn_pool_destroy(self.pool)
        self.pool = None
        self.ctx = None

    def getWorkingDir(self):
        """Returns the path that the repository is checked out into"""

        return self.rDir

    def getConfigBase(self):
        """Returns the path that svn config files should live in"""
        if self.rDir is None:
            return None
        return "%s/inputs" % self.rDir

    def _getFsPtr(self):
        # Strip scheme from URL
        path = self.svnroot[self.svnroot.find("://")+3:]
        rep = repos.svn_repos_open(path, self.pool)
        fs_ptr = repos.svn_repos_fs(rep)
        return fs_ptr

    def _checkForModified(self, cDir, recursed=False):
        """Performs svn actions on changed files in the specified directory"""
        # Nothing to check if no repository is checked out
        if self.rDir is None:
            return

        # Don't check the status of a read-only revision
        if self.mParentSession is None or self.mChangeset is None:
            log_warn("Cannot check status on a read-only revision!")
            return

        if not recursed:
            self._needsCommit = False

        # Recurse through if we were passed a list
        if type(cDir) == type([]):
            for d in cDir:
                self._checkForModified(d)
            return

        self.lock.acquire()
        try:
            # Callback function to process status information
            def status_cb(epath, entry):
                # Check the text of the entry
                if entry.text_status == wc.svn_wc_status_unversioned:
                    if epath.startswith(self.rDir):
                        ename = epath[len(self.rDir)+1:]
                    log_debug("Added %s in changeset %s" % \
                            (ename, self.mChangeset))
                    client.svn_client_add(epath, False, self.ctx, self.pool)
                    self._needsCommit = True
                    # Recurse if we added a directory
                    if os.path.isdir(epath):
                        self._checkForModified(epath)
                    else:
                        # Ensure the date property is set on files
                        self.propset(epath, "svn:keywords", "Date")
                        # Check if there are any other pending properties to
                        # set
                        path = epath
                        if path in self.pendingProps.keys():
                            for prop,value in self.pendingProps[path].items():
                                self.propset(path, prop, value, False)
                elif entry.text_status == wc.svn_wc_status_modified or \
                        entry.text_status == wc.svn_wc_status_added or \
                        entry.text_status == wc.svn_wc_status_deleted or \
                        entry.text_status == wc.svn_wc_status_replaced or \
                        entry.text_status == wc.svn_wc_status_merged:
                    self._needsCommit = True
                elif entry.text_status == wc.svn_wc_status_ignored:
                    # Ignore it!
                    pass
                elif entry.text_status != wc.svn_wc_status_normal:
                    log_debug("%s (%s) has bad state in changeset %s!" % \
                            (epath, entry.text_status, self.mChangeset))
                # Now look at the properties of the entry
                if entry.prop_status == wc.svn_wc_status_modified or \
                        entry.prop_status == wc.svn_wc_status_added or \
                        entry.prop_status == wc.svn_wc_status_deleted or \
                        entry.prop_status == wc.svn_wc_status_replaced or \
                        entry.prop_status == wc.svn_wc_status_merged:
                    self._needsCommit = True
                # Ensure that pcs-revision files are always ignored
                if os.path.isdir(epath):
                    if not self.hasIgnore(epath, "pcs-revision"):
                        self.propadd(epath, "svn:ignore", "pcs-revision")
                        self._needsCommit = True

            # Check the status
            client.svn_client_status(cDir, self.mCurRev, status_cb, \
                    True, True, False, False, self.ctx, self.pool)
        finally:
            self.lock.release()

    def propadd(self, path, prop, value, canDefer=True, sep="\n"):
        """Adds the specified value to the property on the specified path"""

        # Use the svn repo directly if nothing is checked out
        if self.rDir is None:
            base = self.svnroot
        else:
            base = self.rDir

        try:
            if not path.startswith(base):
                filename = "%s/%s" % (base, path)
            else:
                filename = path
            filename = filename.rstrip("/")
            self.lock.acquire()
            try:
                rev = core.svn_opt_revision_t()
                rev.kind = core.svn_opt_revision_head
                eprop = client.svn_client_propget(prop, filename, rev, False, \
                        self.ctx, self.pool)
                if eprop == {}:
                    # No existing property set
                    self.propset(path, prop, value, canDefer)
                else:

                    existing = str(eprop.values()[0]).strip()
                    self.propset(path, prop, \
                            "%s%s%s" % (existing, sep, value), canDefer)
            finally:
                self.lock.release()
        except:
            log_error("Could not add '%s' to %s on %s" % \
                    (value, prop, filename), sys.exc_info())

    def propset(self, path, prop, value, canDefer=True):
        """Sets the specified property on the specified path"""

        if self.mParentSession is None or self.mChangeset is None:
            raise pcsd_svn_error("Cannot set property on read-only " \
                    "revision")

        # Use the svn repo directly if nothing is checked out
        if self.rDir is None:
            base = self.svnroot
        else:
            base = self.rDir

        try:
            if not path.startswith(base):
                filename = "%s/%s" % (base, path)
            else:
                filename = path
            filename = filename.rstrip("/")
            self.lock.acquire()
            try:
                client.svn_client_propset(prop, value, filename, False, \
                        self.pool)
            finally:
                self.lock.release()
        except core.SubversionException:
            # Add to a list of pending properties that we'll try and set on
            # commit after adding the file. This covers the case where a
            # caller tries to set a property on an as yet unversioned file
            if filename in self.pendingProps.keys():
                self.pendingProps[filename][prop] = value
            else:
                self.pendingProps[filename] = {prop:value}
            log_debug("Deferred propset on %s" % filename, sys.exc_info())
        except:
            log_error("Could not set %s to '%s' on %s" % \
                    (prop, value, filename), sys.exc_info())

    @registerEvent("revisionCreated")
    def checkin(self, message, paths=None):
        """Checks in the changes to the repository with the specified message"""
        if self.rDir is None:
            raise pcsd_svn_error("Cannot checkin. Not checked out!")

        if self.mParentSession is None or self.mChangeset is None:
            raise pcsd_svn_error("Cannot checkin a read-only revision")

        # Default to the whole repository
        if paths is None:
            paths = [self.rDir]
        if type(paths) != type([]):
            paths = [paths]
        log_debug("%s::%s : paths=[%s]" % (__name__, 'checkin', ", ".join(paths)))

        # Check status of working directory and add / del files etc
        self._checkForModified(paths)
        if not self._needsCommit:
            # Nothing changed
            return -1

        try:
            self.lock.acquire()
            try:
                # Run cleanup on any directories in the set to clear locks
                # Our lock above ensures that there should be no legitimate
                # WC locks at this point
                for path in paths:
                    if not os.path.isdir(path): continue
                    client.svn_client_cleanup(path, self.ctx, self.pool)
                # Commit
                i = client.svn_client_commit(paths, False, self.ctx, self.pool)
                if i.revision < 0:
                    return -1
                n = self.saveRevProps(i.revision, message)
            finally:
                self.lock.release()
        except:
            log_error("Could not commit revision", sys.exc_info())
            return -1

        if n<0:
            # Nothing changed
            return -1

        if self.mParentSession:
            triggerEvent(self.mParentSession.session_id, "revisionCreated", \
                    revision_no=n)
        log_info("Committed revision %s to version control" % i.revision)

        return n

    def saveRevProps(self, r, message=""):
        """Saves customised properties against each revision

        These properties are used to help keep track of how the database/svn
        repository changes match up.
        """

        if r is None:
            # Nothing changed
            return -1

        rev = core.svn_opt_revision_t()
        rev.kind = core.svn_opt_revision_number
        rev.value.number = int(r)

        # Set the log message if specified
        if message != "":
            try:
                self.lock.acquire()
                try:
                    client.svn_client_revprop_set("svn:log", message, \
                            self.svnroot, rev, False, self.ctx, self.pool)
                finally:
                    self.lock.release()
            except:
                (type, value, tb) = sys.exc_info()
                log_warn("Could not set log property on revision %s - %s" % \
                        (r, value), (type, value, tb))

        # Set the author property on the checkin
        try:
            self.lock.acquire()
            try:
                client.svn_client_revprop_set("svn:author", \
                        str(self.mParentSession.username), self.svnroot, rev, \
                        False, self.ctx, self.pool)
            finally:
                self.lock.release()
        except:
            (type, value, tb) = sys.exc_info()
            log_warn("Could not set author property on revision %s - %s" % \
                    (r, value), (type, value, tb))

        # Record the changeset that triggered this revision
        try:
            self.lock.acquire()
            try:
                client.svn_client_revprop_set("pcs:changeset", "%s" % \
                        self.mChangeset, self.svnroot, rev, \
                        False, self.ctx, self.pool)
            finally:
                self.lock.release()
        except:
            (type, value, tb) = sys.exc_info()
            log_warn("Could not set changeset property on " \
                    "revision %s - %s" % (r, value), (type, value, tb))

        return r

    def fileExists(self, path):
        """Checks if the specified file exists in the repository"""

        # Use the svn repo directly if nothing is checked out
        if self.rDir is None:
            base = self.svnroot
        else:
            base = self.rDir

        try:
            if not path.startswith(base):
                filename = "%s/%s" % (base, path)
            else:
                filename = path
            filename = filename.rstrip("/")
            self.lock.acquire()
            try:
                rev = core.svn_opt_revision_t()
                rev.kind = core.svn_opt_revision_head
                e = client.svn_client_ls(filename, rev, False, \
                        self.ctx, self.pool)
            finally:
                self.lock.release()
            if len(e) > 0:
                return True
        except core.SubversionException:
            (type, value, tb) = sys.exc_info()
            if value[0].find("non-existent") == -1:
                log_warn("%s::%s : Failed to check existance of file: [%s]" \
                        % (__name__, 'fileExists', filename), (type, value, tb))
            return False
        except:
            log_warn("Failed to check existance of file: %s" % filename, \
                    sys.exc_info())
            return False

        return False

    def revinfo(self, revno):
        if revno in self._revinfocache.keys():
            return self._revinfocache[revno]

        self.lock.acquire()
        try:
            rev = core.svn_opt_revision_t()
            rev.kind = core.svn_opt_revision_number
            rev.value.number = int(revno)
            props = client.svn_client_revprop_list(self.svnroot, rev, \
                    self.ctx, self.pool)
        finally:
            self.lock.release()
        if len(props) != 2:
            return {}
        info = {}
        info["number"] = props[1]
        for prop,value in props[0].items():
            info[prop.strip("svn:")] = str(value)
        self._revinfocache[revno] = info
        return info

    def copy(self, oldpath, newpath):
        """Moves the specified file from the oldpath to the newpath"""

        # Use the svn repo directly if nothing is checked out
        if self.rDir is None:
            base = self.svnroot
        else:
            base = self.rDir

        try:
            if not oldpath.startswith(base):
                oldname = "%s/%s" % (base, oldpath)
            else:
                oldname = oldpath
            if not newpath.startswith(base):
                newname = "%s/%s" % (base, newpath)
            else:
                newname = newpath
            oldname = oldname.rstrip("/")
            newname = newname.rstrip("/")
            self.lock.acquire()
            try:
                rev = core.svn_opt_revision_t()
                rev.kind = core.svn_opt_revision_head
                e = client.svn_client_copy(oldname, rev, newname, \
                        self.ctx, self.pool)
            finally:
                self.lock.release()
            return True
        except:
            log_warn("Could not move file: %s => %s" % (oldpath, newpath),
                    sys.exc_info())

        return False

    def ls(self, path, revno=None):
        """Returns a list of entries in the specified directory"""

        # Use the svn repo directly if nothing is checked out
        if self.rDir is None:
            base = self.svnroot
        else:
            base = self.rDir

        try:
            if not path.startswith(base):
                filename = "%s/%s" % (base, path)
            else:
                filename = path
            filename = filename.rstrip("/")
            self.lock.acquire()
            try:
                if revno is None or revno=="":
                    rev = core.svn_opt_revision_t()
                    rev.kind = core.svn_opt_revision_head
                else:
                    rev = core.svn_opt_revision_t()
                    rev.kind = core.svn_opt_revision_number
                    rev.value.number = int(revno)
                e = client.svn_client_ls(filename, rev, False, self.ctx, \
                        self.pool)
            finally:
                self.lock.release()
            if len(e) > 0:
                if revno is None:
                    revno = self.getYoungestRevision()
                entries = []
                for entry,details in e.items():
                    t = {}
                    if path.endswith(entry):
                        t["name"] = "%s/%s" % (os.path.dirname(path), entry)
                    else:
                        t["name"] = "%s/%s" % (path, entry)
                    t["created_rev"] = self.revinfo(details.created_rev)
                    t["kind"] = details.kind
                    t["last_author"] = details.last_author
                    t["size"] = details.size
                    t["time"] = details.time/1000000
                    entries.append(t)
                return (revno, entries)
        except:
            log_warn("Could not list directory: %s" % filename, sys.exc_info())

        return (-1, [])

    def getYoungestRevision(self, path=""):
        """Returns the number of the youngest revision in the repository"""
        revno = -1

        try:
            self.lock.acquire()
            try:
                # Strip scheme from URL
                fs_ptr = self._getFsPtr()
                revno = fs.youngest_rev(fs_ptr, self.pool)
            finally:
                self.lock.release()
        except:
            log_warn("Could not determine youngest revision", sys.exc_info())

        return revno

    def getLog(self, revno):
        """Returns the log message for the specified revision"""
        log = ""

        def rcvMessage(a,b,c,d,msg,f):
            log = msg.strip()

        try:
            self.lock.acquire()
            try:
                rev = core.svn_opt_revision_t()
                rev.kind = core.svn_opt_revision_number
                rev.value.number = int(revno)
                client.svn_client_log([self.svnroot], rev, rev, False, \
                        False, nmsg, self.ctx, self.pool)
            finally:
                self.lock.release()
        except:
            log_warn("Could not retrieve log for revision %s" % revno, \
                    sys.exc_info())

        return log

    def getFile(self, path, revno=None):
        """Returns the contents of the file at the specified path and rev"""

        # Use the svn repo directly if nothing is checked out
        if self.rDir is None:
            base = self.svnroot
        else:
            base = self.rDir

        try:
            if path.startswith(base):
                filename = path[len(base)+1:]
            else:
                filename = path
            filename = filename.rstrip("/")
            self.lock.acquire()
            try:
                if revno is None or revno=="":
                    revno = self.getYoungestRevision()
                else:
                    revno = int(revno)
                fs_ptr = self._getFsPtr()
                root = fs.revision_root(fs_ptr, revno, self.pool)
                s = core.Stream(fs.file_contents(root, filename, self.pool))
                contents = s.read()
            finally:
                self.lock.release()
            return contents
        except:
            log_warn("Could not retrieve file: %s" % filename, sys.exc_info())

        return ""

    def getProps(self, path, revno=None):
        """Returns the properties set on the specified file"""

        # Use the svn repo directly if nothing is checked out
        if self.rDir is None:
            base = self.svnroot
        else:
            base = self.rDir

        try:
            if not path.startswith(base):
                filename = "%s/%s" % (base, path)
            else:
                filename = path
            filename = filename.rstrip("/")
            self.lock.acquire()
            try:
                if revno is None or revno=="":
                    rev = core.svn_opt_revision_t()
                    rev.kind = core.svn_opt_revision_head
                else:
                    rev = core.svn_opt_revision_t()
                    rev.kind = core.svn_opt_revision_number
                    rev.value.number = int(revno)
                contents = client.svn_client_proplist(filename, rev, \
                        False, self.ctx, self.pool)
            finally:
                self.lock.release()
            if len(contents) > 0:
                props = {}
                for prop,value in contents[0][1].items():
                    props[prop] = str(value)
                return props
        except:
            log_warn("Could not retrieve properties: %s" % \
                    filename, sys.exc_info())

        return {}

    def hasIgnore(self, path, value):
        """Checks whether the specified ignore value is set on the path"""
        try:
            props = client.svn_client_proplist(path, self.mCurRev, \
                    False, self.ctx, self.pool)
        except:
            return False
        if len(props)<1:
            return False

        (path, pdict) = props[0]
        if "svn:ignore" not in pdict.keys():
            return False
        if str(pdict["svn:ignore"]).find(value) == -1:
            return False

        return True

    def checkRepoStructure(self):
        """Checks the repository has all the required base directories.

        If a base directory is not present it is created. The base directories
        are:
        inputs/        Host/Service configuration files

        Further hierarchy within each base directory is the responsibility of
        other modules.
        """

        if self.rDir is None:
            raise pcsd_svn_error("Cannot check repository structure. " \
                    "Not checked out!")

        if self.mParentSession is None or self.mChangeset is None:
            log_warn("Cannot check repository structure on a read-only " \
                    "revision")
            return

        flag = 0

        configsDir = self.getConfigBase()
        n = ensureDirExists(configsDir)
        self.lock.acquire()
        try:
            if n > 0:
                # Schedule Additions
                bDir = configsDir
                while n>1:
                    bDir = os.path.dirname(configsDir)
                    n-=1
                log_info("Created configuration directory (%s) within " \
                        "repository" % configsDir)
                client.svn_client_add(bDir, False, self.ctx, self.pool)
                flag = 1

            # Commit directory changes immediately
            if flag==1:
                self.checkin("checkRepoStructure created missing directories")
                #i = client.svn_client_commit([self.rDir], False, self.ctx, \
                #        self.pool)
                #self.saveRevProps(i.revision, \
                #        "checkRepoStructure created missing directories")
        finally:
            self.lock.release()

        # Check for the script that updates the pcs-revision files
        filename = "%s/update-revisioninfo" % configsDir
        docreate=False
        doupdate=False
        if not os.path.exists(filename):
            docreate=True
        else:
            contents = file(filename, "r").read()
            if contents.find("svn info") == -1:
                doupdate = True
        if docreate or doupdate:
            self.lock.acquire()
            try:
                # Create the script
                fp = open(filename, "w")
                fp.write("""#!/bin/bash
echo "Updating version information"
for d in `find $1 -type d | grep -v ".svn" | xargs`; do
    version=`svn info $d/* | grep "Last Changed Rev" | awk '{print $4}' | sort -nr | head -n1`
    echo "  $d -> $version"
    echo "$version" > $d/pcs-revision
done
# vim:set sw=4 ts=4 sts=4 et:
""")
                fp.close()
                if docreate:
                    client.svn_client_add(filename, False, self.ctx, self.pool)
                    action = "Created"
                else:
                    action = "Updated"
                i = client.svn_client_commit([self.rDir], False, self.ctx, \
                        self.pool)
                self.saveRevProps(i.revision, \
                        "%s update-revisioninfo script" % action)
            finally:
                self.lock.release()

def validateRepository(svnroot):
    """Checks for the existance of a valid svn repository at svnroot"""

    # Extract the path from the URL
    svnpath = svnroot[svnroot.find("://")+3:]
    # Check directory exists
    if not os.path.exists(svnpath):
        log_debug("Specified repository path does not exist: %s" % svnpath)
        return False

    # Check it looks a bit like a subversion repository
    #if not os.path.exists():
    #    return False
    try:
        fp = open("%s/README.txt" % svnpath, "r")
    except:
        log_debug("No README.txt inside repository: %s" % svnpath)
        return False
    if not fp:
        log_debug("No README.txt inside repository: %s" % svnpath)
        return False
    tmp = fp.read().strip()
    fp.close()
    if not tmp.startswith("This is a Subversion repository"):
        log_debug("invalid README.txt in repository: %s" % svnpath)
        return False

    # Final, master check, can we check it out, instantiate a revision class
    revision = pcsd_svn(None, None, True)
    del revision

    # All OK
    return True

def createRepository(svnroot):
    """Initialises a blank repository and configures it for use by pcsd"""

    # Look for the svnadmin utility
    fd = os.popen("/usr/bin/which svnadmin 2>/dev/null")
    path = fd.read().strip()
    if fd.close() != None:
        log_error("Cannot find svnadmin utility.")
        return False

    # Check we can execute the svnadmin utilty
    if not os.access(path, os.X_OK):
        log_error("Cannot execute svnadmin utility.")
        return False

    # Try and create the repository
    svnpath = svnroot[svnroot.find("://")+3:]
    fd = os.popen("%s create --fs-type fsfs %s 2>&1" % (path, svnpath))
    result = fd.read().strip()
    if fd.close() != None:
        log_error("svnadmin create failed. See tb log for more details.")
        log_tb(None, result)
        return False

    # Add a pre-revprop-change hook to allow the daemon to set author
    # revision properties
    hook = "%s/hooks/pre-revprop-change" % svnpath
    fd = open(hook, "w")
    if not fd:
        log_warning("Unable to setup pre-revprop-change hook in new " \
                "repository!")
    else:
        fd.write("""#!/bin/bash

# PRE-REVPROP-CHANGE HOOK

# Created by the Poli Configuration System Daemon on
# %s

# Allow all changes at this time
exit 0
""" % time.ctime())
        fd.close()
        os.chmod(hook, 0755)

    # Success
    log_info("Subversion repository created at %s" % svnpath)
    return True

