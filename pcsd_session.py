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
#   This file contains common code used throughout the system and extensions
#   - Constant values
#   - Small helper functions
#   - Base classes
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
from pcsd_common import *
from pcsd_log import *
from pcsd_config import config_get, config_getboolean
from pcsd_events import catchEvent
from pcsd_server import pcsd_xmlrpc, exportViaXMLRPC
from version import pcsd_version
import pgdb
#from pyPgSQL import PgSQL
from mx import DateTime

import sys
import time
import crypt
import threading

# A list of tables that are regarded as system tables. These are excluded
# from the standard revision history stuff
SYSTEM_TABLES = [ "sessions", "cookies", "changeset", "first_login" ]

class pcsd_session_error(pcsd_error):
    pass

#####################################################################
# Session Class
#####################################################################
class pcsd_session:
    """Wrapper for a session.

    Maintains a database connection and tracks changesets/transactions.

    """

    # Log database query timings
    log_times = False

    # Currently active sessions
    sessions = {}

    timeout = config_get("session", "timeout", DEFAULT_SESSION_TIMEOUT)
    cookie_timeout = config_get("session", "cookie_timeout", \
            DEFAULT_COOKIE_TIMEOUT)

    def __init__(self, login_id, mode, token="", initiated=-1, expires=-1, \
            sid=-1):

        self.login_id = login_id
        self.mode = mode
        self.lock = threading.RLock()
        self.db = None

        # Session Time Records
        if initiated == -1:
            self.initiated = time.time()
        else:
            self.initiated = initiated
        if expires == -1:
            self.expires = time.time() + (self.timeout*60)
        else:
            self.expires = expires

        # Create a session token
        if token == "":
            self.token = createPassword(8)
        else:
            self.token = token

        # Setup a database connection
        log_info("Setup a database connection for %s" % (self.login_id))
        self._connect()

        # Setup session in the database
        if sid==-1:
            # Use the admin session to create this sessions record
            session = getSession(ADMIN_SESSION_ID)
            if session is None:
                raise pcsd_session_error("No admin session!")
            sql = "INSERT INTO sessions (login_id, mode, token, initiated, " \
                    "expires) VALUES (%s, %s, %s, %s, %s)"
            res = session.execute(sql, (self.login_id, self.mode, \
                    self.token, time.ctime(self.initiated), \
                    time.ctime(self.expires)))

            sql = "SELECT currval('sessions_sid_seq') as sid"
            res = session.query(sql, ())
            if res == -1:
                raise pcsd_session_error("Unable to allocate session ID")

            # Save session id
            self.session_id = res[0]["sid"]
        else:
            self.session_id = sid

        #Find my username
        if login_id == 'admin':
            self.username = 'admin'
        else:
            sql = "SELECT username, domain FROM logins where login_id=%s"
            res =  self.query(sql, (self.login_id))[0]
            self.username = "%s@%s" % (res['username'], res['domain'])

        # No changeset or revision active initially
        self.changeset = 0
        self.changesetOpen = 0
        self.changesetInitiator = ""
        self.revision = None
        self.cursor = None
        self.permCache = {}

        self.is_invalid = 0
        log_info("Session #%s created for %s. Mode %s." % \
                (self.session_id, self.username, self.mode))

    def _connect(self):
        # Close the existing connection
        if self.db is not None:
            try:
                self.db.close()
            except:
                log_warn("Could not close existing db connection cleanly " \
                        "in session #%s" % self.session_id, sys.exc_info())

        # Setup a database connection
        log_debug("%s::%s pgdb.connect(user=[%s], dbhost=[%s], database=[%s], port=[%s])" % \
        (__name__, '_connect', self.duser, self.dhost, self.database, self.dport))
        self.db = pgdb.connect(host= self.dhost+':'+self.dport, database=self.database, \
                user=self.duser, password=self.dpass)
        log_debug("%s::%s database connection set" % (__name__, '_connect'))

    def getSessionObject(self):
        """Returns a dictionary containing information about the session"""

        if self.is_invalid == 1:
            raise pcsd_session_error("Invalid session object!")

        dict = {}
        # Deprecate this entry
        dict["sessionID"] = self.session_id
        # In favour of this one
        dict["session_id"] = self.session_id
        dict["login_id"] = self.login_id
        dict["mode"] = self.mode
        dict["token"] = self.token
        dict["initiated"] = self.initiated
        dict["expires"] = self.expires

        return dict

    def getCookieToken(self):
        """Returns a token that can be used to login via a cookie"""
        session = getSessionE(ADMIN_SESSION_ID)

        token = createPassword(31)
        expires = expires = time.ctime(time.time() + 60*self.cookie_timeout)

        sql = "INSERT INTO cookies (login_id, token, expires) VALUES (" \
                "%s, %s, %s)"
        session.execute(sql, (self.login_id, token, expires))

        return token

    def begin(self, description="", initiator="", implicit=0):
        """Begins a new changeset"""
        # Don't let threads race to start a new changeset
        self.lock.acquire()

        if self.is_invalid == 1:
            self.lock.release()
            raise pcsd_session_error("Invalid session object!")

        if self.changeset != 0:
            self.lock.release()
            raise pcsd_session_error("There is already a changeset open!")

        # Create a database changeset which is wrapped in a transaction.
        # Note PgSQL automatically begins transactions when a cursor is created
        # so the check above (that no transaction is in progress) allows us to
        # know that we are at the start of a new transaction for the following
        # statements
        try:
            ecur = self.db.cursor()
            ecur.execute("INSERT INTO changeset (username, " \
                "description, pending) VALUES (%s, %s, %s)", \
                (self.username, description, "t"))
        except:
            if ecur:
                ecur.close()
            log_error("Could not create changeset", sys.exc_info())
            self.lock.release()
            raise pcsd_session_error("Could not create changeset!")

        # Retrieve changeset id
        res = self.query("SELECT currval('changeset_changeset_id_seq')", (), \
                ecur)
        if len(res) != 1:
            # Rollback
            ecur.close()
            self.db.rollback()
            # Raise error
            self.lock.release()
            raise pcsd_session_error("Could not retrieve changeset id!")
        self.changeset = res[0][0]

        ecur.close()

        # Initialise a revision of the configuration files
        if not implicit:
            try:
                from pcsd_cfengine import pcs_revision
                self.revision = pcs_revision(self, self.changeset)
            except:
                log_error("Could not generate revision for " \
                        "changeset!", sys.exc_info())
                self.revision = None
        else:
            self.revision = None

        # Mark changeset as open for queries
        self.changesetOpen = 1
        self.changesetInitiator = initiator

        self.lock.release()
        return self.changeset

    def commit(self, description=""):
        """Commits the changeset with the specified description appended.

        If append is 0 the description overwrites the current value.
        """

        # Don't let threads race to close a changeset
        self.lock.acquire()

        if self.is_invalid == 1:
            self.lock.release()
            raise pcsd_session_error("Invalid session object!")

        # Mark the changeset as finished (no further changes accepted)
        self.changesetOpen = 0

        # Update changeset description
        desc = self.getChangesetDescription()
        if description != "":
            desc = "%s\n%s" % (desc, description)

        # Checkin the revision and get revision number
        if self.revision != None:
            rev = self.revision.checkin("Automatic revision\n\n%s" % desc)
        else:
            rev = -1

        # Commit the changeset
        params = {}
        sql = "UPDATE changeset SET description=%(d)s,"
        if rev != -1:
            sql = "%s svn_revision=%%(r)s," % sql
            params["r"] = rev
        sql = "%s pending='f' WHERE changeset_id=%%(c)s" % sql
        params["d"] = desc.strip()
        params["c"] = self.changeset

        # Execute the query
        try:
            cur = self.db.cursor()
            cur.execute(sql, params)
            cur.close()
            self.db.commit()
        except:
            log_error("Could not commit changeset!", sys.exc_info())
            # XXX: Rollback revision here
            self.lock.release()
            raise pcsd_session_error("Could not commit changeset!")

        t = self.changeset
        self.changeset = 0
        self.changesetOpen = 0
        self.changesetInitiator = ""

        # XXX: Check changeset was successfully committed
        self.revision = None

        self.lock.release()
        return {"changeset":t,"revision":rev}

    def getChangesetDescription(self):
        """Returns the current changeset description"""

        if self.changeset == 0:
            return ""

        res = self.query("SELECT description FROM changeset WHERE " \
                "changeset_id=%s", (self.changeset))
        return res[0][0]

    def rollback(self):
        """Rollsback the current changeset"""

        # Don't let threads race to rollback a changeset
        self.lock.acquire()

        if self.is_invalid == 1:
            self.lock.release()
            raise pcsd_session_error("Invalid session object!")

        if self.changeset == 0:
            self.lock.release()
            return

        # Cancel the database changeset
        self.db.rollback()
        self.changeset = 0
        self.changesetOpen = 0
        self.changesetInitiator = ""

        # Cancel the revision
        self.revision = None

        self.lock.release()
        return 0

    def getCountOf(self, sql, params):
        res = self.query(sql, params)
        if res == -1:
            return 0
        if len(res) != 1:
            return 0
        return res[0][0]

    def query(self, sql, params, icursor=None):

        # Only one DB query per session at a time please!
        self.lock.acquire()

        # Return now for queries that are not select
        if not sql.lower().startswith("select"):
            self.lock.release()
            raise pcsd_session_error("Queries must begin with select!")

        if self.log_times:
            stime = time.time()

        # Get a cursor to use
        try:
            cursor = icursor is None and self.db.cursor() or icursor
        except:
            log_error("Unable to obtain cursor for query!", sys.exc_info())
            # This pretty much means our db connection is hosed, reconnect
            self._connect()
            self.lock.release()
            raise pcsd_session_error("Unable to obtain cursor for query!")

        # Run the query
        try:
            res = cursor.execute(sql, params)
        except:
            (et, value, bt) = sys.exc_info()
            errStr = "%s - Failed Query: %s (%s)" %  (value, sql, params)
            log_error(errStr, (et, value, bt))
            if icursor is None:
                cursor.close()
            # If the error seems to be connection related, reconnect
            if isinstance(value, str) and value.startswith("no connection"):
                self._connect()
            self.lock.release()
            raise pcsd_session_error(errStr)

        if self.log_times:
            mtime = time.time()

        # Fetch the data
        d = cursor.description
        rows = cursor.fetchall()

        if self.log_times:
            mtime2 = time.time()

        r = 0
        rows2 = []
        for row in rows:
            rd = {}
            i=0
            for v in row:
                if v == None:
                     rd[d[i][0]] = ""
                     rd[i] = ""
                elif type(v) == type(DateTime.DateTime(1)):
                    rd[d[i][0]] = str(v)
                    rd[i] = str(v)
                else:
                    rd[d[i][0]] = v
                    rd[i] = v
                i+=1
            rows2.append(rd)
            r+= 1

        # Close the cursor we opened
        if icursor is None:
            cursor.close()

        if self.log_times:
            etime = time.time()
            log_debug("Queried database in %0.3f/%0.3f/%0.3f seconds\n  %s" % \
                    ((mtime-stime), (mtime2-stime), (etime-stime), sql))

        self.lock.release()
        return rows2

    def execute(self, sql, params):

        # Only one DB query per session at a time please!
        self.lock.acquire()

        if self.changeset > 0 and self.changesetOpen==0:
            self.lock.release()
            raise pcsd_session_error("Session is currently completing a " \
                    "changeset. No modifications to database allowed!")

        # Return now for queries that are a select
        if sql.lower().startswith("select"):
            self.lock.release()
            return pcsd_session_error("Select queries cannot be executed. " \
                    "Use query instead.")

        if self.log_times:
            stime = time.time()

        table = "unknown"
        try:
            if sql.startswith("UPDATE"):
                table = sql.split(" ")[1]
            elif sql.startswith("INSERT INTO") or \
                    sql.startswith("DELETE FROM"):
                table = sql.split(" ")[2]
        except: pass

        # Don't require a changeset for updates to "system" tables
        require_changeset = True
        if table in SYSTEM_TABLES:
            require_changeset = False

        # Handle implicit transactions
        commit = 0
        if self.changeset == 0 and require_changeset:
            self.begin(implicit=1, initiator="pcsd_session.execute" , \
                    description="Autogenerated changeset on table %s" % \
                    table)
            commit = 1

        # Obtain a cursor
        try:
            cursor = self.db.cursor()
        except:
            # This pretty much means our db connection is hosed, reconnect
            self._connect()
            log_error("Could not obtain cursor for execute", sys.exc_info())
            self.lock.release()
            raise pcsd_session_error("Could not obtain cursor")

        # Execute the query
        try:
            res = cursor.execute(sql, params)
        except:
            (et, value, bt) = sys.exc_info()
            try:
                if cursor: cursor.close()
            except:
                pass
            # Always rollback, session is dead anyway!
            self.rollback();
            errStr = "%s - Failed Execute: %s (%s)" %  (value, sql, params)
            log_error(errStr, (et, value, bt))
            # If the error seems to be connection related, reconnect
            if isinstance(value, str) and value.startswith("no connection"):
                self._connect()
            self.lock.release()
            raise pcsd_session_error(errStr)

        # Commit an implicit transaction
        if commit or (table in SYSTEM_TABLES and self.changeset==0):
            self.commit()
        cursor.close()

        if self.log_times:
            etime = time.time()
            log_debug("Updated database in %0.3f seconds\n  %s" % \
                    ((etime-stime), sql))

        self.lock.release()
        return 0

    def hasPerms(self, mode, group):
        """Checks that the specified session has the appropriate group
        memberships"""

        # Import here to avoid circular dependencies
        from server.modules.pcs_contact import getUserCache, getCustomerCache, getGroupCache

        # Check session is of appropriate type
        if mode == SESSION_RW:
            if self.mode != SESSION_RW:
                return SESSION_NONE

        # normal users have AUTH_AUTHENTICATED by default
        if group == AUTH_AUTHENTICATED:
            return mode

        # If we have a cached permission record, return that
        if group in self.permCache.keys():
            return self.permCache[group]

        # Check group membership
        users = getUserCache(self.session_id)
        customers = getCustomerCache(self.session_id)
        groups = getGroupCache(self.session_id)
        admin_id = users[self.login_id]["admin_id"]

        if self._isGroupMember(admin_id, groups[group], groups):
            self.permCache[group] = mode
            return mode

        self.permCache[group] = SESSION_NONE
        return SESSION_NONE

    def _isGroupMember(self, admin_id, group, groups):
        """Helper function to emulate isGroupMemberU but working from cache"""
        if admin_id in group["members"]:
            return True
        for group_id in group["group_members"]:
            rv = self._isGroupMember(admin_id, groups[group_id], groups)
            if rv: return True
        return False

    def getGroupMemberships(self):
        """Returns a list of all groups this session belongs to"""
        # Import here to avoid circular dependencies
        from server.modules.pcs_contact import getUserCache, getCustomerCache, getGroupCache

        # Check group membership
        users = getUserCache(self.session_id)
        customers = getCustomerCache(self.session_id)
        groups = getGroupCache(self.session_id)
        if self.login_id in users.keys():
            contact_id = users[self.login_id]["admin_id"]
        else:
            return []

        # Cache memberships
        res = []
        for group in groups.keys():
            if self._isGroupMember(contact_id, groups[group], groups):
                res.append(group)
        return res

    def updateExpiry(self):
        """Postpones the sessions expiry by EXPIRY_TIME

        This function should be called periodically whenever activity is
        detected on the session. By default it is called by is_session_valid
        which will be triggered by each incoming authenticated XML-RPC call.
        """

        if self.is_invalid == 1:
            raise pcsd_session_error("Invalid session object!")

        # update expiry time
        self.expires = time.time() + (self.timeout*60)

    def lifetime(self):
        """Returns the number of seconds before this session expires"""
        return self.expires - time.time()

    def isExpired(self):
        """Checks if the session has expired

        This function should be regularly called for each session.

        Returns 1 if the session has expired, 0 otherwise
        """

        if self.is_invalid == 1:
            return True

        # Check that expiry is still in the future
        if self.lifetime() > 0:
            return False

        log_info("Removing expired session %s (%s)" % \
                (self.session_id, self.username))

        # Session has expired!
        if self.changeset > 0:
            # Commit the changeset
            self.commit("Autocommitted due to session expiry")

        # Shutdown
        self.shutdown()

        return True

    def close(self, persist=False):
        """Nicely closes the session and commits all pending changes.

        If persist is set to True, the session entry remains in the database.
        """

        # Don't let threads race to close a session
        self.lock.acquire()

        if self.is_invalid==1:
            self.lock.release()
            return

        if self.changeset != 0:
            self.commit("Autocommited due to session close")

        # Shutdown will do the rest
        self.shutdown(persist)
        self.lock.release()

    def shutdown(self, persist=False):
        """Forcibly closes the session.

        Any pending changesets will be rolled back.
        """
        # Don't let threads race to close a session
        self.lock.acquire()

        if self.is_invalid==1:
            self.lock.release()
            return

        # Rollback
        if self.changeset != 0:
            self.rollback()

        # Mark session as expired
        self.is_invalid = 1

        # Remove session record
        if not persist:
            sql = "DELETE FROM sessions WHERE sid=%s"
            session = getSessionE(ADMIN_SESSION_ID)
            session.execute(sql, (self.session_id))
        elif self.session_id != ADMIN_SESSION_ID:
            # Update expiry time
            sql = "UPDATE sessions SET expires=%s WHERE sid=%s"
            session = getSessionE(ADMIN_SESSION_ID)
            session.execute(sql, (time.ctime(self.expires), self.session_id))

        # Close Database
        self.db.close()

        del self.sessions[self.session_id]
        log_info("Session #%s (%s) shutdown." % \
               (self.session_id, self.username))
        self.lock.release()

class pcsd_basic_session(pcsd_session):
    """Basic session used for certificate logons that have no user account

    This session allows the calling party to access any functions that require
    only AUTH_AUTHENTICATED access.

    The session is not stored in the database and ends as soon as the reply
    is sent.
    """

    def __init__(self, login_id, mode):

        self.username = "username"
        self.login_id = login_id
        self.mode = mode
        self.lock = threading.RLock()
        self.db = None

        # Session Time Records
        self.initiated = time.time()
        self.expires = time.time() + 60
        self.token = ""

        # Setup a database connection
        self._connect()

        # Steal a session ID from the sequence, but don't put the session
        # into the DB
        session = getSession(ADMIN_SESSION_ID)
        if session is None:
            raise pcsd_session_error("No admin session!")
        sql = "SELECT nextval('sessions_sid_seq') as sid"
        res = session.query(sql, ())
        if res == -1:
            raise pcsd_session_error("Unable to allocate session ID")
        self.session_id = res[0]["sid"]

        # No changeset or revision active initially
        self.changeset = 0
        self.changesetOpen = 0
        self.changesetInitiator = ""
        self.revision = None
        self.cursor = None

        self.is_invalid = 0
        log_info("Basic Session #%s created for %s. Mode %s." % \
                (self.session_id, self.username, self.mode))

    def getSessionObject(self):
        if self.is_invalid == 1:
            raise pcsd_session_error("Invalid session object!")

        dict = pcsd_session.getSessionObject(self)
        dict["basicSession"] = True
        return dict

    def getCookieToken(self):
        raise pcsd_session_error("Basic sessions do not support cookie tokens")

    def hasPerms(self, mode, group):
        """Checks that the specified session has the appropriate group
        memberships"""

        # Check session is of appropriate type
        if mode == SESSION_RW:
            if self.mode != SESSION_RW:
                return SESSION_NONE

        # Check group membership - basic session only belong to
        # AUTH_AUTHENTICATED
        if group != AUTH_AUTHENTICATED:
            return SESSION_NONE

        return mode

    def updateExpiry(self):
        return

    def shutdown(self, persist=False):
        """Forcibly closes the session.

        Any pending changesets will be rolled back.
        """
        # Don't let threads race to close a session
        self.lock.acquire()

        if self.is_invalid==1:
            self.lock.release()
            return

        # Rollback
        if self.changeset != 0:
            self.rollback()

        # Mark session as expired
        self.is_invalid = 1

        # Close Database
        self.db.close()

        del self.sessions[self.session_id]
        log_info("Session #%s (%s) shutdown." % \
               (self.session_id, self.username))
        self.lock.release()

#####################################################################
# Session Helper Functions
#####################################################################
def loadSessions():
    """Loads sessions from the database"""
    session = getSessionE(ADMIN_SESSION_ID)

    sessions = {}

    # Remove expired sessions
    sql = "DELETE FROM sessions WHERE expires<NOW()"
    session.execute(sql, ())

    # Now select remaining sessions
    sql = "SELECT sid, login_id, mode, token, " \
            "date_part('epoch', initiated) as initiated, " \
            "date_part('epoch', expires) as expires FROM sessions"
    res = session.query(sql, ())

    for row in res:
        try:
            session = pcsd_session(row["login_id"], \
                    row["mode"], row["token"], row["initiated"], \
                    row["expires"], row["sid"])
        except pcsd_session_error:
            log_error("Could not load session id: %s" % row["sid"], \
                    sys.exc_info())

        obj = session.getSessionObject()
        sessions[obj["sessionID"]] = session

    return sessions

def getSession(session_id):
    """Returns a session object for the specified session"""

    if session_id not in pcsd_session.sessions.keys():
        return None

    return pcsd_session.sessions[session_id]

def getSessionE(session_id):
    """Returns a session object for the specified session

    Identical in every respect to getSession, but raises an exception
    if the session is not found.
    """

    if session_id not in pcsd_session.sessions.keys():
        raise pcsd_session_error("Session(%s)does not exist!" % (session_id))

    return pcsd_session.sessions[session_id]

@exportViaXMLRPC(SESSION_NONE, AUTH_NONE)
def isSessionValid(sauth):
    """Checks the state of the specified session.

    Parameters  sauth   Session credentials dictionary

    Returns     The mode of the session
    """

    # Validate parameters
    if type(sauth) != type({}):
        raise pcsd_session_error("Invalid session dictionary!")
    if "session_id" not in sauth.keys():
        raise pcsd_session_error("Invalid session dictionary!")
    if "login_id" not in sauth.keys():
        raise pcsd_session_error("Invalid session dictionary!")
    if "token" not in sauth.keys():
        raise pcsd_session_error("Invalid session dictionary!")
    if sauth["session_id"] <= 0:
        raise pcsd_session_error("Invalid session ID")

    # Validate the session parameters
    if sauth["session_id"] not in pcsd_session.sessions.keys():
        raise pcsd_session_error("Session does not exist")
    session = pcsd_session.sessions[sauth["session_id"]]
    if session.login_id != sauth["login_id"]:
        raise pcsd_session_error("Session login_id does not match!")
    if session.token != sauth["token"]:
        raise pcsd_session_error("Session token is invalid!")

    # Update the expiry time
    session.updateExpiry()
    pcsd_session.sessions[sauth["session_id"]] = session

    return True

@exportViaXMLRPC(SESSION_NONE, AUTH_NONE, asynchronous=True)
def getSessionInformation(sauth=None):
    """Retrieves information about the state of the system

    If the current session parameters are given the current changeset is
    returned if present.
    """

    # Retrieve some system information
    nsessions = getNoSessions()
    if sauth is not None:
        try:
            session = pcsd_session.sessions[sauth["session_id"]]
        except:
            session = None

    if session is None:
        nchangesets = getNoChangesets(-1)
        changeset = 0
        mode = SESSION_NONE
    else:
        nchangesets = getNoChangesets(session.session_id)
        changeset = session.changeset
        mode = session.mode

    return (mode, nsessions, nchangesets, changeset)

@catchEvent("maintenance")
def sessionMaintenance(*args, **kwargs):
    """Checks for expired sessions and removes them"""
    global sessionLock

    # Ensure that only one thread is executing session maintenance at once
    if not sessionLock.acquire(False):
        log_warn("A previous session maintenance task is still in progress!")
        return
    try:
        ct = threading.currentThread()
        ct.setName("sessionMaintenance")
        start = time.time()
        asession = getSessionE(ADMIN_SESSION_ID)

        # Loop through the list of sessions and remove expired ones
        for sessionID,session in pcsd_session.sessions.items():
            # Never expire the admin session
            if sessionID==ADMIN_SESSION_ID: continue
            if session.isExpired(): continue
            # Not expired, update db expiry time if we're expiring "soon"
            if session.lifetime() < MAINT_INTERVAL * 3:
                sql = "UPDATE sessions SET expires=%s WHERE sid=%s"
                res = asession.execute(sql, \
                        (time.ctime(session.expires), session.session_id))

        # Also delete expired login cookies
        session = getSessionE(ADMIN_SESSION_ID)
        sql = "DELETE FROM cookies WHERE expires<NOW()"
        res = session.execute(sql, ())
        if pcsd_xmlrpc.log_times:
            log_debug("Session maintenance completed successfully in %.3f " \
                    "seconds" % (time.time()-start))
    except:
        log_error("Failed to complete session maintenace", sys.exc_info())
    sessionLock.release()

@catchEvent("shutdown")
def shutdownSessions(*args, **kwargs):
    """Closes all sessions as the program shuts down.

    Sessions are left in the database so they can be reloaded when the
    program restarts.
    """
    for sessionID,session in pcsd_session.sessions.items():
        if sessionID == ADMIN_SESSION_ID: continue
        session.close(persist=True)
    session = getSessionE(ADMIN_SESSION_ID)
    session.close(persist=True)

def _validateCustomerPassword(username, password):
    """Helper routine for login. Validates the users password"""
    from server.modules.pcs_contact import getCustomerCache
    users = getCustomerCache(ADMIN_SESSION_ID)

    if username not in users.keys():
        log_warn("No user %s" % username)
        return FALSE

    # Get password
    passwd = users[username]["passwd"]
    if len(passwd) <= 0:
        log_warn("No password set for %s" % username)
        return FALSE

    # Check password
    if crypt.crypt(password, passwd) != passwd:
        log_info("Password check failed for %s" % username)
        return FALSE

    return users[username]['login_id']
def _validatePassword(username, password):
    """Helper routine for login. Validates the users password"""
    from server.modules.pcs_contact import getUserCache

    session = getSessionE(ADMIN_SESSION_ID)
    users = getUserCache(ADMIN_SESSION_ID)

    # Check if user exists
    if username not in users.keys():
        log_warn("No user %s" % username)
        return None

    # Get password
    passwd = users[username]["passwd"]
    if len(passwd) <= 0:
        log_warn("No password set for %s" % username)
        return None

    # Check password
    if crypt.crypt(password, passwd) != passwd:
        log_info("Password check failed for %s" % username)
        return None

    return users[username]['login_id']

def _validateCookieToken(login_id, token):
    """Helper routine for login. Validates the token"""
    session = getSessionE(ADMIN_SESSION_ID)

    sql = "SELECT count(*) FROM cookies WHERE login_id=%s and token=%s"
    n = session.getCountOf(sql, (login_id, token))
    if n<=0:
        log_info("No matching cookies for %s" % login_id)
        return FALSE

    return TRUE

def startSession(login_id, mode):
    """Starts a new session for the user in the specified mode

    If there is an existing session open at the specified mode (or a lower
    mode) then it is reused instead.
    """
    session = getSessionE(ADMIN_SESSION_ID)
    newsession = None

    # Check for existing sessions
    for sess_id, sess in pcsd_session.sessions.items():
        # Skip the administrative session
        if sess_id == ADMIN_SESSION_ID:
            continue
        # Skip other users session
        if sess.login_id != login_id:
            continue
        # Other matches are good
        if sess.mode == mode:
            return sess.getSessionObject()
        elif mode == SESSION_RW and sess.mode == SESSION_RO:
            # Upgrade the session
            session.execute("UPDATE sessions SET mode=%s WHERE " \
                    "sid=%s", (SESSION_RW, sess_id))
            sess.mode = SESSION_RW
            sess.permCache = {}
            pcsd_session.sessions[sess_id] = sess
            return sess.getSessionObject()

    # Create a new session if we didn't find an existing one
    if newsession is None:
        newsession = pcsd_session(login_id, mode)

    # Register it in the list of sessions
    obj = newsession.getSessionObject()
    pcsd_session.sessions[obj["sessionID"]] = newsession

    # Check for first_login
    n = session.getCountOf("SELECT count(*) AS n FROM first_login WHERE " \
            "login_id=%s", (login_id))
    if n>0:
        obj["passchange"] = True

    return obj

def startBasicSession(login_id, mode):
    """Starts a new session for a certificate login in the specified mode

    These sessions by default only exist for a short time
    """
    newsession = pcsd_basic_session(login_id, mode)
    obj = newsession.getSessionObject()
    pcsd_session.sessions[obj["sessionID"]] = newsession

    return obj

@exportViaXMLRPC(SESSION_NONE, AUTH_NONE)
def cookieLogin(username, token):
    """Allows authentication with the server using a stored token.

    Looks up token & username in the cookies table. If a match is found
    the authentication is successful.

    Returns a session description dictionary as returned by the session
    object.
    """
    from server.modules.pcs_contact import getUserCache

    # Validate username / token
    #if len(username) <= 0:
    #    raise pcsd_session_error("Username too short, must be > 0 characters!")
    #if len(username) > 16:
    #    raise pcsd_session_error("Username too long, must be < 16 characters!")
    if len(token) <= 0:
        raise pcsd_session_error("Token too short, must be > 0 characters!")
    if len(token) > 32 :
        raise pcsd_session_error("Token too long, must be < 32 characters!")

    #Get the login_id from the users cache
    users = getUserCache(ADMIN_SESSION_ID)
    if username in users.keys():
        login_id = users[username]['login_id']
    else:
        raise pcsd_session_error("Invalid username or cookie token!")

    # Check username / token
    if not _validateCookieToken(login_id, token):
        raise pcsd_session_error("Invalid username or cookie token!")

    # Return the users read-only session
    return startSession(login_id, SESSION_RO)

@exportViaXMLRPC(SESSION_NONE, AUTH_NONE, asynchronous=True)
def customer_login(username, password):
    """Called by clients to authenticate with the server.

    Looks up accounts in the contact table, if passwords match the user is
    logged in and we start a session for them.

    Returns a session description dictionary as returned by the session
    object.
    """
    session = getSessionE(ADMIN_SESSION_ID)

    # Validate username / password
    #if len(username) <= 0:
    #    raise pcsd_session_error("Username too short, must be > 0 characters!")
    #if len(username) > 16:
    #    raise pcsd_session_error("Username too long, must be < 16 characters!")
    if len(password) <= 0:
        raise pcsd_session_error("Password too short, must be > 0 characters!")

    # Check username / password
    login_id =  _validateCustomerPassword(username, password)
    if not login_id:
        raise pcsd_session_error("Invalid username or password")

    # Return the users read-write session
    return startSession(login_id, SESSION_RW)
@exportViaXMLRPC(SESSION_NONE, AUTH_NONE, asynchronous=True)
def login(username, password):
    """Called by clients to authenticate with the server.

    Looks up accounts in the contact table, if passwords match the user is
    logged in and we start a session for them.

    Returns a session description dictionary as returned by the session
    object.
    """
    session = getSessionE(ADMIN_SESSION_ID)

    # Validate username / password
    #if len(username) <= 0:
    #    raise pcsd_session_error("Username too short, must be > 0 characters!")
    #if len(username) > 16:
    #    raise pcsd_session_error("Username too long, must be < 16 characters!")
    if len(password) <= 0:
        raise pcsd_session_error("Password too short, must be > 0 characters!")

    # Check username / password
    login_id =  _validatePassword(username, password)
    if not login_id:
        raise pcsd_session_error("Invalid username or password")

    # Return the users read-write session
    return startSession(login_id, SESSION_RW)

@exportViaXMLRPC(SESSION_RO, AUTH_AUTHENTICATED)
def logout(session_id):
    """Closes a session voluntarily"""

    # Ask the session to shutdown
    session = getSessionE(session_id)
    session.shutdown()

    return 0

@exportViaXMLRPC(SESSION_RO, AUTH_AUTHENTICATED)
def getCookieToken(session_id):
    """Creates a new cookie token"""
    session = getSessionE(session_id)
    return session.getCookieToken()

@exportViaXMLRPC(SESSION_RO, AUTH_AUTHENTICATED, asynchronous=True)
def getGroupMemberships(session_id):
    """Called by clients to retreive a list of all groups they are a member of
    """
    session = getSessionE(session_id)

    # Return the users read-write session
    return session.getGroupMemberships()

@exportViaXMLRPC(SESSION_RO, AUTH_USER, asynchronous=True)
def getChangesetNo(session_id):
    """Returns the changeset number for the current sesssion"""

    session = getSessionE(session_id)
    return session.changeset

@exportViaXMLRPC(SESSION_RW, AUTH_USER)
def beginChangeset(session_id, description=""):
    """Initialises a new changeset for the user

    While this will allow a session to begin a changeset even if other
    sessions have currently open changesets, it does not make any guarantees
    that the session will be able to commit it's changeset if it conflicts
    with changes made in other concurrent sessions.

    The calling application should take care to inform the user of this.
    """
    session = getSessionE(session_id)
    return session.begin(description)

@exportViaXMLRPC(SESSION_RW, AUTH_USER)
def commitChangeset(session_id, description=""):
    """Commits the changes made in the currently open changeset

    If the changeset was running currently to changesets in another session
    this could cause an error if the changes conflicted.

    Callers should be aware of this and be ready to take appropriate action.
    """
    session = getSessionE(session_id)
    return session.commit(description)

@exportViaXMLRPC(SESSION_RW, AUTH_USER)
def cancelChangeset(session_id):
    """Cancels all changes made to the database in this changeset

    This function restores the database to the condition it was in prior to
    the changeset being started.
    """
    session = getSessionE(session_id)
    session.rollback()

    return 0

@exportViaXMLRPC(SESSION_RO, AUTH_USER, asynchronous=True)
def getNoChangesets(session_id):
    """Returns the number of active changesets not including this session"""

    count = 0
    for session_id2,tsession in pcsd_session.sessions.items():
        if session_id2 == session_id:
            continue
        if tsession.changeset > 0:
            count += 1

    return count

@exportViaXMLRPC(SESSION_RO, AUTH_USER)
def getChangesetHistory(session_id, start_date=None, days=1):
    """Returns the changeset history from the database"""
    session = getSessionE(session_id)

    if start_date is None:
        now = time.localtime()
    else:
        now = time.localtime(start_date)
    start_date = time.mktime((now[0], now[1], now[2], 23, 59, 59, now[6], \
            now[7], now[8]))
    end_date = int(start_date) - (int(days) * (3600*24))
    start = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_date*1.0))
    end = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end_date*1.0))
    res = session.query("SELECT username, description, svn_revision, " \
            "date_part('epoch', timestamp) as timestamp FROM changeset " \
            "WHERE pending='f' AND timestamp>%s AND timestamp<%s " \
            "ORDER BY timestamp DESC", (end, start))
    return res

@exportViaXMLRPC(SESSION_NONE, AUTH_NONE, asynchronous=True)
def getNoSessions():
    return len(pcsd_session.sessions)

@exportViaXMLRPC(SESSION_NONE, AUTH_NONE, asynchronous=True)
def getVersion():
    """Returns a version string """

    return "CRCnet Configuration System Daemon %s" % (pcsd_version)

#####################################################################
# Session Initialisation
#####################################################################
def initSessions():
    global sessionLock
    try:
        log_debug("%s::%s" % (__name__, 'initSessions()'))
        # Get database connection parameters
        _dhost = config_get("database", "host")
        pcsd_session.dhost = _dhost!="" and _dhost or None
        log_info("host = %s" % pcsd_session.dhost)

        _ddatabase = config_get("database", "database")
        pcsd_session.database = _ddatabase!="" and _ddatabase or None
        log_info("database = %s" % pcsd_session.database)

        _duser = config_get("database", "user")
        pcsd_session.duser = _duser!="" and _duser or None
        log_info("duser = %s" % pcsd_session.duser)

        _dpass = config_get("database", "password")
        pcsd_session.dpass = _dpass!="" and _dpass or None

        _dport = config_get("database", "port")
        pcsd_session.dport = _dport!="" and _dport or None
        log_info("dport = %s" % pcsd_session.dport)

        # Does the admin want us to log query times
        pcsd_session.log_times = config_getboolean(None, "log_db_times", False)

        # Create a program wide 'admin' session which is always present
        pcsd_session.sessions[ADMIN_SESSION_ID] = \
                pcsd_session("admin", SESSION_RW, "", -1, -1, ADMIN_SESSION_ID)
        log_info("program wide 'admin' created")

        # Load any other saved sessions
        pcsd_session.sessions.update(loadSessions())

        # Initialise the lock
        sessionLock = threading.RLock()

        log_info("Successfully loaded sessions")
    except:
        log_fatal("Failed to load initial program state!", sys.exc_info())
