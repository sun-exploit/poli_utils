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
import re
import os
import os.path
import sys
import socket
import struct
import optparse
import fcntl
import string
from BaseHTTPServer import HTTPServer
import xmlrpclib

#############################################################################
# Constants
#############################################################################

# Site details
DEFAULT_ADMIN_EMAIL = "root@localhost"
DEFAULT_SITE_NAME = "Default Poli Configuration System Installation"
DEFAULT_SITE_ADDRESS = "https://localhost/"

# How often to run generic maintenance commands (seconds)
MAINT_INTERVAL = 60

# How many minutes of activity cause a session to timeout
DEFAULT_SESSION_TIMEOUT = 30

# How many minutes should a cookie be issued for
DEFAULT_COOKIE_TIMEOUT = 60*24*30

# How many minutes should a session last for
DEFAULT_SESSION_TIMEOUT = 30

# Die after 10 fatal errors
DEFAULT_FATAL_ERR_COUNT = 10

# The maximum number of threads that can run at once
DEFAULT_MAX_THREADS = 15

# Default Server Port
DEFAULT_HTTP_SERVER_PORT = 5575
DEFAULT_HTTPS_SERVER_PORT = 5565
# Default Client Port
DEFAULT_CLIENT_PORT = 80

# Possible command line options
OPTION_LIST = "c:d:v"

# Default File Locations
DEFAULT_CONFFILE = "/etc/pcsd/%s.conf" % os.path.basename(sys.argv[0])
DEFAULT_PIDFILE = "/var/run/%s.pid" % os.path.basename(sys.argv[0])
DEFAULT_CONFIG_SVNROOT = "/var/lib/svn/pcsd/configs"
DEFAULT_REQUEST_LOG = "/tmp/pcsd.log"
DEFAULT_SERVICE_LIB_DIR = "/usr/lib/pcsd/services"
DEFAULT_SERVICE_DATA_DIR = "/usr/share/pcsd/services"
DEFAULT_TMPDIR = "/tmp"
DEFAULT_PROFILE_DIR = "/tmp/pcsd-profile"

# Types of session
SESSION_NONE = "NO"
SESSION_RO = "RO"
SESSION_RW = "RW"

# ID of the ever present session
ADMIN_SESSION_ID = 0

# RPC errors
ERROR_BASE = 9000

PCSD_ERROR = ERROR_BASE + 1

PCSD_BADPARAM = ERROR_BASE + 10

PCSD_DBERROR = ERROR_BASE + 20

PCSD_AUTHFAIL = ERROR_BASE + 30

PCSD_CALLFAILED = ERROR_BASE + 40

TRUE = 1
FALSE = 0

RFC1918 = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]

# Bytes (as floats so divisions and stuff work nicely)
KILO = 1024.0
MEGA = KILO * 1024.0
GIGA = MEGA * 1024.0

# Types of link
PCSD_LINK_ADHOC = "AdHoc"
PCSD_LINK_MANAGED = "Managed"
PCSD_LINK_ETHERNET = "Ethernet"
PCSD_LINK_QB20 = "QuickBridge20"
PCSD_LINK_TRANGO = "Trango"

# Group Names
AUTH_NONE = "None"
AUTH_AUTHENTICATED = "Authenticated"
AUTH_ADMINISTRATOR = "Administrators"
AUTH_USER = "Users"
AUTH_ASSET_MANAGER = "Asset Managers"
AUTH_CERT_ADMINS = "Certificate Administrators"
AUTH_HELPDESK = "Helpdesk"

# Care needs to be taken to keep these in sync with the database table
ASSET_EVENT_IMPORTED = 1
ASSET_EVENT_LOCATION_CHANGED = 2
ASSET_EVENT_ATTACHED = 3
ASSET_EVENT_CREATED = 4
ASSET_EVENT_REMOVED = 5
ASSET_EVENT_DETAILS_UPDATED = 6
ASSET_EVENT_PROPERTY_UPDATED = 7
ASSET_EVENT_SUBASSET_ADDED = 8
ASSET_EVENT_SUBASSET_REMOVED = 9
ASSET_EVENT_ASSIGNED = 10

# Status Values
STATUS_OK = "ok"
STATUS_WARNING = "warning"
STATUS_CRITICAL = "critical"
STATUS_UNKNOWN = "unknown"

# Server / Client Constants
PCSD_NONE = -1
PCSD_CLIENT = 0
PCSD_SERVER = 1

# From net/route.h
RTF_UP = 0x0001             #U Route usable
RTF_GATEWAY = 0x0002        #G Destination is a gateway.
RTF_HOST = 0x0004           #H Host entry (net otherwise).
RTF_REINSTATE = 0x0008      #A Reinstate route after timeout.
RTF_DYNAMIC = 0x0010        #D Created dyn. (by redirect).
RTF_MODIFIED = 0x0020       #D Modified dyn. (by redirect).
RTF_MTU = 0x0040            #M Specific MTU for this route
RTF_WINDOW = 0x0080         #W Per route window clamping.
RTF_IRTT = 0x0100           #I Initial round trip time.
RTF_REJECT = 0x0200         #R Reject route.
RTF_STATIC = 0x0400         #S Manually injected route.
RTF_XRESOLVE = 0x0800       #E External resolver.
RTF_NOFORWARD = 0x1000      #F Forwarding inhibited.
RTF_THROW = 0x2000          #T Go to next class.
RTF_NOPMTUDISC = 0x4000     #N Do not send packets with DF.

ROUTE_FLAG_CHARS = {RTF_UP:"U", RTF_GATEWAY:"G", RTF_HOST:"H", \
        RTF_REINSTATE:"A", RTF_DYNAMIC:"D", RTF_MODIFIED:"D", RTF_MTU:"M", \
        RTF_WINDOW:"W", RTF_IRTT:"I", RTF_REJECT:"R", RTF_STATIC:"S", \
        RTF_XRESOLVE:"X", RTF_NOFORWARD:"F", RTF_THROW:"T", RTF_NOPMTUDISC:"N"}

# From if.h
IFF_UP = 0x1                # interface is up
IFF_BROADCAST = 0x2         # broadcast address valid
IFF_LOOPBACK = 0x8          # is a loopback net
IFF_POINTOPOINT= 0x10       # interface is has p-p link
IFF_RUNNING = 0x40          # resources allocated
IFF_NOARP = 0x80            # no ARP protocol
IFF_PROMISC = 0x100         # receive all packets
IFF_MULTICAST = 0x1000      # Supports multicast

IFACE_FLAG_CHARS = {IFF_BROADCAST:"BROADCAST", IFF_LOOPBACK:"LOOPBACK", \
        IFF_MULTICAST:"MULTICAST", IFF_NOARP:"NOARP", \
        IFF_POINTOPOINT:"POINTOPOINT", IFF_PROMISC:"PROMISC", \
        IFF_RUNNING:"RUNNING", IFF_UP:"UP"}

SIOCGIFCONF    = 0x8912
SIOCGIFFLAGS   = 0x8913
SIOCGIFADDR    = 0x8915
SIOCGIFBRDADDR = 0x8919
SIOCGIFMTU     = 0x8921
SIOCGIFHWADDR  = 0x8927
SIOCGIFINDEX   = 0x8933
SIOCGIFNETMASK = 0x891b

# Only variables named in the following list are inherited from the environment
# that is used to start the daemon
ALLOWED_ENV_VARS = [ "TERM", "SHELL", "SHLVL", "PWD", "PATH", "USER", "MAIL", \
        "HOME", "_"]

#############################################################################
# Base Classes
#############################################################################
class pcsd_error(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class pcs_class(object):
    """Provides generic functionality that all pcs classes will use

    Derived classes must define global variables that are initialised
    in the __init__ routine as specified below.

    _session_id     The session ID that the class should use to access shared
                    resources
    _properties     A dictionary of properties that can be accessed via the
                    class.
    _errMsg         The last error that occured during processing
    """

    SUCCESS = 0
    FAILURE = -1

    # Internal variables
    #
    # Derived classes should set these
    #
    #_session_id = None
    #_properties = {}
    #_errMsg = ""

    def __getitem__(self,x):
        """Returns an item from the classes properties.

        This enables the class to act as a dictionary to reveal it's properties
        in a read-only manner.
        """
        return self._properties[x]

    def keys(self):
        return self._properties.keys()
    def items(self):
        return self._properties.items()
    def values(self):
        return self._properties.values()

    def returnError(self, errMsg):
        """Returns an error code and stores the error message

        Rollsback any implicit transactions started by this class.
        """

        # Record error message
        self._errMsg = errMsg

        from pcsd_session import getSessionE
        session = getSessionE(self._session_id)

        # Rollback an implicit changeset
        if session.changesetInitiator == self._csInit and self._csInit != "":
            session.rollback()

        return self.FAILURE

    def returnSuccess(self):
        """Returns indicating success"""

        from pcsd_session import getSessionE
        session = getSessionE(self._session_id)

        # Commit implicit changeset
        if session.changesetInitiator == self._csInit and self._csInit != "":
            session.commit()

        return self.SUCCESS

    def getErrorMessage(self):
        """Returns the last error message generated and clears the buffer"""
        t = self._errMsg
        self._errMsg = ""
        return t

    def _forceChangeset(self, message, initiator="pcs_class"):
        """Starts an implicit changeset if there is no active changeset

        If you use this function it is *imperative* that you use the
        returnError and returnSuccess functions to leave the function you
        call it from to ensure any implicit changeset is finished properly.
        """
        from pcsd_session import getSessionE
        session = getSessionE(self._session_id)

        if session.changeset==0:
            session.begin(message, initiator=initiator)
            self._csInit = initiator

class PCSHTTPServer(HTTPServer):

    def server_bind(self):
        """Overrides the standard bind to set the no_inherit flag"""
        HTTPServer.server_bind(self)
        fcntl.fcntl(self.socket, fcntl.F_SETFD, fcntl.FD_CLOEXEC)

class PCSTransport(xmlrpclib.Transport):
    """Adds support to the standard XMLRPC Transport class for client certs"""

    def __init__(self, key, cert):
        self.key_file = key
        self.cert_file = cert

    def make_connection(self, host):
        # create a HTTPS connection object from a host descriptor
        # host may be a string, or a (host, x509-dict) tuple
        import httplib
        host, extra_headers, x509 = self.get_host_info(host)
        try:
            HTTPS = httplib.HTTPS
        except AttributeError:
            raise NotImplementedError(
                "your version of httplib doesn't support HTTPS"
            )
        else:
            return HTTPS(host, None, key_file=self.key_file, \
                    cert_file=self.cert_file)

#############################################################################
# Helper Functions
#############################################################################
def enc(inobj):
    """Convert a dictionary to the types needed by xmlrpclib"""

    if type(inobj) == type([]):
        out = []
        for row in inobj:
            out.append(enc(row))
    elif type(inobj) == type({}):
        out = {}
        for key,item in inobj.items():
            nkey = str(key)
            if type(item) == type({}):
                out[nkey] = enc(item)
            elif type(item) == type([]):
                out[nkey] = enc(item)
            elif type(item) == type(int(1)):
                out[nkey] = item
            elif type(item) == type(long(1)):
                out[nkey] = item
            elif type(item) == type(float(1)):
                out[nkey] = item
            elif type(item) == type(None):
                out[nkey] = ""
            else:
                out[nkey] = str(item)
    else:
        out = inobj

    return out

def buildInsertFromDict(tableName, props, newDetails, doNull=False, \
        forceNull=[]):
    """Builds an SQL insert string from the specified dictionary.

    tableName is the name of the database table to insert into

    props must list all possible fields in the database that can be inserted
    newDetails is a dictionary containing new values for the table, indexed
    by values in props. newDetails must contain all fields that are required
    by the database or an error will occur when you try to execute the query.

    If an entry in newDetails contains the value "DEFAULT" no quotes, then
    the default value for the column will be used. If doNull is true any
    property with a value of -1 is inserted as NULL in the update statement

    The forceNull list may be used to specify a list of properties which must
    be inserted as NULL into the table regardless of any value that may be
    specified in the newDetails dictionary.

    A tuple containing two items is returned. The SQL insert string and a list
    containing the values to be substituted into it by the database.
    """

    # Base
    sql = "INSERT INTO %s (" % tableName
    f = 0

    # Go through the properties to be inserted
    values = []
    for prop in props:
        if prop not in newDetails.keys() and prop not in forceNull:
            continue
        c=","
        if f==0:
            f=1
            c=""
        sql = "%s%s %s" % (sql, c, prop)
        if prop not in forceNull:
            values.append(newDetails[prop])
        else:
            values.append("NULL")

    # Error out if no values to insert
    if f == 0:
        return (None, None)

    # Values
    sql = "%s) VALUES (" % sql
    values2 = []
    f=0
    for val in values:
        c=","
        if f==0:
            f=1
            c=""
        try:
            tv = int(val)
        except ValueError:
            tv = None
        if val == "DEFAULT":
            sql = "%s%s DEFAULT" % (sql, c)
        elif (doNull and tv==-1) or (len(forceNull)>0 and val=="NULL"):
            sql = "%s%s NULL" % (sql, c)
        else:
            sql = "%s%s %%s" % (sql, c)
            values2.append(val)

    sql = "%s)" % sql
    return (sql, values2)

def buildUpdateFromDict(tableName, props, newDetails, keyField, keyValue, \
        doNull=False, forceNull=[]):
    """Builds an SQL update string from the specified dictionary.

    tableName is the name of the database table to update
    keyField and keyValue specify the parameters required to limit the update

    props must list all possible fields in the database that can be updated
    newDetails is a dictionary containing new values for the table, indexed
    by values in props. If doNull is true any property with a value of -1 is
    inserted as NULL in the update statement

    The forceNull list may be used to specify a list of properties which must
    be set to NULL.

    A tuple containing two items is returned. The SQL update string and a list
    containing the values to be substituted into it by the database.
    """

    # Base
    sql = "UPDATE %s SET " % tableName
    f = 0

    # Go through the properties to be updated
    values = []
    for prop in props:
        if prop not in newDetails.keys() or prop in forceNull:
            continue
        c=","
        if f==0:
            f=1
            c=""
        v = newDetails[prop]
        try:
            tv = int(v)
        except ValueError:
            tv = None
        if doNull and tv==-1:
            sql = "%s%s %s=NULL" % (sql, c, prop)
        else:
            sql = "%s%s %s=%%s" % (sql, c, prop)
            values.append(v)
    # Go through the properties to be set to NULL
    for prop in forceNull:
        c=","
        if f==0:
            f=1
            c=""
        sql = "%s%s %s=NULL" % (sql, c, prop)

    # Error out if no values updated
    if f == 0:
        return (None, None)

    # Condition
    sql = "%s WHERE %s=%%s" % (sql, keyField)
    values.append(keyValue)

    return (sql, values)

def filter_keys(indict):
    """Returns the dictionary with all numeric keys removed"""
    return dict(filter(lambda x:type(x[0])!=type(0), indict.items()))

def createPassword(length):
    """Creates a new password of the specified length

    The password is created of characters from the set [A-Za-z0-9] as chosen
    by the rand.sample function, with some easily confused characters removed.
    """
    import random
    candidates = "aAbBcCdDeEfFgGhHjJkKmMnNpPqrRsStTuUvVwWxXyYzZ23456789"
    return "".join(random.sample(candidates, length))

def createSalt():
    """Creates an MD5 salt for a password

    See crypt(3) for details.
    """
    return "$1$%s$" % createPassword(8)

def ensureDirExists(dir):
    """Ensures that the specified directory exists.

    Obviously this will create parent directories too if need be.

    Returns the number of directories that were created.
    """

    # If the path exists all is good
    if os.path.exists(dir):
        return 0

    # Otherwise check if the parent path exists
    head, tail = os.path.split(dir)
    n = ensureDirExists(head)

    # Now make the directory
    os.mkdir(dir, 0750)
    return 1 + n

def ensureFileExists(file):
    """Ensures that the specified file exists.

    Obviously this will create parent directories too if need be.

    Returns True if the file was successfully created.
    """

    # If the file exists all is good
    if os.path.exists(file):
        return True

    try:
        remountrw("ensureFileExists")

        # Ensure the parent path exists
        ensureDirExists(os.path.dirname(file))

        # Touch the file
        fp = open(file, "w")
        fp.close()
        remountro("ensureFileExists")
    except:
        remountro("ensureFileExists")
        return False

    return True

def removeDir(rDir):
    """Recursively removes a directory and its children"""

    try:
        for root, dirs, files in os.walk(rDir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(rDir)
    except OSError:
        # Ignore dir not exists errors
        pass

def getIP(name):
    """Resolves the hostname to an IP address"""
    print "%s::%s : name=[%s]" % (__name__, 'getIP', name)
    try:
        return socket.gethostbyname(name)
    except:
        print "pcsd_common::getIP: invalid name=[{0}]".format(name)
        raise

def getFQDN():
    """Returns the fully qualified hostname of the current host"""
    fd = os.popen("/bin/hostname -f", "r")
    hostname = fd.read()
    fd.close()
    return hostname.strip()

def bitsToNetmask(length):
    """Retuns an integer netmask representing the given number of bits"""
    return (2 ** length) - 1L << (32 - length)
def netmaskToBits(bits):
    """Returns an integer represnting the bitlength of the given netmask"""
    if bits==0: return 0
    pos = 0
    while ((2**pos) & bits) == 0:
        pos+=1
    return 32-pos
def cidrToNetwork(cidr_network):
    """Returns an integer network address from a CIDR string of the network"""
    validateCIDR(cidr_network)
    parts = str(cidr_network).split('/')
    return ipnum(parts[0]) & bitsToNetmask(int(parts[1]))

def cidrToNetworkS(cidr_network):
    """Returns a string network address from a CIDR string of the network"""
    return formatIP(cidrToNetwork(cidr_network))

def cidrToNetmask(cidr_network):
    """Returns an integer netmask from a CIDR string of the network"""
    validateCIDR(cidr_network)
    bits = int(str(cidr_network).split('/')[1])
    return bitsToNetmask(bits)

def cidrToIP(cidr_network):
    validateCIDR(cidr_network)
    return str(cidr_network).split('/')[0]

def cidrToNetmaskS(cidr_network):
    """Returns a string netmask from a CIDR string of the network"""
    return formatIP(cidrToNetmask(cidr_network))

def cidrToBroadcast(cidr_network):
    """Returns the broadcast address from a CIDR string of the network"""
    validateCIDR(cidr_network)
    parts = str(cidr_network).split('/')
    netmask = bitsToNetmask(int(parts[1]))
    return ipbroadcast(ipnum(parts[0]), netmask)

def cidrToBroadcastS(cidr_network):
    """Returns a string broadcast address from a CIDR string of the network"""
    return formatIP(cidrToBroadcast(cidr_network))

def cidrToLength(cidr_network):
    """Returns the mask length portion of a CIDR address"""
    validateCIDR(cidr_network)
    return int(str(cidr_network).split('/')[1])

def ipnetwork(ip, netmask):
    """Calculate an integer network address from a given ip and netmask"""
    return ip & netmask

def ipbroadcast(ip, netmask):
    """Claculate an integer broadcast address from a given ip and netmask"""
    return (ip & netmask) | (pow(2L,32)-1-netmask)

def inNetwork(ip, network, netmask):
    """Returns true if the specified IP is part of the specified network"""
    return (ip & netmask)==network

def ipnum(ip_netmask):
    """Convert a IP string into an integer"""
    if (ip_netmask == 0):
        return 0
    else:
        return reduce(lambda a,b:a*256+b,
                      map(int, str(ip_netmask).split(".")),0L)

def ipcmp(a, b):
    """Compare two IP addresses"""
    return cmp(ipnum(a), ipnum(b))

def formatIP(ip):
    """Returns a string formatted IP address from a numeric ip"""

    # Make sure our input is valid
    try:
        ip = int(ip)
    except ValueError:
        return ""

    result = ""

    # Move "left" along the integer prepending the octets to the string
    step = 256
    for i in range(1,5):
       result = ".%s%s" % (str(ip%step), result)
       ip /= step

    # First char will be an extra ., strip it and return
    return result[1:]

def formatIPB(ip):
    """Returns a binary string formatted IP address from a numeric ip"""

    # Make sure our input is valid
    try:
        ip = int(ip)
    except ValueError:
        return ""

    result = ""

    # Move "left" along the integer prepending the octets to the string
    step = 256
    for i in range(1,5):
        bits = ip%step
        result = ".%s%s" % (binary(bits), result)
        ip /= step

    # First char will be an extra ., strip it and return
    return result[1:]

def binary(bits):
    """Returns a binary string for the specified octet"""
    # Make sure our input is valid
    try:
        ip = int(ip)
    except ValueError:
        return ""
    str = ""
    pos = 0
    while pos < 8:
        if (bits & (2**pos)) != 0:
            str = "1%s" % str
        else:
            str = "0%s" % str
        pos+=1
    return str

def validateCIDR(cidr_network):
    """Checks that the specified network in cidr format is valid"""
    parts = str(cidr_network).split('/')
    if len(parts) != 2:
        raise pcsd_error("Invalid CIDR format! %s" % cidr_network)
    try:
        if int(parts[1]) < 0 or int(parts[1]) > 32:
            raise pcsd_error("Invalid bitmask in CIDR expression! %s" % \
                    cidr_network)
    except:
        raise pcsd_error("Invalid bitmask in CIDR expression! %s" % \
                cidr_network)
    octets = parts[0].split(".")
    if len(octets) != 4:
        raise pcsd_error("Invalid IP format! %s" % cidr_network)
    for octet in octets:
        try:
            if int(octet) < 0 or int(octet)>255:
                raise pcsd_error("Invalid octet value in CIDR expression!" \
                        "%s" % cidr_network)
        except:
            raise pcsd_error("Invalid octet value in CIDR expression! %s" % \
                    cidr_network)

    return

def formatTime(secs, display_seconds=False):
    """Take a period of time in seconds and format it as a readable string"""

    days = hours = mins = 0

    if secs > (60*60*24):
        days = int(secs/(60*60*24))
        secs -= (days*(60*60*24))

    if secs > (60*60):
        hours = int(secs/(60*60))
        secs -= (hours*(60*60))

    if secs > 60:
        mins = int(secs/60)
        secs -= (mins*60)

    str = ""
    if days > 0:
        str += pluralise(days, "day")
        str += " "
    if hours > 0:
        str += pluralise(hours, "hour")
        str += " "
    if mins > 0:
        str += pluralise(mins, "min")
        str += " "
    if secs > 0 and display_seconds:
        str += pluralise(secs, "sec")

    return str

def roundTime(secs):
    """Takes a period of time in seconds and rounds it to the nearest unit"""

    # Years
    if secs > (60*60*24*365):
        years = int(secs/(60*60*24*365))
        return pluralise(years, "year")

    # Months
    if secs > (60*60*24*30):
        months = int(secs/(60*60*24*30))
        return pluralise(months, "month")

    # Weeks
    if secs > (60*60*24*7):
        weeks = int(secs/(60*60*24*7))
        return pluralise(weeks, "week")

    # Days
    if secs > (60*60*24):
        days = int(secs/(60*60*24))
        return pluralise(days, "day")

    # Hours
    if secs > (60*60):
        hours = int(secs/(60*60))
        return pluralise(hours, "hour")

    # Minutes
    if secs > (60):
        minutes = int(secs/(60))
        return pluralise(minutes, "minute")

    # Seconds
    return pluralise(int(secs), "sec")

def pluralise(number, root):

    if number > 1:
        return "%s %ss" % (number, root)
    else:
        return "%s %s" % (number, root)

def formatBytes(bytes):
    """Displays the number of bytes in the largest unit whose value is > 1"""

    if bytes > GIGA:
        bytes /= GIGA
        return "%2.2fGB" % bytes

    if bytes > MEGA:
        bytes /= MEGA
        return "%2.1fMB" % bytes

    if bytes > KILO:
        bytes /= KILO
        return "%2.1fKB" % bytes

    return "%sB" % bytes

def remountrw(name=None):
    """Ensures that the root drive is mounted read-write"""

    if name is None:
        name = sys.argv[0]

    os.system("/usr/bin/remountrw %s" % name)

def remountro(name=None):
    """Ensures that the root drive is mounted read-only"""

    if name is None:
        name = sys.argv[0]

    os.system("/usr/bin/remountro %s" % name)

def bisect(a, x, lo=0, hi=None, cmpfunc=cmp):
    """Return the index where to insert item x in list a, assuming a is sorted.

    The return value i is such that all e in a[:i] have e <= x, and all e in
    a[i:] have e > x.  So if x already appears in the list, i points just
    beyond the rightmost x already there.

    Optional args lo (default 0) and hi (default len(a)) bound the
    slice of a to be searched.
    """

    if hi is None:
        hi = len(a)
    while lo < hi:
        mid = (lo+hi)//2
        if cmpfunc(x,a[mid])<0: hi = mid
        else: lo = mid+1
    return lo

def do_ioctl(ifname, req):
    ifreq = (ifname + '\0'*32)[:32]
    try:
        sfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        result = fcntl.ioctl(sfd.fileno(), req, ifreq)
        sfd.close()
    except IOError:
        return None
    return result

def isAdministrativeInterface(ifname):
    """Returns true if the specified interface is classied as Administrative"""

    if ifname.startswith("lo") or ifname.startswith("dummy") or \
            ifname.endswith("-base") or ifname.startswith("vbase") or \
            ifname.startswith("wifi"):
        return True

    return False

def getInterfaces(returnAll=False, returnOne=None):
    """Reads the interface informatin from /proc"""
    interfaces = []

    f=open("/proc/net/dev", "r")
    for l in f.readlines()[2:]:
        # Parse the line
        name,l = l.strip().split(":")
        parts = [name] + l.split()
        # Store the information
        iface = {}
        iface["name"] = parts[0]
        # If we have a specific interface specified return only that
        if returnOne is not None and iface["name"] != returnOne:
            continue
        # Skip 'Administrative' interfaces, the user doesn't care about them
        if isAdministrativeInterface(iface["name"]) and not (returnAll or \
                returnOne):
            continue
        # Get interface flags
        t = do_ioctl(parts[0], SIOCGIFFLAGS)
        if t:
            iface["flags"], = struct.unpack("H", t[16:18])
        else:
            iface["flags"] = 0
        iface["up"] = iface["flags"] & IFF_UP or False
        # Skip down interfaces
        if not iface["up"] and not (returnAll or returnOne):
            continue
        rcv = {}
        rcv["bytes"] = parts[1]
        rcv["packets"] = parts[2]
        rcv["errs"] = parts[3]
        rcv["drop"] = parts[4]
        rcv["fifo"] = parts[5]
        rcv["frame"] = parts[6]
        rcv["compressed"] = parts[7]
        rcv["multicast"] = parts[8]
        iface["rcv_stats"] = rcv
        tx = {}
        tx["bytes"] = parts[9]
        tx["packets"] = parts[10]
        tx["errs"] = parts[11]
        tx["drop"] = parts[12]
        tx["fifo"] = parts[13]
        tx["frame"] = parts[14]
        tx["compressed"] = parts[15]
        tx["multicast"] = parts[16]
        iface["tx_stats"] = tx
        t = do_ioctl(parts[0], SIOCGIFADDR)
        if t:
            iface["address"] = socket.inet_ntoa(t[20:24])
        else:
            iface["address"] = ""
        t = do_ioctl(parts[0], SIOCGIFNETMASK)
        if t:
            iface["address"] += "/%s" % \
                    netmaskToBits(ipnum(socket.inet_ntoa(t[20:24])))
        t = do_ioctl(parts[0], SIOCGIFHWADDR)
        if t:
            iface["mac"] = ""
            for b in t[18:24]:
                iface["mac"] += "%02x:" % ord(b)
            iface["mac"] = iface["mac"][:len(iface["mac"])-1]
        else:
            iface["mac"] = ""
        t = do_ioctl(parts[0], SIOCGIFINDEX)
        if t:
            iface["ifindex"] = int(struct.unpack("I",t[16:20])[0])
        else:
            iface["ifindex"] = -1
        t = do_ioctl(parts[0], SIOCGIFMTU)
        if t:
            iface["mtu"] = int(struct.unpack("I",t[16:20])[0])
        else:
            iface["mtu"] = -1
        flag_str = []
        for flag, char in IFACE_FLAG_CHARS.items():
            if (iface["flags"] & flag)==flag:
                flag_str.append(char)
        iface["flag_str"] = flag_str
        interfaces.append(iface)
    f.close()

    return interfaces

def getInterfaceNames(returnAll=False):
    """Return a list of internet names"""
    interfaces = []

    f=open("/proc/net/dev", "r")
    for l in f.readlines()[2:]:
        # Parse the line
        name,l = l.strip().split(":")
        # Skip 'Administrative' interfaces, the user doesn't care about them
        if isAdministrativeInterface(name) and not returnAll:
            continue
        interfaces.append(name)
    f.close()

    return interfaces

def getRoutes():
    """Reads the routing table from /proc"""
    routes = []

    f=open("/proc/net/route","r")
    for l in f.readlines()[1:]:
        # Parse the line
        iface,network,gateway,flags,x,x,metric,mask,x,x,x = l.split()
        # Parse the flags
        flags = int(flags, 16)
        flag_str = ""
        for flag, char in ROUTE_FLAG_CHARS.items():
            if (flags & flag)==flag:
                flag_str += char
        # Store the values
        route = {}
        route["network"] = formatIP(socket.ntohl(long(network, 16)))
        route["gateway"] = formatIP(socket.ntohl(long(gateway, 16)))
        route["netmask"] = formatIP(socket.ntohl(long(mask, 16)))
        route["iface"] = iface
        route["metric"] = metric
        route["flags"] = flag_str
        routes.append(route)
    f.close()

    # Kernel gives us a list sorted by netmask length, sort by prefix
    # as well
    routes.sort(route_cmp)

    return routes

def getLinkMACs(iface):
    """Returns a dictionary of ip:mac for all ARP entries on the link"""

    macs = {}

    fh = os.popen("/sbin/ip neigh show dev %s" % iface)
    output = fh.readlines()
    rv = fh.close()
    for line in output:
        parts = line.strip().split(" ")
        if parts[-1] != "reachable":
            continue
        macs[parts[0]] = parts[2].lower()

    return macs

def getiwspyMAC(iface):

    fh = os.popen("/sbin/iwspy %s" % iface)
    output = fh.readlines()
    rv = fh.close()
    if len(output) < 2: return ""
    parts = output[1].strip().split(" : ")
    mac = parts[0]
    if isValidMAC(mac):
        return mac.lower()
    return ""

def getTrafficCounters():
    """Returns a dictionary of the current traffic counters for each interface"""
    ifaces = {}

    # Read /proc
    try:
        fp = open("/proc/net/dev", "r")
        lines = fp.readlines()
        fp.close()
    except:
        log_error("Could not read interface traffic counters!", sys.exc_info())
        return ifaces

    # Parse values, skip first two header lines
    for line in lines[2:]:
        parts = line.strip().split(":")
        if len(parts) != 2:
            log_warn("Ignoring invalid /proc/net/dev line: %s" % line)
            continue
        ifname = parts[0].strip()
        counters = parts[1].strip().split()
        if len(counters) != 16:
            log_warn("Ignoring invalid /proc/net/dev entry '%s': %s" % \
                    (ifname, parts[2]))
            continue
        iface = {"rx":long(counters[0]), "rx_packets":long(counters[1]), \
                "tx":long(counters[8]), "tx_packets":long(counters[9])}
        ifaces[ifname] = iface

    return ifaces

def route_cmp(a, b):
    """Comparison function to sort the route table by netmask then prefix"""

    # Compare netmask first
    rv = cmp(ipnum(a["netmask"]), ipnum(b["netmask"]))
    if rv != 0:
        return rv*-1

    # Equal netmasks compare prefixes
    return cmp(ipnum(a["network"]), ipnum(b["network"]))*-1

def getIfaceForIP(ipaddr):
    """Returns the name of the interface this IP address is connected to

    Assumes no assymetric routing.
    """

    ip = ipnum(ipaddr)
    iface = None

    # Find the interface we would route to that client on
    routes = getRoutes()
    for r in routes:
        if not inNetwork(ip, ipnum(r["network"]), ipnum(r["netmask"])):
            continue
        # Found the network
        iface = r["iface"]
        break

    return iface

def getIfaceIPForIP(ipaddr):
    """Returns the IP address of the iface connected to the specified IP

    We assume that we don't have assymetric any routing
    """

    # Find the interface we would route to that client on
    iface = getIfaceForIP(ipaddr)

    # Return the IP address for that interface
    ifaces = getInterfaces()
    for i in ifaces:
        if i["name"] != iface:
            continue
        return cidrToIP(i["address"])

    # Uh-oh
    return ""

def getNeighbourIP(ifname):
    """Returns the IP address of the interfaces neighbour

    Assumes that if this interface has the lowest IP in the network, the
    neighbour will have the highest, and vice versa. If this interface has
    neither the lowest or the highest IP address, then the lowest IP is
    returned.
    """

    iface = getInterfaces(returnOne=ifname)
    if len(iface)!=1:
        return ""
    iface = iface[0]

    ip = ipnum(cidrToIP(iface["address"]))
    net = cidrToNetwork(iface["address"])
    mask = cidrToNetmask(iface["address"])
    bcast = ipbroadcast(net, mask)

    # If this interface has the lowest IP, neighbour is the highest
    if ip == (net+1):
        return formatIP(bcast-1)

    # Otherwise return the lowest
    return formatIP(net+1)

def ensureFileContains(search, stanza, file):
    """Checks whether the specified file contains the specified stanza

    Searchs for this stanza using the regexp specified in search. If this
    regexp does not match any part of the file then the stanza is appended
    to the end.
    """

    # Open file and read all lines
    fp = open(file, "r")
    if not fp:
        return False
    content = "".join(fp.readlines())
    fp.close()

    if re.search(search, content) is not None:
        # Stanza found
        return True

    # Not found, insert
    return appendFile(stanza, file)

def filterFile(search, replace, file):
    """Filters all lines of the file

    Replacing all instances of search with the value of replace.
    """

    # Open file and read all lines
    fp = open(file, "r")
    if not fp:
        return False
    lines = fp.readlines()
    fp.close()

    # Perform the substitution
    nlines = [re.sub(search, replace, line) for line in lines]

    # Check if the replace value is found, return false if not
    tstr = "\n".join(nlines)
    if tstr.find(replace) == -1:
        return False

    # Write out the file again
    fp = open(file, "w")
    if not fp:
        return False
    fp.writelines(nlines)
    fp.close()

    return True

def appendFile(string, file):
    """Appends the string to the file"""
    fp = open(file, "a")
    if not fp:
        return False
    fp.write(string)
    fp.close()

    return True

def getSoekrisMac(serial, iface=0):
    """Returns (in hexadecimal format) the MAC address for a soekris interface

    The mac address is derived from the soekris serial number via the format
    described in the following mailing post:
    http://lists.soekris.com/pipermail/soekris-tech/2005-August/023941.html

    For posterity:
    00 00 24 CX XX XX, where the XXXXX are the serial number from label on
    the bottom multiplied by 4, then add 0, 1, 2 for each eth controller.
    """
    serial = int(serial)

    if serial < 0 or serial > 0xFFFFF:
        raise pcsd_error("Invalid soekris Serial number!")
    if iface < 0 or iface > 3:
        raise pcsd_error("Invalid interface number!")

    # Calculation is easy
    mac = serial*4 + iface

    # Now convert to hexadecimal
    hexmac = "%05x" % mac
    return "00:00:24:c%s:%s:%s" % (hexmac[0:1], hexmac[1:3], hexmac[3:])

def getSoekrisSerial(mac):
    """Returns the serial number for a soekris given the MAC of eth0

    See the getSoekrisMac function for details of how this works.

    The incoming mac must be formatted as:
    XX:XX:XX:XX:XX:XX
    """

    if len(mac) != 17 or not \
            (mac.startswith("00:00:24:c") or mac.startswith("00:00:24:C")):
        # Invalid MAC address
        raise pcsd_error("Invalid soekris MAC address")

    serial = int(mac.replace(":", "")[-5:], 16)/4
    return serial

def getGatewayIP():
    """Parses the routing table to retrieve the default GW IP address"""

    routes = getRoutes()
    if len(routes) <= 0:
        return ""

    # Try the last one first
    t = routes[len(routes)-1]
    if t["network"]=="0.0.0.0" and t["netmask"]=="0.0.0.0":
        return t["gateway"]

    # Loop through
    for route in routes:
        if route["network"]=="0.0.0.0" and route["netmask"]=="0.0.0.0":
            return t["gateway"]

    # No default gateway
    return ""


def getGatewayIface():
    """Parses the routing table to retrieve the default GW interface"""

    routes = getRoutes()
    if len(routes) <= 0:
        return ""

    # Try the last one first
    t = routes[len(routes)-1]
    if t["network"]=="0.0.0.0" and t["netmask"]=="0.0.0.0":
        return t["iface"]

    # Loop through
    for route in routes:
        if route["network"]=="0.0.0.0" and route["netmask"]=="0.0.0.0":
            return t["iface"]

    # No default gateway
    return ""

def isHostUp(ip):
    """Using fping to test whether a host is alive"""
    if ip == "" or ip is None:
        return 0
    command = "fping -am  %s" % ip
    result = os.popen("%s 2>/dev/null" % command).readlines()
    return len(result)

def getNeighbourMAC(neigh_ip):
    """Returns the MAC address for a directly connected neighbour"""

    # Ping the neighbour first to ensure we have an ARP entry
    os.system("fping -c 1 -r 1 -a %s 2>/dev/null" % neigh_ip)

    # Read the arp cache from /proc
    fp = open("/proc/net/arp", "r")
    lines = fp.readlines()
    fp.close()

    for line in lines[1:]:
        parts = line.strip().split()
        if len(parts) != 6:
            continue
        if parts[0] == neigh_ip:
            return parts[3]

    # Not found
    return None

def processExists(pname):
    """Returns true if the named process is currently running"""
    fh = os.popen("/bin/ps | /bin/grep %s | /bin/grep -v grep" % pname)
    output = fh.readlines()
    rv = fh.close()
    if len(output) > 0:
        return True
    return False

def isValidMAC(mac):
    """Checks that the specified MAC address is valid"""

    if re.match("^([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}$", mac.lower()) is None:
        return False

    return True

def split_mac(mac):
    """Break the mac address into bytes, ensure 0 padding"""

    m = mac.split(":")
    if len(m) != 6 or len(mac) > 17:
        syslog.syslog(syslog.LOG_ERROR, "Invalid MAC: %s" % mac)
        return False
    m = [ len(t)==2 and t or "0%s" % t for t in m ]
    return m

def isValidIP(ip):
    """Checks that the specified IP address is valid"""
    # Check format
    if re.match("^([0-9]{1,3}\.){3}[0-9]{1,3}$", ip) is None:
        return False
    # Check octets
    parts = ip.split(".")
    for part in parts:
        if int(part)<0 or int(part)>255:
            return False
    # All good
    return True

def setInterfaceForwardingState(ifname, forward):
    """Enables or disables forwarding on an interface"""
    fp = open("/proc/sys/net/ipv4/conf/%s/forwarding" % ifname, "w")
    fp.write(forward and "1" or "0")
    fp.close()
