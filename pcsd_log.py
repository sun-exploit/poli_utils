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
import sys
import os
import os.path
import signal
import syslog
import traceback
import time

_isDaemon = 0
_verbose = 0
_tracebackLog = None

def setVerbose():
    global _verbose
    _verbose = 1

def isVerbose():
    if _verbose:
        return True
    else:
        return False

def setDaemonStatus(val, name=None):
    global _isDaemon
    _isDaemon = val
    if _isDaemon:
        if name is None: name = os.path.basename(sys.argv[0])
        syslog.openlog(name, syslog.LOG_PID, syslog.LOG_DAEMON)

def setTracebackLog(log=None):
    global _tracebackLog
    _tracebackLog = log

def prepareTraceback(exc_info):
    if exc_info is None:
        return ""
    (type, value, tb) = exc_info
    return traceback.format_exception(type, value, tb)

def log_tb(exc_info, msg=""):
    global _tracebackLog
    tb = prepareTraceback(exc_info)
    if len(tb) <= 0 and msg == "":
        return
    if _tracebackLog is None:
        return
    try:
        fd = open(_tracebackLog, "a")
        fd.write("%s\n" % time.ctime())
        if msg!="": fd.write("%s\n" % msg)
        for line in tb: fd.write(line)
        fd.write("")
        fd.close()
    except:
        (etype, value, etb) = sys.exc_info()
        log_error("Failed to write traceback logfile: %s" % value)

def log_debug(msg, exc_info=None):
    """Logs a debugging message"""
    global _isDaemon
    if not _isDaemon:
        sys.stderr.write("D: %s\n" % msg)
    log_tb(exc_info, msg)

def log_info(msg, exc_info=None):
    """Logs an information message"""
    global _isDaemon
    if _isDaemon:
        syslog.syslog(syslog.LOG_INFO, msg)
    else:
        sys.stdout.write("I: %s\n" % msg)
    log_tb(exc_info)

def log_notice(msg, exc_info=None):
    """Logs an notice message"""
    global _isDaemon
    if _isDaemon:
        syslog.syslog(syslog.LOG_NOTICE, msg)
    else:
        sys.stdout.write("N: %s\n" % msg)
    log_tb(exc_info)

def log_warn(msg, exc_info=None):
    """Logs a warning message"""
    global _isDaemon
    if _isDaemon:
        syslog.syslog(syslog.LOG_WARNING, msg)
    else:
        sys.stderr.write("W: %s\n" % msg)
    log_tb(exc_info)

def log_error(msg, exc_info=None):
    """Logs an error message"""
    global _isDaemon
    tb = prepareTraceback(exc_info)
    if _isDaemon:
        syslog.syslog(syslog.LOG_ERR, msg)
    else:
        sys.stderr.write("E: %s\n" % msg)
    log_tb(exc_info)

def log_fatal(msg, exc_info=None):
    """Logs a fatal error message and exits"""
    global _isDaemon
    tb = prepareTraceback(exc_info)
    if _isDaemon:
        for line in tb: syslog.syslog(syslog.LOG_CRIT, line.strip())
        syslog.syslog(syslog.LOG_CRIT, msg)
    else:
        sys.stderr.write("F: %s\n" % msg)
    log_tb(exc_info)
    # Tell ourselves to shutdown!
    os.kill(os.getpid(), signal.SIGTERM)

def log_command(command):
    with os.popen(command) as fh:
        output = fh.readlines()
    rv = fh.close()
    str = "".join(output).strip()
    if rv != None and len(str)>0:
        log_debug("Command (%s) output:\n %s" % (command, str))
    return rv

def log_custom(file, msg):
    try:
        fd = open(file, "a")
        fd.write("%s " % time.ctime())
        fd.write("%s\n" % msg)
        fd.close()
    except:
        (etype, value, etb) = sys.exc_info()
        log_error("Failed to write to custom logfile(%s): %s" % (file,msg))

