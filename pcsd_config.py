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
import os.path
import ConfigParser
import getopt
import traceback
from pcsd_common import *
from pcsd_log import *

class pcs_config_error(pcsd_error):
    pass

_config = None

def config_init():
    global _config

    try:
        # Read configuration from config file
        _config = ConfigParser.ConfigParser()

        # Add config file specified on command line
        conffile = ""
        optlist, args = getopt.gnu_getopt(sys.argv[1:], OPTION_LIST)
        for (arg, val) in optlist:
            if arg == "-c":
                conffile =  val
            if arg == "-v":
                setVerbose()

        if not os.path.isfile(conffile) and \
           not os.path.isfile(DEFAULT_CONFFILE):
            raise

        print "D: pcsd_config::config_init : DEFAULT_CONFFILE=[%s], conffile=[%s]" \
            % (DEFAULT_CONFFILE, conffile)

        _config.read([DEFAULT_CONFFILE, conffile])

    except:
        (type, value, tb) = sys.exc_info()
        try:
            # pcsd_log may not have been initialised yet...
            log_fatal("Could not read configuration file!", sys.exc_info())
        except:
            print "Could not read configuration file!"
            for line in traceback.format_exception(type, value, tb):
                print line.strip()
            sys.exit(1)

def config_get(section, option, default=None, raw=0, vars=None, obj=None):
    """Get a value from the configuration, with a default."""
    print "%s::%s : section=[%s], option=[%s]" % (__name__, 'config_get', section, option)
    global _config
    if obj is None: obj=_config
    if obj is None: return default
    if section is None:
        section = os.path.basename(sys.argv[0])
    if obj.has_option(section, option):
        return obj.get(section, option, raw=raw, vars=None)
    else:
        print "%s::%s : no option for %s" % (__name__, 'config_get', section)
        return default
def config_getint(section, option, default=None, obj=None):
    """Get an integer value from the configuration, with a default."""
    global _config
    if obj is None: obj=_config
    if obj is None: return default
    if section is None:
        section = os.path.basename(sys.argv[0])
    if obj.has_option(section, option):
        return obj.getint(section, option)
    else:
        return default
def config_getboolean(section, option, default=None, obj=None):
    """Get a boolean value from the configuration, with a default."""
    global _config
    if obj is None: obj=_config
    if obj is None: return default
    if section is None:
        section = os.path.basename(sys.argv[0])
    if obj.has_option(section, option):
        return obj.getboolean(section, option)
    else:
        return default
def config_get_required(section, option, raw=0, vars=None, obj=None):
    print "%s::%s : section=[%s], option=[%s]" % (__name__, 'config_get_required', section, option)
    global _config
    if obj is None: obj=_config
    if obj is None: return default
    if section is None:
        section = os.path.basename(sys.argv[0])
    if obj.has_option(section,option):
        return obj.get(section, option, raw=raw, vars=None)
    else:
        raise pcs_config_error("Configuration file is missing required " \
                "value '%s' from section '%s'" % (option , section))

def init_pref_store(preffile):
    """Open a configuration file to use for preference storage

    There is no real difference between this file and any other, except we
    return the configparser handle to the user instead of keeping it globally
    to allow the user to manage multiple preference stores if desired.
    """
    # Initialise a preference store object
    pref = ConfigParser.ConfigParser()
    pref.pcsd_filename = preffile

    # Read from the preference file
    pref.read(preffile)

    return pref

def pref_get(section, option, store, default=None):
    """Returns a preference from the specified preference store"""
    return config_get(section, option, default=default, obj=store)
def pref_getint(section, option, store, default=None):
    """Returns a preference from the specified preference store"""
    return config_getint(section, option, default=default, obj=store)
def pref_getboolean(section, option, store, default=None):
    """Returns a preference from the specified preference store"""
    return config_getboolean(section, option, default=default, obj=store)
def pref_set(section, option, value, store):
    """Sets a preference to the specified value"""
    # Can't store a preference in an invalid store
    if store is None:
        log_error("Invalid preference stored passed to pref_set!")
        return None
    if section is None:
        section = os.path.basename(sys.argv[0])
    if not store.has_section(section):
        store.add_section(section)
    store.set(section, option, value)
    try:
        remountrw()
        fp = open(store.pcsd_filename, "w")
        store.write(fp)
        fp.close()
    finally:
        remountro()
