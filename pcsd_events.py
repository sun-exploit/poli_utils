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
from pcsd_config import config_get

class pcs_event_error(pcsd_error):
    pass

# The list of events
_events = {}

def registerEvent(eventName):
    """Decorator function to register an event.

    This decorator is used by functions that may trigger the specified event
    sometime during processing. It should be called once for every event that
    the function could fire.
    """

    if eventName == "":
        raise pcs_event_error("Invalid event name!")

    if eventName in _events.keys():
        return lambda f:f

    # Create a new dictionary to hold callback functions for the event
    event = {}
    event["eventName"] = eventName
    event["eventHostId"] = -1
    event["eventCallbacks"] = {}
    _events[eventName] = event
    log_debug("Registered event: %s" % eventName)

    # Continue on, noop decorator
    return lambda f:f


def triggerEvent(session_id, eventName, **kwargs):
    """Calls each of the registered functions for an normal event"""

    return triggerHostEvent(session_id, eventName, -1, **kwargs)

def triggerHostEvent(session_id, eventName, host_id, **kwargs):
    """Calls each of the registered functions for a host event

    If host_id is -1 the event is not a host event.
    """

    rvs = {}

    if not eventName in _events.keys():
        raise pcs_event_error("Unknown event!");

    for name,function in _events[eventName]["eventCallbacks"].items():
        try:
            print "triggerHostEvent::%s(eventName=%s, host_id=%s, session_id=%s, %s)" %\
                (function,eventName, host_id, session_id, kwargs)
            rv = function(eventName=eventName, host_id=host_id, \
                    session_id=session_id, **kwargs)
        except SystemExit:
            raise
        except:
            log_error("Failed to process callback (%s) for event %s" % \
                    (name, eventName), sys.exc_info())
            rv = None
        rvs[name] = rv

    return rvs

def catchEvent(eventName, cbFunc=None):
    """Decorator function to register a function as an event catcher.

    This decorator should be placed on functions who want to catch the
    specified event.

    If the second parameter (cbFunc) is specified, the function does not
    act as a decorator and simply registers the specified function to
    catch the event.
    """
    # Register the event if it's not already registered. Hopefully something
    # that triggers it will check in soon, otherwise this callback is useless!
    if not eventName in _events.keys():
        registerEvent(eventName)

    # Handle being called as a normal function
    if cbFunc is not None:
        _events[eventName]["eventCallbacks"][cbFunc.func_name] = cbFunc
        return

    # The real decorator function we will return
    def decorator(func):
        _events[eventName]["eventCallbacks"][func.func_name] = func
        log_debug("Added callback on %s to %s" % (eventName, func.func_name))
        return func

    return decorator
