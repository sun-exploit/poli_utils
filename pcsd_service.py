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
#   Service Class - Provides basic service functionality for the configuration
#   system. This class is intended to be overriden by service specific classes.
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
import inspect

from pcsd_common  import *
from pcsd_log     import *
from pcsd_events  import *
from pcsd_server  import exportViaXMLRPC, processClassMethods
from pcsd_session import getSession, getSessionE

class pcsd_service_error(pcsd_error):
    pass

class pcsd_service(pcs_class):
    """Base class to implement a service in the configuration system

    This class should never be used directly for a service, instead it
    should be subclassed to implement logic for specific services.
    """

    # Implementing classes must define the following members
    # serviceName
    # allowNewProperties
    # networkService

    def __init__(self, session_id, service_id):
        """Initialises a new class for a specified service.

        The specified session must be valid and have appropriate access to
        the database for the tasks you intend to perform with the class. All
        database access / configuration manipulation triggered by this
        instance will pass through the specified session.
        """

        self._errMsg = ""
        self._commit = 0
        self._csInit = ""
        self._service = {}
        self._structure = {}

        session = getSession(session_id)
        if session is None:
            raise pcsd_service_error("Invalid session id")
        self._session_id = session_id
        log_debug("pcsd_service::pcsd_service class, session_id=[{0}]".format(session_id))

        # See if the specified service id makes sense
        sql = "SELECT * FROM service WHERE service_id=%s"
        res = session.query(sql, (service_id))
        if len(res) < 1:
            raise pcsd_service_error("Invalid service. Unable to retrieve "
                "details")

        # Store details
        if not hasattr(self, "service_id"):
            self.service_id = service_id
        if not hasattr(self, "serviceName"):
            self.serviceName = res[0]["service_name"]
        self._service = res[0]
        self._properties = {}

        # Read service property structure & data
        res = session.query("SELECT * FROM service_prop WHERE service_id=%s", \
                (self.service_id))
        for prop in res:
            prop["value"] = None
            prop["network_value"] = None
            self._properties[prop["prop_name"]] = prop

    @registerEvent("serviceRemoved")
    @exportViaXMLRPC(SESSION_RW, AUTH_ADMINISTRATOR, True)
    def removeService(self, host_id):
        """Removes the service from the host."""
        session = getSessionE(self._session_id)

        # Raise an event
        triggerHostEvent(self._session_id, "serviceRemoved", host_id, \
                service_id=self.service_id)

        self._forceChangeset("Removing service from host")

        # Delete service from the host
        res = session.execute("DELETE FROM service_host WHERE service_id=" \
                "%s AND host_id=%s", (self.service_id, host_id))
        res = session.execute("DELETE FROM service_hostdata WHERE " \
                "service_id=%s AND host_id=%s", (self.service_id, host_id))

        return self.returnSuccess()

    @registerEvent("serviceAdded")
    @exportViaXMLRPC(SESSION_RW, AUTH_ADMINISTRATOR, True)
    def addService(self, host_id):
        """Adds the specified service to this host"""
        from modules.pcs_host import validateHostId

        session = getSessionE(self._session_id)

        validateHostId(self._session_id, host_id)

        # If there are required properties service must be disabled initially
        if self.hasPropRequiringData():
            session.execute("INSERT INTO service_host (service_id, host_id, " \
                    "enabled) VALUES (%s, %s, %s)", \
                    (self.service_id, host_id, "f"))
        else:
            session.execute("INSERT INTO service_host (service_id, host_id, " \
                    "enabled) VALUES (%s, %s, NULL)", \
                    (self.service_id, host_id))

        triggerHostEvent(self._session_id, "serviceAdded", host_id, \
                service_id=self.service_id)

        return True

    @registerEvent("servicePropertyModified")
    @exportViaXMLRPC(SESSION_RW, AUTH_ADMINISTRATOR, True, \
            "updateServiceHostProperty")
    def updateHostProperty(self, host_id, propName, propValue):
        """Updates the details of the service.

        Returns SUCCESS.
        """
        session = getSessionE(self._session_id)

        ################## Validate incoming data ##################

        if propName not in self._properties.keys():
            raise pcsd_service_error("Unknown service property!")
        validateServiceProp(self._session_id, self._properties[propName], \
                propValue, self.getHostState(host_id))

        ################## Update the database ##################

        n = session.getCountOf("SELECT count(*) FROM service_hostdata WHERE " \
                "service_prop_id=%s AND service_id=%s AND host_id=%s", \
                (self._properties[propName]["service_prop_id"], \
                self.service_id, host_id))

        # Build SQL
        if n>0:
            sql = "UPDATE service_hostdata SET value=%s WHERE " \
                    "service_prop_id=%s AND service_id=%s AND host_id=%s"
            session.execute(sql, (propValue, \
                    self._properties[propName]["service_prop_id"], \
                    self.service_id, host_id))
        else:
            sql = "INSERT INTO service_hostdata (service_id, host_id, " \
                    "service_prop_id, value) VALUES (%s, %s, %s, %s)"
            session.execute(sql, (self.service_id, host_id, \
                    self._properties[propName]["service_prop_id"], propValue))

        # Raise the event
        triggerHostEvent(self._session_id, "servicePropertyModified", \
                service_id=self.service_id, host_id=host_id, \
                service_prop_id=self._properties[propName]["service_prop_id"])

        ################## Clean Up and Return ##################
        return self.returnSuccess()

    @registerEvent("servicePropertyModified")
    @exportViaXMLRPC(SESSION_RW, AUTH_ADMINISTRATOR, True, \
            "clearServiceHostProperty")
    def clearHostProperty(self, host_id, propName):
        """Removes the property for the service_hostdata table.

        Returns SUCCESS.
        """
        session = getSessionE(self._session_id)

        ################## Validate incoming data ##################

        if propName not in self._properties.keys():
            raise pcsd_service_error("Unknown service property!")

        ################## Update the database ##################

        session.execute("DELETE FROM service_hostdata WHERE " \
                "service_prop_id=%s AND service_id=%s AND host_id=%s", \
                (self._properties[propName]["service_prop_id"], \
                self.service_id, host_id))

        # Raise the event
        triggerHostEvent(self._session_id, "servicePropertyModified", \
                service_id=self.service_id, host_id=host_id, \
                service_prop_id=self._properties[propName]["service_prop_id"])

    @registerEvent("servicePropertyModified")
    @exportViaXMLRPC(SESSION_RW, AUTH_ADMINISTRATOR, True, \
            "updateServiceProperty")
    def updateProperty(self, propName, propValue):
        """Updates the details of the service.

        Returns SUCCESS.
        """
        session = getSessionE(self._session_id)

        ################## Validate incoming data ##################

        if propName not in self._properties.keys():
            raise pcsd_service_error("Unknown service property!")
        validateServiceProp(self._session_id, self._properties[propName], \
                propValue)

        ################## Update the database ##################

        n = session.getCountOf("SELECT count(*) FROM service_data WHERE " \
                "service_prop_id=%s AND service_id=%s", \
                (self._properties[propName]["service_prop_id"], \
                self.service_id))

        # Build SQL
        if n>0:
            sql = "UPDATE service_data SET value=%s WHERE " \
                    "service_prop_id=%s AND service_id=%s"
            session.execute(sql, (propValue, \
                    self._properties[propName]["service_prop_id"], \
                    self.service_id))
        else:
            sql = "INSERT INTO service_data (service_id, " \
                    "service_prop_id, value) VALUES (%s,%s, %s)"
            session.execute(sql, (self.service_id, \
                    self._properties[propName]["service_prop_id"], propValue))

        # Raise the event
        triggerEvent(self._session_id, "servicePropertyModified", \
                service_id=self.service_id, \
                service_prop_id=self._properties[propName]["service_prop_id"])

        ################## Clean Up and Return ##################
        return self.returnSuccess()

    @registerEvent("servicePropertyModified")
    @exportViaXMLRPC(SESSION_RW, AUTH_ADMINISTRATOR, True, \
            "clearServiceProperty")
    def clearProperty(self, propName):
        """Removes the property for the service_data table.

        Returns SUCCESS.
        """
        session = getSessionE(self._session_id)

        ################## Validate incoming data ##################

        if propName not in self._properties.keys():
            raise pcsd_service_error("Unknown service property!")

        ################## Update the database ##################

        session.execute("DELETE FROM service_data WHERE " \
                "service_prop_id=%s AND service_id=%s", \
                (self._properties[propName]["service_prop_id"], \
                self.service_id))

        # Raise the event
        triggerEvent(self._session_id, "servicePropertyModified", \
                service_id=self.service_id, \
                service_prop_id=self._properties[propName]["service_prop_id"])

    @exportViaXMLRPC(SESSION_RO, AUTH_ADMINISTRATOR, True, "getServiceDetails")
    def getDetails(self):
        """Returns a detailed object describing the service"""
        session = getSessionE(self._session_id)

        service = self._service
        service["properties"] = self._properties
        for prop in self._getData():
            service["properties"][prop["prop_name"]]["network_value"] = \
                    prop["value"]

        return service

    def _getData(self):
        """Retrieves the service data"""
        session = getSessionE(self._session_id)

        return session.query("SELECT sp.prop_name, sd.value FROM " \
                "service_prop sp LEFT JOIN service_data sd ON " \
                "sp.service_prop_id=sd.service_prop_id WHERE " \
                "sp.service_id=%s", (self.service_id))

    def _getHostData(self, host_id):
        """Retrieves the service data for the specified host"""
        session = getSessionE(self._session_id)

        return session.query("SELECT sp.prop_name, shd.value FROM " \
                "service_prop sp LEFT JOIN service_hostdata shd ON " \
                "sp.service_prop_id=shd.service_prop_id WHERE " \
                "sp.service_id=%s AND shd.host_id=%s", \
                (self.service_id, host_id))

    @exportViaXMLRPC(SESSION_RO, AUTH_ADMINISTRATOR, True, \
            "getServiceHostDetails")
    def getHostDetails(self, host_id):
        """Returns data relating to a service instance on a host"""
        session = getSessionE(self._session_id)

        res = session.query("SELECT * FROM service_host WHERE " \
                "service_id=%s AND host_id=%s", (self.service_id, host_id))
        if len(res) < 1:
            raise pcsd_service_error("Service is not configured on host!")

        service = self._service
        service["service_host_enabled"] = res[0]["enabled"]
        service["properties"] = self.getPropertyData(host_id)

        return service

    def getPropertyData(self, host_id=-1):
        """Returns a dictionary of all the properties for the service

        For each property the default, network-wide and host specific
        (if a host was specified) value is provided.
        """

        properties = self._properties
        if host_id != -1:
            for prop in self._getHostData(host_id):
                properties[prop["prop_name"]]["value"] = prop["value"]
        for prop in self._getData():
            properties[prop["prop_name"]]["network_value"] = prop["value"]

        return properties

    def getPropertyValues(self, host_id=-1):
        """Returns a simple dictionary mapping for each property

        The most specific available value for each property is chosen to
        be returned. Host beats network, network beats default. The default
        value is only used if the property is required. A non-required
        property with a default value will return an empty string, 0 or false.
        """

        variables = {}

        # Determine value for each property
        for propName, prop in self.getPropertyData(host_id).items():
            if host_id == -1 or prop["value"] is None or prop["value"] == "":
                if prop["network_value"] is None or \
                        prop["network_value"] == "":
                    variables[propName] = prop["default_value"]
                else:
                    variables[propName] = prop["network_value"]
            else:
                variables[propName] = prop["value"]
            # Ensure type is correct
            if prop["prop_type"] == "integer":
                try:
                    variables[propName] = int(variables[propName])
                except:
                    variables[propName] = 0
            elif prop["prop_type"] == "boolean":
                if variables[propName]=="t":
                    variables[propName] = True
                else:
                    variables[propName] = False
            else:
                variables[propName] = str(variables[propName])

        return variables

    @registerEvent("serviceHostStateChanged")
    @exportViaXMLRPC(SESSION_RW, AUTH_ADMINISTRATOR, True)
    def changeServiceHostState(self, host_id, state):
        """Enables or Disables the specified service on a host basis"""
        session = getSessionE(self._session_id)

        if state!="t" and state!="f" and state!="":
            raise pcsd_service_error("Invalid state value!")

        if state=="":
            session.execute("UPDATE service_host SET enabled=NULL WHERE " \
                    "service_id=%s AND host_id=%s", (self.service_id, host_id))
        else:
            session.execute("UPDATE service_host SET enabled=%s WHERE " \
                    "service_id=%s AND host_id=%s", \
                    (state, self.service_id, host_id))

        triggerHostEvent(self._session_id, "serviceHostStateChanged", host_id,
                service_id=self.service_id)

        return state

    @exportViaXMLRPC(SESSION_RO, AUTH_ADMINISTRATOR, True, \
            "getServiceState")
    def getState(self):
        """Returns the current state of the service"""

        if self._service["enabled"]:
            return True
        return False

    @exportViaXMLRPC(SESSION_RO, AUTH_ADMINISTRATOR, True, \
            "getServiceHostState")
    def getHostState(self, host_id):
        """Returns the current state of the service on the host.

        If the service is not added to the host False will be returned.
        """
        session = getSessionE(self._session_id)

        res = session.query("SELECT enabled FROM service_host WHERE " \
                "service_id=%s AND host_id=%s", (self.service_id, host_id))

        # If there are no record then not enabled on host, False
        if len(res) <= 0:
            return False

        # If enabled is NULL use the global service value
        if res[0]["enabled"] == None or res[0]["enabled"]=="":
            return self.getState()

        # Otherwise use the explicit host value
        return res[0]["enabled"]

    def getHostList(self):
        """Returns a list of hosts that this service is configured on"""
        session = getSessionE(self._session_id)

        hosts = []
        res = session.query("SELECT h.host_name, h.host_active FROM " \
                "service_host sh, host h WHERE sh.host_id=h.host_id " \
                "AND sh.service_id=%s", (self.service_id))
        for host in res:
            hosts.append(host["host_name"])

        return hosts

    def getEnabledHostList(self):
        """Returns a list of hosts that this service is enabled on"""
        session = getSessionE(self._session_id)

        hosts = []
        res = session.query("SELECT h.host_name, h.host_active, sh.enabled " \
                "FROM service_host sh, host h WHERE sh.host_id=h.host_id " \
                "AND sh.service_id=%s", (self.service_id))
        for host in res:
            # Host is enabled if the host is active, and the service is
            # explicitly enabled, or has no host enable state
            if host["host_active"] and host["enabled"] == "" or host["enabled"]:
                hosts.append(host["host_name"])

        return hosts

    def getTemplateVariables(self, host_id=-1):
        """Returns a dictionary containing template variables.

        Template variables contain information about this service that may be
        used in templates. This function attempts to be as comprehensive as
        possible in returning information about the service.

        There are two ways to call this method. One passes a host_id and
        the returned dictionary contains information for that host only.
        The second passes no host_id (or -1) and returns information on
        all hosts that use this service on the network.

        WARNING: The returned dictionary could be very large!
        """

        if host_id != -1:
            return self.getHostTemplateVariables(host_id)
        else:
            return self.getNetworkTemplateVariables()

    def getHostTemplateVariables(self, host_id):
        """Returns a dictionary containing template variables for a host

        See the getTemplateVariables function for more details.
        """
        variables = {}
        name = self._service["service_name"]

        variables["service_name"] = name
        variables["%s_enabled" % name] = self.getHostState(host_id)

        # Include service properties
        variables.update(self.getPropertyValues(host_id))

        return variables

    def getNetworkTemplateVariables(self):
        """Returns a dictionary containing template variables for all hosts

        See the getTemplateVariables function for more details.
        """
        variables = {}
        name = self._service["service_name"]

        variables["service_name"] = name
        variables["%s_enabled" % name] = self.getState()

        # Include basic properties
        variables.update(self.getPropertyValues())

        # Include a list of hosts that the service is enabled on
        variables["hosts"] = self.getEnabledHostList()

        return variables

    def hasPropRequiringData(self):
        """Returns true if this service has a property that requires data

        A property requires data if it is marked as required and has no
        default value defined.
        """

        data = self._getData()

        for propName,prop in self._properties.items():
            if prop["required"] and \
                    (prop["default_value"] is None or \
                    prop["default_value"]==""):
                # Check if a network value is defined
                f=False
                for nprop in data:
                    if nprop["prop_name"] != propName:
                        continue
                    f=True
                    if nprop["value"] is None or nprop["value"]=="":
                        return True
                    else:
                        break
                if not f:
                    return True

        return False

    def hasRequiredProps(self):
        """Returns true if this service has required properties"""

        for propName,prop in self._properties.items():
            if prop["required"]:
                return True

        return False

    # The following methods must be defined by implementing classes
    #initialiseService
    @staticmethod
    def initialiseService():
        """Called by the system the very first time the service is loaded.

        This should setup an entry in the service table and load any default
        service properties into the service_prop table.
        """
        raise pcsd_service_error("initialiseService cannot be called on " \
                "the pcsd_service class. You must override it")

@exportViaXMLRPC(SESSION_RO, AUTH_USER)
def getServiceName(session_id, service_id):
    """Return the name of the specified service"""
    session = getSessionE(session_id)

    # Retrieve the service name
    sql = "SELECT * FROM service WHERE service_id=%s"
    res = session.query(sql, (service_id))
    if len(res) != 1:
        raise pcsd_service_error("Invalid service ID!")
    return res[0]["service_name"]

@exportViaXMLRPC(SESSION_RO, AUTH_USER)
def getServiceID(session_id, service_name):
    """Return the id of the specified service"""
    session = getSessionE(session_id)

    # Retrieve the service name
    sql = "SELECT * FROM service WHERE service_name=%s"
    res = session.query(sql, (service_name))
    if len(res) != 1:
        raise pcsd_service_error("Invalid service name!")
    return res[0]["service_id"]

def getServiceTemplateVars(session_id):
    """Returns variables to use on templates for all services"""
    global _services

    variables = {}

    for service in _services.keys():
        inst = getServiceInstance(session_id, service)
        variables[service] = inst.getTemplateVariables()

    return variables

@exportViaXMLRPC(SESSION_RO, AUTH_USER)
def getServiceList(session_id):
    """Returns a list of services"""
    session = getSessionE(session_id)

    # Retrieve the services
    sql = "SELECT * FROM service"
    res = session.query(sql, ())
    return res

@registerEvent("serviceStateChanged")
@exportViaXMLRPC(SESSION_RW, AUTH_ADMINISTRATOR)
def changeServiceState(session_id, service_id, state):
    """Enables or Disables the specified service on a global basis"""
    session = getSessionE(session_id)

    if state!="t" and state!="f":
        raise pcsd_service_error("Invalid state value!")

    session.execute("UPDATE service SET enabled=%s WHERE service_id=%s", \
            (state, service_id))

    triggerEvent(session_id, "serviceStateChanged", service_id=service_id)

    return state

def validateServiceProp(session_id, propDetails, propValue, enabledState=False):
    """Checks that the value of the specified property is OK"""

    if propDetails["required"] and enabledState:
        if len(propValue) <= 0 or propValue is None:
            raise pcsd_service_error("Required Property!")
    if propDetails["prop_type"] == "number":
        try:
            n = long(propValue)
        except:
            raise pcsd_service_error("Invalid numeric property!")

    return

#####################################################################
# Service Initialisation
#####################################################################
_services = {}

def getServiceInstance(session_id, name):
    """Returns an instance of the service class for the specified service"""

    if name not in _services.keys():
        raise pcsd_service_error("Invalid service name! - %s" % name)

    res_class = _services[name]
    service_id = res_class.service_id
    return eval("res_class(session_id, service_id)")

def registerService(res_class, **kwargs):
    """Function to register a service

    The service must be derived from pcsd_service. The service must have
    at least one private member called serviceName that provides
    a textual description of the service. Other private members as described
    in the pcsd_service class must also be present.
    """
    session = getSession(ADMIN_SESSION_ID)

    try:
        name = res_class.serviceName

        if name in _services:
            raise pcsd_service_error("Service name already registed!")

        # Check it is a child of pcsd_service
        if pcsd_service not in inspect.getmro(res_class):
            raise pcsd_service_error("Invalid service class type!")

        # Check it has an entry in the service table
        res = session.query("SELECT * FROM service WHERE service_name=%s", \
                (name))
        if len(res) != 1:
            # Call the services setup function
            res_class.initialiseService()
        else:
            # Store the service ID in the class for reference
            res_class.service_id = res[0]["service_id"]

        # Register the service
        log_info("Registering service '%s'." % name)
        _services[name] = res_class

    except:
        log_error("Failed to register service!", sys.exc_info())
