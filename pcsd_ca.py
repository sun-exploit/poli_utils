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
#   x509 Certificate Authority
#
#   Manages the x509 certification authority used for the configuration system
#   primary tasks involved in this are:
#   - Keeping track of which certificates have been created
#   - Signing new certificates
#   - Revoking compromised certificates
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

import time
import shutil
from OpenSSL      import crypto
from tempfile     import mkdtemp, mktemp
from subprocess   import Popen, PIPE
import svn.client as client
import svn.core as core

from pcsd_common  import *
from pcsd_log     import *
from pcsd_events  import *
from pcsd_config  import config_get, config_get_required
from pcsd_session import getSession, getSessionE
from pcsd_server  import registerResource, exportViaXMLRPC
from pcsd_svn     import pcsd_svn

class pcsd_ca_error(pcsd_error):
    pass

DEFAULT_SIGN_DAYS = 3650    # 10 years
CERT_PARAM_NAMES = ["C", "ST", "L", "O", "OU", "CN", "emailAddress"]

REVOKE_UNSPECIFIED = "unspecified"
REVOKE_COMPROMISED = "keyCompromise"
REVOKE_SUPERSEDED = "superseded"
REVOKE_OBSOLETE = "cessationOfOperation"

certParams = {}

#####################################################################
# General Certificate Integration Helper Functions
#####################################################################
@exportViaXMLRPC(SESSION_RO, AUTH_AUTHENTICATED)
def getCertificateParameters(session_id=None):
    """Returns a dictionary containing certificate parameters for the system

    The parameters in the returned dictionary are intended to be used as a
    template when creating new certificates.
    """
    global certParams
    return certParams

def emptyCertParameters():
    """Helper function returns a empty set of certificate parameters"""
    global CERT_PARAM_NAMES
    params = {}
    for param in CERT_PARAM_NAMES:
        params[param] = ""
    return params

@exportViaXMLRPC(SESSION_RO, AUTH_USER)
def createKey(session_id, params):
    """Creates a new key with the specified parameters are returns it

    The return value is a tuple containing the signing request and the
    private key.
    """
    global CERT_PARAM_NAMES

    # Check key parameters
    name = params["CN"]
    if name == "":
        raise pcsd_ca_error("Cannot create certificate with blank CN!")
    for k,v in params.items():
        if v=="" or v is None: params[k]="."

    # Generate the key and the signing request in a temporary directory
    dir = mkdtemp("", "pcsd")
    csr = ""
    key = ""
    keyfile = "%s/%s-key.pem" % (dir, name)
    csrfile = "%s/%s-req.pem" % (dir, name)
    log_debug("%s::%s : keyfile=[%s], csrfile=[%s]" % (__name__, "createKey", keyfile, csrfile))
    try:
        print "openssl req -new -nodes -out %s -keyout %s"  % (csrfile, keyfile)
        po = Popen("openssl req -new -nodes -out %s -keyout " \
                "%s 2>&1" % (csrfile, keyfile), shell=True, stdout=PIPE, stdin=PIPE)
        (fdi, fdo) = (po.stdin, po.stdout)
        for p in CERT_PARAM_NAMES:
            log_debug("%s::%s : params[%s]=[%s]" % (__name__, "createKey", p, params[p]))
            fdi.write("%s\n" % params[p])
        fdi.write("\n\n")
        fdi.close()
        output = fdo.readlines()
        fdo.close()
        # Wait for generation to finish, if key doesn't appear after 1s
        # assume generation failed
        time.sleep(1)
        # Read the requests
        try:
            csr = open(csrfile, "r").read()
            key = open(keyfile, "r").read()
        except IOError:
            log_error("Failed to load key after generation", sys.exc_info())
            log_debug("".join(output))
            raise pcsd_ca_error("Unable to generate new key!")
    finally:
        removeDir(dir)
        log_debug("%s::%s END" % (__name__, "createKey"))

    return (csr, key)

@exportViaXMLRPC(SESSION_RO, AUTH_AUTHENTICATED)
def fetchCRL(self):

    ca = pcsd_ca(ADMIN_SESSION_ID)

    # Check when the next CRL is due
    os.environ["PCS_CA_DIR"] = ca.rDir
    p = Popen("openssl crl -text -in %s/crl.pem 2>&1" % ca.rDir, shell=True, stdout=PIPE, stdin=PIPE)
    (fdi, fdo) = (p.stdin, p.stdout)
    fdi.close()
    lines = fdo.readlines()
    fdo.close()
    del os.environ["PCS_CA_DIR"]

    try:
        for line in lines:
            if line.strip().startswith("Next Update"):
                parts = line.strip().split(":")
                tmp = ":".join(parts[1:]).strip()
                next = time.mktime(time.strptime(tmp, \
                        "%b %d %H:%M:%S %Y %Z"))
                now = time.time()
                if (next - now) < (60*60*24*2):
                    # Update the CRL if it expires in less than 2 days
                    ca.updateCRL()
                    ca.checkin("Updated CRL to satisfy user request")
                break
    except:
        log_error("Could not parse CRL output. " \
                "Returned CRL may be old.\n%s" % "".join(lines), \
                sys.exc_info())

    # Read and return the CRL
    crl = open("%s/crl.pem" % ca.rDir, "r").read()
    return crl

#####################################################################
# Certificate Authority Class
#####################################################################
class pcsd_ca(pcsd_svn):
    """Wrapper for a a certification authority.

    The certification authority exists inside the svn repository managed by
    the configuration system. Creating an instance of the ca class intiates
    a new revision of the repository in case new certificates are signed and
    need to be checked in.
    """

    def __init__(self, session_id=None):

        # Setup parameters expected by the base class
        if session_id is None:
            session_id = ADMIN_SESSION_ID
        self.mParentSession = getSession(session_id)
        self.mChangeset = self.mParentSession.changeset

        # Call base constructor
        pcsd_svn.__init__(self, self.mParentSession, self.mChangeset, \
                False)

        # Setup a working directory for this revision
        self.rDir = mkdtemp("", "pcsd")

        # Checkout the current configuration HEAD to this directory
        try:
            rev = core.svn_opt_revision_t()
            rev.kind = core.svn_opt_revision_head
            client.svn_client_checkout("%s/ca" % self.svnroot, self.rDir, \
                    rev, True, self.ctx, self.pool)
            self.mCurRev = rev
        except core.SubversionException:
            # CA not initialised
            raise pcsd_ca_error("infrastructure not found in repository!")

        # Check basic repository structure
        if self.mParentSession is not None and self.mChangeset is not None:
            log_debug("%s::%s : Check basic repository structure" % (__name__, '__init__'))
            self.checkRepoStructure()

        # Start with no errors
        self.mErrors = {}

    def getConfigBase(self):
        raise pcsd_ca_error("Configuration files not available from pcsd_ca")

    def checkRepoStructure(self):
        """Checks the repository has all the required infrastructure.

        CA itself (cannot be automatically created)
        cacert.pem      The CA certificate
        cakey.pem       The CA private key

        The remaining infrastructure is automatically created if not present
        certs/          Signed certificates
        crl/            Certificate Revocation Lists
        crlnumber       Current CRL serial number
        serial          Current certificate serial number
        index.txt       Certificate database
        ca.cnf          CA Configuration File
        """
        log_debug("%s::%s" % (__name__, 'checkRepoStructure()'))
        if self.mParentSession is None or self.mChangeset is None:
            log_warn("Cannot check repository structure on a read-only " \
                    "revision")
            return

        # Is the certification authority cert and key present?
        if not os.path.exists("%s/cacert.pem" % self.rDir):
            raise pcsd_ca_error("certificate not found in repository!")
        if not os.path.exists("%s/cakey.pem" % self.rDir):
            raise pcsd_ca_error("key not found in repository!")

        # Check for required directories
        s = 0
        flag = 0
        if not os.path.exists("%s/certs" % self.rDir):
            # Storage directory for signed certificates needs creating
            ensureDirExists("%s/certs" % self.rDir)
            client.svn_client_add("%s/certs" % self.rDir, False, self.ctx, \
                    self.pool)
            s+=1
            log_info("CA: Certificate storage directory created")
        # Check for required files
        if not os.path.exists("%s/crlnumber" % self.rDir):
            # CRL number needs initialising
            fd = open("%s/crlnumber" % self.rDir, "w")
            fd.write("00\n")
            fd.close()
            client.svn_client_add("%s/crlnumber" % self.rDir, False, \
                    self.ctx, self.pool)
            s+=1
            log_info("CA: CRL number initialised to 0x00")
        if not os.path.exists("%s/index.txt" % self.rDir):
            # Certificate list needs initialising
            fd = open("%s/index.txt" % self.rDir, "w")
            fd.close()
            fd = open("%s/index.txt.attr" % self.rDir, "w")
            fd.close()
            client.svn_client_add("%s/index.txt" % self.rDir, False, \
                    self.ctx, self.pool)
            client.svn_client_add("%s/index.txt.attr" % self.rDir, False, \
                    self.ctx, self.pool)
            s+=1
            log_info("CA: Certificate list initialised")
        if not os.path.exists("%s/serial" % self.rDir):
            # Serial number needs initialising
            fd = open("%s/serial" % self.rDir, "w")
            fd.write("00\n")
            fd.close()
            s+=1
            client.svn_client_add("%s/serial" % self.rDir, False, \
                    self.ctx, self.pool)
            log_info("CA: Serial number initialised to 0x00")
        if not os.path.exists("%s/ca.cnf" % self.rDir):
            # Configuration file needs initialising
            self.initConfFile()
            flag=1
        # Check svn:ignore is set
        if not self.hasIgnore(self.rDir, "*.old"):
            self.propadd(self.rDir, "svn:ignore", "*.old")
            flag=1
        if s>0: flag=1
        if flag==0:
            # All ok
            return

        if s>0 and s!=4:
            # Warn if only partial changes were made
            log_warn("CA: Initialised from incomplete state!")

        # Commit the changes
        r = self.checkin("Initialising Certificate Authority")
        #i = client.svn_client_commit([self.rDir], False, self.ctx, self.pool)
        #self.saveRevProps(i.revision, "Initialising Certificate Authority")
        if r > 0 :
            log_info("CA: Structure initialised in revision %s" % r)
        return r

    def initConfFile(self):
        """Initialises the CA configuration file"""

        signdays = config_get("ca", "signdays", DEFAULT_SIGN_DAYS)
        site_name = config_get_required("network", "site_name")
        domain = config_get_required("network", "domain")
        log_debug("%s::initConfFile : open(%s/ca.cnf)" % (__name__, self.rDir) )
        fd = open("%s/ca.cnf" % self.rDir, "w")
        fd.write("""#
# OpenSSL configuration file for the CRCnet Configuration System CA

# This definition stops the following lines choking if HOME isn't
# defined.
HOME                    = .
RANDFILE                = $ENV::HOME/.rnd

####################################################################
[ ca ]
default_ca              = CA_default            # The default ca section

####################################################################
[ CA_default ]

dir                 = $ENV::PCS_CA_DIR      # Where everything is kept
certs               = $dir/certs            # Where the issued certs are kept
crl_dir             = $dir/crl              # Where the issued crl are kept
database            = $dir/index.txt        # database index file.
new_certs_dir       = $dir/certs            # default place for new certs.

certificate         = $dir/cacert.pem       # The CA certificate
private_key         = $dir/cakey.pem        # The private key
serial              = $dir/serial           # The current serial number
crlnumber           = $dir/crlnumber        # the current crl number
crl                 = $dir/crl.pem          # The current CRL
RANDFILE            = $dir/.rand            # private random number file

x509_extensions     = usr_cert              # The extentions to add to the cert
name_opt            = ca_default            # Subject Name options
cert_opt            = ca_default            # Certificate field options

default_days        = %s                    # how long to certify for
default_crl_days    = 30                    # how long before next CRL
default_md          = sha1                  # which md to use.
preserve            = no                    # keep passed DN ordering

policy          = policy_match

# For the CA policy
[ policy_match ]
countryName             = match
stateOrProvinceName     = optional
localityName            = optional
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

####################################################################
[ req ]
default_bits            = 1024
default_keyfile         = privkey.pem
distinguished_name      = req_distinguished_name
attributes              = req_attributes
x509_extensions         = v3_ca  # Extensions to add to self signed certs
string_mask = nombstr

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = NZ
countryName_min                 = 2
countryName_max                 = 2

localityName                    = Locality Name (eg, city)

0.organizationName              = Organization Name (eg, company)
0.organizationName_default      = %s

organizationalUnitName          = Organizational Unit Name (eg, section)
organizationalUnitName_default  = CRCnet Configuration System

commonName                      = Common Name (eg, YOUR name)
commonName_max                  = 64

emailAddress                    = Email Address
emailAddress_max                = 64

[ req_attributes ]
challengePassword               = A challenge password
challengePassword_min           = 4
challengePassword_max           = 20

unstructuredName                = An optional company name

# These extensions are added when 'ca' signs a request.
[ usr_cert ]
basicConstraints                = CA:FALSE

# nsCertType                    = server
# nsCertType                    = client

# This will be displayed in Netscape's comment listbox.
nsComment                       = "Signed by the CRCnet Configuration System"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier            = hash
authorityKeyIdentifier          = keyid,issuer

nsRevocationUrl                 = https://%s/certs/crl.pem

# Extensions to add to a certificate request
[ v3_req ]
basicConstraints        = CA:FALSE
keyUsage                = nonRepudiation, digitalSignature, keyEncipherment

# Extensions for a typical CA
[ v3_ca ]
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always,issuer:always
basicConstraints        = CA:true

# CRL extensions.
[ crl_ext ]
authorityKeyIdentifier  = keyid:always,issuer:always
""" % (signdays, site_name, domain))
        fd.close()
        client.svn_client_add("%s/ca.cnf" % self.rDir, False, \
                    self.ctx, self.pool)
        log_info("CA: Initialised configuration file")
        return

    def getCAParameters(self):
        """Returns a dictionary containing the DN components of the CA"""

        params = {}

        # Read the certificate parameters
        cacert = self.loadcert("cacert.pem")
        subj = cacert.get_subject()
        for p in CERT_PARAM_NAMES:
            params[p] = getattr(subj, p)

        return params

    def _checkName(self, name):
        """Checks that the specified name references a file in the repo"""

        # Check the filename is not trying to write out of the repository
        filename = os.path.realpath("%s/%s" % (self.rDir, name))
        if os.path.commonprefix([self.rDir, filename]) != self.rDir:
            raise pcsd_ca_error("Invalid filename!")
        # Check the base directory exists in the repository
        if not os.path.exists(os.path.dirname(filename)):
            raise pcsd_ca_error("Invalid directory!")

        return filename

    def hasfile(self, name):
        """Returns true if the specified filename is found in the CA repo"""

        # Check the filename is not out of the repository
        filename = os.path.realpath("%s/%s" % (self.rDir, name))
        if os.path.commonprefix([self.rDir, filename]) != self.rDir:
            raise pcsd_ca_error("Invalid filename!")

        return os.path.exists(filename)

    def addfile(self, name, contents):
        """Adds a new file to the CA repository

        The file is scheduled for addition, you must make sure you call
        commit before closing the class or the file will not be committed

        name must refer to a valid path within the repository (eg. it should
        not contain uplevel references '../' or references to directories
        that do not exists.
        """
        filename = self._checkName(name)

        # Write the file to the working directory
        try:
            fd = open(filename, "w")
            fd.write(contents)
            fd.close()
        except:
            raise pcsd_ca_error("Could not write new file!", sys.exc_info())

        # Schedule it for addition
        client.svn_client_add(filename, False, self.ctx, self.pool)
        log_info("CA: Marked %s for addition to repository" % name)
        return filename

    def loadkey(self, name):
        """Returns the PKey object resulting from loading the named file"""
        filename = self._checkName(name)
        return crypto.load_privatekey(crypto.FILETYPE_PEM, \
                open(filename, "r").read())

    def loadcert(self, name):
        """Returns the X509 object resulting from loading the named file"""
        filename = self._checkName(name)
        return crypto.load_certificate(crypto.FILETYPE_PEM, \
                open(filename, "r").read())

    def loadCACerts(self):
        """Returns a list of CA certificates used for verification

        The first item in the list is the CA certificate managed by the
        configuration system. Any further items are parent certificates needed
        to complete the verification tree.
        """
        certs = []

        # PCS managed cert
        certs.append(self.loadcert("cacert.pem"))

        # Parent certs
        # XXX: This might blow up if more than 1 parent? Need to test
        if self.hasfile("cacerts.pem"):
            certs.append(self.loadcert("cacerts.pem"))

        return certs

    def signReq(self, csr):
        """Signs the specified request and returns the new certificate

        This function will commit any pending changes to the serial, index.txt
        and certs/XX.pem files after signing the key. To be safe it is best to
        ensure that there are no other pending changes before calling this
        method.
        """
        serial = ""
        cn = ""
        # Write out the request to a temporary file
        filename = "%s/%s" % (self.rDir, mktemp("", "csr", ""))
        log_debug("%s::%s filename=[%s]" % (__name__, 'signReq', filename))
        try:
            try:
                fd = open(filename, "w")
                fd.write(csr)
                fd.close()
            except:
                raise pcsd_ca_error("Could not write temp CSR file!", \
                        sys.exc_info())

            # Sign the key
            os.environ["PCS_CA_DIR"] = self.rDir
            log_debug("%s::%s PCS_CA_DIR=[%s]" % (__name__, 'signReq', self.rDir))
            log_debug("%s::%s openssl_cmd=[%s]" % (__name__, 'signReq', "openssl ca -config %s/ca.cnf -in %s " \
                "-batch" % (self.rDir, filename)))
            p = Popen("openssl ca -config %s/ca.cnf -in %s " \
                    "-batch 2>&1" % (self.rDir, filename), shell=True, stdout=PIPE, stdin=PIPE)
            (fdi, fdo) = (p.stdin, p.stdout)
            fdi.close()
            lines = fdo.readlines()
            fdo.close()
            del os.environ["PCS_CA_DIR"]

            # Find the serial number in the output
            log_debug("%s::%s : Find the serial number in the output" % (__name__, 'signReq'))
            try:
                for line in lines:
                    if line.strip().startswith("commonName"):
                        parts = line.strip().split("=")
                        cn = parts[1]
                    if line.strip().startswith("Serial Number"):
                        parts = line.split(":")
                        parts = parts[1].strip().split(" ")
                        serial = "%X" % int(parts[0])
                        if len(serial)%2 == 1: serial = "0%s" % serial
                    if cn != "" and serial != "":
                        break
            except:
                log_debug("".join(lines))
                raise pcsd_ca_error("Could not read certificate properties!")

            certfile = "%s/certs/%s.pem" % (self.rDir, serial)
            if not os.path.exists(certfile):
                log_debug("".join(lines))
                raise pcsd_ca_error("Failed to sign certificate!")

            # Add the new certificate to the repository and commit the changes
            paths = ["%s/serial" % self.rDir, "%s/index.txt" % self.rDir, \
                    "%s/index.txt.attr" % self.rDir, certfile]
            self.checkin("Signed new certificate for %s" % cn, paths)
            log_info("CA: Signed new certificate (0x%s) for %s" % (serial, cn))
        finally:
            os.unlink(filename)

        # Read the certificate and return it
        cert = open(certfile, "r").read()
        return cert

    def updateCRL(self):
        """Regenerates the Certificate Revocation List"""

        os.environ["PCS_CA_DIR"] = self.rDir
        p = Popen("openssl ca -config %s/ca.cnf -gencrl -out " \
                "%s/crl.pem -batch 2>&1" % (self.rDir, self.rDir), shell=True, stdout=PIPE, stdin=PIPE)
        (fdi, fdo) = (p.stdin, p.stdout)
        fdi.close()
        rlines = fdo.readlines()
        fdo.close()
        del os.environ["PCS_CA_DIR"]

        return True

    def revoke(self, serial, reasonCode=REVOKE_UNSPECIFIED, reasonText=""):
        """Revokes the specified certificate optionally giving a reason

        This function will revoke the key, giving the reason specified, the
        certificate will be moved from certs/XX.pem to certs/XX-revoked.pem
        and a new CRL will be issued. This function will commit changes to
        index.txt. To be safe it is best to ensure that there are no other
        pending changes before calling this method.
        """
        # Sign the key
        os.environ["PCS_CA_DIR"] = self.rDir
        p = Popen("openssl ca -config %s/ca.cnf -revoke " \
                "%s/certs/%s.pem -crl_reason %s -batch 2>&1" % \
                (self.rDir, self.rDir, serial, reasonCode), shell=True, stdout=PIPE, stdin=PIPE)
        (fdi, fdo) = (p.stdin, p.stdout)
        fdi.close()
        lines = fdo.readlines()
        fdo.close()
        del os.environ["PCS_CA_DIR"]

        # Find the works "Revoking Certificate" in the output
        try:
            ok = False
            for line in lines:
                if line.strip().startswith("Revoking Certificate"):
                    ok=True
                    break
            if not ok:
                raise pcsd_ca_error()
        except:
            log_debug("".join(lines))
            raise pcsd_ca_error("Could not validate certificate revocation!")

        # Move the certificate
        try:
            client.svn_client_move("%s/certs/%s.pem" % (self.rDir, serial), \
                    self.mCurRev, \
                    "%s/certs/%s-revoked.pem" % (self.rDir, serial), True, \
                    self.ctx, self.pool)
        except:
            log_error("Could not move revoked certificate to new name!", \
                    sys.exc_info())

        # Generate a new CRL
        self.updateCRL()

        # Commit the changes
        message = "Revoked (%s) certificate 0x%s: %s" % \
                (reasonCode, serial, reasonText)
        self.checkin(message)
        log_info("CA: %s" % message)

    def ensureCertificateExists(self, name):
        certname = "%s-cert.pem" % name
        keyname = "%s-key.pem" % name
        reqname = "%s-req.pem" % name
        if self.hasfile(certname) and self.hasfile(keyname):
            return True
        # No cert/key in repository
        log_info("Creating certificate for %s" % name)
        sParams = self.getCAParameters().copy()
        sParams["CN"] = name
        sParams["emailAddress"] = "root@%s" % \
                config_get_required("network", "domain")
        # Generate the new key / request
        (csr, key) = createKey(0, sParams)
        # Get it signed
        cert = self.signReq(csr)
        # Add it to the repository for safe-keeping
        try:
            a = self.addfile(certname, cert)
            b = self.addfile(keyname, key)
            c = self.addfile(reqname, csr)
            self.checkin("Added %s certificate and key" % name, [a, b, c])
            return True
        except pcsd_ca_error:
            (type, value, tb) = sys.exc_info()
            log_error("CA: Failed to create key for %s: %s" % \
                    (name, value), (type, value, tb))

        return False

    def findByCN(self, desiredCN):
        """Searches the certificate database for records with matching CNs"""
        certs = []

        # Read the database
        try:
            fd = open("%s/index.txt" % self.rDir, "r")
            lines = fd.readlines()
            fd.close()
        except:
            raise pcsd_ca_error("Unable to read certificate database!")

        # Parse the database
        n=0
        for line in lines:
            n+=1
            parts = line.split("\t")
            if len(parts) != 6:
                log_warn("Skipping malformed line %s in certificate DB" % \
                        n)
                continue
            # Look for the CN
            if parts[5].find("CN=%s" % desiredCN) == -1:
                continue
            # Certificate parameters
            t = parts[5][1:].split("/")
            params = emptyCertParameters()
            for p in t:
                pp = p.split("=")
                params[pp[0]] = pp[1]
            # Store the match
            cert = {"state":parts[0], "exp_date":parts[1], \
                    "rev_date":parts[2], "serial":parts[3], "file":parts[4], \
                    "params":params}
            # Add to the list
            certs.append(cert)

        # Return results
        return certs

#####################################################################
# Initialisation
#####################################################################
def init_ca():
    """Called during server startup to initialise the CA environment

    The CA must not be initialised until after the cfengine module so that the
    subversion repository is ready to use
    """
    global certParams

    # Load the repository to check for a CA
    session_id = ADMIN_SESSION_ID
    session = getSession(session_id)
    changeset = session.changeset

    revision = pcsd_svn(session, changeset);

    # Check for required directories
    wDir = revision.getWorkingDir()
    if not os.path.exists("%s/ca" % wDir):
        log_debug("%s::%s : Creating storage directory for CA environment" % (__name__, 'init_ca()'))
        # Storage directory for CA environment needs creating
        ensureDirExists("%s/ca" % wDir)
        revision.checkin("Added CA directory", ["%s/ca" % (wDir)])
        log_info("CA: Certificate storage directory created")
    if not revision.fileExists("ca/cacert.pem"):
        log_info("%s::%s : Creating CA for the certificates" % (__name__, 'init_ca()'))
        siteName = config_get("network","site_name")
        if siteName == "":
            siteName = "CRCnet Default Site"
        log_debug("%s::%s : siteName=[%s]" % (__name__, 'init_ca()',siteName))
        log_debug("%s::%s : wDir=%s" % (__name__, 'init_ca()', wDir))
        try:
            p = Popen("openssl req -new -x509 -nodes -keyout "\
                "%s/ca/cakey.pem -out %s/ca/cacert.pem -days 3650 2>&1"\
                 % (wDir,wDir), shell=True, stdout=PIPE, stdin=PIPE)
            (fdi, fdo) = (p.stdin, p.stdout)
        except:
            log_debug("%s::%s : openssl command Failed : %s !!" % (__name__, 'init_ca()', p.stderr))
            raise
        fdi.write("FR\n") #country
        fdi.write(".\n")  #ignore state of province
        fdi.write(".\n")  #ignore location
        fdi.write("%s\n" % siteName) #Organisation
        fdi.write("pcsd\n") #Organisation Unit
        fdi.write("Certification Authority\n") #Common Name
        fdi.write(".\n")  #ignore email
        fdo.close()
        fdi.close()
        time.sleep(1)
        log_debug("%s::%s : init_ca() : Added CA [%s/ca/cacert.pem]" % \
            (__name__, 'init_ca()', wDir))
        revision.checkin("Added CA", ["%s/ca/cacert.pem" % (wDir),\
            "%s/ca/cakey.pem" % (wDir)])

    # Load the CA
    try:
        ca = pcsd_ca()
        certParams = ca.getCAParameters()
    except pcsd_ca_error:
        (type, value, tb) = sys.exc_info()
        log_fatal("CA: Unable to initialise: %s" % value, \
                (type, value, tb))

    # Ensure there is a server key, and a client key for the web interface
    # and the pxeboot scripts
    for name in ["server", "pcsweb", "pxe-scripts"]:
        if not ca.ensureCertificateExists(name):
            log_fatal("CA: %s is a required key. Exiting!" % name)

