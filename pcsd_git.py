# Copyright (C) 2014 sun-exploit <a1@sun-exploit.com>
#
# This file is part of pcsd - Poli Configuration System Daemon
#
# This file contains common code used throughout the system and extensions
# - Constant values
# - Small helper functions
# - Base classes
#
# Author:       a1 <a1@sun-exploit.com>
# Version:      $Id$
#
# pcsd is free software; you can redistribute it and/or modify it under the
# terms of the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# pcsd is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# crcnetd; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
import os

from git      import *
from gitdb    import IStream
from StringIO import StringIO

_isDaemon = 0
_verbose = 0

#############################################################################
# Constants
#############################################################################


#############################################################################
# pcs_git Classes
#############################################################################

class PCSGit(object):
    """PCSGit class ..."""
    def __init__ ( self, repository, extension, index ):
        self.index      = index
        self.extension  = extension

        if os.path.isdir( os.path.join( repository, '.git' ) ):
            self.repository = Repo( repository, odbt=GitDB )
        else:
            if not os.path.isdir( repository ):
                os.makedirs( repository )

            os.chdir( repository )
            self.repository = Repo.init()

    def find_all ( self ):
        repo  = self.repository

        if len(repo.refs) == 0:
            return []
        else:
            components = []
            for entry in repo.tree().traverse():
                if entry.type == 'blob':
                    componentss.append( Component( entry, repo ) )

            return components

    def find ( self, name ):
        blob = self.find_blob(name)

        if blob is None:
            raise PCSGitComponentNotFound( name )

        return Component(blob, self.repository)

    def find_blob ( self, path ):
        repo = self.repository

        if len(repo.refs) == 0:
            return None
        else:
            tree = repo.tree()
            blob = None

            try:
                blob = tree/("%s.%s" % ( path, self.extension ))
            except KeyError, e:
                pass

            return blob

    def find_or_create ( self, name, content='' ):
        try:
            return self.find( name )
        except PCSGitComponentNotFound, e:
            component = Component( self.create_blob_for(name, data=content), self.repository )
            component.commit('Component (%s) is created.' % ( name ))
            return component

    def create_blob_for ( self, path, data='' ):
        repo    = self.repository
        istream = IStream('blob', len(data), StringIO(data))

        repo.odb.store( istream )
        blob    = Blob( repo, istream.binsha, 0100644, "%s.%s" % ( path, self.extension ) )

        return blob

class PSCGitComponentNotFound ( Exception ):
    """PCSGitComponentNotFound exeption class ..."""
    def __init__ ( self, name ):
        self.name = name
    def __str__ ( self ):
        return 'Component (%s) is not found' % ( self.name )

class PSCGitComponent ( object ):
    """PSCComponent class ..."""
    def __init__ ( self, blob, repository ):
        self.blob       = blob
        self.repository = repository

    def __str__ ( self ):
        return self.blob.name

    def name ( self ):
        return os.path.splitext( self.blob.name )[0]

    def content ( self ):
        try:
            return self.blob.data_stream.read()
        except AttributeError, e:
            return None

    def update_content ( self, new ):
        if self.content == new:
            return None

        fh = open( self.blob.abspath, 'w' )
        fh.write( new )
        fh.close()

        return self.commit('Updated: %s' % ( self.blob.name ))

    def commit ( self, message ):
        index = self.repository.index
        blob  = self.blob

        if os.path.isfile( blob.abspath ):
            index.add([ blob.path ])
        else:
            index.add([ IndexEntry.from_blob( blob ) ])

        return index.commit( message );

