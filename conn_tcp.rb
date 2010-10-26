# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2010.
# License: The MIT License
# (See README.TXT or http://www.opensource.org/licenses/mit-license.php for details.)
#
require 'socket'

#Establish a connection over TCP.
#
#Parameters: dest_host (string), dest_port (0-65535), source_port (0-65535, defaults to whatever source
#port is supplied by the OS)
module CONN_TCP
    
    #These methods will override the stubs present in the Connector
    #class, and implement the protocol specific functionality for 
    #these generic functions.
    #
    #Arguments required to set up the connection are stored in the
    #Connector instance variable @module_args.
    #
    #Errors should be handled at the Module level (ie here), since Connector
    #just assumes everything is going to plan.
    
    #Set up a new socket.
    def establish_connection
        @dest, @dport, @sport = @module_args
        retries=0
        begin
            BasicSocket.do_not_reverse_lookup=true
            @sock=Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
            remote_addr=Socket.pack_sockaddr_in(@dport, @dest)
            if @sport
                local_addr=Socket.pack_sockaddr_in(@sport, Socket::INADDR_ANY)
                @sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_REUSEADDR, 0)
                @sock.bind local_addr
            end
            @sock.connect remote_addr
            @connected=true
        rescue Errno::EPERM
            raise ArgumentError, "CONN_TCP: establish: need root access (tried to bind to a local port < 1024?)"
        rescue
            destroy_connection
            if retries < @retries
                sleep 0.25
                retries+=1
                retry
            else
                raise RuntimeError, "CONN_TCP: establish: couldn't establish socket after #{@retries} tries. (#{$!})"
            end
        end
    end

    #Blocking read from the socket.
    def blocking_read
        raise RuntimeError, "CONN_TCP: blocking_read: Not connected!" unless connected?
        begin
            loop do
                data=@sock.recvfrom(8192)[0]
                return data unless data == ""
            end
        rescue
            destroy_connection
            raise RuntimeError, "CONN_TCP: blocking_read: Couldn't read from socket! (#{$!})"
        end
    end

    #Blocking write to the socket.
    def blocking_write( data )
        raise RuntimeError, "CONN_TCP: blocking_write: Not connected!" unless connected?
        begin
            @sock.send(data, 0)
        rescue
            destroy_connection
            raise RuntimeError, "CONN_TCP: blocking_write: Couldn't write to socket! (#{$!})"
        end
    end

    #Return a boolen.
    def is_connected?
        @connected and not @sock.closed?
    end

    #Cleanly destroy the socket. 
    def destroy_connection
        begin
            @sock.close if @sock
        rescue
            nil
        ensure
            @connected=false
        end
    end

end
