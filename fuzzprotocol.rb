# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2010.
# License: The MIT License
# (See README.TXT or http://www.opensource.org/licenses/mit-license.php for details.)

require File.dirname(__FILE__) + '/objhax'
require 'digest/md5'
require 'msgpack'

# This class just handles the serialization, the mechanics of the protocol itself
# is "defined" in the FuzzClient / FuzzServer implementations. It is very lazy
# which allows the protocol to be changed by simply changing the code at each peer.

class OutMsg < EventMachine::DefaultDeferrable
    attr_reader :msg_hash
    def initialize( msg_hash )
        @msg_hash=msg_hash
    end
end

class FuzzMessage
    # .new can take a Hash or a serialzied Hash.
    # method_missing allows access to the hash keys as 'methods',  making the protocol
    # self extending.
    def initialize(data)
        if data.kind_of? String
            deserialize(data)
        else
            unless data.kind_of? Hash
                raise ArgumentError, "FuzzMessage: .new takes a Hash or a serialized Hash."
            end
            @msghash=data
        end
    end

    def to_hash
        @msghash
    end

    def deserialize(data)
        begin
            hsh=MessagePack.unpack(data)
            unless hsh.kind_of? Hash
                raise ArgumentError, "FuzzMessage (deserialize): data not a Hash!"
            end
            @msghash=hsh
        rescue
            raise ArgumentError, "FuzzMessage (deserialize): Bad data."
        end
    end

    def to_s
        @msghash.to_msgpack
    end
    alias :pack :to_s

    def method_missing( meth, *args)
        @msghash[meth.to_s]
    end
end

# This class is used to centralize some common code which is used by all
# the Harness classes, so I can maintain it in one place. It's not exactly
# elegantly separated and abstracted, but at least it's not duplicated
# 5 times.
class HarnessComponent < EventMachine::Connection

    def self.queue
        @queue||=Hash.new {|hash, key| hash[key]=Array.new}
    end
    def self.lookup
        @lookup||=Hash.new {|hash, key| hash[key]=Hash.new}
    end

    def self.new_ack_id
        @ack_id||=rand(2**32)
        @ack_id+=1
    end

    def self.setup( config_hsh={})
        @config||=self::DEFAULT_CONFIG.merge config_hsh
        @config.merge! config_hsh # Allows setup to be called multiple times
        @config.each {|k,v|
            meta_def k do @config[k] end
            meta_def k.to_s+'=' do |new| @config[k]=new end
        }
        unless File.directory? @config['work_dir']
            print "Work directory #{@config['work_dir']} doesn't exist. Create it? [y/n]: "
            answer=STDIN.gets.chomp
            if answer =~ /^[yY]/
                begin
                    Dir.mkdir(@config['work_dir'])
                rescue
                    raise RuntimeError, "#{self::COMPONENT}: Couldn't create directory: #{$!}"
                end
            else
                raise RuntimeError, "#{self::COMPONENT} Work directory unavailable. Exiting."
            end
        end
    end

    # --- Send functions

    def dump_debug_data( msg_hash )
        begin
            port, ip=Socket.unpack_sockaddr_in( get_peername )
            warn "OUT: #{msg_hash['verb']}:#{msg_hash['ack_id'] rescue ''}  to #{ip}:#{port}"
        rescue
            warn "OUT: #{msg_hash['verb']}, not connected."
        end
    end

    def send_once( msg_hash )
        unless (self.class.listen_ip rescue false)
            self.reconnect(self.class.server_ip, self.class.server_port) if self.error?
        end
        dump_debug_data( msg_hash ) if self.class.debug
        send_data FuzzMessage.new(msg_hash).pack
    end

    def send_message( msg_hash, queue=nil )
        # The idea here is that if we want the message delivered
        # to one specific host, we don't pass a queue and it gets
        # resent. For stuff like tests, we don't care who gets them
        # so we just put them back in the outbound queue if they
        # time out.
        msg_hash['ack_id']=msg_hash['ack_id'] || self.class.new_ack_id
        unless (self.class.listen_ip rescue false)
            # server components don't reconnect, but clients do.
            self.reconnect(self.class.server_ip, self.class.server_port) if self.error?
        end
        dump_debug_data( msg_hash ) if self.class.debug
        send_data FuzzMessage.new(msg_hash).pack
        waiter=OutMsg.new msg_hash
        waiter.timeout(self.class.poll_interval)
        waiter.errback do
            self.class.lookup[:unanswered].delete(msg_hash['ack_id'])
            warn "#{self.class::COMPONENT}: Timed out sending #{msg_hash['verb']}#{msg_hash['ack_id'] rescue ''}. "
            if queue
                warn "Putting it back on the queue.\n"
                queue << msg_hash
            else
                warn "Resending it.\n"
                send_message msg_hash
            end
        end
        self.class.lookup[:unanswered][msg_hash['ack_id']]=waiter
    end

    def send_ack(ack_id, extra_data={})
        msg_hash={
            'verb'=>'ack_msg',
            'ack_id'=>ack_id,
        }
        msg_hash.merge! extra_data
        send_once msg_hash
    end

    # Used for 'heartbeat' messages that get resent when things
    # are in an idle loop
    def start_idle_loop( msg_hsh )
        send_once msg_hsh
        waiter=EventMachine::DefaultDeferrable.new
        waiter.timeout(self.class.poll_interval)
        waiter.errback do
            self.class.queue[:idle].shift
            warn "#{self.class::COMPONENT}: Timed out sending #{msg_hsh['verb']}. Retrying."
            start_idle_loop( msg_hsh )
        end
        self.class.queue[:idle] << waiter
    end

    def cancel_idle_loop
        self.class.queue[:idle].shift.succeed rescue nil
        raise RuntimeError, "#{self.class::COMPONENT}: idle queue not empty?" unless self.class.queue[:idle].empty?
    end

    # --- Receive Functions

    # If the ack needs special processing, the client code should
    # overload this and do something like stored_hsh=super and 
    # then inspect the data in the stored hash.
    def handle_ack_msg( msg )
        waiter=self.class.lookup[:unanswered].delete( msg.ack_id )
        waiter.succeed
        stored_msg_hsh=waiter.msg_hash
        if self.class.debug
            warn "(ack of #{stored_msg_hsh['verb']})"
        end
        stored_msg_hsh
    rescue
        if self.class.debug
            warn "(can't handle that ack, must be old.)"
        end
    end

    # FuzzMessage#verb returns a string so self.send activates
    # the corresponding 'handle_' instance method above, 
    # and passes the message itself as a parameter.
    def receive_data(data)
        @buffer << data
        loop do
            @offset = @handler.execute(@buffer, @offset)
            if @handler.finished?
                m=@handler.data
                @buffer.slice!(0, @offset)
                @offset = 0
                @handler.reset
                msg=FuzzMessage.new(m)
                if self.class.debug
                    port, ip=Socket.unpack_sockaddr_in( get_peername )
                    warn "IN: #{msg.verb}:#{msg.ack_id rescue ''} from #{ip}:#{port}"
                end
                self.send("handle_"+msg.verb.to_s, msg)
                next unless @buffer.empty?
            end
            break
        end
    end

    def connection_completed
        port, ip=Socket.unpack_sockaddr_in( get_peername )
        warn "#{self.class::COMPONENT} #{self.class::VERSION}: Connection: #{ip}:#{port}"
    end

    def method_missing( meth, *args )
        raise RuntimeError, "Unknown Command: #{meth.to_s}!"
    end

    def initialize
        @handler=MessagePack::Unpacker.new
        @offset=0
        @buffer=""
    end
end
