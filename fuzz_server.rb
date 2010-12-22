# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2010.
# License: The MIT License
# (See README.TXT or http://www.opensource.org/licenses/mit-license.php for details.)

require 'rubygems'
require 'eventmachine'
require 'zlib'
require 'digest/md5'
require 'socket'
require File.dirname(__FILE__) + '/fuzzprotocol'
require File.dirname(__FILE__) + '/objhax'

# This class is a generic class that can be inherited by task specific fuzzservers, to 
# do most of the work. It speaks my own Metafuzz protocol which is pretty much JSON
# serialized hashes, containing a verb and other parameters.
#
# In the overall structure, this class is the broker between the production clients
# and the fuzz clients. It is single threaded, using the Reactor pattern, to make it
# easier to debug.
#
# To be honest, if you don't understand this part, (which is completely fair) 
# you're better off reading the EventMachine documentation, not mine.

class FuzzServer < HarnessComponent

    VERSION="3.5.0"
    COMPONENT="FuzzServer"
    DEFAULT_CONFIG={
        'listen_ip'=>"0.0.0.0",
        'listen_port'=>10001,
        'poll_interval'=>60,
        'debug'=>false,
        'dummy'=>false,
        'queue_shedding'=>false,
        'dbq_max'=>50,
        'work_dir'=>File.expand_path('~/fuzzserver'),
    }

    # --- Class stuff.

    def self.setup( *args )
        super
        # The fuzzclient and test case queues are actually hashes of
        # queues, to allow for multiple fuzzing runs simultaneously. 
        # EG the producer puts 'word' in its message.queue and those 
        # messages will only get farmed out to fuzzclients with a 
        # matching message.queue
        queue[:fuzzclients]=Hash.new {|hash, key| hash[key]=Array.new}
        queue[:test_cases]=Hash.new {|hash, key| hash[key]=Array.new}
        lookup[:summary]=Hash.new {|h,k| h[k]=0}
        lookup[:ready_fuzzclients]=Hash.new {|h,k| h[k]=Hash.new}
    end

    def self.next_server_id
        @server_id||=rand(2**31)
        @server_id+=1
    end

    # --- Instance Methods

    def post_init
        # Makes the rest of the code more readable...
        @db_msg_queue=self.class.queue[:db_messages]
        @tc_queue=self.class.queue[:test_cases]
        @db_conn_queue=self.class.queue[:dbconns]
        @fuzzclient_queue=self.class.queue[:fuzzclients]
        @ready_dbs=self.class.lookup[:ready_dbs]
        @ready_fuzzclients=self.class.lookup[:ready_fuzzclients]
        @unanswered=self.class.lookup[:unanswered]
        @delayed_results=self.class.lookup[:delayed_results]
        @delivery_receipts=self.class.lookup[:delivery_receipts]
        @summary=self.class.lookup[:summary]
    end

    def process_result( arg_hsh )
        # If this result isn't in the delayed result hash
        # there is something wrong.
        if @delayed_results.has_key? arg_hsh['server_id']
            send_result_to_db( arg_hsh ) unless self.class.dummy
            @summary['total']+=1
            @summary[arg_hsh['result']]+=1
        else
            # We can't handle this result. Probably the server
            # restarted while the fuzzclient had a result from
            # a previous run. Ignore.
            warn "Bad result... #{$!}" if self.class.debug
        end
    rescue
        warn $!
    end

    # --- Send functions

    def db_send( msg_hash )
        # Don't add duplicates to the outbound db queue.
        unless @db_msg_queue.any? {|hsh| msg_hash==hsh}
            # If we have a ready DB, send the message, otherwise
            # put a callback in the queue.
            if dbconn=@db_conn_queue.shift
                dbconn.succeed msg_hash
            else
                # If it goes onto the outbound queue we don't add a timeout
                # because it will get sent when the next db_ready comes in
                # This would happen before the DB connects for the first
                # time, for example.
                @db_msg_queue << msg_hash
            end
        end
        if (len=@db_msg_queue.length) > self.class.dbq_max
            # Note that the dbq_max isn't the real maximum - if many fuzzbots
            # are in the process of delivering, once the queue max is hit we
            # still need to accept their results, so we have to queue them for the DB...
            if self.class.debug
                warn "Fuzzserver: SHEDDING: DBQ > configured max of #{self.class.dbq_max} items (#{len})"
            end
            self.class.queue_shedding=true
        end
    end

    def send_result_to_db( arg_hsh )
        msg_hash={
            'verb'=>'test_result',
        }
        db_send( msg_hash.merge( arg_hsh ) )
    end

    # --- Receive functions

    # Acks might need special processing, if they contain additional
    # information, such as the acks to test_result and deliver
    # messages.
    def handle_ack_msg( their_msg )
        begin
            our_stored_msg=super
            case our_stored_msg['verb']
            when 'test_result'
                dr=@delayed_results.delete( our_stored_msg['server_id'])
                if our_stored_msg['result']=='crash'
                    # Send the crashdetail, crc32 and tag back to the production client
                    extra={'crashdetail'=>our_stored_msg['crashdetail'], 'crc32'=>our_stored_msg['crc32'], 'tag'=>their_msg.tag}
                    dr.succeed( our_stored_msg['result'], their_msg.db_id, extra )
                else
                    dr.succeed( our_stored_msg['result'], their_msg.db_id )
                end
            when 'deliver'
                return if their_msg.status=='error'
                if their_msg.status=='crash'
                    unless our_stored_msg['crc32']==their_msg.crc32
                        # Hopefully this never happens, it would mean we're getting crashes
                        # missed or lost or otherwise screwed up.
                        File.open("fuzzserver_error.log", "wb+") {|io| io.puts their_msg.inspect}
                        raise RuntimeError, "#{COMPONENT}:#{VERSION} - BARF, CRC mismatch!"
                    end
                    process_result(
                        'server_id'=>our_stored_msg['server_id'],
                        'result'=>their_msg.status,
                        'crashdetail'=>(their_msg.data rescue nil),
                        'crashfile'=>our_stored_msg['data'],
                        'tag'=>their_msg.tag,
                        'chain'=>their_msg.chain,
                        'crc32'=>our_stored_msg['crc32']
                    )
                else
                    process_result(
                        'server_id'=>our_stored_msg['server_id'],
                        'result'=>their_msg.status,
                        'crashdetail'=>nil,
                        'crashfile'=>nil,
                        'tag'=>their_msg.tag,
                        'crc32'=>our_stored_msg['crc32']
                    )
                end

            else
                # nothing extra to do.
            end
        rescue Exception => e
            warn "Weird, failed in handle_ack_msg"
            p $!
            p our_stored_msg
            puts e.backtrace
        end
    end

    def handle_db_ready( msg )
        port, ip=Socket.unpack_sockaddr_in( get_peername )
        # If this DB is already ready, ignore its heartbeat
        # messages, UNLESS there is something in the db queue.
        # (which can happen depending on the order in which stuff
        # starts up or restarts)
        if @ready_dbs[ip+':'+port.to_s] and @db_msg_queue.empty?
            if self.class.debug
                warn "(DB already ready, no messages in queue, ignoring.)"
            end
        else
            dbconn=EventMachine::DefaultDeferrable.new
            dbconn.callback do |msg_hash|
                send_message msg_hash, @db_msg_queue
                # we just sent something, this conn is no longer ready until
                # we get a new db_ready from it.
                @ready_dbs[ip+':'+port.to_s]=false
            end
            if @db_msg_queue.empty?
                # we have nothing to send now, so this conn is ready
                # and goes in the queue
                @db_conn_queue << dbconn
                @ready_dbs[ip+':'+port.to_s]=true
                warn "SHEDDING OVER" if self.class.queue_shedding and self.class.debug
                self.class.queue_shedding=false
            else
                # use this connection right away
                dbconn.succeed @db_msg_queue.shift
            end
        end
    end

    # Only comes from fuzzclients. Same idea as handle_db_ready (above).
    def handle_client_ready( msg )
        port, ip=Socket.unpack_sockaddr_in( get_peername )
        if @ready_fuzzclients[msg.queue][ip+':'+port.to_s] and (@tc_queue[msg.queue].empty? || self.class.queue_shedding)
            if self.class.debug
                warn "(fuzzclient already ready, no messages in queue, ignoring.)"
            end
        else
            clientconn=EventMachine::DefaultDeferrable.new
            # If the message has been redelivered there will be no receipt
            # anymore, because send_message takes only a msg_hash and a
            # queue. Since we already told the producer that we had accepted 
            # the message for delivery, this is not a problem.
            clientconn.callback do |msg_hash, receipt|
                receipt.succeed rescue nil
                send_message msg_hash, @tc_queue[msg.queue]
                @ready_fuzzclients[msg.queue][ip+':'+port.to_s]=false
            end
            if @tc_queue[msg.queue].empty?
                @ready_fuzzclients[msg.queue][ip+':'+port.to_s]=true
                @fuzzclient_queue[msg.queue] << clientconn
                warn "Starving" if self.class.debug
            else
                if self.class.queue_shedding
                    # queue this until the queue is under control.
                    @ready_fuzzclients[msg.queue][ip+':'+port.to_s]=true
                    @fuzzclient_queue[msg.queue] << clientconn
                else
                    clientconn.succeed @tc_queue[msg.queue].shift
                end
            end
        end
    end

    def handle_client_startup( msg )
        # Actually, the production client is the only one
        # that sends a client_startup, now..
        send_ack msg.ack_id, {'startup_ack'=>true}
    end

    def handle_new_test_case( msg )
        unless @tc_queue[msg.queue].any? {|msg_hash, receipt| msg_hash['producer_ack_id']==msg.ack_id }
            server_id=self.class.next_server_id
            # Note: we send two acks. Once when the test has been accepted by a fuzzbot
            # and once when the result comes back and has been inserted into the DB.
            # Serial prodclients (that need to know the result) need to wait for the
            # delayed result, general prodclients can send their next test as soon as
            # they get the receipt (which is faster). All prodclients should ignore
            # one of the acks, otherwise they'll flood the queue.
            # Create a delivery receipt, so we can let the prodclient know
            # once this test has been sent to the fuzzbots
            receipt=EventMachine::DefaultDeferrable.new
            receipt.callback do
                send_ack(msg.ack_id)
            end
            # Create a callback, so we can let the prodclient know once this
            # result has been accepted by the analysis server
            dr=EventMachine::DefaultDeferrable.new
            dr.callback do |result, db_id, *extra_info|
                m_hash={'result'=>result, 'db_id'=>db_id}
                m_hash.merge!(*extra_info) unless extra_info.empty?
                send_ack( msg.ack_id, m_hash)
            end
            @delayed_results[server_id]=dr
            # We're passing this test through without verifying
            # the CRC, that's done at the fuzzclient.
            msg_hash={
                'verb'=>'deliver',
                'data'=>msg.data,
                'server_id'=>server_id,
                'producer_ack_id'=>msg.ack_id,
                'crc32'=>msg.crc32,
                'fuzzbot_options'=>msg.fuzzbot_options,
                'tag'=>msg.tag
            }
            if self.class.queue_shedding
                # queue this until the DB queue is under control.
                @tc_queue[msg.queue] << [msg_hash, receipt]
            else
                if waiting=@fuzzclient_queue[msg.queue].shift
                    waiting.succeed msg_hash, receipt
                else
                    @tc_queue[msg.queue] << [msg_hash, receipt]
                end
            end
        else
            if self.class.debug
                warn "Ignoring duplicate #{msg.ack_id}"
            end
        end
    end
end
