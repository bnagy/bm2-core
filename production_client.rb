# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2010.
# License: The MIT License
# (See README.TXT or http://www.opensource.org/licenses/mit-license.php for details.)

require 'rubygems'
require 'eventmachine'
require 'zlib'
require 'digest/md5'
require File.dirname(__FILE__) + '/objhax'
require File.dirname(__FILE__) + '/fuzzprotocol'
require File.dirname(__FILE__) + '/detail_parser'

# This class is a generic class that can be inherited by task specific production clients, to 
# do most of the work. It speaks my own Metafuzz protocol which is pretty much
# serialized hashes, containing a verb and other parameters.
#
# In the overall structure, one or more of these will feed test cases to one or more fuzz servers.
# In a more complicated implementation it would also be able to adapt, based on the results.
#
# To be honest, if you don't understand this part, (which is completely fair) 
# you're better off reading the EventMachine documentation, not mine.

class ProductionClient < HarnessComponent

    COMPONENT="ProdClient"
    VERSION="3.5.0"
    DEFAULT_CONFIG={
        'server_ip'=>"127.0.0.1",
        'server_port'=>10001,
        'work_dir'=>File.expand_path('~/prodclient'),
        'poll_interval'=>60,
        'production_generator'=>nil,
        'queue_name'=>'bulk',
        'debug'=>false,
        'base_tag'=>'',
        'fuzzbot_options'=>[]
    }

    def self.next_case_id
        @case_id||=0
        @case_id+=1
    end

    def self.case_id
        @case_id||=0
    end

    # --- Send methods

    def send_test_case( tc, case_id, crc, tag )
        send_message(
            'verb'=>'new_test_case',
            'id'=>case_id,
            'crc32'=>crc,
            'data'=>tc,
            'queue'=>self.class.queue_name,
            'tag'=>tag,
            'fuzzbot_options'=>self.class.fuzzbot_options
        )
    end

    def send_client_startup
        send_message(
            'verb'=>'client_startup',
            'client_type'=>'production'
        )
    rescue
        puts $!
    end

    def send_next_case
        if self.class.production_generator.next?
            test=self.class.production_generator.next
            crc=Zlib.crc32(test)
            tag=""
            tag << self.class.base_tag
            tag << "PRODUCER_CRC32:#{"%x" % crc}\n"
            tag << "PRODUCER_TIMESTAMP:#{Time.now}\n"
            tag << "PRODUCER_ITERATION:#{self.class.case_id+1}\n"
            send_test_case test, self.class.next_case_id, crc, tag
        else
            puts "All done, exiting."
            EventMachine::stop_event_loop
        end
    end

    # Receive methods...

    # By default, we just use the second ack which contains the result
    # to keep stats. If you need to have a sequential producer, overload 
    # this function to ignore the first ack which just signifies receipt.
    def handle_ack_msg( their_msg )
        begin
            if their_msg.startup_ack
                super
                send_next_case
                warn "Started, shouldn't see this again..." if self.class.debug
                return
            end
            if their_msg.result
                self.class.lookup[:results][their_msg.result]||=0
                self.class.lookup[:results][their_msg.result]+=1
                if their_msg.result=='crash' and their_msg.crashdetail
                    crashdetail=their_msg.crashdetail
                    self.class.lookup[:buckets][DetailParser.hash( crashdetail )]=true
                    # You might want to clear this when outputting status info.
                    self.class.queue[:bugs] << DetailParser.long_desc( crashdetail )
                    # Just initials - NOT EXPLOITABLE -> NE etc
                    classification=DetailParser.classification( crashdetail).split.map {|e| e[0]}.join
                    self.class.lookup[:classifications][classification]||=0
                    self.class.lookup[:classifications][classification]+=1
                end
            else
                # Don't cancel the ack timeout here - this is the first ack
                # We wait to get the full result, post delivery.
                super
                send_next_case
            end
        rescue
            raise RuntimeError, "#{COMPONENT}: Unknown error. #{$!}"
        end
    end

    def handle_reset( msg )
        # Note that we don't cancel unacked test cases or
        # restart the production generator, we just send
        # the startup so the server will get our template
        send_client_startup
    end

    def post_init
        send_client_startup
    end
end
