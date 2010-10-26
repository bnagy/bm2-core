# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2010.
# License: The MIT License
# (See README.TXT or http://www.opensource.org/licenses/mit-license.php for details.)
#
require 'enumerator'
require 'objhax'

#The FSA class lets you create mini FSAs. Rather than implement a full FSA parser, this class allows you to create objects that are
#fairly simple to track state and to run blocks of code to create protocol elements. It's quite possible for the state of the application
#being tested to be out of sync with these FSA objects, but they are a good way to quickly arrive at a certain state when fuzzing stateful
#applications. There are two kinds of edges, SendEdge and RecvEdge. Both take a source and destination node. Send edges take one block which will
#be called when the edge is invoked (the block should produce the required output to move from the source state to the destination state). Recv edges
#also take a match block which should examine a lump of data and return a boolean response as to whether or not that data is valid for the current state
#(correct packet type, matching cookies, for example).
#
#The easiest way to explain the FSA is with an example: 
# class TestFSA < FSA
#	node :init, root=true
#	node :req_sent
#	node :established
#	node :closing
#	
#	edge :init, :req_sent, :send, proc {set_state(:cookie, "abcdef"); output_pkt="<<Imagine I am a packet...>>"}
#	req_sent_match=proc {|data| data.slice(0,6)==get_state(:cookie)}
#	req_sent_action=proc {|data| set_state(:trans_id, data.slice(6..-1))}
#	edge :req_sent, :established, :recv,  req_sent_match, req_sent_action
#	#more edges here...
# end
#
# t=TestFSA.new
# puts "Starting at Node #{t.current_node.name}"
# output=t.navigate(t.current_node,t.req_sent)
# puts "Need to send: #{output} to get to req_sent..."
# # would send output here.
# puts "sending..."
# puts "New Node: #{t.current_node.name}"
# puts "Current State: #{t.state.inspect}"
# # would read response here
# response="abcdef165"
# puts "Got response: #{response}"
# if t.current_node.can_process?(response)
#	puts "Response Match - sending #{response.inspect} to FSA..."
#	t.deliver(response) 
# end
# puts "New Node: #{t.current_node.name}"
# puts "Current State: #{t.state.inspect}"
# puts "Resetting..."
# t.reset
# puts "New Node: #{t.current_node.name}"
# puts "Current State: #{t.state.inspect}"
#Produces:
# Starting at Node init
# Need to send: <<Imagine I am a packet...>> to get to req_sent...
# sending...
# New Node: req_sent
# Current State: {:cookie=>"abcdef"}
# Got response: abcdef165
# Response Match - sending "abcdef165" to FSA...
# New Node: established
# Current State: {:trans_id=>"165", :cookie=>"abcdef"}
# Resetting...
# New Node: init
# Current State: {}

class FSA
	
	# start constructor methods
	
	#Construct a new node.
	def self.node( sym, is_root_node=false )
		@nodes_to_create||=[]
		if @nodes_to_create.any? {|node_name, root| root==true} && is_root_node
			raise ArgumentError, "FSA: Error, only one root node allowed per FSA."
		end
		raise ArgumentError, "FSA: Error, node name not a symbol." unless sym.is_a? Symbol
		if @nodes_to_create.any? {|node_name, is_root| sym==node_name}
			puts "Warning: redefining node #{sym}"
		end
		@nodes_to_create << [sym, is_root_node]
	end
	
	#Construct an edge between two nodes.
	def self.edge( from_sym, to_sym, edge_type, *blocks )
		raise ArgumentError, "FSA: Error, from_node name not a symbol." unless from_sym.is_a? Symbol
		raise ArgumentError, "FSA: Error, to_node name not a symbol." unless to_sym.is_a? Symbol
		raise ArgumentError, "FSA: Error, invalid block." unless blocks.all? {|blk| blk.kind_of? Proc}
		unless edge_type==:send || edge_type==:recv
			raise ArgumentError, "FSA: Error, unknown type #{edge_type}. Valid: :send, :recv."
		end
		if edge_type==:send
			raise ArgumentError, "FSA: Error, send node requires exactly one block [action block]" unless blocks.length==1
		else
			raise ArgumentError, "FSA: Error, recv node requires exactly two blocks [match block, action block]" unless blocks.length==2
		end
		@edges_to_create||=[]
		if @edges_to_create.any? {|from, to, type, *blks| from==from_sym && to==to_sym && type==edge_type}
			puts "Warning: redefining edge from #{from_sym} to #{to_sym}." 
		end
		@edges_to_create << [from_sym, to_sym, edge_type, *blocks]
	end
	
	def self.nodes_to_create #:nodoc:
		@nodes_to_create||=[]
	end
	
	def self.edges_to_create#:nodoc:
		@edges_to_create||=[]
	end
	# end constructor methods
	
	attr_reader :root_nodes, :nodes, :current_node
	attr_accessor :state
	
	# start instance methods
	
	def initialize #:nodoc:
		@state||={}
		@nodes||={}
		self.class.nodes_to_create.each do |node_arg_array|
			name, isroot=node_arg_array
			# dump the nodes in a hash by name, since that is unique.
			@nodes[node_arg_array[0]]=Node.new(name)
			@nodes[node_arg_array[0]].parent_fsa=self
			@root_node=@nodes[node_arg_array[0]] if isroot
		end
		self.class.edges_to_create.each do |edge_arg_array|
			from, to, type, *blocks=edge_arg_array
			unless @nodes.any? {|name, node| name==from}
				raise ArgumentError, "FSA: Error, tried to add edge from invalid node #{from}."
			end
			unless @nodes.any? {|name, node| name==to}
				raise ArgumentError, "FSA: Error, tried to add edge to invalid node #{to}."
			end
			if type==:send
				new_edge=SendEdge.new(to, @nodes[from], *blocks)
			else
				new_edge=RecvEdge.new(to, @nodes[from], *blocks)
			end
			@nodes[from].add_edge(new_edge)
		end
		unless (badnodes=nodes.select {|name,node| node.edges.empty?}).empty?
			puts "Warning: Dead-End node(s) <#{badnodes.map {|name,node| name}.join(', ')}> without exits."
		end
		unless (badnodes=nodes.reject {|name,node| self.class.edges_to_create.any? {|from, to| to==name} || node==@root_node}).empty?
			puts "Warning: Orphan node(s) <#{badnodes.map {|name, node| name}.join(', ')}> cannot be reached."
		end
		unless @root_node
			raise RuntimeError, "Error: no root node defined."
		end
		@nodes.each_key {|node_name| meta_def node_name do @nodes[node_name] end}
		self.reset
	end
	
	#Manually set current node.
	def current_node=( new_node)
		raise ArgumentError, "Error: input not a Node." unless new_node.kind_of? Node
		raise ArgumentError, "Error: FSA does not contain node #{node.name}." unless self.nodes.any? {|name, node| node==new_node}
		@current_node=new_node
	end
	
	#Reset to root node, clear state.
	def reset
		self.current_node=@root_node
		self.state={}
	end
	
	# Return an array of edges starting at start_node and ending at target_node
	# TO DO: some shortest path algorithm goes here
	def route( start_node, target_node )
	end
	
	# Send data to current node, adjust state.
	# Raise StateError if the node cannot handle the input.
	def deliver( data )
		raise StateError, "Error: current node #{self.current_node.name} unable to process input." unless self.current_node.can_process? data
		self.current_node.invoke_recv_edge( self.current_node.can_process?(data), data ) 
	end
	
	#Invoke the send edge between from_node and to_node, invoking the first if there is more than one. This will
	#run the action block attached to the edge and return the result. Raises StateError if there is no send edge linking the nodes.
  #Note that navigate updates the state immediately, assuming that the data was successfully sent.
	def navigate( from_node, to_node )
		raise StateError, "Error: No send edge from #{from_node.name} to #{to_node.name}." unless from_node.send_edge_to? to_node
		from_node.invoke_send_edge(from_node.send_edges_to( to_node ).first)
	end

    def inspect
        self.class.to_s + " ready."
    end

end

class StateError < Exception
end

#The <tt>get_state</tt> and <tt>set_state</tt> methods are mainly provided for use inside the action blocks.
class Edge
	
	attr_reader :type, :destination
	attr_accessor :parent_node
	
	def initialize(dest, parent, *blocks )
		@parent_node=parent
		@destination=@parent_node.parent_fsa.nodes[dest]
	end
	
	#Return the entry for key in the current state hash of this FSA object.
	def get_state( key )
		@parent_node.parent_fsa.state[key]
	end
	
	#Set a key value pair in the current state hash of this FSA object.
	def set_state( key, val )
		@parent_node.parent_fsa.state[key]=val
	end

    def inspect
        "<#{self.class} From #{self.parent_node.name} to #{self.destination.name}>"
    end
	
end
	
class SendEdge < Edge
	
	def initialize(dest, parent, action_block)
		super
		@action_block=action_block
		@type=:send
	end
	
	#Each SendEdge connects a source and a destination node. This method returns the output created by the
	#action_block that is defined in the FSA, which should be the data that must be sent to the target in order
	#to reach the state defined by destination node. It will read and update the FSA state as neccessary, and return
	#the output that must be delivered.
	def invoke
		self.parent_node.parent_fsa.current_node=self.destination
		self.instance_eval &@action_block
	end

end

class RecvEdge < Edge
	
	def initialize(dest, parent, match_block, action_block)
		super
		@match_block=match_block
		@action_block=action_block
		@type=:recv
	end
	
	#Return the boolean result of match_block when called with the input_data. Usually called by the parent node
	#as part of <tt>can_process?</tt>
	def input_match?( input_data )
		!!(self.instance_exec(input_data, &@match_block))
	end
	
	# Runs the action block to process the input data and adjust current_node, updating the FSA state as neccessary.
	# Returns the new current_node.
	def invoke( input_data )
		self.instance_exec(input_data, &@action_block)
		self.parent_node.parent_fsa.current_node=self.destination
	end
	
end

class Node
	
	attr_reader :name, :edges
	attr_accessor :parent_fsa
	def initialize( name )
		@name=name
		@edges=[]
	end
	
	#Used in the construction phase to add edges to a Node.
	def add_edge( edge )
		raise ArgumentError, "Error: argument not an edge" unless edge.kind_of? Edge
		@edges << edge
	end
	
	#Returns "true" if the node has a Recv edge that can process this data.
  #(actually it returns the first edge it finds that can do the processing)
	#Only one recv edge should be valid for a certain input, and if that's not the
	#case then they'd better be equivalent or the FSA was created incorrectly. :)
	def can_process?( data )
    return false unless data
		self.recv_edges.select {|edge| edge.input_match? data.clone}.first
	end
	
	def send_edge_to?( node )
		not self.send_edges_to( node ).empty?
	end
	
	#Invoke the action block of a Recv edge, returns the new current_node of the FSA. Usually called by
	#the parent FSA as part of <tt>deliver</tt>
	def invoke_recv_edge( recv_edge, data )
		recv_edge.invoke( data )
	end
	
	# Return an array of all send edges
	def send_edges
		@edges.select {|edge| edge.type==:send}
	end
	
	# Return an array of all recv edges
	def recv_edges
		@edges.select {|edge| edge.type==:recv}
	end
	
	#Return an array of all send edges leading to a given destination node.
	def send_edges_to( dest_node )
		self.send_edges.select {|edge| edge.destination==dest_node}
	end
	
	# Invokes the action block of a given Send edge. Returns the output that should be sent.
	def invoke_send_edge( send_edge )
		raise ArgumentError, "Error: argument not an edge" unless send_edge.kind_of? Edge
		raise ArgumentError, "Error: edge #{send_edge.name} is not a send edge." unless send_edge.type==:send
		send_edge.invoke
	end

	# True if this node is the current node in the FSA
	def current_node?
		@parent_fsa.current_node==self
	end

    def inspect
        "<Node #{self.name}>"
    end

end

