# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2010.
# License: The MIT License
# (See README.TXT or http://www.opensource.org/licenses/mit-license.php for details.)

require 'digest/md5'

#This module implements the Ruby 1.8 Generator class for 1.9, using fibers.
#Mainly, it is for my own Generators, and isn't supposed to be a true language
#addition / fix.It is massively less suckful in terms of memory leakage and 
#speed, but I'm sure there is room for improvement. One limitation is that 
#when you define your subclasses of NewGen you need to define a block in your
#initialize function in a specific way for .next? to work cleanly:
#Example:
# 
#   class Foo < NewGen
#       def initialize (*args)
#           @block=Fiber.new do
#               # code here
#               nil # nil or false at the end of the block
#           end
#           super 
#       end
module Generators
    class NewGen

        def initialize (*args)
            @args=args
            @alive=true
            @cache=@block.resume
        end

        def next?
            @alive
        end
        
        def finished?
            not @alive
        end

        def next
            @current=@cache
            begin
                @cache=@block.resume
            rescue FiberError
                @cache=false
            end
            @alive=false unless @cache
            @current
        end

        def to_a
            a=[]
            a << self.next while self.next?
            self.rewind
            a
        end
        
        def each(&blk)
            blk.yield self.next while self.next?
            self.rewind
        end

        def rewind
            initialize(*@args)
            true
        end
    end

    #In: Series, Start, Step, Limit, [Transform1, [...] TransformN]
    # 
    #Series can be anything that can be coerced into 
    #an array including Array, String, Generator etc.
    #Start, Step and Limit are the initial value, stepsize
    #and maximum repeat count. 
    #If start=0
    #then the first step will be skipped, so start=0 step=50
    #will produce 50 whatevers as the first iteration.
    #If step=0 then an exponential step will be used, adding
    #3, 5, 9, 17, 33, 65, 129 [...] to the start value ( (2**stepnum) + 1 ),
    #with the final step being replaced by the limit variable.
    #Transform1..N are Proc objects that will
    #be run, in order, at each iteration to perform
    #output feedback mutation.
    #The first transform is run on the final array itself, so 
    #it needs to be able to cope with an array (eg Proc.new {|a| a.to_s})
    #A Repeater with start,step,limit=1,1,1 can be used as a Dictionary
    #by passing a list or an Incrementor by passing a range.
    #
    #Examples:
    # g=Generators::Repeater.new('A',0,2,10, proc {|a| a.to_s })
    # g.to_a
    # => ["AA", "AAAA", "AAAAAA", "AAAAAAAA", "AAAAAAAAAA"]
    #
    # g=Generators::Repeater.new( (1..6),1,1,1,proc {|a| a.first })
    # g.to_a
    # => [1, 2, 3, 4, 5, 6]
    #
    # g=Generators::Repeater.new( %w( dog cat monkey love ),1,1,1,proc {|a| a.to_s })	
    # g.to_a
    # => ["dog", "cat", "monkey", "love"]
    #
    # g=Generators::Repeater.new( %w( dog cat monkey love ),1,1,1,proc {|a| a.to_s}, proc {|s| Base64.encode64(s).chop })
    # g.to_a
    # => ["ZG9n", "Y2F0", "bW9ua2V5", "bG92ZQ=="]
    #
    # g=Generators::Repeater.new( "replace me!",1,1,10,proc {|a| a.map {|e| rand(256).chr }.join} )
    # g.to_a
    # => ["\252", "j\302", "\264\231C", "\245\303\334\314", "\351\230R\207K", 
    #      "\343;\356b\201\t", "\204\212sR\027$\344", "B\274~8\2128G\242", 
    #      "/9,<*\365}\023q", "u\212\3129\241X\267Ao\246"]
    class Repeater < NewGen

        def initialize(series,start,step,limit,*transforms)
            @series,@start,@step,@limit=series,start,step,limit
            @transforms=transforms
            if @series.respond_to? :each
                @repeatables=@series
            else
                @repeatables=Array(@series)
            end
            @block=Fiber.new do
                @repeatables.each {|r|
                    if @step==0 # exponential step + startval
                        a=(1..10000000000).step # slightly lame way of doing it, but short
                        while (i=@start+(2**(a.next)+1)) < @limit
                            Fiber.yield(@transforms.inject(Array.new(i,r)) {|v,p| v=p.call(v)})
                        end
                        Fiber.yield(@transforms.inject(Array.new(@limit,r)) {|v,p| v=p.call(v)})
                    else
                        (@start...@limit).step(@step) {|i|
                            next if i==0
                            Fiber.yield(@transforms.inject(Array.new(i,r)) {|v,p| v=p.call(v)})
                        }
                        Fiber.yield(@transforms.inject(Array.new(@limit,r)) {|v,p| v=p.call(v)})
                    end
                }
                nil
            end
            super
        end
    end


    #In: n Series where n>0.
    #Out: Arrays, each having n elements
    #	
    #The Cartesian generator will output each item in the cartesian
    #product of the series passed as arguments. Output
    #is in the form of an array. 
    #
    #Example: 
    # require 'generators'
    # g=Generators::Cartesian.new( ('a'..'c'), [1,2], %w( monkey hat ) )
    # while g.next?
    #	foo, bar, baz=g.next
    #	puts "#{foo} : #{bar} -- #{baz}"
    # end
    #Produces:
    # a : 1 -- monkey
    # a : 1 -- hat
    # a : 2 -- monkey
    # a : 2 -- hat
    # b : 1 -- monkey
    # b : 1 -- hat
    # b : 2 -- monkey
    # b : 2 -- hat
    # c : 1 -- monkey
    # [etc]
    #Note: The cartesian product function is quite forgiving
    #and will take Generators, Ranges and Arrays (at least)
    class Cartesian < NewGen

        def cartprod(base, *others) #:nodoc:
            if block_given?
                if others.empty?
                    base.each {|a| yield [a]}   
                else
                    base.each do | a |
                        cartprod(*others) do | b |
                        yield [a, *b] 
                        end
                    end
                end
                nil
            else
                return base.map{|a|[a]} if others.empty?
                others = cartprod(*others)
                base.inject([]) { | r, a | others.inject(r) { | r, b | r << ([a, *b]) } }
            end
        end

        def initialize (*series)
            @series=series
            @block=Fiber.new do
                cartprod(*series) {|elem|
                    Fiber.yield elem
                }
                nil
            end
            super 
        end
    end

    #Outputs a stream of corner cases for the given bitlength as Integers
    #
    #Currently, this will output all 1's, all 0s,
    #plus a few corner cases like 1000, 0001, 1110, 0111
    #0101, 1010 etc
    #
    #I am presently more inclined to use RollingCorrupt in my own work.
    #
    # require 'generators'
    # g=Generators::BinaryCornerCases.new(16)
    # g.to_a.map {|case| "%.16b" % case}
    #Produces:
    # ["1111111111111111", "0000000000000000", "1000000000000000", "0000000000000001", 
    #  "0111111111111111", "1111111111111110", "1100000000000000", "0000000000000011", 
    #  "0011111111111111", "1111111111111100", "1110000000000000", "0000000000000111", 
    #  "0001111111111111", "1111111111111000", "1010101010101010", "0101010101010101"]
    class BinaryCornerCases < NewGen

        def initialize (bitlength)
            @bitlength=bitlength
            cases=[]
            # full and empty
            cases << ('1'*bitlength).to_i(2)
            cases << ('0'*bitlength).to_i(2)
            # flip up to 4 bits at each end
            # depending on bitlength
            case
            when @bitlength > 32
                lim=4
            when (16..32) === @bitlength
                lim=3
            when (8..15) === @bitlength
                lim=2
            else
                lim=1
            end
            for i in (1..lim) do
                cases << (('1'*i)+('0'*(bitlength-i))).to_i(2)
                cases << (('0'*(bitlength-i))+('1'*i)).to_i(2)
                cases << (('0'*i)+('1'*(bitlength-i))).to_i(2)
                cases << (('1'*(bitlength-i))+('0'*i)).to_i(2)
            end
            # alternating
            cases << ('1'*bitlength).gsub(/11/,"10").to_i(2)
            cases << ('0'*bitlength).gsub(/00/,"01").to_i(2)

            @block=Fiber.new do
                # The call to uniq avoids repeated elements
                # when bitlength < 4
                cases.uniq.each {|c| Fiber.yield c}
                nil
            end 
            super
            @alive=false if bitlength==0
        end
    end

    # Takes a series of kind_of? Generator objects and produces a generator which will produce the output of 
    # all the others by calling g.next over and over.
    # You could also do this by passing g1.to_a+g2.to_a
    # to the Repeater, but this is cleaner and uses lazier
    # evaluation.
    class Chain < NewGen
        def initialize ( *generators )
            @generators=generators
            @block=Fiber.new do
                @generators.each {|gen|
                    while gen.next?
                        Fiber.yield gen.next
                    end
                }
                false
            end 
            super
            @alive=false unless @generators.any? {|g| g.next?}
        end

        def rewind
            @generators.each {|g| g.rewind}
            super
        end
    end

    #In: A NewGen
    #Out: A NewGen which strips duplicate output from the first
    #generator by using a 10,000 item ring buffer of MD5 hashes.
    #
    #Might eat too much RAM, and/or be slow, YMMV.
    class DuplicateFilter < NewGen

        def hash( item )
            Digest::MD5.hexdigest(String(item))
        end

        def initialize( gen )
            @generator=gen
            @seen=Hash.new(false)
            @limit=10000
            @block=Fiber.new do
                until @generator.finished?
                    this_value=gen.next
                    Fiber.yield( this_value ) unless @seen[hash(this_value)]
                    @seen[hash(this_value)]=true
                    @seen.shift if @seen.length > @limit
                end
                false
            end
            @alive=false unless gen.respond_to?(:alive?) && gen.alive?
            super
        end

        def rewind
            @generator.rewind
            super
        end
    end

    #Enumerates all binary strings up to length
    #(bitlength). Useful as a primitive.
    class EnumerateBits < NewGen
        def initialize ( bitlength )
            @bitlength, @count=bitlength
            @block=Fiber.new do
                0.upto (2**@bitlength)-1 do |i|
                    Fiber.yield "%.#{bitlength}b" % i
                end
                false
            end 
            super
            @alive=false if bitlength==0
        end
    end
    #Produces (count) random numbers of (bitlength).
    #Looks dumb, but can be useful as a primitive.
    class Rand < NewGen
        def initialize ( bitlength, count )
            @bitlength, @count=bitlength, count
            @block=Fiber.new do
                @count.times do
                    Fiber.yield(rand(2**@bitlength))
                end
                false
            end 
            super
            @alive=false if bitlength==0
        end
    end
    # Parameters: String, Bitlength, Stepsize,Random Cases=0
    # Will corrupt Bitlength bits of the provided string by substituting each of the binary outputs
    # of the BinaryCornerCases generator and also adding and subtracting 1..9 from the existing value. 
    # If the bitlength is 16, 32 or 64 and the endianness is specified as :little, it will byteswap for you
    # both ways.
    # At each step it will advance the 'rolling window' that is
    # being corrupted by Stepsize bits. So, with Bitlength 11 and Stepsize 3 it will first corrupt bits
    # [0..10] then bits [3..13] and so on. Note that it is assumed that the string is packed already, so it 
    # will be unpacked to binary, corrupted at the binary level and then repacked.
    # If an integer is specified for the Random Cases parameter then the generator will also add that number
    # of random binary strings to the corruption
    # This generator also works quite well for packed integers, by just specifying a bitlength and stepsize
    # identical to the length of the integer.
    class RollingCorrupt < NewGen
        
        def byteswap_bitstring( bitstring )
            bitstring.scan(/.{8}/).reverse.join
        end

        def initialize(str, bitlength, stepsize,random_cases=0,endian=:big)
            @str,@bitlength,@stepsize,@random_cases=str,bitlength,stepsize,random_cases
            @binstr=str.unpack('B*').first
            @swap=(endian==:little && (bitlength==16 || bitlength==32 || bitlength==64))
            raise RuntimeError, "Generators::RollingCorrupt: internal bitstring conversion broken?" unless @binstr.length==(@str.length*8)
            @block=Fiber.new do 
                gBin=Generators::BinaryCornerCases.new(bitlength)
                if random_cases > 0
                    gRand=Generators::Rand.new(bitlength, random_cases)
                    gFinal=Generators::Chain.new(gBin,gRand)
                else
                    gFinal=gBin
                end
                rng=Range.new(0, @binstr.length-1)
                rng.step(stepsize) {|idx|
                    gFinal.rewind
                    # Add / Subtract 1..9 from the value that was there
                    # This code is a little puke-worthy.
                    (1..9).each {|num|
                        out_str=@binstr.clone
                        to_change=out_str[idx..idx+(bitlength-1)]
                        to_change=byteswap_bitstring(to_change) if @swap
                        changed="%.#{bitlength}b" % (to_change.to_i(2) + num)
                        changed=byteswap_bitstring(changed) if @swap
                        out_str[idx..idx+(bitlength-1)]=changed[0,bitlength]
                        out_str=[out_str[0..@binstr.length-1]].pack('B*')
                        raise RuntimeError, "Generators:RollingCorrupt: Data corruption." unless out_str.length==@str.length
                        Fiber.yield out_str
                        out_str=@binstr.clone
                        to_change=out_str[idx..idx+(bitlength-1)]
                        to_change=byteswap_bitstring(to_change) if @swap
                        changed="%.#{bitlength}b" % (to_change.to_i(2) - num)
                        changed=byteswap_bitstring(changed) if @swap
                        out_str[idx..idx+(bitlength-1)]=changed[0,bitlength]
                        out_str=[out_str[0..@binstr.length-1]].pack('B*')
                        raise RuntimeError, "Generators:RollingCorrupt: Data corruption." unless out_str.length==@str.length
                        Fiber.yield out_str
                    }
                    while gFinal.next?
                        out_str=@binstr.clone
                        out_str[idx..idx+(bitlength-1)] = "%.#{bitlength}b" % gFinal.next
                        out_str=[out_str[0..@binstr.length-1]].pack('B*')
                        raise RuntimeError, "Generators:RollingCorrupt: Data corruption." unless out_str.length==@str.length
                        Fiber.yield out_str
                    end
                }
                nil
            end 
            super
            @alive=false if str.empty?
        end

    end

    #Removes the middle third of a given string until the final length is 2. 
    class Chop < NewGen
        def remove_middle_third( instr )
            len=instr.length
            return instr if len < 3
            case (len % 3)
            when 0 # smallest case 3 => 1 (1) 1
                return instr[0..(len/3)-1] + instr[-(len/3)..-1]
            when 1 # smallest case 4 => 1 (2) 1
                return instr[0..((len-1)/3)-1] + instr[-((len-1)/3)..-1]
            when 2 # smallest case 5 => 2 (1) 2
                return instr[0..((len+1)/3)-1] + instr[-((len+1)/3)..-1]
            else
                raise RuntimeError, "Universe broken, modulus doesn't work."
            end
        end

        def initialize(str)
            @str=str
            @block=Fiber.new do |g|
                while str.length >= 3
                    str=remove_middle_third(str)
                    Fiber.yield str
                end
                nil
            end 
            super
        end
    end

    # In: value, limit, *transforms
    # Outputs (value), (limit) times or forever when limit==-1. 
    # However, using transforms can drastically modify the behaviour of this generator.
    class Static < NewGen

        def initialize (*args)
            @val=args[0]
            @limit=args[1]
            @transforms=args[2..-1]
            @block=Fiber.new do
                if @limit==-1
                    loop do
                        Fiber.yield(@transforms.inject(Marshal.load(Marshal.dump(@val))) {|val, proc|
                            val=proc.call(val)
                        })
                    end
                else
                    for i in (1..@limit)
                        Fiber.yield(@transforms.inject(Marshal.load(Marshal.dump(@val))) {|val, proc|
                            val=proc.call(val)
                        })
                    end
                end
                nil
            end
            super
        end

    end
end

if __FILE__==$0
    puts "Starting tests..."
    include Generators
    puts "Static..."
    g=Static.new("dog",4,proc do |s| s.upcase end,proc do |s| s.reverse end)
    while g.next?
        puts g.next
    end
    g.rewind
    puts g.next.downcase.reverse
    puts "Repeater..."
    g=Repeater.new(['a','b'],0,0,100,proc do |a| a.join.upcase end,proc do |s| s.tr('AEIOU','Q') end)
    while g.next?
        puts g.next
    end
    g.rewind
    puts g.next
    puts "Cartesian..."
    g=Generators::Cartesian.new( ('a'..'c'), [1,2], %w( monkey hat ) )
    while g.next?
        foo, bar, baz=g.next
        puts "#{foo} : #{bar} -- #{baz}"
    end
    g1=Generators::Repeater.new((1..4),1,1,1,proc do |a| a.join end)
    g2=Generators::Repeater.new((5..8),1,1,1,proc do |a| a.join end)
    g=Generators::Cartesian.new(g1,g2)
    while g.next?
        a,b=g.next
        puts "#{a}--#{b}"
    end
    puts "Binary Corner..."
    g=Generators::BinaryCornerCases.new(8)
    puts g.to_a.map {|c| "%.8b" % c}
    puts "Chain"
    g1=Generators::BinaryCornerCases.new(16)
    g2=Generators::BinaryCornerCases.new(8)
    chain=Generators::Chain.new(g1,g2)
    p chain
    p chain.to_a
    puts "Binary Corrupt..."
    g=Generators::RollingCorrupt.new("a",8,8,0)
    while g.next?
        p g.next
    end
    g.rewind
    puts g.to_a.length
end
