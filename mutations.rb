# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2010.
# License: The MIT License
# (See README.TXT or http://www.opensource.org/licenses/mit-license.php for details.)

#The main point of interest of this module are the two hashes Injection_Generators and Replacement_Generators which 
#allow users to create custom blocks of fuzzing code that will be run for fields of a certain type. Want to run the cool
#x509 fuzzing code you just wrote and define an x509 field for use within Binstruct? Just add the code as a proc to these hashes
#and add a new Fields::Field subclass to the Fields module.
#
#If your new field type is Fields::FooField you do it like this:
# module Mutations
# 	Injection_Generators["foo"]=Proc.new {|maxlen| # l33t code here} 
# 	Replacement_Generators["foo"]=Proc.new {|maxlen| # more l33t code}
# end
#
#Now your code gets run to generate the injection and replacement elements whenever the fuzzer gets to a FooField.
module Mutations

    # creates an incrementing generator from a set of tokens. Resulting strings will contain
    # an exponentially incrementing number of tokens chosen from the set, until the maximum 
    # length is reached (tokens can be more than one character).
    # sets is an Array of sets to choose from, and the percentages control how often one
    # random element is chosen from each set.
    # Percentages should look like [50,75,100] or [70,90,95,100]
    def mix_and_match(maxlen, sets, percentages, utf16=false)
        unless sets.size==percentages.size
            raise ArgumentError, "Mutations: mix_and_match, percentages and sets must be the same"
        end
        combined=sets.zip( percentages )
        mapper=proc do |a|
            a.map {|e|
                r=(rand(100)+1)
                combined.each {|set, percent|
                    if r <= percent
                        if utf16
                            tok=set.sample
                            # Not perfect for tokens of length 3, 5, etc
                            # but there sren't any of those yet...
                            # double up on 1 byte tokens to keep alignment.
                            tok << set.sample if tok.length==1
                            break tok
                        else
                            break set.sample
                        end
                    end
                }
            }.join
        end
        Generators::Repeater.new(false,0,0,maxlen,mapper)
    end
    module_function :mix_and_match

    # Tweakable blocks that create the fuzz element generators, based on field type.
    # New field types might want to add their own fuzz element generators. The default
    # is to generate random 8-bit junk, but a special case is defined for string types.
    # The overflow elements for strings are four sets of strings of random selections from 
    # {/^*.[]$+@?1234()\'`} (regexp)  rand(256) (junk) and {%x%s%n} (format string) and {'p'} (ASCII).
    # This hash is for the injected elements, not the replacement elements.
    
    Junk=[*0..255].map(&:chr)
    Tokens=[' ',"\t","\n",':',';',',','<','>','=''80','08','&','#','{','}','[',']',"\x00", '\'','"','\\', "\x0d\x0a"]
    UTF16Tokens=Tokens.map {|s| (s.split(//).join("\x00"))<<"\x00"}
    ASCII=['H','p']
    UTF16ASCII=["H\x00", "p\x00"]
    BadUTF16=["\x3f\xd8","\x7f\xd8","\xfe\xdf","\xff\xdf","\x60\x20","\xef\xfd","\xfe\xff", "\x3f\xd8\xfe\xdf","\xbf\xd9\xff\xdf"]

    injection_default=Proc.new{|maxlen| 
        mostly_binary=mix_and_match(maxlen,[Junk,ASCII,Tokens],[70,85,100])
        nasty_unicode_binary=mix_and_match(maxlen,[Junk,BadUTF16,UTF16Tokens],[50,75,100],utf16=true)
        Generators::Chain.new(mostly_binary, nasty_unicode_binary)
    }
    Injection_Generators=Hash.new(injection_default) #:nodoc:
    Injection_Generators["string"]=Proc.new {|maxlen|
        mostly_ascii=mix_and_match(maxlen,[ASCII,Tokens,Junk],[65,95,100])
        unicode_mostly_ascii=mix_and_match(maxlen,[UTF16ASCII,UTF16Tokens,BadUTF16,Junk],[70,80,90,100],utf16=true)
        mostly_binary=mix_and_match(maxlen,[Junk,ASCII,Tokens],[70,85,100])
        nasty_unicode_binary=mix_and_match(maxlen,[Junk,BadUTF16,UTF16Tokens],[50,75,100],utf16=true)
        Generators::Chain.new(mostly_ascii, unicode_mostly_ascii, mostly_binary, nasty_unicode_binary)
    }
    # This hash is for the blocks that will create generators for field replacement generators.
    # The default looks at the length type. For fixed length fields it will enumerate possible values
    # if the field is <= 8 bits in length. For longer fields it will yield a set of binary corner cases.
    # For variable length fields like strings, hexstrings and the like it expands them by repeating the field up to maxlen times. 
    # and then runs a rolling corruption pass over them at the binary level (see the RollingCorrupt Generator)
    # Users would want to add
    # new blocks to the hash when they have types that need complicated fuzzing, eg ASN.1,
    # compressed chunks and the like.
    Replacement_Generators={} #:nodoc:
    Replacement_Generators.default=Proc.new{|field, maxlen, preserve_length, random_cases, fuzzlevel|
        if field.length_type=="fixed" or maxlen==0
            # for fields > 8 bits, just test the corner cases
            if field.length > 8
                # If length is fixed, this should be a signed or unsigned integer.
                # We're actually using RollingCorrupt, which was designed for strings, because it gives
                # us the ability to add random cases and also it adds and subtracts 1..9 from the initial
                # value, as well as doing the binary corner cases.   
                str=field.to_s
                g=Generators::RollingCorrupt.new(str,str.length*8,str.length*8,random_cases,field.endianness)
            else # enumerate fully
                # Must return a String, hence the pack fixup.
                g=Generators::Repeater.new((0..(2**field.length)-1),1,1,1,proc {|a| a.pack('c')})
            end
        elsif field.length_type=="variable"
            if field.length < 16
                g=Generators::RollingCorrupt.new(field.to_s,8,8,random_cases,field.endianness)
            elsif field.length < 32
                g=Generators::RollingCorrupt.new(field.to_s,16,16,random_cases,field.endianness)
            else
                rc1=Generators::RollingCorrupt.new(field.to_s,16,16,random_cases,field.endianness)
                rc2=Generators::RollingCorrupt.new(field.to_s,32,32,random_cases,field.endianness)
                g=Generators::Chain.new(rc1,rc2)
                if fuzzlevel > 1
                    rc3=Generators::RollingCorrupt.new(field.to_s,13,5,random_cases,field.endianness)
                    rc4=Generators::RollingCorrupt.new(field.to_s,7,7,random_cases,field.endianness)
                    g=Generators::Chain.new(g,rc3,rc4)
                end
            end
            if preserve_length
                g
            else
                chopper=Generators::Chop.new(field.to_s)
                rep=Generators::Repeater.new(field.to_s,0,0,maxlen/field.to_s.length,proc {|a| a.join})
                Generators::Chain.new(g,rep,chopper)
            end
        else
            raise RuntimeError, "Mutations::replace_field: Unknown length type #{field.length_type}"
        end
    }
    #Yields a series of data elements that can be used to replace the field which is passed as a parameter.
    #
    #Looks up the field.type as a string in a Replacement_Generators hash, so users can expand the repetoire of
    #generators by creating custom field types that require particular fuzzing approaches.
    def replace_field(field, maxlen, fuzzlevel, preserve_length, random_cases=16) #:yields:replacement_data
        #grab a generator
        g=Replacement_Generators[field.type].call(field, maxlen, preserve_length, random_cases*fuzzlevel, fuzzlevel)
        while g.next?
            yield g.next
        end 
    end #replace_field
    module_function :replace_field

    #Yields a series of data elements that can be injected immediately before the field which is passed as a parameter,
    #and once after the final field.
    #
    #Looks up the field.type as a string in an Injection_Generators hash, so users can expand the repetoire of
    #generators by creating custom field types that require particular fuzzing approaches. The separator string
    #for the structure (if any) is also passed as a parameter, and will be expanded during the fuzzing process.
    def inject_data(field, maxlen, fuzzlevel) #:yields:data_to_inject
        #grab a generator
        gens=[]
        fuzzlevel.times do
            gens << Injection_Generators[field.type].call(maxlen)
        end
        g=Generators::Chain.new(*gens)
        while g.next?
            yield g.next
        end
    end #inject_data
    module_function :inject_data

end

if __FILE__==$0
    require 'binstruct'
    require 'generators'
    bs=Binstruct.new("\x02\x01") {|buf| endian :little;string buf, :foo, 16, "thing"}
    a=[]
    bs.fields.each {|f|
        Mutations.inject_data(f,10,2) {|val| a << val}
    }
    p a
    g=Mutations.create_string_generator(['a','b'],100)
    puts g.next.length while g.next?
end



