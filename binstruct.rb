# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2010.
# License: The MIT License
# (See README.TXT or http://www.opensource.org/licenses/mit-license.php for details.)

require File.dirname(__FILE__) + '/fields'
require File.dirname(__FILE__) + '/objhax'

# There are two main classes of methods for a Binstruct, but because of the
# implementation they are all actually instance methods. The "construction"
# methods are +endian+, +bitfield+, +substruct+ and all the builders for field
# subtypes. Each class in the Fields module has a builder, so UnsignedField is
# just unsigned. Those methods are created at runtime, so they can't be 
# seen by rdoc, but they all look like:
#    unsigned, buffer_name, :accessor_sym, length_in_bits, "Description"
# Inside a parse block, the buffer name used for the field builders should match
# the block parameter, unless you are manually messing with the buffer. The
# same applies to fields created inside the blocks for substructs and bitfields.
#
# The other methods are 'proper' instance methods, to work with the structure
# once it is created and filled with data. Each field creates a getter and 
# setter method matching its symbol, and also a direct access via [:field_sym]
# that returns the field itself, which gives you access to the field's own
# instance methods like +set_raw+ (see Fields).
class Binstruct
    VERSION="1.0.3"

    class Bitfield < Binstruct # :nodoc:
    end
    attr_reader :groups
    attr_accessor :fields, :endian

    # Set the endianness for the whole structure. Default is +:big+, options
    # are +:big+ or +:little+. Fields created after this method is invoked in
    # a construction block will be created with the new endianness. You can also
    # set the endianness after construction with <code>somestruct.endian=:little
    # </code>.
    def endian( sym )
        unless sym==:little || sym==:big
            raise RuntimeError, "Binstruct: Construction: Unknown endianness #{sym.to_s}"
        end
        @endian=sym
        meta_def :endian do @endian end
        meta_def :endianness do @endian end
    end

    # In little endian structures, byte-swaps 16, 32 or 64 bits and presents
    # them for carving into fields. Only really neccessary for non-byte aligned
    # field sets in little endian structures. The bitfield itself is invisible
    # but the fields are created with the usual accessors.
    def bitfield(bitbuf, len, &blk)
        if @endian==:little
            unless len==16||len==32||len==64
                raise RuntimeError, "Binstruct: Bitfield: Don't know how to endian swap #{len} bits. :("
            end
            instr=bitbuf.slice!(0,len).scan(/.{8}/).reverse.join
        else
            instr=bitbuf.slice!(0,len)
        end
        new=Bitfield.new([instr].pack('B*'), &blk)
        if @endian==:little
            # This is so we know to flip the bytes back in #to_s
            new.instance_variable_set :@endian_flip_hack, true
        end
        @fields << new
        # Add direct references and accessor methods to the containing Binstruct
        new.fields.each {|f| 
            unless f.is_a? Fields::Field
                raise RuntimeError, "Binstruct: Construction: Illegal content #{f.class} in bitfield - use only Fields"
            end
            @hash_references[f.name]=f
            meta_def f.name do f.get_value end
            meta_def (f.name.to_s + '=').to_sym do |val| f.set_value(val) end
        }
    end

    # Creates a nested structure, and a direct accesor for it that returns the 
    # structure itself, so accessors like <code>main.sub1.sub2.some_val</code>
    # are possible.
    # When iterating over the Binstruct contents, see +#each+, which will pass
    # substructs to the block and +#deep_each+ which recursively enters 
    # substructs and passes only Fields.
    def substruct(strbuf, name, len, klass, *extra_args)
        new=klass.new(strbuf, *extra_args)
        @fields << new
        @hash_references[name]=new
        meta_def name do new end
        # More informative than the NoMethodError they would normally get.
        meta_def (name.to_s + '=').to_sym do raise NoMethodError, "Binstruct: Illegal call of '=' on a substruct." end
    end

    #fieldtype builders
    Fields::Field_Subtypes.each {|fieldname|
        field_klass=Fields.const_get(String(fieldname).capitalize.to_s+"Field")
        define_method fieldname do |*args|
            bitbuf, name, len, desc=args
            @fields << thisfield=field_klass.new(bitbuf.slice!(0,len),name,len,desc,nil,@endian||:big)
            @hash_references[name.to_sym]=thisfield
            meta_def name do thisfield.get_value end
            meta_def (name.to_s + '=').to_sym do |val| thisfield.set_value(val) end
        end
    }

    # Groups a list of fields under +:groupname+. Designed for use in Metafuzz.
    # +somestruct.groups+ will return the hash of <code>{:group_sym=>[field1,
    # field2...]}</code>
    def group( groupname, *fieldsyms )
        @groups[groupname] << fieldsyms
    end

    class << self
        attr_reader :init_block
    end

    # There are two ways to create a Binstruct subclass, one is by calling
    # parse inside the structure definition:
    #   class Foo < Binstruct
    #       parse {|buffer_as_binary|
    #           #definitions here
    #       }
    #   end
    # and the other is by just supplying a block to new:
    #   quick_struct=Binstruct.new {|b| string, b, :foo, 32, "Some String"}
    # Otherwise, +Binstruct.new+ will just create a blank structure (this can
    # be useful if you want to fill in the fields at runtime).
    def self.parse( &blk )
        @init_block=blk
    end

    def initialize(buffer=nil, *extra_args, &blk)
        # We don't use the extra args, but I need to overload
        # init sometimes, as might substructs.
        @fields=[]
        @hash_references={}
        @endian_flip_hack=false
        @groups=Hash.new {|h,k| h[k]=[]}
        buffer||=""
        @bitbuf=buffer.unpack('B*').join
        if block_given?
            instance_exec(@bitbuf, &blk)
        elsif self.class.init_block
            instance_exec(@bitbuf, &self.class.init_block)
        else
            # do nothing, user probably just wants a blank struct to manually add fields.
        end
        endian :big unless @endian
        @groups.each {|group, contents|
            unless contents.flatten.all? {|sym| @hash_references.keys.any? {|othersym| othersym==sym}}
                raise RuntimeError, "Binstruct: Construction: group #{group} contains invalid field name(s)"
            end
        }
        # This is not ideal for structures that aren't byte aligned, but raising an exception 
        # would be less flexible.
        buffer.replace [@bitbuf].pack('B*') unless buffer.nil?
    end

    # return an object, specified by symbol. May be a field or a substruct.
    # not designed for bitfields, since they're supposed to be invisible
    # containers.
    def []( sym )
        @hash_references[sym]
    end

    # yield each object to the block. This is a little messy, because
    # substructs are not Fields::Field types. For Bitfields, just silently
    # yield each component, not the container field. The upshot of all this
    # is that the caller needs to be prepared for a Field or a Binstruct in the
    # block. This is the 'shallow' each.
    def each( &blk ) #:yields: a Field or a Bitstruct
        @fields.each {|atom|
            if atom.is_a? Bitfield
                atom.fields.each {|f| yield f}
            else
                yield atom
            end
        }

    end

    # yield all fields in the structure, entering nested substructs as necessary
    def deep_each( &blk ) #:yields: a Field
        @fields.each {|atom|
            if atom.is_a? Binstruct
                atom.deep_each &blk unless atom.fields.empty?
            else
                yield atom
            end
        }
    end

    # Searches a Binstruct, recursing through nested structures as neccessary,
    # and replaces a given object with a new object. Note that this replaces 
    # the object that ==oldthing, so a reference to it is needed first.
    def replace(oldthing, newthing)
        k,v=@hash_references.select {|k,v| v==oldthing}.flatten
        @hash_references[k]=newthing
        @fields.map! {|atom|
            if atom==oldthing
                newthing
            else
                if atom.is_a? Binstruct
                    atom.replace(oldthing,newthing)
                end
                atom
            end
        }
    end

    # Flattens all fields in nested structures into an array, preserving order.
    # In some cases (eg little endian structures with bitfields) this will mean
    # that struct.flatten.join will not be the same as struct.to_s.
    def flatten
        a=[]
        self.deep_each {|f| a << f}
        a
    end

    #pack current struct as a string - for Fields, it will use the bitstring, 
    #for anything else (including Bitfields and Binstructs) it will use 
    #<code>to_s.unpack('B*')</code>. Via a filthy internal hack, bitfields 
    #get byte-swapped
    #back in here. Finally, once the bitstring is assembled, it is 
    #packed as a string. If your structure is not byte-aligned, you will get
    #weirdness with to_s!
    def to_s
        bits=""
        @fields.each {|f| 
            if f.kind_of? Fields::Field
                bits << f.bitstring
            else
                bits << f.to_bitstring
            end
        }
        [bits].pack('B*')
    end

    def to_bitstring
        bits=""
        @fields.each {|f| 
            if f.kind_of? Fields::Field
                bits << f.bitstring
            else
                bits << f.to_bitstring
            end
        }
        return "" if bits.empty?
        if @endian_flip_hack
            # This only happens for Binstructs that have the endian_flip_hack ivar
            # set, so only inside a Bitfield structure  when little endian.
            bits.scan(/.{1,8}/).reverse.join
        else
            bits
        end
    end

    # Packed length in bytes.
    def length
        self.to_s.length
    end

    # Returns an array of terse field descriptions which show the index, field
    # class, name and length in bits, plus a hexdumped snippet of the contents.
    def inspect
        # This could possibly be more readable...
        self.flatten.map {|field| "<IDX:#{self.flatten.index(field)}><#{field.class.to_s.match(/::(.+)Field/)[1]}><#{field.name}><#{field.length}><#{field.to_s[0..12].each_byte.to_a.map {|b| "%.2x" % b}.join(' ') + (field.to_s.length>12?"...":"")}>"}
    end
end
