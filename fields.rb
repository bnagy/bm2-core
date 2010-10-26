# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2010.
# License: The MIT License
# (See README.TXT or http://www.opensource.org/licenses/mit-license.php for details.)

#If you add new Field subclasses, you need to name them with a capitalized 'Field' at the end, eg CrazyField, and use it in Binstruct by declaring the
#first half in lower case. Like this:
# module Fields
# 	class CrazyField < StringField
#		# I act just like a StringField, only crunchy!
# 	end
# end
#
# class MyStruct < Binstruct
# 	crazy :field_name, 32, "A Crazy Field!"
#	[...]
#
#Take a look at the documentation for Fields::Field for some other guidlines on creating new Field subclasses that can't trivially
#inherit one of the base classes like Fields::StringField or Fields::HexstringField.
module Fields

    #Subclasses of Fields::Field should probably at least overload <tt>input_to_bitstring</tt> and <tt>get_value</tt> and
    #set <tt>@length_type</tt>. Check the source code for the base subclasses for ideas. Remember that for the
    #purposes of fuzzing you can probably get away with
    #inheriting from one of the base classes a lot of the time - an EmailField can probably just inherit StringField unless you want
    #stringent checking in your parser.
    class Field

        attr_reader :bitstring, :desc, :length, :type, :default_value, :name, :length_type, :endianness

        def initialize(bitstring, name, length, desc, default, endian)
            @name=name
            @length=length
            @desc=desc
            default&&=self.input_to_bitstring(default)
            @default_value=default # can still be nil
            @bitstring=self.parse_buffer(bitstring)
            @type=self.class.to_s[/\w+(?=Field)/].downcase #fricking ugly
            @endianness=endian
            unless @endianness.downcase==:big or @endianness.downcase==:little
                raise ArgumentError, "#{self.class.to_s[/\w+$/]} (#{@name}): Unknown endianness #{endianness}, use :little or :big (default)."
            end
        end

        # Provided for classes that require strict lengths. Left pads with 0 to @length
        # if the input buffer is incomplete. Truncates at @length if too long. Called by <tt>parse_buffer</tt> internally.
        def parse_buffer_strict( bitstring )
            return "" unless bitstring
            bitstring||=""
            unless bitstring.is_a? String and bitstring=~/^[10]*$/
                raise ArgumentError, "Field: <Internal> bitstring buffer borked?? #{bitstring.inspect}"
            end
            if bitstring.length <= @length
        "0"*(@length-bitstring.length)+bitstring
            elsif bitstring.length > @length
                bitstring.slice(0,@length)
            else
                raise RuntimeError, "Universe Broken Error: value neither less/equal nor greater"
            end
        end

        # Provided for classes that don't care about length matching
        # when assigning the contents. Called by <tt>parse_buffer</tt> internally.
        def parse_buffer_lazy( bitstring )
            return "" unless bitstring
            bitstring||=""
            unless bitstring.is_a? String and bitstring=~/^[10]*$/
                raise ArgumentError, "#{self.class.to_s[/\w+$/]} (#{@name}): <Internal> bitstring buffer borked??"
            end
            bitstring
        end

        # Placeholder, subclasses should probably redefine for clarity. Defaults to calling parse_buffer_strict, but uses
        # parse_buffer_lazy for variable length fields.
        def parse_buffer( bitstring )
            return self.parse_buffer_lazy( bitstring ) if self.length_type=="variable"
            self.parse_buffer_strict( bitstring ) # default to this for subclasses that forget to define @length_type
        end

        #Sets the raw field contents. Can be useful if the set_value method does inconvenient checking when you want
        #to set crazy values.
        def set_raw( bitstring )
            @bitstring=self.parse_buffer( bitstring )
        end

        # Placeholder, classes should override as neccessary.
        # Parse a value in whatever format is determined by the class
        # and return a bitstring.
        # This default does zero checking, so expects a bitstring as input
        def input_to_bitstring( value )
            value
        end

        # Randomize the bitstring for this field, bit by bit
        def randomize!
            random_bitstring=Array.new(self.length).map {|e| e=rand(2).to_s}.join
            if self.length_type=="variable"
                slice=random_bitstring[0,(rand((self.length/8)+1)*8)]
                set_raw(slice)
            else
                set_raw(random_bitstring)
            end
        end

        #Set the field value. Calls self.input_to_bitstring which is expected to return a binary string.
        def set_value(new_val)
            @bitstring=self.input_to_bitstring(new_val)
        end

        #Subclasses should override this. This default returns the raw bitstring.
        def get_value
            @bitstring
        end

        # This really only makes sense for fields that are byte aligned, but what the hey. For the rest it effectively
        # packs them as left padded with zeroes to a byte boundary (so a 3 bit field "110" will pack as \006)
        def to_s
            @bitstring.reverse.scan(/.{1,8}/).map {|s| s.reverse}.reverse.map {|bin| "" << bin.to_i(2)}.join
        end

    end # Field

    #Accepts negative numbers on assignment, but stores them as 2s complement.
    class UnsignedField < Field

        def initialize *args
            @length_type="fixed"
            super
        end

        def input_to_bitstring( value )
            unless value.kind_of? Integer
                raise ArgumentError, "UnsignedField (#{@name}): attempted to assign non-integer"
            end
            if value.to_s(2).length > @length
                # works for negative assignments as well, since to_s(2) adds a '-' to the start of the binary string
                raise ArgumentError, "UnsignedField (#{@name}): value too big for field length"
            end
            # accept negative numbers, but store them as their two's complement representation for this bitlength
            # (get_value will return the positive interpretation)
            unpadded=value < 0 ? (("1"+"0"*@length).to_i(2)-value.abs).to_s(2) : value.to_s(2)
            value="0"*(@length-unpadded.length)+unpadded # left pad with zeroes to full length
            if self.endianness==:little
                if value.length > 8 && value.length % 8 ==0
                    value=value.scan(/.{8}/).reverse.join
                end
            end
            value
        end

        def get_value
            tempstring=@bitstring
            if self.endianness==:little
                if tempstring.length > 8 && tempstring.length % 8 ==0
                    tempstring=tempstring.scan(/.{8}/).reverse.join
                end
            end
            tempstring.to_i(2)
        end

    end #UnsignedField

    #For IP addresses etc
    class OctetstringField < Field

        def initialize(*args)
            raise ArgumentError, "OctetstringField  (#{args[1]})(CREATE): Length must be a multiple of 8 bits" unless args[2]%8==0
            @length_type="fixed"
            super
        end

        def input_to_bitstring( value )
            # Expects [0-255][.0-255] .....
            begin
                unless value.split('.').all? {|elem| Integer(elem)<256 && Integer(elem) >= 0}
                    raise ArgumentError, "OctetstringField (#{@name})(PARSE): Unable to parse input value"
                end
            rescue
                raise ArgumentError, "OctetstringField (#{@name})(PARSE): Unable to parse input value"
            end
            octets=value.split('.')
            raise ArgumentError, "OctetstringField (#{@name}): Not enough octets?" if (octets.length)*8 < @length
            raise ArgumentError, "OctetstringField (#{@name}): Too many octets?" if (octets.length*8) > @length
            octets.inject("") do |str,num| 
                str << "%.8b"%num
            end
        end

        def get_value
            @bitstring.scan(/.{8}/).map {|e| e.to_i(2).to_s}.join('.')
        end
    end #OctetstringField


    #For getting and setting via hex strings.
    class HexstringField < Field

        def initialize *args
            @length_type="variable"
            super
        end

        def input_to_bitstring( value )
            if (value.respond_to? :to_int) and value >= 0
                bs=value.to_int.to_s(2)
            elsif (value.respond_to? :to_str) and value.to_str=~/^[a-f0-9\s]*$/
                bs=value.to_str.gsub(/\s/,'').to_i(16).to_s(2)
            else
                raise ArgumentError, "HexstringField (#{@name}): Unable to parse input value."
            end
            (bs.length % 8 != 0) && bs=("0"*(8-bs.length%8) + bs)
            bs
        end

        def get_value
            return '' if @bitstring==""
            unless @bitstring.length > 8 && @bitstring.length % 8 == 0
                #do the best we can..
                hexstring=@bitstring.to_i(2).to_s(16)
                (hexstring.length % 2 == 1) && hexstring="0"+hexstring
            else
                hexstring=bitstring.scan(/.{8}/).map {|e| "%.2x" % e.to_i(2)}.join
            end
            hexstring
        end

    end #HexstringField

    class SignedField < Field

        def initialize *args
            @length_type="fixed"
            super
        end

        def input_to_bitstring( value )
            unless value.kind_of? Integer
                raise ArgumentError, "SignedField (#{@name}): attempted to assign non-integer"
            end
            if value < 0 and value.to_s(2).length > @length
                # int.to_s(2) will return "-1001001" etc for negative numbers in binary, so this length check will work.
                raise ArgumentError, "SignedField (#{@name}): negative value too long for field length"
            end
            if value > 0 and value.to_s(2).length > @length-1 # positive integers shouldn't overflow the sign bit
                raise ArgumentError, "SignedField (#{@name}): positive value too long for field length"
            end
            unpadded=value <= 0 ? (("1"+"0"*@length).to_i(2)-value.abs).to_s(2) : value.to_s(2)
            value="0"*(@length-unpadded.length)+unpadded # left pad with zeroes to full length
            if self.endianness==:little
                if value.length > 8 && value.length % 8==0
                    value=value.scan(/.{8}/).reverse.join
                end
            end
            value
        end

        def get_value
            tempstring=@bitstring
            if self.endianness==:little
                if tempstring.length > 8 && tempstring.length % 8 ==0
                    tempstring=tempstring.scan(/.{8}/).reverse.join
                end
            end
            if tempstring.slice(0,1)=="1" #sign bit set
                0-(("1"+"0"*@length).to_i(2)-tempstring.to_i(2))
            elsif  @bitstring.slice(0,1)=="0"
                tempstring.to_i(2)
            else	
                raise RuntimeError, "SignedField: Ouch, internal contents screwed somehow."
            end
        end			  

    end # SignedField

    class StringField < Field
        def initialize *args
            @length_type="variable"
            super
        end

        def input_to_bitstring( value )
            unless value.respond_to? :to_str 
                raise ArgumentError, "StringField(#{@name}): Input value not a string."
            end
            value.to_str.unpack('B*').join
        end

        def get_value
            return @bitstring if @bitstring==""
            [@bitstring].pack('B*')
        end
    end # StringField

    #For getting and setting via binary strings
    class BitstringField < Field

        def initialize *args
            @length_type="fixed"
            super
        end

        def input_to_bitstring( value )
            unless value.respond_to? :to_str  and value.to_str=~/^[01\s]*$/
                raise ArgumentError, "BitstringField(#{@name}) (PARSE): Input value not a bitstring."
            end
            parse_buffer(value.to_str.gsub(/\s/,''))
        end

        def get_value
            @bitstring
        end
    end #BitstringField

    Field_Subtypes=self.constants.map {|const| const.to_s.sub(/Field/,'').downcase.to_sym if const=~/^.+Field/}.compact
end # Fields
