require 'date'
# Some code to parse crash detail files, mainly focused on the machine
# parseable output of !exploitable.
module DetailParser

    # In: the !exploitable output as a string
    # Out: [[0, "wwlib!wdCommandDispatch+0x14509b"], [1, ... etc
    def self.stack_trace( detail_string )
        frames=detail_string.scan( /STACK_FRAME:(.*)$/ ).flatten
        (0..frames.length-1).to_a.zip frames
    end

    # In: the !exploitable output as a string
    # Out: a hash of (Integer) module_base => [(Boolean) syms_loaded, detail_hsh]
    # where detail_hsh has the !exploitable output as a string) :name,
    # (Integer) :size, (String) :version, (Integer) :checksum.
    def self.loaded_modules( detail_string )
        # Module entries look like this in the file:
        # Note that the stuff in brackets can be "export symbols"
        # "pdb symbols" or "deferred" if the symbols weren't loaded yet.
        # 01ff0000 022b5000   xpsp2res   (deferred)             
        #    Image path: C:\WINDOWS\system32\xpsp2res.dll
        #    Image name: xpsp2res.dll
        #    Timestamp:        Mon Apr 14 01:39:24 2008 (4802454C)
        #    CheckSum:         002CA420
        #    ImageSize:        002C5000
        #    File version:     5.1.2600.5512
        #    [... etc ...]
        # Take the image base and symbol status from the first line
        # then grab all the key : value stuff as one big chunk, until the 
        # next header line which is the zero-width lookahead (?=
        barf=detail_string.scan(/([0-9a-f]{8}) [0-9a-f]{8}.+?\((.*?)\).+?$(.+?)(?=[0-9a-f]{8} [0-9a-f]{8})/m)
        # Now take the !exploitable output as a string pairs
        barf=barf.map {|a| [a[0],a[1],a[2].scan(/^\s+(\S.+):\s+(\S.+)$/)]}
        # Take the !exploitable output as a string pairs and turn them into a hash
        barf=barf.map {|a| [a[0],a[1],Hash[*a[2].flatten]]} 
        # Now we have ["01ff0000", "export symbols", {"Image path"=>"C:\\WINDOWS\\ ... etc
        # Unloaded modules entries don't have an image name. Remove them. 
        barf=barf.select {|a| a[2].has_key? "Image name"}
        final_result={}

        barf.each {|a|
            old_hsh=a[2]
            clean_results={}
            clean_results[:timestamp]=DateTime.parse(old_hsh["Timestamp"])
            clean_results[:size]=old_hsh["ImageSize"].to_i(16)
            clean_results[:name]=old_hsh["Image name"].downcase
            clean_results[:checksum]=old_hsh["CheckSum"].to_i(16)
            clean_results[:version]=old_hsh["File version"].downcase
            final_result[a[0].to_i(16)]=[!!(a[1]=~/pdb/), clean_results]
        }
        final_result
    end

    # In: the !exploitable output as a string
    # Out: [[0, "316c5a0e mov eax,dword ptr [eax]"], [1, 
    def self.disassembly( detail_string )
        instructions=detail_string.scan( /BASIC_BLOCK_INSTRUCTION:(.*)$/ ).flatten
        (0..instructions.length-1).to_a.zip instructions
    rescue
        [] 
    end

    def self.faulting_instruction( detail_string )
        detail_string.match(/^(.*?)IDENTITY/m)[1].split("\n").last
    rescue
        ""
    end


    # In: the !exploitable output as a string
    # Out: [["eax", "00000000"], ["ebx", ... etc
    def self.registers( detail_string )
        # *? is non-greedy, m is multiline. We take the !exploitable output as a string 
        # because if there is more than one the first one will be from the
        # initial breakpoint
        detail_string.scan(/^eax.*?iopl/m).last.scan(/(e..)=([0-9a-f]+)/)
    rescue
        [] 
    end

    # In: the !exploitable output as a string
    # Out: Long bug description, eg "Data from Faulting Address controls
    # Branch Selection"
    def self.long_desc( detail_string )
        detail_string.match(/^BUG_TITLE:(.*)$/)[1]
    rescue
        ""
    end

    # In: the !exploitable output as a string
    # Out: !exploitable classification, "UNKNOWN", "PROBABLY EXPLOITABLE" etc
    def self.classification( detail_string )
        detail_string.match(/^CLASSIFICATION:(.*)$/)[1].tr('_',' ')
    rescue
        "<none?>"
    end

    # In: the !exploitable output as a string
    # Out: !exploitable exception type, "STATUS_ACCESS_VIOLATION" etc
    def self.exception_type( detail_string )
        detail_string.match(/^EXCEPTION_TYPE:(.*)$/)[1]
    rescue
        ""
    end

    # In: the !exploitable output as a string
    # Out: !exploitable exception subtype, "READ" or "WRITE" etc
    def self.exception_subtype( detail_string )
        detail_string.match(/^EXCEPTION_SUBTYPE:(.*)$/)[1]
    rescue
        ""
    end

    # In: the !exploitable output as a string
    # Out: !exploitable Hash as a string eg "0x6c4b4441.0x1b792103"
    def self.hash( detail_string )
        maj=detail_string.match(/MAJOR_HASH:(.*)$/)[1]
        min=detail_string.match(/MINOR_HASH:(.*)$/)[1]
        "#{maj}.#{min}"
    rescue
        begin
            detail_string.match(/Hash=(.*)\)/)[1]
        rescue
            ""
        end
    end

end

# Quick wrapper class, for more complex, OO analysis
class Detail < BasicObject
    def initialize( detail_string )
        @detail_string=detail_string
    end

    def method_missing( meth, *args )
        DetailParser.send(meth, @detail_string)
    end
end
