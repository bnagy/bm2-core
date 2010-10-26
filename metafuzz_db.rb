# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2010.
# License: The MIT License
# (See README.TXT or http://www.opensource.org/licenses/mit-license.php for details.)
 
require File.dirname(__FILE__) + '/detail_parser'
require File.dirname(__FILE__) + '/result_db_schema'
require 'rubygems'
require 'sequel'
require 'pg'

# Just a quick wrapper, so I can change the underlying DB.
module MetafuzzDB

    class ResultDB

        CRASHFILE_ROOT='/fuzzfiles/dbfiles/crashfiles'
        CRASHDATA_ROOT='/fuzzfiles/dbfiles/crashdata'
        TEMPLATE_ROOT='/fuzzfiles/dbfiles/templates'

        def initialize(url, username, password)
            @db=Sequel::connect(url, :username=>username, :password=>password)
            ResultDBSchema.setup_schema( @db )
            # This is probably going to die on perms error. Create them manually?
            [CRASHFILE_ROOT, CRASHDATA_ROOT, TEMPLATE_ROOT].each {|dirname|
                Dir.mkdir dirname unless File.directory? dirname
            }
        end

        # Inserts the string to the given table if it's not there
        # already, and returns the id
        def id_for_string( table_sym, string )
            @db[table_sym][(table_sym.to_s[0..-2].to_sym)=>string][:id]
        rescue
            @db[table_sym].insert((table_sym.to_s[0..-2].to_sym)=>string)
        end

        # Add a new result, return the db_id
        def add_result(status, crashdetail=nil, crashfile=nil, template_hash=nil, encoding='base64')
            db_id=false
            @db.transaction do
                db_id=@db[:results].insert(:result_id=>id_for_string(:result_strings, status))
                if status=='crash'
                    # Fill out the crashes table, use crash_id for rest.
                    crash_id=@db[:crashes].insert(
                        :result_id=>db_id,
                        :timestamp=>Time.now,
                        :hash_id=>id_for_string(:hash_strings, DetailParser.hash(crashdetail)),
                        :desc_id=>id_for_string(:descs, DetailParser.long_desc(crashdetail)),
                        :exception_type_id=>id_for_string(:exception_types, DetailParser.exception_type(crashdetail)),
                        :exception_subtype_id=>id_for_string(:exception_subtypes, DetailParser.exception_subtype(crashdetail)),
                        :classification_id=>id_for_string(:classifications, DetailParser.classification(crashdetail)),
                        :template_id=>id_for_string(:templates, template_hash)
                    )

                    loaded_modules=DetailParser.loaded_modules crashdetail
                    mod_id_hsh=add_modules(crash_id, loaded_modules)

                    frames=DetailParser.stack_trace crashdetail
                    add_stacktrace(crash_id, frames, mod_id_hsh)

                    registers=DetailParser.registers crashdetail
                    add_registers(crash_id, registers)

                    disassembly=DetailParser.disassembly crashdetail
                    add_disassembly(crash_id, disassembly)

                    begin
                        crashdetail_path=File.join(CRASHDATA_ROOT, crash_id.to_s+'.txt')
                        crashfile_path=File.join(CRASHFILE_ROOT, crash_id.to_s+'.raw')
                        File.open(crashdetail_path, 'wb+') {|fh| fh.write crashdetail}
                        File.open(crashfile_path, 'wb+') {|fh| fh.write crashfile}
                    rescue
                        # If we can't write the files for some reason,
                        # roll back the whole transaction.
                        p __method__
                        puts $!
                        raise Sequel::Rollback
                    end
                end
            end
            db_id
        rescue
            puts $!
        end

        def add_modules( crash_id, loaded_modules )
            # Since we produce the module_id as a side effect, return it
            # so we save ugly lookups to connect module name with 
            # exact module_id for each crash.
            mod_id_hsh={}
            loaded_modules.each {|base_addr, ary|
                syms_loaded, mod_data=*ary
                begin
                    id=@db[:modules][:name=>mod_data[:name],:checksum=>mod_data[:checksum]][:id]
                rescue
                    id=@db[:modules].insert mod_data
                end
                mod_id_hsh[mod_data[:name]]=[id, syms_loaded]
                @db[:loaded_modules].insert(
                    :crash_id=>crash_id,
                    :module_id=>id,
                    :syms_loaded=>syms_loaded,
                    :base_address=>base_addr
                )
            }
            mod_id_hsh
        rescue
            p __method__
            puts $!
        end

        def add_template( raw_template, template_hash )
            template_id=@db[:templates].insert(:template=>template_hash)
            name=File.join(TEMPLATE_ROOT, template_id.to_s+'.raw')
            File.open(name, 'wb+') {|fh| fh.write raw_template}
        rescue Sequel::DatabaseError
            # Must already be there.
        end

        def get_template( template_hash )
            name=id_for_string(:templates, template_hash).to_s+'.raw'
            File.open( File.join(TEMPLATE_ROOT, name), 'rb+') {|fh| fh.read}
        end

        def add_disassembly(crash_id, disasm)
            disasm.each {|seq, instruction|
                address, asm=instruction.split(' ',2)
                @db[:disasm].insert(
                    :crash_id=>crash_id,
                    :seq=>seq,
                    :address=>address,
                    :asm=>asm
                )
            }
        rescue
            p __method__
            puts $!
        end

        def add_registers(crash_id, registers) 
            register_hash={}
            registers.each {|r,v| register_hash[r.to_sym]=v.to_i(16)}
            register_hash[:crash_id]=crash_id
            @db[:register_dumps].insert register_hash
        rescue
            p __method__
            puts $!
        end

        def add_stacktrace(crash_id, stackframes, mod_id_hsh)
            stacktrace_id = @db[:stacktraces].insert(:crash_id=>crash_id)
            stackframes.each {|frame|
                sequence, full_function=frame
                mod_name, func_name = full_function.split('!')
                mod_id, has_syms=mod_id_hsh[mod_name] # hash of name->module_id for this crash
                if has_syms
                    func_name, offset=func_name.split('+')
                    offset=offset.to_i(16)
                else
                    offset=-1
                end
                begin
                    function_id=@db[:functions][:module_id=>mod_id, :name=>function][:id]
                rescue
                    function_id=@db[:functions].insert(
                        :module_id=>mod_id,
                        :name=>func_name,
                    )
                end
                @db[:stackframes].insert(
                    :stacktrace_id=>stacktrace_id,
                    :function_id=>function_id,
                    :offset=>offset,
                    :sequence=>sequence
                )
            }
        rescue
            p __method__
            puts $!
        end

        def get_stacktrace(crash_id)
            trace_id = @db[:stacktraces][:crash_id=>crash_id][:id]
            @db[:stackframes].filter(:stacktrace_id=>trace_id).order(:sequence).all()
        end


        # In: database unique db_id as an int
        # Out: the result string, 'success', 'crash' or 'fail'
        def result( id )
            result_string_id=@db[:results][:id=>id][:result_id]
            @db[:result_strings][:id=>result_string_id][:result_string]
        end

        # In: database unique crash_id as an int
        # Out: the crashfile, base64 encoded by default
        def crashfile( id, encoding='base64' )
            raw=File.open( File.join(CRASHFILE_ROOT, id+'.raw'),'rb+') {|f| f.read}
            case encoding
            when 'base64'
                Base64::encode64 raw
            else
                raw
            end
        end

        # In: database unique crash_id as an int
        # Out: the raw detail file (cdb output)
        def crashdetail( id )
            File.open( File.join(CRASHDETAIL_ROOT, id+'.txt'),'rb+') {|f| f.read}
        end

        # In: database unique crash_id as an int
        # Out: Registers at crash time, as a hash {'eax'=>'0x00000000' etc
        def registers( id )
        end

        # In: database unique crash_id as an int
        # Out: The stack trace as an array of strings sorted top to bottom
        def stack_trace( id )
        end

        # In: database unique crash_id as an int
        # Out: Exception subtype as a string
        def exception_subtype( id )
        end

        # In: database unique crash_id as an int
        # Out: Exception short description as a string
        def exception_short_desc( id )
        end

        # In: database unique crash_id as an int
        # Out: Exception long description as a string
        def exception_long_desc( id )
        end

        # In: Major hash as provided by !exploitable as a string
        # Out: Array of crash ids as ints
        def crashes_by_major_hash( hash_string )
        end

        # In: Full hash as provided by !exploitable as a string
        # Out: Array of crash ids as ints
        def crashes_by_hash( hash_string )
        end

        # Run an SQL query string against the database
        def execute_raw_sql( sql_string )
        end

        def method_missing( meth, *args )
            @db.send meth, *args
        end
    end

    class TraceDB
    end

end
