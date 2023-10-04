#include "hooks.hpp"
#include <stdexcept>


namespace hooks
{
    void* allocate_near_page( void* address )
    {
        SYSTEM_INFO system_info;
        GetSystemInfo( &system_info );

        const std::uintptr_t page_size = system_info.dwPageSize;

        uintptr_t start_address = ( uintptr_t( address ) & ~( page_size - 1 ) );
        uintptr_t min_address = min( start_address - 0x7FFFFF00, ( uintptr_t )system_info.lpMinimumApplicationAddress );
        uintptr_t max_address = max( start_address + 0x7FFFFF00, ( uintptr_t )system_info.lpMaximumApplicationAddress );

        uintptr_t page_start = ( start_address - ( start_address % page_size ) );
        
        std::int16_t current_page = 1;

        while ( 1 )
        {
            std::uintptr_t byte_offset = current_page * page_size;
            std::uintptr_t high_address = page_start + byte_offset;
            std::uintptr_t low_address = ( page_start > byte_offset ) ? page_start - current_page : 0;

            if ( high_address < max_address )
            {
                void* allocated_mem = VirtualAlloc( ( void* )high_address, page_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
                if ( allocated_mem )
                    return allocated_mem;
            }

            if ( low_address > min_address )
            {
                void* allocated_mem = VirtualAlloc( ( void* )low_address, page_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
                if ( allocated_mem )
                    return allocated_mem;
            }

            current_page++;

            if ( high_address > max_address && low_address < min_address )
                break;
        }

        return nullptr;
    }

    // handle jump tables
    bool create_trampoline_func( std::uintptr_t function_address, void* allocated_memory )
    {
        std::uintptr_t current_addr = function_address;
        std::uint32_t current_offset = 0;
        std::vector<std::uint8_t> function_buffer = { };

        for ( HDE hde; hde_disasm( ( void* )current_addr, &hde ), !( hde.flags & F_ERROR ); current_offset += hde.len, current_addr += hde.len )
        {
            if ( hde.flags & F_ERROR )
                return false;
            
            function_buffer.insert( function_buffer.end( ), ( std::uint8_t* )current_addr, ( std::uint8_t* )current_addr + hde.len );

            if ( hde.opcode == INT3 || hde.opcode == RET || hde.opcode == RET_FAR )
                break;

            std::uintptr_t disp_offset = ( hde.modrm_mod == 0x00 && hde.modrm_rm == 0x05 ) ? 3 : 1;

            #if defined(_M_X64) || defined(__x86_64__)
            if ( hde.flags & F_DISP32 )
            {
                std::int32_t disp = *reinterpret_cast< std::int32_t* >( current_addr + disp_offset );

                const std::uintptr_t dst_address = ( std::uintptr_t )allocated_memory + current_offset + hde.len;
                const std::uintptr_t function_end = function_address + current_offset + hde.len;

                disp -= static_cast< std::int32_t >( dst_address - function_end );

                *reinterpret_cast< std::int32_t* >( &function_buffer[current_offset + disp_offset] ) = disp;
            }
            #endif

            if ( hde.opcode == JMP_REL || hde.opcode == CALL_REL )
            {
                std::int32_t disp = *reinterpret_cast< std::int32_t* >( current_addr + disp_offset );

                const std::uintptr_t dst_address = ( std::uintptr_t )allocated_memory + current_offset + hde.len;
                const std::uintptr_t function_end = function_address + current_offset + hde.len;

                disp -= static_cast< std::int32_t >( dst_address - function_end );

                *reinterpret_cast< std::int32_t* >( &function_buffer[current_offset + disp_offset] ) = disp;
            }
        }

        std::memcpy( allocated_memory, function_buffer.data( ), function_buffer.size( ) );

        return true;
    }

    status_t c_hook_manager::create_hook( void* function_address, void* hook_address, void** original_address )
    {
        void* trampoline_addr = allocate_near_page( function_address );
       
        if ( !trampoline_addr )
            throw std::runtime_error( "failed to allocate memory for trampoline" );

        #if defined(_M_X64) || defined(__x86_64__)
        void* redirect_page = allocate_near_page( function_address );

        if ( !redirect_page )
            throw std::runtime_error( "failed to allocate memory for the redirect" );

        std::vector<std::uint8_t> far_jmp_bytes = {
            0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        std::uintptr_t absolute_addr = reinterpret_cast< std::uintptr_t >( hook_address );

        memcpy( &far_jmp_bytes[6], &absolute_addr, sizeof( absolute_addr ) );
        memcpy( redirect_page, far_jmp_bytes.data( ), far_jmp_bytes.size( ) );
        #endif
 
        if ( !create_trampoline_func( ( std::uintptr_t )function_address, trampoline_addr ) )
        {
            return status_t::failure;
        }

        std::vector<std::uint8_t> jmp_bytes( 5, NOP );
        jmp_bytes.at( 0 ) = JMP_REL;

        #if defined(_M_X64) || defined(__x86_64__)
        const std::uint32_t relative_addr = static_cast< std::uint32_t >( ( std::uintptr_t )redirect_page - ( ( std::uintptr_t )function_address + 5 ) );
        #else
        const std::uint32_t relative_addr = static_cast< std::uint32_t >( ( std::uintptr_t )hook_address - ( ( std::uintptr_t )function_address + 5 ) );
        #endif


        memcpy( &jmp_bytes[1], &relative_addr, sizeof( relative_addr ) );

        std::vector<std::uint8_t> original_bytes( 5 );
        memcpy( &original_bytes[0], function_address, original_bytes.size( ) );

        hook_t hook( function_address, std::move( original_bytes ), std::move( jmp_bytes ) );
        hook.allocated_pages.push_back( trampoline_addr );

        #if defined(_M_X64) || defined(__x86_64__)
        hook.allocated_pages.push_back( redirect_page );
        #endif

        this->m_hooks[function_address] = std::move( hook );

        if ( original_address )
            *original_address = trampoline_addr;

        return status_t::success;     
    }

    status_t c_hook_manager::enable_hook( void* function_address )
    {
        if ( const auto hook_it = this->m_hooks.find( function_address ); hook_it != this->m_hooks.end( ) )
        {
            hook_it->second.enable( );
            return status_t::success;
        }

        return status_t::failure;
    }

    void c_hook_manager::enable_all( )
    {
        for ( const auto& hook : this->m_hooks )
        {
            hook.second.enable( );
        }
    }

    void c_hook_manager::disable_all( )
    {
        for ( const auto& hook : this->m_hooks )
        {
            hook.second.disable( );
        }
    }

    status_t c_hook_manager::disable_hook( void* function_address )
    {
        if ( const auto hook_it = this->m_hooks.find( function_address ); hook_it != this->m_hooks.end( ) )
        {
            hook_it->second.disable( );
            return status_t::success;
        }

        return status_t::failure;
    }
}