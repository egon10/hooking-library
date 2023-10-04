#pragma once
#include <unordered_map>

#if defined(_M_X64) || defined(__x86_64__)
#include <hde/hde64.h>
typedef hde64s HDE;
#define hde_disasm(code, hs) hde64_disasm(code, hs)
#else
#include <hde/hde32.h>
typedef hde32s HDE;
#define hde_disasm(code, hs) hde32_disasm(code, hs)
#endif

constexpr std::uint8_t JMP_REL = 0xE9;
constexpr std::uint8_t CALL_REL = 0xE8;
constexpr std::uint8_t NOP = 0x90;
constexpr std::uint8_t INT3 = 0xCC;
constexpr std::uint8_t RET = 0xC3;
constexpr std::uint8_t RET_FAR = 0xC2;

namespace hooks
{

	enum class status_t
	{
		unknown,
		success,
		failure
	};

	struct hook_t
	{
	public:
		void* func_address;

		std::vector<std::uint8_t> original_bytes;
		std::vector<std::uint8_t> patched_bytes;
		std::vector<void*> allocated_pages;

		hook_t( ) = default;

		hook_t( void* func_addr, std::vector<std::uint8_t>&& original, const std::vector<std::uint8_t>&& patched )
			: func_address( func_addr ), original_bytes( std::move( original ) ), patched_bytes( patched )
		{

		}

		hook_t( const hook_t& ) = default;

		hook_t( hook_t&& other ) noexcept = default;

		hook_t& operator=( hook_t && other ) noexcept = default;

		~hook_t( )
		{
			this->disable( );
		}

		void enable( ) const
		{
			unsigned long old_protect;

			VirtualProtect( func_address, patched_bytes.size( ), PAGE_EXECUTE_READWRITE, &old_protect );
			memcpy( func_address, patched_bytes.data( ), patched_bytes.size( ) );
			VirtualProtect( func_address, patched_bytes.size( ), old_protect, &old_protect );
		}

		void disable( ) const
		{
			unsigned long old_protect;

			VirtualProtect( func_address, original_bytes.size( ), PAGE_EXECUTE_READWRITE, &old_protect );
			memcpy( func_address, original_bytes.data( ), original_bytes.size( ) );
			VirtualProtect( func_address, original_bytes.size( ), old_protect, &old_protect );
		}

		void destroy( ) const
		{
			this->disable( );

			for ( auto* page : this->allocated_pages )
				VirtualFree( page, 0, MEM_RELEASE );		
		}
	};

	class c_hook_manager
	{
	public:
		explicit c_hook_manager( ) : m_hooks( )
		{

		}

		~c_hook_manager( )
		{

		}

		const hook_t& get_hook( void* func_addr ) const { return this->m_hooks.at( func_addr ); }

		/// <summary>
		/// Creates a hook for a specified function, which can be enabled later.
		/// </summary>
		/// <param name="function_address">The address of the function to hook.</param>
		/// <param name="hook_address">The address of your hook function.</param>
		/// <param name="original_address">A pointer to store the original function address.</param>
		/// <returns>A status code indicating the success of the hook creation.</returns>
		status_t create_hook( void* function_address, void* hook_address, void** original_address );

		/// <summary>
		/// Enables a hook for a previously specified function.
		/// </summary>
		/// <param name="function_address">The address of the function with the hook to enable.</param>
		/// <returns>A status code indicating the success of enabling the hook.</returns>
		status_t enable_hook( void* function_address );

		/// <summary>
		/// Enables all previously defined hooks.
		/// </summary>
		void enable_all( );

		/// <summary>
		/// Disables all previously defined hooks.
		/// </summary>
		void disable_all( );

		/// <summary>
		/// Disables a hook for a previously specified function.
		/// </summary>
		/// <param name="function_address">The address of the function with the hook to disable.</param>
		/// <returns>A status code indicating the success of disabling the hook.</returns>
		status_t disable_hook( void* function_address );

	private:
		std::unordered_map<void*, hook_t> m_hooks;
	};
}