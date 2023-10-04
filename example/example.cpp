#include "hooks/hooks.hpp"
#include <iostream>

__declspec( noinline ) void hello_world( )
{
	std::cout << "[original] hello world" << std::endl;
}

void* original_hello_world;
__declspec( noinline ) void hk_hello_world( )
{
	std::cout << "[hook] hello world" << std::endl;

	reinterpret_cast< decltype( hk_hello_world )* >( original_hello_world )( );
}

void* original_message_box_a;
long __stdcall hk_message_box_a( HWND hwnd, LPCSTR text, LPCSTR caption, UINT type )
{
	std::cout << "[hook] MessageBoxA" << std::endl;

	return static_cast< decltype( MessageBoxA )* >( original_message_box_a )( hwnd, "hooked", caption, MB_OKCANCEL );
}

int main()
{
	auto hook_manager = std::make_unique<hooks::c_hook_manager>( );

	hook_manager->create_hook( &hello_world, &hk_hello_world, &original_hello_world );
	hook_manager->create_hook( &MessageBoxA, &hk_message_box_a, &original_message_box_a );

	hook_manager->enable_all( );

	hello_world( );
	MessageBoxA( 0, "Test", "Test", MB_OK );

	const hooks::hook_t& message_box_hook = hook_manager->get_hook( &MessageBoxA );

	message_box_hook.disable( );
	message_box_hook.destroy( );

	MessageBoxA( 0, "Test 2", "Test 2", MB_OK );

	return std::cin.get( ) == 0xffffffff;
}