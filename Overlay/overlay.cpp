#include "overlay.hpp"

#include <dwmapi.h>
#pragma comment(lib, "dwmapi.lib")

#include <numbers>

LRESULT CALLBACK WinProcedure( HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam )
{
	static overlay* this_ptr = {};
	wndproc_this_t* args = {};

	if( Message == WM_NCCREATE )
		args = reinterpret_cast< wndproc_this_t* >( lParam );

	switch( Message )
	{
		
		case WM_NCCREATE:
			this_ptr = args->m_this;
			break;

		case WM_PAINT:
			this_ptr->render();
			break;

		case WM_DESTROY:
			PostQuitMessage( 1 );
			break;

		case WM_SIZE:
			auto target_dim = RECT();
			GetWindowRect( this_ptr->get_target_window_handle(), &target_dim );

			this_ptr->set_overlay_width(  target_dim.right - target_dim.left );
			this_ptr->set_overlay_height( target_dim.bottom - target_dim.top );
			break;

		default:
			break;
	}
	return DefWindowProc( hWnd, Message, wParam, lParam );
}

DWORD WINAPI ThreadProc( LPVOID lpParam )
{
	const auto this_ptr = static_cast< overlay* >( lpParam );

	if (!this_ptr->create_window_class())
		return false;

	if (!this_ptr->create_window_overlay())
		return false;

	auto object_ptr = this_ptr->get_object_as_ptr();

	if ( FAILED( Direct3DCreate9Ex( D3D_SDK_VERSION, &object_ptr ) ) )
		return false;

	this_ptr->set_object_ptr( object_ptr );

	D3DPRESENT_PARAMETERS params;

	ZeroMemory(&params, sizeof(params));
	params.Windowed = true;
	params.BackBufferFormat = D3DFMT_A8R8G8B8;
	params.BackBufferHeight = this_ptr->get_overlay_height();
	params.BackBufferWidth = this_ptr->get_overlay_width();
	params.SwapEffect = D3DSWAPEFFECT_DISCARD;
	params.hDeviceWindow = this_ptr->get_overlay_window_handle();
	params.PresentationInterval = D3DPRESENT_INTERVAL_ONE;

	auto device_ptr = this_ptr->get_device_as_ptr();

	const auto create_ret = this_ptr->get_object_as_ptr()->CreateDeviceEx(
		D3DADAPTER_DEFAULT,
		D3DDEVTYPE_HAL,
		this_ptr->get_overlay_window_handle(),
		D3DCREATE_FPU_PRESERVE | D3DCREATE_MULTITHREADED | D3DCREATE_SOFTWARE_VERTEXPROCESSING,
		&params,
		nullptr,
		&device_ptr
	);

	if( FAILED( create_ret ) )
		return false;

	this_ptr->set_device_ptr( device_ptr );

	auto line_ptr = this_ptr->get_line_as_ptr();

	if ( FAILED( D3DXCreateLine( device_ptr, &line_ptr ) ) )
		return false;

	this_ptr->set_line_ptr( line_ptr );

	if (!this_ptr->register_font("Arial"))
		return false;

	if (!this_ptr->set_used_font("Arial"))
		return false;

	MSG current_msg = {};
	RtlZeroMemory( &current_msg, sizeof( MSG ) );

	while( true )
	{
		if (PeekMessage(&current_msg, this_ptr->get_overlay_window_handle(), 0, 0, PM_REMOVE))
		{
			DispatchMessage(&current_msg);
			TranslateMessage(&current_msg);
		}

		if (current_msg.message == WM_QUIT)
			break;

		this_ptr->move_target_window();

		this_ptr->render();
	}

	this_ptr->get_device_as_ptr()->Release();

	return 0;
}

bool overlay::register_font( const std::string& font_name, const int32_t height, const int32_t width, const int32_t weight )
{
	if ( !this->m_Device || font_name.empty() || height <= 0 || width < 0 || weight < 0 )
		return false;

	ID3DXFont* font_ptr = nullptr;

	const auto ret = D3DXCreateFontA( 
		this->m_Device, 
		height,
		width,
		weight,
		1,
		FALSE,
		DEFAULT_CHARSET,
		OUT_DEFAULT_PRECIS,
		DEFAULT_QUALITY,
		DEFAULT_PITCH | FF_DONTCARE,
		font_name.c_str(),
		&font_ptr
	);

	if( ret != S_OK )
		return false;


	this->m_Fonts[ font_name ] = font_ptr;

	return true;
}

bool overlay::create_window_class()
{
	this->m_WindowClass.cbClsExtra = 0;
	this->m_WindowClass.cbSize = sizeof( WNDCLASSEX );
	this->m_WindowClass.cbWndExtra = 0;
	this->m_WindowClass.hbrBackground = CreateSolidBrush( RGB( 0, 0, 0 ) );
	this->m_WindowClass.hCursor = LoadCursor( nullptr, IDC_ARROW );
	this->m_WindowClass.hIcon = LoadIcon( nullptr, IDI_APPLICATION );
	this->m_WindowClass.hIconSm = LoadIcon( nullptr, IDI_APPLICATION );
	this->m_WindowClass.hInstance = this->m_HandleInstance;
	this->m_WindowClass.lpfnWndProc = WinProcedure;
	this->m_WindowClass.lpszClassName = L"OVCRG";
	this->m_WindowClass.lpszMenuName = L"OVCRG";
	this->m_WindowClass.style = CS_HREDRAW | CS_VREDRAW;

	if( !RegisterClassEx( &this->m_WindowClass ) )
		return false;

	return true;
}

bool overlay::create_window_overlay()
{
	const std::string name = "OVCRG";

	const auto ret = CreateWindowExA( 
		WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT, 
		name.data(), 
		name.data(), 
		WS_POPUP, 
		1, 
		1, 
		this->m_Width, 
		this->m_Height, 
		nullptr, 
		nullptr, 
		this->m_HandleInstance, 
		this // very important to pass here the this pointer because of the handling in the windowproc function
	);

	if( !ret )
		return false;

	const auto ret2 = SetLayeredWindowAttributes( 
		ret, 
		RGB(0, 0, 0), 
		255, 
		LWA_ALPHA
	);

	if( !ret2 )
		return false;

	ShowWindow( ret, SW_SHOW );

	const auto margin = MARGINS( 0, 0, this->m_Height, this->m_Width );

	const auto ret3 = DwmExtendFrameIntoClientArea( ret, &margin );

	if( ret3 != S_OK )
		return false;

	this->m_OverlayWindow = ret;

	return true;
}

bool overlay::move_target_window()
{
	auto target_dim = RECT();

	GetWindowRect( this->m_TargetWindow, &target_dim );
	this->m_Width = target_dim.right - target_dim.left;
	this->m_Height = target_dim.bottom - target_dim.top;

	auto target_style = DWORD();

	target_style = GetWindowLong( this->m_TargetWindow, GWL_STYLE );

	if( !target_style )
		return false;

	if( target_style & WS_BORDER )
	{
		target_dim.top += 23;
		this->m_Height -= 23;
	}

	return MoveWindow( 
		this->m_OverlayWindow, 
		target_dim.left, 
		target_dim.top, 
		this->m_Width, 
		this->m_Height, 
		true
	);
}

bool overlay::initialize( const std::string& target_window_title )
{
	BOOL status;
	const auto dwm_ret = DwmIsCompositionEnabled( &status );

	if ( !status || dwm_ret != S_OK )
		return false;

	if( target_window_title.empty() )
		return false;

	const auto ret = FindWindowA( nullptr, target_window_title.c_str() );

	if( !ret )
		return false;

	this->m_TargetWindow = ret;

	auto target_dim = RECT();

	GetWindowRect(this->m_TargetWindow, &target_dim);
	this->m_Width = target_dim.right - target_dim.left;
	this->m_Height = target_dim.bottom - target_dim.top;

	CreateThread( 
		nullptr, 
		NULL, 
		(LPTHREAD_START_ROUTINE)ThreadProc, 
		 this,
		NULL,
		nullptr
	);

	return true;
}

bool overlay::initialize(const HWND& window_handle)
{
	if( !window_handle )
		return false;

	BOOL status;
	const auto dwm_ret = DwmIsCompositionEnabled(&status);

	if ( !status || dwm_ret != S_OK )
		return false;

	this->m_TargetWindow = window_handle;

	auto target_dim = RECT();

	GetWindowRect(this->m_TargetWindow, &target_dim);
	this->m_Width = target_dim.right - target_dim.left;
	this->m_Height = target_dim.bottom - target_dim.top;

	CreateThread(
		nullptr,
		NULL,
		(LPTHREAD_START_ROUTINE)ThreadProc,
		this,
		NULL,
		nullptr
	);

	return true;
}

void overlay::draw_string( const std::string& msg, const int32_t x, const int32_t y, const int32_t red, const int32_t green, const int32_t blue, const int32_t alpha )
{
	if( msg.empty() || x < 0 || y < 0 || red < 0 || blue < 0 || green < 0 || alpha < 0 )
		return;

	const auto current_font = this->get_used_font_ptr();

	if( !current_font )
		return;

	RECT Position = {};

	Position.left = x;
	Position.top = y;

	current_font->DrawTextA( nullptr, msg.data(), msg.size(), &Position, DT_NOCLIP, D3DCOLOR_ARGB( alpha, red, green, blue ) );
}

void overlay::draw_rect( const int32_t x, const int32_t y, const int32_t width, const int32_t height, const int32_t red, const int32_t green, const int32_t blue, const int32_t width_rect )
{
	D3DXVECTOR2 Rect[ 5 ];

	Rect[ 0 ] = D3DXVECTOR2( x, y );
	Rect[ 1 ] = D3DXVECTOR2( x + width, y );
	Rect[ 2 ] = D3DXVECTOR2( x + width, y + height );
	Rect[ 3 ] = D3DXVECTOR2( x, y + height );
	Rect[ 4 ] = D3DXVECTOR2( x, y );

	this->m_Line->SetWidth( width_rect > 0 ? width_rect : 1 );

	this->m_Line->Draw( Rect, 5, D3DCOLOR_ARGB( 255, red, green, blue ) );

}

void overlay::draw_line( const int32_t x, const int32_t y, const int32_t x2, const int32_t y2, const int32_t red, const int32_t green, const int32_t blue, const int32_t width )
{
	D3DXVECTOR2 Line[ 2 ];

	Line[ 0 ] = D3DXVECTOR2( x, y );
	Line[ 1 ] = D3DXVECTOR2( x2, y2 );

	this->m_Line->SetWidth( width > 0 ? width : 1 );

	this->m_Line->Draw( Line, 2, D3DCOLOR_ARGB( 255, red, green, blue ) );
}

void overlay::draw_filled_rect(const int32_t x, const int32_t y, const int32_t width, const int32_t height, const int32_t red, const int32_t green, const int32_t blue)
{
	D3DXVECTOR2 Rect[ 2 ];
	Rect[ 0 ] = D3DXVECTOR2( x + width / 2, y );
	Rect[ 1 ] = D3DXVECTOR2( x + width / 2, y + height );
	this->m_Line->SetWidth( width );
	this->m_Line->Draw( Rect, 2, D3DCOLOR_ARGB( 255, red, green, blue ) );
}

void overlay::draw_circle(const int32_t x, const int32_t y, const int32_t radius, const int32_t red, const int32_t green, const int32_t blue)
{
}