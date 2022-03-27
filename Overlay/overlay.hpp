#pragma once

#include <cstdint>
#include <unordered_map>
#include <memory>

#include <d3d9.h>
#include <d3dx9.h>
#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "d3dx9.lib")

class overlay
{

public:

	overlay() :
	m_Object( nullptr ),
	m_Device( nullptr ),
	m_Width( 0 ),
	m_Height( 0 ),
	m_OverlayWindow( HWND() ),
	m_TargetWindow( HWND() ),
	m_WindowClass( { } ),
	m_HandleInstance( nullptr ),
	m_Line( nullptr )
	{ }

	overlay( const int32_t overlay_width, const int32_t overlay_height ) :
	m_Object( nullptr ),
	m_Device( nullptr ),
	m_Width( overlay_width ),
	m_Height( overlay_height ),
	m_OverlayWindow( HWND() ),
	m_TargetWindow( HWND() ),
	m_WindowClass( { } ),
	m_HandleInstance( nullptr ),
	m_Line( nullptr )
	{ }

	virtual ~overlay()
	{
		if( this->m_Object )
			this->m_Object->Release();

		if( this->m_OverlayWindow )
			DestroyWindow( this->m_OverlayWindow );
	}

	overlay( const overlay & ) = delete;
	overlay( const overlay && ) = delete;
	overlay& operator=( overlay && ) = delete;
	overlay& operator=( const overlay & ) = delete;

	[[nodiscard]] inline int32_t get_overlay_width() const noexcept
	{
		return this->m_Width;
	}

	[[nodiscard]] inline int32_t get_overlay_height() const noexcept
	{
		return this->m_Height;
	}

	[[nodiscard]] inline HWND get_overlay_window_handle() const noexcept
	{
		return this->m_OverlayWindow;
	}

	[[nodiscard]] inline HWND get_target_window_handle() const noexcept
	{
		return this->m_OverlayWindow;
	}

	[[nodiscard]] inline WNDCLASSEX get_window_class() const noexcept
	{
		return this->m_WindowClass;
	}

	[[nodiscard]] inline HINSTANCE get_handle_instance() const noexcept
	{
		return this->m_HandleInstance;
	}

	[[nodiscard]] inline IDirect3D9Ex* get_object_as_ptr() const noexcept
	{
		return this->m_Object;
	}

	[[nodiscard]] inline IDirect3DDevice9Ex* get_device_as_ptr() const noexcept
	{
		return this->m_Device;
	}

	[[nodiscard]] inline ID3DXLine* get_line_as_ptr() const noexcept
	{
		return this->m_Line;
	}

	void set_target_window( HWND handle )
	{
		this->m_TargetWindow = handle;
	}

	void set_object_ptr( IDirect3D9Ex* obj_ptr )
	{
		this->m_Object = ( obj_ptr != nullptr ) ? obj_ptr : this->m_Object;
	}

	void set_device_ptr( IDirect3DDevice9Ex* device_ptr )
	{
		this->m_Device = ( device_ptr != nullptr ) ? device_ptr : this->m_Device;
	}

	void set_line_ptr( ID3DXLine* line_ptr )
	{
		this->m_Line = ( line_ptr != nullptr ) ? line_ptr : this->m_Line;
	}

	void set_overlay_height( const int32_t height )
	{
		this->m_Height = ( height > 0 ) ? height : this->m_Height;
	}

	void set_overlay_width( const int32_t width )
	{
		this->m_Width = ( width > 0 ) ? width : this->m_Width;
	}

	[[nodiscard]] ID3DXFont* get_font_as_ptr( const std::string& font_name ) const noexcept
	{
		try
		{
			return this->m_Fonts.at( font_name );

		}
		catch( std::exception& e )
		{
			UNREFERENCED_PARAMETER( e );
			return nullptr;
		}
	}

	[[nodiscard]] bool set_used_font( const std::string & font_name )
	{
		if( !this->m_Fonts.contains( font_name ) )
			return false;

		this->m_UsedFont = font_name;

		return true;
	}

	[[nodiscard]] inline ID3DXFont* get_used_font_ptr() noexcept
	{
		if( this->m_Fonts.empty() )
			return nullptr;

		return this->m_Fonts.at( this->m_UsedFont );
	}

	[[nodiscard]] bool register_font( const std::string & font_name, const int32_t height = 20, const int32_t width = 0, const int32_t weight = FW_NORMAL );

	[[nodiscard]] bool create_window_class();

	[[nodiscard]] bool create_window_overlay();

	bool move_target_window();

	[[nodiscard]] bool initialize( const std::string & target_window_title );

	[[nodiscard]] bool initialize( const HWND & window_handle );

	virtual void render() = 0;

	void draw_string( const std::string & msg, const int32_t x, const int32_t y, const int32_t red, const int32_t green, const int32_t blue, const int32_t alpha = 255 );

	void draw_rect( const int32_t x, const int32_t y, const int32_t width, const int32_t height, const int32_t red, const int32_t green, const int32_t blue );

	void draw_line( const int32_t x, const int32_t y, const int32_t x2, const int32_t y2, const int32_t red, const int32_t green, const int32_t blue );

	void draw_filled_rect( const int32_t x, const int32_t y, const int32_t width, const int32_t height, const int32_t red, const int32_t green, const int32_t blue );

	void draw_circle( const int32_t x, const int32_t y, const int32_t radius, const int32_t red, const int32_t green, const int32_t blue );

protected:

	IDirect3D9Ex* m_Object;
	IDirect3DDevice9Ex* m_Device;

	int32_t m_Width;
	int32_t m_Height;

	HWND m_OverlayWindow, m_TargetWindow;

	std::unordered_map< std::string, ID3DXFont* > m_Fonts;

	WNDCLASSEX m_WindowClass;

	HINSTANCE m_HandleInstance;

	std::string m_UsedFont;

	ID3DXLine* m_Line;
};

struct wndproc_this_t
{
	overlay* m_this;
};