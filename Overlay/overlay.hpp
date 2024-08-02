#pragma once

#include <cstdint>
#include <unordered_map>
#include <memory>

#include <d3d9.h>
#include <d3dx9.h>
#include <string>
#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "d3dx9.lib")

class overlay
{

public:

	///-------------------------------------------------------------------------------------------------
	/// <summary>Default constructor.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

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

	///-------------------------------------------------------------------------------------------------
	/// <summary>Constructor.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="overlay_width"> 	Width of the overlay.</param>
	/// <param name="overlay_height">	Height of the overlay.</param>
	///-------------------------------------------------------------------------------------------------

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

	///-------------------------------------------------------------------------------------------------
	/// <summary>Destructor, which releases the DirectX object and destroys the overlay window.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

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

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets overlay width.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The overlay width.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline int32_t get_overlay_width() const noexcept
	{
		return this->m_Width;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets overlay height.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The overlay height.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline int32_t get_overlay_height() const noexcept
	{
		return this->m_Height;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets overlay window handle.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The overlay window handle.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline HWND get_overlay_window_handle() const noexcept
	{
		return this->m_OverlayWindow;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets target window handle.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The target window handle.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline HWND get_target_window_handle() const noexcept
	{
		return this->m_TargetWindow;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets window class.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The window class.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline WNDCLASSEX get_window_class() const noexcept
	{
		return this->m_WindowClass;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets handle instance.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The handle instance.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline HINSTANCE get_handle_instance() const noexcept
	{
		return this->m_HandleInstance;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the used DirectX object as pointer.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>Null if it fails, else the object as pointer.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline IDirect3D9Ex* get_object_as_ptr() const noexcept
	{
		return this->m_Object;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the DirectX device as pointer.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>Null if it fails, else the device as pointer.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline IDirect3DDevice9Ex* get_device_as_ptr() const noexcept
	{
		return this->m_Device;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the DirectX line as pointer.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>Null if it fails, else the line as pointer.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline ID3DXLine* get_line_as_ptr() const noexcept
	{
		return this->m_Line;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets the target window.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="handle">	Handle of the target window.</param>
	///-------------------------------------------------------------------------------------------------

	void set_target_window( HWND handle )
	{
		this->m_TargetWindow = handle;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets the DirectX object pointer.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="obj_ptr">	[in,out] If non-null, the object pointer.</param>
	///-------------------------------------------------------------------------------------------------

	void set_object_ptr( IDirect3D9Ex* obj_ptr )
	{
		this->m_Object = ( obj_ptr != nullptr ) ? obj_ptr : this->m_Object;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets the DirectX device pointer.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="device_ptr">	[in,out] If non-null, the device pointer.</param>
	///-------------------------------------------------------------------------------------------------

	void set_device_ptr( IDirect3DDevice9Ex* device_ptr )
	{
		this->m_Device = ( device_ptr != nullptr ) ? device_ptr : this->m_Device;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets the DirectX line pointer.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="line_ptr">	[in,out] If non-null, the line pointer.</param>
	///-------------------------------------------------------------------------------------------------

	void set_line_ptr( ID3DXLine* line_ptr )
	{
		this->m_Line = ( line_ptr != nullptr ) ? line_ptr : this->m_Line;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets overlay height.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="height">	The height.</param>
	///-------------------------------------------------------------------------------------------------

	void set_overlay_height( const int32_t height )
	{
		this->m_Height = ( height > 0 ) ? height : this->m_Height;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets overlay width.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="width">	The width.</param>
	///-------------------------------------------------------------------------------------------------

	void set_overlay_width( const int32_t width )
	{
		this->m_Width = ( width > 0 ) ? width : this->m_Width;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets a DirectX font as pointer, by it's name.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="font_name">	Name of the font.</param>
	///
	/// <returns>Null if it fails, else the font as pointer.</returns>
	///-------------------------------------------------------------------------------------------------

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

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets the current used DirectX font, be careful the font must be already registered!</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="font_name">	Name of the font, which should be used (must be already registered!!!).</param>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool set_used_font( const std::string & font_name )
	{
		if( !this->m_Fonts.contains( font_name ) )
			return false;

		this->m_UsedFont = font_name;

		return true;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the current used DirectX font pointer.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>Null if it fails, else the used font pointer.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline ID3DXFont* get_used_font_ptr() noexcept
	{
		if( this->m_Fonts.empty() )
			return nullptr;

		return this->m_Fonts.at( this->m_UsedFont );
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Registers the DirectX font.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="font_name">	Name of the font.</param>
	/// <param name="height">   	(Optional) The height.</param>
	/// <param name="width">		(Optional) The width.</param>
	/// <param name="weight">   	(Optional) The weight.</param>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool register_font( const std::string & font_name, const int32_t height = 20, const int32_t width = 0, const int32_t weight = FW_NORMAL );

	///-------------------------------------------------------------------------------------------------
	/// <summary>Creates window class.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool create_window_class();

	///-------------------------------------------------------------------------------------------------
	/// <summary>Creates window overlay.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool create_window_overlay();

	///-------------------------------------------------------------------------------------------------
	/// <summary>Determines if we can move target window and replace it in the correct position.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	bool move_target_window();

	///-------------------------------------------------------------------------------------------------
	/// <summary>Initializes the overlay with an window title, this function also creates the window, overlay and thread.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="target_window_title">	Target window title.</param>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool initialize( const std::string & target_window_title );

	///-------------------------------------------------------------------------------------------------
	/// <summary>Initializes the overlay with an handle to the game window, this function also creates the window, overlay and thread.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="window_handle">	Handle of the window.</param>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool initialize( const HWND & window_handle );

	///-------------------------------------------------------------------------------------------------
	/// <summary>This virtual function you need to implement and should contain your render logic.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	virtual void render() = 0;

	///-------------------------------------------------------------------------------------------------
	/// <summary>Draw string.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="msg">  	The string.</param>
	/// <param name="x">		The x coordinate.</param>
	/// <param name="y">		The y coordinate.</param>
	/// <param name="red">  	The red color (0-255).</param>
	/// <param name="green">	The green color (0-255).</param>
	/// <param name="blue"> 	The blue color (0-255).</param>
	/// <param name="alpha">	(Optional) The alpha (0-255).</param>
	///-------------------------------------------------------------------------------------------------

	void draw_string( const std::string & msg, const int32_t x, const int32_t y, const int32_t red, const int32_t green, const int32_t blue, const int32_t alpha = 255 );

	///-------------------------------------------------------------------------------------------------
	/// <summary>Draw rectangle.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="x">	 	The x coordinate.</param>
	/// <param name="y">	 	The y coordinate.</param>
	/// <param name="width"> 	The width.</param>
	/// <param name="height">	The height.</param>
	/// <param name="red">   	The red color (0-255).</param>
	/// <param name="green"> 	The green color (0-255).</param>
	/// <param name="blue">  	The blue color (0-255).</param>
	/// <param name="width_rect"> 	The width of the line.</param>
	///-------------------------------------------------------------------------------------------------

	void draw_rect( const int32_t x, const int32_t y, const int32_t width, const int32_t height, const int32_t red, const int32_t green, const int32_t blue, const int32_t width_rect = 1);

	///-------------------------------------------------------------------------------------------------
	/// <summary>Draw line.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="x">		The start x coordinate.</param>
	/// <param name="y">		The start y coordinate.</param>
	/// <param name="x2">   	The end x coordinate.</param>
	/// <param name="y2">   	The end y coordinate.</param>
	/// <param name="red">  	The red color (0-255).</param>
	/// <param name="green">	The green color (0-255).</param>
	/// <param name="blue"> 	The blue color (0-255).</param>
	/// <param name="width"> 	The width of the line.</param>
	///-------------------------------------------------------------------------------------------------

	void draw_line( const int32_t x, const int32_t y, const int32_t x2, const int32_t y2, const int32_t red, const int32_t green, const int32_t blue, const int32_t width = 1 );

	///-------------------------------------------------------------------------------------------------
	/// <summary>Draw filled rectangle.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="x">	 	The x coordinate.</param>
	/// <param name="y">	 	The y coordinate.</param>
	/// <param name="width"> 	The width.</param>
	/// <param name="height">	The height.</param>
	/// <param name="red">   	The red color (0-255).</param>
	/// <param name="green"> 	The green color (0-255).</param>
	/// <param name="blue">  	The blue color (0-255).</param>
	///-------------------------------------------------------------------------------------------------

	void draw_filled_rect( const int32_t x, const int32_t y, const int32_t width, const int32_t height, const int32_t red, const int32_t green, const int32_t blue );

	///-------------------------------------------------------------------------------------------------
	/// <summary>Draw circle.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="x">	 	The x coordinate.</param>
	/// <param name="y">	 	The y coordinate.</param>
	/// <param name="radius">	The radius.</param>
	/// <param name="red">   	The red color (0-255).</param>
	/// <param name="green"> 	The green color (0-255).</param>
	/// <param name="blue">  	The blue color (0-255).</param>
	///-------------------------------------------------------------------------------------------------

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