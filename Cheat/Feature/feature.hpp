#pragma once
#include <cstdint>
#include <chrono>
#include <string>

class feature
{
public:

	///-------------------------------------------------------------------------------------------------
	/// <summary>Default constructor.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	feature() :
		m_status( false ),
		m_virtualkey_code( int32_t() ),
		m_timepoint( std::chrono::high_resolution_clock::now() ),
		m_activation_delay( uint32_t() ),
		m_was_activated( false ),
		m_name( std::wstring() ),
		m_print_status( false ),
		m_should_draw( false )
	{}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Constructor.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="status"> 	True to enable the cheat, false to disable it.</param>
	/// <param name="vk_code">	The virtual key code.</param>
	/// <param name="delay">  	The activation delay.</param>
	///-------------------------------------------------------------------------------------------------

	feature( const bool status, const int32_t vk_code, const uint32_t delay ) :
		m_status( status ),
		m_virtualkey_code( vk_code ),
		m_timepoint( std::chrono::high_resolution_clock::now() ),
		m_activation_delay( delay ),
		m_was_activated( false) ,
		m_name( std::wstring() ),
		m_print_status( false ),
		m_should_draw( false )
	{}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Constructor.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="name">	The name of the feature.</param>
	///-------------------------------------------------------------------------------------------------

	explicit feature( const std::wstring & name ) : feature()
	{
		this->m_name = name;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Print the status of the feature to console.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	inline void print_status() const
	{
		wprintf( L"[%ws] is %ws!\n", this->m_name.c_str(), this->m_status ? L"enabled" : L"disabled" );
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Query if the feature is active.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>True if active, false if not.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] bool is_active() const noexcept
	{
		return this->m_status;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Enables the feature and sets the new status, refreshes the timepoint and prints the status.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	void enable() noexcept
	{
		// check here if this is the first activation
		if (!this->m_was_activated)
		{
			this->on_first_activation();

			this->m_was_activated = true;
		}

		// if the feature is not yet ready to be activated, just return.
		if (!this->is_activatable())
			return;

		this->m_status = true;

		this->on_enable();

		// reset the timepoint here after the activation
		this->refresh_timepoint();

		if( this->m_print_status )
			this->print_status();
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Disables the feature and sets the new status, refreshes the timepoint and prints the status.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	void disable() noexcept
	{
		// if the feature is not yet ready to be activated, just return.
		if (!this->is_activatable())
			return;

		this->m_status = false;

		this->on_disable();

		// reset the timepoint here after the activation
		this->refresh_timepoint();

		if (this->m_print_status)
			this->print_status();
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Toggles the feature and sets the new status, refreshes the timepoint and prints the status.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	void toggle() noexcept
	{

		// check here if this is the first activation
		if (!this->m_was_activated)
		{
			this->on_first_activation();

			this->m_was_activated = true;
		}

		// if the feature is not yet ready to be activated, just return.
		if (!this->is_activatable())
			return;

		this->m_status = !this->m_status;

		// check here if the feature was enabled or disabled and call the correct startup function for the different case.
		if (this->m_status)
			this->on_enable();
		else
			this->on_disable();

		// reset the timepoint here after the activation
		this->refresh_timepoint();

		if (this->m_print_status)
			this->print_status();
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets the status of the feature.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="new_status">	The new status of the feature.</param>
	///-------------------------------------------------------------------------------------------------

	void set_status(const bool new_status) noexcept
	{
		this->m_status = new_status;

		if (this->m_status)
			this->on_enable();
		else
			this->on_disable();

		if (this->m_print_status)
			this->print_status();
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the virtual key code of the feature.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The virtual key code of the feature.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] int32_t get_virtual_key_code() const noexcept
	{
		return this->m_virtualkey_code;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets virtual key code of the feature.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="vk_code">	The virtual key code of the feature.</param>
	///-------------------------------------------------------------------------------------------------

	void set_virtual_key_code(const int32_t vk_code) noexcept
	{
		this->m_virtualkey_code = vk_code;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the current timepoint in milliseconds.
	/// 
	/// merci beaucoup, mon frère:
	/// 	https://stackoverflow.com/questions/16177295/get-time-since-epoch-in-milliseconds-preferably-using-c11-chrono.
	/// </summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The current timepoint in milliseconds.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline uint32_t get_current_timepoint_in_ms() const noexcept
	{
		// I am ignoring the possible data loss here, thank you.
		// Oh no, that shit will eventually result in really long debug sessions.

#pragma warning(disable:4244)
		return this->m_timepoint.time_since_epoch() / std::chrono::milliseconds(1);
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Refresh the current timepoint.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	inline void refresh_timepoint() noexcept
	{
		this->m_timepoint = std::chrono::high_resolution_clock::now();
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the activation delay of the feature.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The activation delay.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline uint32_t get_activation_delay() const noexcept
	{
		return this->m_activation_delay;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets the activation delay of the feature.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="new_delay">	The new activation delay of the feature in milliseconds.</param>
	///-------------------------------------------------------------------------------------------------

	inline void set_activation_delay(const uint32_t new_delay) noexcept
	{
		this->m_activation_delay = new_delay;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Query if the feature is activatable.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>True if activatable, false if not.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline bool is_activatable() const noexcept
	{
		return (std::chrono::high_resolution_clock::now().time_since_epoch() / std::chrono::milliseconds(1)) - this->m_timepoint.time_since_epoch() / std::chrono::milliseconds(1) >= this->m_activation_delay;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Determines if the feature was already activated.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>True if the feature was already activated, false if it was not.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline bool was_already_activated() const noexcept
	{
		return this->m_was_activated;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the name of the feature.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The name of the feature.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline std::wstring get_name() const noexcept
	{
		return this->m_name;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets the name of the feature.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="name">	The new name of the feature.</param>
	///-------------------------------------------------------------------------------------------------

	void set_name( const std::wstring & name )
	{
		this->m_name = name;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Query if the status change of the feature will be printed or not.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>True if status will be printed, false if not.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline bool is_status_printed() const noexcept
	{
		return this->m_print_status;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets the print status of the feature.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <param name="status">	If true the status will be printed on change, false it will not be printed.</param>
	///-------------------------------------------------------------------------------------------------

	inline void set_print_status( const bool status ) noexcept
	{
		this->m_print_status = status;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Enables the print status.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	inline void enable_print_status() noexcept
	{
		this->m_print_status = true;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Disables the print status.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	inline void disable_print_status() noexcept
	{
		this->m_print_status = false;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Toggle the print status.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	inline void toggle_print_status() noexcept
	{
		this->m_print_status = !this->m_print_status;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Determine if the feature should be drawn/ on_render function should be called in the overlay logic.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline bool should_be_drawn() const noexcept
	{
		return this->m_should_draw;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets the feature drawing status to true, so the feature should draw.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	void enable_drawing() noexcept
	{
		this->m_should_draw = true;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets the feature drawing status to false, so the feature should not be draw.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	void disable_drawing() noexcept
	{
		this->m_should_draw = false;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Toggle the drawing status of the feature.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	void toggle_drawing() noexcept
	{
		this->m_should_draw = !this->m_should_draw;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>The virtual function which should be called frequently in the cheat logic.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	virtual void tick() = 0;

	///-------------------------------------------------------------------------------------------------
	/// <summary>The virtual function which will be called when the feature is enabled.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	virtual void on_enable() = 0;

	///-------------------------------------------------------------------------------------------------
	/// <summary>The virtual function which will be called when the feature is disabled.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	virtual void on_disable() = 0;

	///-------------------------------------------------------------------------------------------------
	/// <summary>The virtual function which will be called when the cheat is activated the first time.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	virtual void on_first_activation() = 0;

	///-------------------------------------------------------------------------------------------------
	/// <summary>The virtual function in which all drawing should happen because this should be called inside the overlay logic.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	virtual void on_render() = 0;

	///-------------------------------------------------------------------------------------------------
	/// <summary>	The virtual function which should be called when the shutdown function of the cheat was called. </summary>
	///
	/// <remarks>	cragson, 23/12/2022. </remarks>
	///-------------------------------------------------------------------------------------------------

	virtual void on_shutdown() = 0;

protected:
	bool m_status;

	int32_t m_virtualkey_code;

	std::chrono::high_resolution_clock::time_point m_timepoint;

	uint32_t m_activation_delay; // always in ms

	bool m_was_activated;

	std::wstring m_name;

	bool m_print_status;

	bool m_should_draw;
};
