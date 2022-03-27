#pragma once
#include <cstdint>
#include <chrono>
#include <string>

class feature
{
public:
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

	explicit feature( const std::wstring & name ) : feature()
	{
		this->m_name = name;
	}

	inline void print_status() const
	{
		wprintf( L"[%ws] is %ws!\n", this->m_name.c_str(), this->m_status ? L"enabled" : L"disabled" );
	}

	[[nodiscard]] bool is_active() const noexcept
	{
		return this->m_status;
	}

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


	[[nodiscard]] int32_t get_virtual_key_code() const noexcept
	{
		return this->m_virtualkey_code;
	}


	void set_virtual_key_code(const int32_t vk_code) noexcept
	{
		this->m_virtualkey_code = vk_code;
	}

	// merci beaucoup, mon frère: https://stackoverflow.com/questions/16177295/get-time-since-epoch-in-milliseconds-preferably-using-c11-chrono
	[[nodiscard]] inline uint32_t get_current_timepoint_in_ms() const noexcept
	{
		// I am ignoring the possible data loss here, thank you.
		// Oh no, that shit will eventually result in really long debug sessions.

#pragma warning(disable:4244)
		return this->m_timepoint.time_since_epoch() / std::chrono::milliseconds(1);
	}

	inline void refresh_timepoint() noexcept
	{
		this->m_timepoint = std::chrono::high_resolution_clock::now();
	}

	[[nodiscard]] inline uint32_t get_activation_delay() const noexcept
	{
		return this->m_activation_delay;
	}

	inline void set_activation_delay(const uint32_t new_delay) noexcept
	{
		this->m_activation_delay = new_delay;
	}

	[[nodiscard]] inline bool is_activatable() const noexcept
	{
		return (std::chrono::high_resolution_clock::now().time_since_epoch() / std::chrono::milliseconds(1)) - this->m_timepoint.time_since_epoch() / std::chrono::milliseconds(1) >= this->m_activation_delay;
	}

	[[nodiscard]] inline bool was_already_activated() const noexcept
	{
		return this->m_was_activated;
	}

	[[nodiscard]] inline std::wstring get_name() const noexcept
	{
		return this->m_name;
	}

	void set_name( const std::wstring & name )
	{
		this->m_name = name;
	}

	[[nodiscard]] inline bool is_status_printed() const noexcept
	{
		return this->m_print_status;
	}

	inline void set_print_status( const bool status ) noexcept
	{
		this->m_print_status = status;
	}

	inline void enable_print_status() noexcept
	{
		this->m_print_status = true;
	}

	inline void disable_print_status() noexcept
	{
		this->m_print_status = false;
	}

	inline void toggle_print_status() noexcept
	{
		this->m_print_status = !this->m_print_status;
	}

	[[nodiscard]] inline bool should_be_drawn() const noexcept
	{
		return this->m_should_draw;
	}

	void enable_drawing() noexcept
	{
		this->m_should_draw = true;
	}

	void disable_drawing() noexcept
	{
		this->m_should_draw = false;
	}

	void toggle_drawing() noexcept
	{
		this->m_should_draw = !this->m_should_draw;
	}

	virtual void tick() = 0;

	virtual void on_enable() = 0;

	virtual void on_disable() = 0;

	virtual void on_first_activation() = 0;

	virtual void on_render() = 0;

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
