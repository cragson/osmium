#pragma once
#include <cstdint>
#include <chrono>

class feature
{
public:
	feature()
	{
		this->m_status = false;
		this->m_virtualkey_code = int32_t();
		this->m_timepoint = std::chrono::high_resolution_clock::now();
		this->m_activation_delay = uint32_t();
		this->m_was_activated = false;
	}


	feature(const bool _status, const int32_t _vk_code, const uint32_t _delay) : m_status(_status), m_virtualkey_code(_vk_code), m_activation_delay(_delay)
	{
		this->m_timepoint = std::chrono::high_resolution_clock::now();

		this->m_was_activated = false;
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
	}


	void set_status(const bool new_status) noexcept
	{
		this->m_status = new_status;

		if (this->m_status)
			this->on_enable();
		else
			this->on_disable();
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


	virtual void tick() = 0;

	virtual void on_enable() = 0;

	virtual void on_disable() = 0;

	virtual void on_first_activation() = 0;


protected:
	bool m_status;

	int32_t m_virtualkey_code;

	std::chrono::high_resolution_clock::time_point m_timepoint;

	uint32_t m_activation_delay; // always in ms

	bool m_was_activated;
};
