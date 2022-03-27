#pragma once

#include <vector>
#include <memory>
#include "Feature/feature.hpp"

class cheat
{

public:

	virtual bool setup_features() = 0;

	virtual bool setup_offsets() = 0;

	virtual void run() = 0;

	virtual void shutdown() = 0;

	virtual void print_offsets() = 0;

	virtual void print_features() = 0;

	[[nodiscard]] inline size_t get_features_size() const noexcept
	{
		return this->m_features.size();
	}

	[[nodiscard]] inline std::vector< std::unique_ptr< feature > > * get_features_as_ptr() noexcept
	{
		return &this->m_features;
	}

protected:

	std::vector< std::unique_ptr < feature > > m_features;
};