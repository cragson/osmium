#pragma once

#include <vector>
#include <memory>
#include "Feature/feature.hpp"

class cheat
{

public:

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets up the features by creating the instances and adding them to the internal features vector.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	virtual bool setup_features() = 0;

	///-------------------------------------------------------------------------------------------------
	/// <summary>Sets up the offsets.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>True if it succeeds, false if it fails.</returns>
	///-------------------------------------------------------------------------------------------------

	virtual bool setup_offsets() = 0;

	///-------------------------------------------------------------------------------------------------
	/// <summary>Runs the cheats logic, highly individual.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	virtual void run() = 0;

	///-------------------------------------------------------------------------------------------------
	/// <summary>Shuts down the cheat and frees any resources it is using, highly individual.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	virtual void shutdown() = 0;

	///-------------------------------------------------------------------------------------------------
	/// <summary>Print the offsets used by the cheat.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	virtual void print_offsets() = 0;

	///-------------------------------------------------------------------------------------------------
	/// <summary>Print the features of the cheat.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///-------------------------------------------------------------------------------------------------

	virtual void print_features() = 0;

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets the size of the internal features vector, tells how many features are in the cheat.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>The features size.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline size_t get_features_size() const noexcept
	{
		return this->m_features.size();
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>Gets a pointer to the internal vector of features.</summary>
	///
	/// <remarks>cragson, 03/30/22.</remarks>
	///
	/// <returns>Null if it fails, else the vector of features as pointer.</returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] inline std::vector< std::unique_ptr< feature > > * get_features_as_ptr() noexcept
	{
		return &this->m_features;
	}

protected:

	std::vector< std::unique_ptr < feature > > m_features;
};