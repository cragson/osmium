#pragma once

#include <Windows.h>
#include <string>

class shared_memory_instance
{
public:
	shared_memory_instance()
		: m_szObjectName( {} )
	  , m_hMapFile( nullptr )
	  , m_pBuffer( nullptr )
	  , m_pProcessBuffer( nullptr )
	  , m_hProcessMapFile( nullptr )
	  , m_iBufferSize( size_t() ) {}

	shared_memory_instance(
		const std::string& name,
		const HANDLE map,
		void* buffer,
		void* process_buffer,
		const HANDLE process_handle,
		const size_t buffer_size
	)
		: m_szObjectName( name )
	  , m_hMapFile( map )
	  , m_pBuffer( buffer )
	  , m_pProcessBuffer( process_buffer )
	  , m_hProcessMapFile( process_handle )
	  , m_iBufferSize( buffer_size ) {}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Gets a pointer to the shared memory of this process. </summary>
	/// 
	///  <remarks>	cragson, 05/10/2022. </remarks>
	///
	/// <typeparam name="T">	Generic type parameter. </typeparam>
	/// <param name="offset">	(Optional) The offset. </param>
	///
	/// <returns>	Null if it fails, else the buffer pointer. </returns>
	///-------------------------------------------------------------------------------------------------

	template< typename T = void >
	[[nodiscard]] T* get_buffer_ptr( const int32_t offset = 0 ) const noexcept
	{
		return !offset
		       ? static_cast< T* >( this->m_pBuffer )
		       : reinterpret_cast< T* >( reinterpret_cast< std::uintptr_t >( this->m_pBuffer ) + offset );
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Reads the shared memory buffer at the given address. </summary>
	///
	/// <typeparam name="T">	Generic type parameter. </typeparam>
	/// <param name="address">	The address. </param>
	///
	/// <returns>	The value at the given address. </returns>
	///-------------------------------------------------------------------------------------------------

	template< typename T >
	[[nodiscard]] T read( const std::uintptr_t address ) const noexcept
	{
		if( address < reinterpret_cast< std::uintptr_t >( this->m_pBuffer ) || address > reinterpret_cast<
			std::uintptr_t >( this->m_pBuffer ) + this->m_iBufferSize )
			return {};

		return *reinterpret_cast< T* >( address );
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Writes to the shared memory pointer. </summary>
	/// 
	/// <remarks>	cragson, 05/10/2022. </remarks>
	/// 
	/// <typeparam name="T">	Generic type parameter. </typeparam>
	/// <param name="value"> 	The value. </param>
	/// <param name="offset">	(Optional) The offset. </param>
	///-------------------------------------------------------------------------------------------------

	template< typename T >
	void write( const T& value, const int32_t offset = 0 )
	{
		*reinterpret_cast< T* >( this->get_buffer_ptr< T >( offset ) ) = value;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Writes a string to the shared memory pointer. </summary>
	///
	/// <remarks>	cragson, 05/10/2022. </remarks>
	///
	/// <param name="str">   	The string. </param>
	/// <param name="offset">	(Optional) The offset. </param>
	///-------------------------------------------------------------------------------------------------

	void write_string( const std::string& str, const int32_t offset = 0 ) const
	{
		memcpy( this->get_buffer_ptr( offset ), str.data(), str.size() );
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Clears the shared memory buffer by zero'ing it. </summary>
	///
	/// <remarks>	cragson, 05/10/2022. </remarks>
	///-------------------------------------------------------------------------------------------------

	void clear_memory() const
	{
		memset( this->m_pBuffer, 0, this->m_iBufferSize );
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Gets object name. </summary>
	///
	/// <remarks>	cragson, 05/10/2022. </remarks>
	///
	/// <returns>	The object name. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] std::string get_object_name() const noexcept
	{
		return this->m_szObjectName;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Gets file mapping object handle. </summary>
	///
	/// <remarks>	cragson, 05/10/2022. </remarks>
	///
	/// <returns>	The file mapping object handle. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] HANDLE get_file_mapping_object_handle() const noexcept
	{
		return this->m_hMapFile;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Gets the pointer of the target process to the shared memory buffer. </summary>
	///
	/// <remarks>	cragson, 05/10/2022. </remarks>
	///
	/// <returns>	Null if it fails, else the process buffer pointer. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] void* get_process_buffer_ptr() const noexcept
	{
		return this->m_pProcessBuffer;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Gets the mapping object handle of the target process. </summary>
	///
	/// <remarks>	cragson, 05/10/2022. </remarks>
	///
	/// <returns>	The process mapping object handle. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] HANDLE get_process_mapping_object_handle() const noexcept
	{
		return this->m_hProcessMapFile;
	}

	///-------------------------------------------------------------------------------------------------
	/// <summary>	Gets buffer size. </summary>
	///
	/// <remarks>	cragson, 05/10/2022. </remarks>
	///
	/// <returns>	The buffer size. </returns>
	///-------------------------------------------------------------------------------------------------

	[[nodiscard]] size_t get_buffer_size() const noexcept
	{
		return this->m_iBufferSize;
	}

private:
	std::string m_szObjectName;

	HANDLE m_hMapFile;

	void* m_pBuffer;

	void* m_pProcessBuffer;

	HANDLE m_hProcessMapFile;

	size_t m_iBufferSize;
};
