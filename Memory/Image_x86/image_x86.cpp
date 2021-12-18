#include "image_x86.hpp"

std::uintptr_t image_x86::find_pattern(const std::wstring& pattern, const bool should_be_relative )
{
	// Old code, maybe I will rewrite it in the future

	std::vector< uint8_t > m_vecPattern;

	std::string         Temp = std::string();

	std::string         strPattern = std::string(pattern.begin(), pattern.end());
	strPattern.erase(std::remove_if(strPattern.begin(), strPattern.end(), isspace), strPattern.end());

	// Convert string pattern to byte pattern
	for (size_t i = 0; i < strPattern.length(); i++)
	{
		if (strPattern.at(i) == '?')
		{
			m_vecPattern.emplace_back(WILDCARD_BYTE);
			continue;
		}

		if (Temp.length() != 2)
			Temp += strPattern.at(i);

		if (Temp.length() == 2)
		{
			Temp.erase(std::remove_if(Temp.begin(), Temp.end(), isspace), Temp.end());
			auto converted_pattern_byte = strtol(Temp.c_str(), nullptr, 16) & 0xFFF;
			m_vecPattern.emplace_back(converted_pattern_byte);
			Temp.clear();
		}
	}
	const auto vector_size = m_vecPattern.size();

	// m_vecPattern contains now the converted byte pattern
	// Search now the memory area

	bool			 found = false;
	std::uintptr_t   found_addr = 0;

	for (std::uintptr_t current_addr = 0; current_addr < this->m_bytes.size(); current_addr++)
	{
		if (found)
			break;

		for (uint8_t i = 0; i < vector_size; i++)
		{
			const auto current_byte = this->m_bytes.at(current_addr + i);

			const auto pattern_byte = m_vecPattern.at(i);

			if (static_cast<uint8_t>(pattern_byte) == WILDCARD_BYTE)
			{
				if (i == vector_size - 1)
				{
					found = true;
					found_addr = current_addr;
					break;
				}
				continue;
			}

			if (static_cast<uint8_t>(current_byte) != pattern_byte)
				break;

			if (i == vector_size - 1)
			{
				found_addr = current_addr;
				found = true;
			}
		}
	}

	// if nothing was found, just return found_addr which will contain 0
	if (!found_addr)
		return found_addr;

	return should_be_relative ? found_addr : this->m_base + found_addr;
}

std::vector< std::uintptr_t > image_x86::find_all_pattern_occurences( const std::wstring& pattern, const bool should_be_relative )
{
	// Old code, maybe I will rewrite it in the future

	std::vector< uint8_t > m_vecPattern;

	std::string         Temp = std::string();

	std::string         strPattern = std::string(pattern.begin(), pattern.end());
	strPattern.erase( std::remove_if( strPattern.begin(), strPattern.end(), isspace), strPattern.end() );

	// Convert string pattern to byte pattern
	for ( size_t i = 0; i < strPattern.length(); i++ )
	{
		if ( strPattern.at( i ) == '?' )
		{
			m_vecPattern.emplace_back( WILDCARD_BYTE );
			continue;
		}

		if ( Temp.length() != 2 )
			Temp += strPattern.at( i );

		if ( Temp.length() == 2 )
		{
			Temp.erase( std::remove_if( Temp.begin(), Temp.end(), isspace ), Temp.end() );
			auto converted_pattern_byte = strtol( Temp.c_str(), nullptr, 16 ) & 0xFFF;
			m_vecPattern.emplace_back( converted_pattern_byte );
			Temp.clear();
		}
	}
	const auto vector_size = m_vecPattern.size();

	// m_vecPattern contains now the converted byte pattern
	// Search now the memory area

	bool			 found = false;
	std::vector< std::uintptr_t >   found_addresses = {};

	for ( std::uintptr_t current_addr = 0; current_addr < this->m_bytes.size(); current_addr++ )
	{

		for ( uint8_t i = 0; i < vector_size; i++ )
		{
			const auto current_byte = this->m_bytes.at( current_addr + i );

			const auto pattern_byte = m_vecPattern.at( i );

			if ( static_cast< uint8_t >( pattern_byte ) == WILDCARD_BYTE )
			{
				if ( i == vector_size - 1 )
				{
					found_addresses.push_back( should_be_relative ? current_addr : this->m_base + current_addr );
					
					current_addr += i;

					break;
				}
				continue;
			}

			if ( static_cast< uint8_t >( current_byte ) != pattern_byte )
				break;

			if ( i == vector_size - 1 )
			{
				found_addresses.push_back( should_be_relative ? current_addr : this->m_base + current_addr );

				break;
			}
		}
	}

	// if nothing was found, just return the empty vector
	if ( found_addresses.empty() )
		return found_addresses;

	return found_addresses;
}
