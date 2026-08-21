#pragma once

#include <string>
#include <string_view>

#include "common/fs.h"
#include "tx_extra.h"

namespace cryptonote
{
  enum class token_descriptor_json_mode
  {
    registration,
    update,
  };

  bool validate_token_descriptor_for_registration(const token_descriptor_base& descriptor, std::string& error);
  bool load_token_descriptor_from_json(std::string_view data, token_descriptor_base& descriptor, std::string& error, token_descriptor_json_mode mode = token_descriptor_json_mode::registration);
  bool load_token_descriptor_from_json_file(const fs::path& filename, token_descriptor_base& descriptor, std::string& error, token_descriptor_json_mode mode = token_descriptor_json_mode::registration);
}
