// Checks that an output whose one-time public key was already received is not
// credited a second time.
//
// A sender who reuses a transaction key and output index produces a second
// output with the same one-time key. It has its own global id, so the
// scanner's id check let it through, and both were stored and summed into the
// balance although only one can ever be spent: they share a key image.
//
// Built as `lws-duplicate-key-test` when BUILD_TESTS=ON. Takes no arguments;
// prints one line per case and exits non-zero on any failure.

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "crypto/crypto.h"
#include "db/account.h"
#include "db/data.h"

namespace
{
  unsigned failures = 0;

  void check(bool ok, const std::string& what)
  {
    std::cout << (ok ? "  ok   " : "  FAIL ") << what << '\n';
    if (!ok)
      ++failures;
  }

  lws::db::output make_output(std::uint64_t global, const crypto::public_key& key, std::uint64_t amount)
  {
    lws::db::output out{};
    out.spend_meta.id = lws::db::output_id{0, global};
    out.spend_meta.amount = amount;
    out.pub = key;
    return out;
  }

  lws::db::account make_db_account()
  {
    lws::db::account source{};
    source.id = lws::db::account_id(1);
    source.scan_height = lws::db::block_id(100);
    return source;
  }
}

int main()
{
  const crypto::public_key first_key = crypto::rand<crypto::public_key>();
  const crypto::public_key other_key = crypto::rand<crypto::public_key>();

  {
    lws::account user{make_db_account(), {}};
    check(user.add_out(make_output(10, first_key, 1000)), "a new output is credited");
    check(!user.add_out(make_output(10, first_key, 1000)), "the same output seen again is not");
    check(!user.add_out(make_output(11, first_key, 999999999)),
          "a second output with the same one-time key is not credited, even if larger");
    check(user.add_out(make_output(12, other_key, 5)), "an output with a different key is credited");
    check(user.outputs().size() == 2, "two outputs recorded in total");
    check(user.has_spendable(lws::db::output_id{0, 10}) && !user.has_spendable(lws::db::output_id{0, 11}),
          "only the first output with the repeated key counts as ours");

    const lws::account copy = user.clone();
    lws::account again = copy.clone();
    check(!again.add_out(make_output(13, first_key, 1)), "a clone keeps the known keys");
  }

  {
    // A later scan pass: the account is reloaded from the database with the
    // ids and fingerprints of everything it has already received.
    lws::account user{
      make_db_account(),
      {lws::db::output_id{0, 10}},
      {lws::account::key_fingerprint(first_key)}
    };
    check(!user.add_out(make_output(500, first_key, 77)),
          "a repeated key is caught across scan passes, not just within one");
    check(user.add_out(make_output(501, other_key, 77)), "a new key after reload is credited");
  }

  std::cout << (failures ? "FAILED" : "PASSED") << " (" << failures << " failure(s))\n";
  return failures ? 1 : 0;
}
