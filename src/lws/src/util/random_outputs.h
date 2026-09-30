#pragma once

#include <cstdint>
#include <functional>
#include <vector>

#include "common/expect.h"            // monero/src
#include "rpc/message_data_structs.h" // monero/src
#include "span.h"                     // monero/src
#include "util/fwd.h"

namespace lws
{
    using histogram = cryptonote::rpc::output_amount_count;
    using output_ref = cryptonote::rpc::output_amount_and_index;
    using output_keys = cryptonote::rpc::output_key_mask_unlocked;

    struct random_output
    {
        output_keys keys;
        std::uint64_t index;
    };

    struct random_ring
    {
        std::vector<random_output> ring;
        std::uint64_t amount;
        /*! Which distribution this ring is drawn from.

            A transaction can spend both kinds at once - a privacy-token
            transfer takes token outputs for the amount and native outputs for
            the fee, which is always BDX - so the choice is per ring, not per
            request. Carried on the ring itself because rings are erased from
            the working list as they are satisfied, which would desynchronise
            any parallel array. */
        bool is_token = false;
    };

    using key_fetcher = expect<std::vector<output_keys>>(std::vector<output_ref>);

    /*!
        Selects random outputs for use in a ring signature. `amounts` of `0`
        use a gamma distribution algorithm and all other amounts use a
        triangular distribution.

        \param mixin The number of dummy outputs per ring.
        \param amounts The amounts that need dummy outputs to be selected.
        \param pick_rct Ring-ct distribution from the daemon
        \param histograms A histogram from the daemon foreach non-zero value
            in `amounts`.
        \param fetch A function that can retrieve the keys for the randomly
            selected outputs.

        \note `histograms` is modified - the list is sorted by amount.

        \note This currenty leaks the real outputs to `fetch`, because the
            real output is not provided alongside the dummy outputs. This is a
            limitation of the current openmonero/mymonero API. When this is
            resolved, this function can possibly be moved outside of the `lws`
            namespace for use by simple wallet.

        \return Randomly selected outputs in rings of size `mixin`, one for
            each element in `amounts`. Amounts with less than `mixin` available
            are not returned. All outputs are unlocked.
    */
    expect<std::vector<random_ring>> pick_random_outputs(
        std::uint32_t mixin,
        epee::span<const std::uint64_t> amounts,
        gamma_picker& pick_rct,
        epee::span<histogram> histograms,
        std::function<key_fetcher> fetch,
        //! Parallel to `amounts`; true draws that ring from `pick_token`.
        epee::span<const bool> is_token = {},
        //! Token-bucket picker. Required if any `is_token` entry is true.
        gamma_picker* pick_token = nullptr
    );
}
