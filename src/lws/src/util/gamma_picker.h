#include <cstdint>
#include <random>
#include <vector>

namespace lws
{
  //! Select outputs using a gamma distribution with Sarang's output-lineup method
  class gamma_picker
  {
    std::vector<uint64_t> rct_offsets;
    /*! Rank-to-global-index map, empty for the native bucket.

        The distribution for privacy tokens counts ranks within the token
        output set, not global output ids, so a rank picked from it has to be
        translated before it means anything to the daemon. Doing it here keeps
        every caller downstream working in one index space. */
    std::vector<uint64_t> bucket_to_global;
    std::gamma_distribution<double> gamma;
    double outputs_per_second;

    gamma_picker(const gamma_picker&) = default; // force explicit usage of `clone()` to copy.
  public:
    //! \post `!is_valid()` since the chain of offsets is empty.
    gamma_picker()
      : gamma_picker(std::vector<std::uint64_t>{})
    {}

    //! Use default (recommended) gamma parameters with `rct_offsets`.
    explicit gamma_picker(std::vector<std::uint64_t> rct_offsets);
    //! Token bucket: ranks from `rct_offsets` are mapped through `indices`.
    gamma_picker(std::vector<std::uint64_t> rct_offsets, std::vector<std::uint64_t> indices);
    explicit gamma_picker(std::vector<std::uint64_t> rct_offsets, double shape, double scale);

    //! \post Source of move `!is_valid()`.
    gamma_picker(gamma_picker&&) = default;

    //! \post Source of move `!is_valid()`.
    gamma_picker& operator=(gamma_picker&&) = default;

    //! \return A copy of `this`.
    gamma_picker clone() const { return gamma_picker{*this}; }

    //! \return `is_valid()`.
    explicit operator bool() const noexcept { return is_valid(); }

    //! \return True if `operator()()` can pick an output using `offsets()`.
    bool is_valid() const noexcept;

    //! \return An upper-bound on the number of unlocked/spendable outputs based on block age.
    std::uint64_t spendable_upper_bound() const noexcept;

    /*!
      Select a random output index for use in a ring. Outputs in the unspendable
      range (too new) and older than the chain (too old) are filtered out by
      retrying the gamma distribution.

      \throw std::logic_error if `!is_valid()` - considered unrecoverable.
      \throw std::runtiime_error if no output within spendable range was selected
        after 100 attempts.
      \return Selected output using gamma distribution.
    */
    std::uint64_t operator()();

    //! \return Current ringct distribution used for `operator()()` output selection.
    const std::vector<std::uint64_t>& offsets() const noexcept { return rct_offsets; }

    //! \return Ownership of `offsets()` by move. \post `!is_valid()`
    std::vector<std::uint64_t> take_offsets();
  };
} // lws
