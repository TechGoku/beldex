#pragma once

#include <cstdint>
#include <iosfwd>
#include <list>
#include <memory>
#include <utility>
#include <vector>

#include "common/expect.h"
#include "crypto/crypto.h"
#include "fwd.h"
#include "lmdb/transaction.h"
#include "lmdb/key_stream.h"
#include "lmdb/value_stream.h"

#include "db/data.h"
#include "db/account.h"

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace crypto
{
  struct hash;
}

namespace lws
{
namespace db
 {
  namespace cursor
  {
    MONERO_CURSOR(accounts);
    MONERO_CURSOR(outputs);
    MONERO_CURSOR(spends);
    MONERO_CURSOR(images);
    MONERO_CURSOR(requests);

    MONERO_CURSOR(blocks);
    MONERO_CURSOR(accounts_by_address);
    MONERO_CURSOR(accounts_by_height);
  }

  struct storage_internal;

  //! Snapshot of LMDB map/reader utilisation, for monitoring and alerting.
  struct usage_info
  {
    std::uint64_t map_size;    //!< Current memory-map size in bytes.
    std::uint64_t used_bytes;  //!< Bytes of the map actually in use.
    //! High-water mark of reader slots used, not a live count; it never
    //! decreases, including after a stale slot is swept.
    unsigned readers_high_water;
    unsigned max_readers;      //!< Reader slot capacity.

    //! \return Fraction of the map in use, in the range [0, 1].
    double used_fraction() const noexcept
    {
      return map_size ? double(used_bytes) / double(map_size) : 0.0;
    }
  };
  
  struct reader_internal
  {
    cursor::blocks blocks_cur;
    cursor::accounts_by_address accounts_ba_cur;
    cursor::accounts_by_height accounts_bh_cur;
  };

  //! Wrapper for LMDB read access to on-disk storage of light-weight server data.
  class storage_reader
  {
    std::shared_ptr<storage_internal> db;
    lmdb::read_txn txn;
    reader_internal curs;

  public:
    storage_reader(std::shared_ptr<storage_internal> db, lmdb::read_txn txn) noexcept
      : db(std::move(db)), txn(std::move(txn)), curs{}
    {}

    storage_reader(storage_reader&&) = default;
    storage_reader(storage_reader const&) = delete;

    ~storage_reader() noexcept;

    storage_reader& operator=(storage_reader&&) = default;
    storage_reader& operator=(storage_reader const&) = delete;

    //! \return Last known block.
    expect<block_info> get_last_block() noexcept;

    //! \return "Our" block hash at `height`.
    expect<crypto::hash> get_block_hash(const block_id height) noexcept;

    //! \return List for `GetHashesFast` to sync blockchain with daemon.
    // expect<std::list<crypto::hash>> get_chain_sync();
    expect<int> get_chain_sync();

    //! \return All registered `account`s.
    expect<lmdb::key_stream<account_status, account, cursor::close_accounts>>
      get_accounts(cursor::accounts cur = nullptr) noexcept;

    //! \return All `account`s currently in `status` or `lmdb::error(MDB_NOT_FOUND)`.
    expect<lmdb::value_stream<account, cursor::close_accounts>>
      get_accounts(account_status status, cursor::accounts cur = nullptr) noexcept;

    //! \return Info for account `id` iff it has `status`.
    expect<account> get_account(const account_status status, const account_id id) noexcept;

    //! \return Info related to `address`.
    expect<std::pair<account_status, account>>
      get_account(account_address const& address) noexcept;

    //! \return All outputs received by `id`.
    expect<lmdb::value_stream<output, cursor::close_outputs>>
      get_outputs(account_id id, cursor::outputs cur = nullptr) noexcept;

    /*! Outputs are stored sorted by `link.height`, so the tail of a large
        account's history can be reached with a seek rather than a scan. Use this
        instead of walking `get_outputs(id)` and discarding the early records:
        the skipped records are never read from disk.

        \note The returned stream is not positioned at the start of the account's
            outputs, so its `count()` (every output, not the remaining ones) must
            not be used to size a container, and `reset()` must not be called.

        \return Outputs received by `id` in a block at or after `min_height`.
    */
    expect<lmdb::value_stream<output, cursor::close_outputs>>
      get_outputs(account_id id, block_id min_height, cursor::outputs cur = nullptr) noexcept;

    //! \return All potential spends by `id`.
    expect<lmdb::value_stream<spend, cursor::close_spends>>
      get_spends(account_id id, cursor::spends cur = nullptr) noexcept;

    /*! The `get_outputs(id, min_height)` treatment for spends; see there for the
        `count()` / `reset()` caveats.

        \return Potential spends by `id` in a block at or after `min_height`.
    */
    expect<lmdb::value_stream<spend, cursor::close_spends>>
      get_spends(account_id id, block_id min_height, cursor::spends cur = nullptr) noexcept;

    //! \return All key images associated with `id`.
    expect<lmdb::value_stream<db::key_image, cursor::close_images>>
      get_images(output_id id, cursor::images cur = nullptr) noexcept;

    //! \return All `request_info`s.
    expect<lmdb::key_stream<request, request_info, cursor::close_requests>>
      get_requests(cursor::requests cur = nullptr) noexcept;

    //! \return A specific request from `address` of `type`.
    expect<request_info>
      get_request(request type, account_address const& address, cursor::requests cur = nullptr) noexcept;

    //! Dump the contents of the database in JSON format to `out`.
    expect<void> json_debug(std::ostream& out, bool show_keys);

    //! \return Read txn that can be re-used via `storage::start_read`.
    lmdb::suspended_txn finish_read() noexcept;
  };

  //! Wrapper for LMDB on-disk storage of light-weight server data.
  class storage
  {
    std::shared_ptr<storage_internal> db;

    storage(std::shared_ptr<storage_internal> db) noexcept
      : db(std::move(db))
    {}

  public:
    /*!
      Open a light_wallet_server LDMB database.

      \param path Directory for LMDB storage
      \param create_queue_max Maximum number of create account requests allowed.
      \param map_size Initial LMDB memory-map size in bytes; `0` keeps the
        built-in default sizing (see `storage.cpp`).
      \param max_readers Maximum concurrent LMDB reader slots.

      \throw std::system_error on any LMDB error (all treated as fatal).
      \throw std::bad_alloc If `std::shared_ptr` fails to allocate.

      \return A ready light-wallet server database.
    */
    static storage open(const char* path, unsigned create_queue_max, std::size_t map_size = 0, unsigned max_readers = 0);

    /*!
      Open a database for reading only, without modifying it in any way.

      `open` above takes a write transaction and may run the schema migration,
      so it contends for the single LMDB writer lock and can rewrite rows in a
      database a running daemon owns. This overload opens the environment
      `MDB_RDONLY`: it never takes the writer lock, never migrates, and cannot
      alter a single byte, which is what makes it safe to point at the live
      server's database while it is running.

      Every write method still exists on the returned handle but will fail -
      LMDB refuses a write transaction on a read-only environment - so a
      mistake surfaces as an error rather than as corruption.

      \param path Directory for LMDB storage; must already exist.
      \param max_readers Maximum concurrent LMDB reader slots; `0` uses the
        default. Note that LMDB keeps the value the environment was first
        created with while other processes have it open.

      \throw std::system_error on any LMDB error, including a missing table.

      \return A read-only light-wallet server database.
    */
    static storage open_readonly(const char* path, unsigned max_readers = 0);

    //! \return True if this handle was opened by `open_readonly`.
    bool is_read_only() const noexcept;

    storage(storage&&) = default;
    storage(storage const&) = delete;

    ~storage() noexcept;

    storage& operator=(storage&&) = default;
    storage& operator=(storage const&) = delete;

    //! \return A copy of the LMDB environment, but not reusable txn/cursors.
    storage clone() const noexcept;

    /*!
      Copy this database, compacting free space out, to `dest_path`. Safe to
      run against a live, running server - does not block or otherwise
      affect it. Produces a separate, equivalent DB for the operator to swap
      in during a maintenance window.
    */
    expect<void> compact(const char* dest_path) const;

    /*!
      Clear LMDB reader slots left behind by processes that are no longer
      running. A slot orphaned by a killed process pins an old snapshot and
      stops LMDB reclaiming every page freed since - the map then grows without
      bound until MDB_MAP_FULL, even though most of it is reclaimable. Call at
      startup (to clear slots from a previous unclean shutdown) and
      periodically thereafter.

      Safe against a live database; slots owned by running processes are never
      touched.

      \return Number of stale reader slots cleared.
    */
    expect<int> check_readers() noexcept;

    //! \return Current LMDB map and reader-table utilisation.
    expect<usage_info> get_usage() const noexcept;

    // ! Rollback chain and accounts to `height`.
   expect<void> rollback(block_id height);

    /*!
      Sync the local blockchain with a remote version. Pops user txes if reorg
      detected.

      \param height The height of the element in `hashes`
      \param hashes List of blockchain hashes starting at `height`.

      \return True if the local blockchain is correctly synced.
    */
    expect<void> sync_chain(block_id height, epee::span<const crypto::hash> hashes);

    //! Bump the last access time of `address` to the current time.
  //  expect<void> update_access_time(account_address const& address) noexcept;

    //! Change state of `address` to `status`. \return Updated `addresses`.
    expect<std::vector<account_address>>
      change_status(account_status status, epee::span<const account_address> addresses);


    //! Add an account, for immediate inclusion in the active list.
    expect<void> add_account(account_address const& address, crypto::secret_key const& key, account_flags flags =  static_cast<account_flags>(0)) noexcept;

    //! Reset `addresses` to `height` for scanning.
    expect<std::vector<account_address>>
      rescan(block_id height, epee::span<const account_address> addresses);

    //! Add an account for later approval. For use with the login endpoint.
    expect<void> creation_request(account_address const& address, crypto::secret_key const& key, account_flags flags) noexcept;

    /*!
      Request lock height of an existing account. No effect if the `start_height`
      is already older.
    */
    expect<void> import_request(account_address const& address, block_id height) noexcept;

    //! Accept requests by `addresses` of type `req`. \return Accepted addresses.
    expect<std::vector<account_address>>
      accept_requests(request req, epee::span<const account_address> addresses);

    //! Reject requests by `addresses` of type `req`. \return Rejected addresses.
    expect<std::vector<account_address>>
      reject_requests(request req, epee::span<const account_address> addresses);

    /*!
      Updates the status of user accounts, even if inactive or hidden. Duplicate
      receives or spends provided in `accts` are silently ignored. If a gap in
      `height` vs the stored account record is detected, the entire update will
      fail.

      \param height The first hash in `chain` is at this height.
      \param chain List of block hashes that `accts` were scanned against.
      \param accts Updated to `height + chain.size()` scan height.

      \return True iff LMDB successfully committed the update.
    */
    expect<std::size_t> update(block_id height, epee::span<const crypto::hash> chain, epee::span<const lws::account> accts);

    //! `txn` must have come from a previous call on the same thread.
    expect<storage_reader> start_read(lmdb::suspended_txn txn = nullptr) const;
  };

  /*!
    Periodic LMDB housekeeping: clear reader slots orphaned by dead processes
    and log map utilisation, warning as it approaches the map size.

    This is the guard against the recurring MDB_MAP_FULL. An orphaned reader
    slot blocks reclamation of every page freed since its snapshot, so the map
    grows without bound; clearing it restores normal page reuse. Call at
    startup - to sweep slots left by a previous unclean shutdown - and on a
    timer while running.

    Never throws and never fails the caller: any error is logged and swallowed,
    since housekeeping must not take down the scanner or the server.

    \param context Short label identifying the call site, used in log lines.
  */
  void run_maintenance(storage& disk, const char* context) noexcept;
} // db
} // lws
