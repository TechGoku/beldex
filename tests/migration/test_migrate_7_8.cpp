// Exercises the v7 -> v8 blockchain DB migration (token history table +
// blinded_token_id on output metadata) against a synthetic database.
//
// Builds a v7-format LMDB by hand -- old-width output records, version stamped
// at 7 -- then opens it with BlockchainLMDB, which triggers the migration, and
// checks what actually landed on disk afterwards.
//
// Deliberately self-contained: no daemon, no network, no real chain data. The
// migration only reads m_output_amounts and m_properties, so a handful of
// synthetic outputs is enough to cover every branch it has.
//
// Not wired into CMake -- it links the whole node's static libraries, which is
// awkward to express as a target and pointless to rebuild routinely. Build it
// against an existing build tree with:
//
//   LIBS=$(find build -name '*.a' | tr '\n' ' ')
//   g++ -std=c++17 -O1 -o /tmp/mig_test tests/migration/test_migrate_7_8.cpp \
//     -Isrc -Iexternal -Iexternal/db_drivers/liblmdb -Iexternal/easylogging++ \
//     -Iexternal/fmt/include -Iexternal/oxen-encoding -Iexternal/loki-mq \
//     -Icontrib/epee/include -Ibuild/src -Ibuild \
//     -Ibuild/external/oxen-encoding -Ibuild/external/loki-mq \
//     -Iexternal/nlohmann-json/include -Iexternal/date/include \
//     -Iexternal/ghc-filesystem/include \
//     -Wl,--start-group $LIBS -Wl,--end-group \
//     -lsodium -lboost_system -lboost_filesystem -lboost_thread \
//     -lboost_program_options -lpthread -lssl -lcrypto -lunbound
//   /tmp/mig_test
//
// NOTE when extending this: the "version" property key is stored with its
// trailing NUL (MDB_val_str is strlen+1). Writing it without one makes the DB
// look new, so open() stamps the current version and the migration never runs
// -- which looks exactly like a migration that silently did nothing.

#include <lmdb.h>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
namespace tfs = std::filesystem;

#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "crypto/crypto.h"
#include "ringct/rctOps.h"



static int g_fail = 0;
static void check(bool cond, const std::string& what)
{
  std::cout << (cond ? "  PASS  " : "  FAIL  ") << what << "\n";
  if (!cond) ++g_fail;
}
template <typename A, typename B>
static void check_eq(const A& got, const B& want, const std::string& what)
{
  const bool ok = (got == static_cast<A>(want));
  std::cout << (ok ? "  PASS  " : "  FAIL  ") << what
            << " (got " << got << ", want " << want << ")\n";
  if (!ok) ++g_fail;
}

// ── v7 on-disk layouts, copied from the pre-migration source ────────────────
#pragma pack(push, 1)
struct v7_output_data_t
{
  crypto::public_key pubkey;
  uint64_t unlock_time;
  uint64_t height;
  rct::key commitment;
};
struct v7_outkey
{
  uint64_t amount_index;
  uint64_t output_id;
  v7_output_data_t data;
};
struct pre_rct_output_data_t
{
  crypto::public_key pubkey;
  uint64_t unlock_time;
  uint64_t height;
};
struct pre_rct_outkey
{
  uint64_t amount_index;
  uint64_t output_id;
  pre_rct_output_data_t data;
};
// The layout the migration must produce.
struct v8_output_data_t
{
  crypto::public_key pubkey;
  uint64_t unlock_time;
  uint64_t height;
  rct::key commitment;
  crypto::token_id blinded_token_id;
};
struct v8_outkey
{
  uint64_t amount_index;
  uint64_t output_id;
  v8_output_data_t data;
};
#pragma pack(pop)

static constexpr int N_RCT = 40;   // rct outputs, under amount key 0
static constexpr int N_PRE = 7;    // pre-rct outputs, under a non-zero amount
static constexpr uint64_t PRE_AMOUNT = 1000000000;

struct expected_rct { crypto::public_key pubkey; uint64_t unlock_time, height; rct::key commitment; };
static std::vector<expected_rct> g_expected;

static void lmdb_ck(int rc, const char* what)
{
  if (rc) { std::cerr << what << ": " << mdb_strerror(rc) << "\n"; std::exit(2); }
}

// Build a v7 database: the two tables the migration touches, stamped version 7.
static void build_v7_db(const tfs::path& dir)
{
  MDB_env* env = nullptr;
  lmdb_ck(mdb_env_create(&env), "env_create");
  lmdb_ck(mdb_env_set_maxdbs(env, 40), "set_maxdbs");
  lmdb_ck(mdb_env_set_mapsize(env, size_t(1) << 30), "set_mapsize");
  lmdb_ck(mdb_env_open(env, dir.string().c_str(), 0, 0644), "env_open");

  MDB_txn* txn = nullptr;
  lmdb_ck(mdb_txn_begin(env, nullptr, 0, &txn), "txn_begin");

  MDB_dbi outputs = 0, props = 0;
  lmdb_ck(mdb_dbi_open(txn, "output_amounts",
      MDB_INTEGERKEY | MDB_DUPSORT | MDB_DUPFIXED | MDB_CREATE, &outputs), "open outputs");
  lmdb_ck(mdb_dbi_open(txn, "properties", MDB_CREATE, &props), "open properties");

  // rct outputs live under amount key 0, at the old (narrower) record width.
  uint64_t amount = 0;
  for (int i = 0; i < N_RCT; ++i)
  {
    v7_outkey rec{};
    rec.amount_index = static_cast<uint64_t>(i);
    rec.output_id = 5000 + static_cast<uint64_t>(i);
    crypto::secret_key sk;
    crypto::generate_keys(rec.data.pubkey, sk);
    rec.data.unlock_time = 100 + i;
    rec.data.height = 900000 + i;
    rec.data.commitment = rct::commit(static_cast<uint64_t>(i) * 7 + 1, rct::skGen());
    g_expected.push_back({rec.data.pubkey, rec.data.unlock_time, rec.data.height, rec.data.commitment});

    MDB_val k{sizeof(amount), &amount};
    MDB_val v{sizeof(rec), &rec};
    lmdb_ck(mdb_put(txn, outputs, &k, &v, 0), "put rct output");
  }

  // pre-rct outputs are a different width entirely and must survive untouched.
  uint64_t pre_amount = PRE_AMOUNT;
  for (int i = 0; i < N_PRE; ++i)
  {
    pre_rct_outkey rec{};
    rec.amount_index = static_cast<uint64_t>(i);
    rec.output_id = 9000 + static_cast<uint64_t>(i);
    crypto::secret_key sk;
    crypto::generate_keys(rec.data.pubkey, sk);
    rec.data.unlock_time = 0;
    rec.data.height = 1000 + i;
    MDB_val k{sizeof(pre_amount), &pre_amount};
    MDB_val v{sizeof(rec), &rec};
    lmdb_ck(mdb_put(txn, outputs, &k, &v, 0), "put pre-rct output");
  }

  uint32_t version = 7;
  const char* vkey = "version";
  MDB_val k{strlen(vkey) + 1, const_cast<char*>(vkey)};
  MDB_val v{sizeof(version), &version};
  lmdb_ck(mdb_put(txn, props, &k, &v, 0), "put version");

  lmdb_ck(mdb_txn_commit(txn), "txn_commit");
  mdb_env_close(env);
}

// Read the database back with raw LMDB and verify what the migration produced.
static void verify_v8_db(const tfs::path& dir)
{
  MDB_env* env = nullptr;
  lmdb_ck(mdb_env_create(&env), "env_create");
  lmdb_ck(mdb_env_set_maxdbs(env, 40), "set_maxdbs");
  lmdb_ck(mdb_env_open(env, dir.string().c_str(), MDB_RDONLY, 0644), "env_open ro");

  MDB_txn* txn = nullptr;
  lmdb_ck(mdb_txn_begin(env, nullptr, MDB_RDONLY, &txn), "txn_begin ro");

  MDB_dbi outputs = 0, props = 0, histories = 0;
  lmdb_ck(mdb_dbi_open(txn, "output_amounts", MDB_INTEGERKEY | MDB_DUPSORT | MDB_DUPFIXED, &outputs), "open outputs ro");
  lmdb_ck(mdb_dbi_open(txn, "properties", 0, &props), "open properties ro");

  // The token history table is the other half of this migration.
  const int hist_rc = mdb_dbi_open(txn, "token_histories", 0, &histories);
  check(hist_rc == 0, "token history table was created");

  {
    const char* vkey = "version";
    MDB_val k{strlen(vkey) + 1, const_cast<char*>(vkey)};
    MDB_val v{};
    lmdb_ck(mdb_get(txn, props, &k, &v), "get version");
    uint32_t got = 0;
    memcpy(&got, v.mv_data, sizeof(got));
    check_eq(got, 8u, "db version was stamped to 8");
  }

  // rct records: widened, contents preserved, blinded_token_id null.
  {
    MDB_cursor* cur = nullptr;
    lmdb_ck(mdb_cursor_open(txn, outputs, &cur), "cursor_open");
    uint64_t amount = 0;
    MDB_val k{sizeof(amount), &amount}, v{};
    int rc = mdb_cursor_get(cur, &k, &v, MDB_SET);
    check(rc == 0, "rct amount key still present");

    int seen = 0, wrong_size = 0, mismatched = 0, non_null_tid = 0;
    while (rc == 0)
    {
      if (v.mv_size != sizeof(v8_outkey)) { ++wrong_size; }
      else
      {
        const v8_outkey* rec = static_cast<const v8_outkey*>(v.mv_data);
        const auto idx = rec->amount_index;
        if (idx < g_expected.size())
        {
          const auto& want = g_expected[idx];
          if (memcmp(&rec->data.pubkey, &want.pubkey, sizeof(want.pubkey)) != 0
              || rec->data.unlock_time != want.unlock_time
              || rec->data.height != want.height
              || memcmp(&rec->data.commitment, &want.commitment, sizeof(want.commitment)) != 0
              || rec->output_id != 5000 + idx)
            ++mismatched;
        }
        if (rec->data.blinded_token_id != crypto::null_tid)
          ++non_null_tid;
      }
      ++seen;
      rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT_DUP);
    }
    mdb_cursor_close(cur);

    check_eq(seen, N_RCT, "every rct output survived");
    check_eq(wrong_size, 0, "every rct record is the new width");
    check_eq(mismatched, 0, "every rct record kept its pubkey, times, height and commitment");
    check_eq(non_null_tid, 0, "every migrated output has a null blinded_token_id");
  }

  // pre-rct records must be byte-identical -- the migration copies them as-is.
  {
    MDB_cursor* cur = nullptr;
    lmdb_ck(mdb_cursor_open(txn, outputs, &cur), "cursor_open pre");
    uint64_t amount = PRE_AMOUNT;
    MDB_val k{sizeof(amount), &amount}, v{};
    int rc = mdb_cursor_get(cur, &k, &v, MDB_SET);
    check(rc == 0, "pre-rct amount key still present");
    int seen = 0, wrong_size = 0;
    while (rc == 0)
    {
      if (v.mv_size != sizeof(pre_rct_outkey)) ++wrong_size;
      ++seen;
      rc = mdb_cursor_get(cur, &k, &v, MDB_NEXT_DUP);
    }
    mdb_cursor_close(cur);
    check_eq(seen, N_PRE, "every pre-rct output survived");
    check_eq(wrong_size, 0, "pre-rct records were left at their original width");
  }

  mdb_txn_abort(txn);
  mdb_env_close(env);
}

int main()
{
  const tfs::path dir = tfs::temp_directory_path() / "beldex-migrate-7-8-test";
  tfs::remove_all(dir);
  tfs::create_directories(dir);

  std::cout << "=== building a synthetic v7 database ===\n";
  build_v7_db(dir);
  std::cout << "  " << N_RCT << " rct outputs (" << sizeof(v7_outkey) << " bytes each), "
            << N_PRE << " pre-rct outputs (" << sizeof(pre_rct_outkey) << " bytes each)\n";

  std::cout << "=== opening it with BlockchainLMDB (runs the migration) ===\n";
  try
  {
    cryptonote::BlockchainLMDB db;
    db.open(dir.string(), cryptonote::network_type::FAKECHAIN, 0);
    db.close();
  }
  catch (const std::exception& e)
  {
    std::cerr << "  migration threw: " << e.what() << "\n";
    return 1;
  }

  std::cout << "=== verifying the result ===\n";
  verify_v8_db(dir);

  // Re-opening must be a no-op: the version is already 8.
  std::cout << "=== re-open is idempotent ===\n";
  try
  {
    cryptonote::BlockchainLMDB db;
    db.open(dir.string(), cryptonote::network_type::FAKECHAIN, 0);
    db.close();
    check(true, "second open did not re-run the migration or throw");
  }
  catch (const std::exception& e)
  {
    std::cerr << "  second open threw: " << e.what() << "\n";
    ++g_fail;
  }
  verify_v8_db(dir);

  tfs::remove_all(dir);
  std::cout << "\n" << (g_fail ? "FAILURES: " + std::to_string(g_fail) : "ALL PASSED (failures: 0)") << "\n";
  return g_fail ? 1 : 0;
}
