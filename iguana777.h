/******************************************************************************
 * Copyright © 2014-2015 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#ifndef iguana777_net_h
#define iguana777_net_h

//#define IGUANA_DISABLEPEERS
#ifdef __linux__
#define IGUANA_MAXPEERS 128
#define IGUANA_MAPHASHTABLES 1
#define IGUANA_MAXMEMALLOCATED (1024L * 1024 * 1024L * 32)
#else
#define IGUANA_MAXPEERS 32
#define IGUANA_MAPHASHTABLES 1
#define IGUANA_MAXMEMALLOCATED (1024L * 1024 * 1024L * 1)
#endif

#ifdef __APPLE__
//#define IGUANA_VERIFYFLAG
#endif

#define IGUANA_RECENTPEER (3600 * 24 * 7)
#define IGUANA_MAXPENDING 1 //((512 / IGUANA_MAXPEERS) + 1)

#define IGUANA_MAXPACKETSIZE (2 * 1024 * 1024)
#define IGUANA_RSPACE_SIZE (IGUANA_MAXPACKETSIZE * 128)

#define IGUANA_PERMTHREAD 0
#define IGUANA_CONNTHREAD 1
#define IGUANA_SENDTHREAD 2
#define IGUANA_RECVTHREAD 3

#define IGUANA_DEDICATED_THREADS
#ifdef IGUANA_DEDICATED_THREADS
#define IGUANA_MAXCONNTHREADS IGUANA_MAXPEERS
#define IGUANA_MAXSENDTHREADS IGUANA_MAXPEERS
#define IGUANA_MAXRECVTHREADS IGUANA_MAXPEERS
#else
#define IGUANA_MAXCONNTHREADS 8
#define IGUANA_MAXSENDTHREADS 32
#define IGUANA_MAXRECVTHREADS 32
#endif

#define IGUANA_LHASH_TXIDS 0 //
#define IGUANA_LHASH_UNSPENTS 1 //
#define IGUANA_LHASH_UPREV 2
#define IGUANA_LHASH_USPEND 3 //
#define IGUANA_LHASH_SPENDS 4 //
#define IGUANA_LHASH_SPREV 5 //
#define IGUANA_LHASH_PKHASHES 6 //
#define IGUANA_LHASH_PKFIRSTSPEND 7 //
#define IGUANA_NUMAPPENDS (IGUANA_LHASH_PKFIRSTSPEND + 1)

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <poll.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/mman.h>
#include "includes/utlist.h"
#include "includes/uthash.h"
#include "includes/curve25519.h"
void PostMessage(const char* format, ...);

#ifdef __PNACL
#define printf PostMessage
#define MS_ASYNC	1		/* Sync memory asynchronously.  */
#define MS_SYNC		4		/* Synchronous memory sync.  */
#else
#define PostMessage printf
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0x4000	// Do not generate SIGPIPE
#endif
int32_t msync(void *addr,size_t len,int32_t flags);

#define BIP0031_VERSION	 60000
#define CADDR_TIME_VERSION 31402
#define MIN_PROTO_VERSION 209
#define MAX_BLOCK_SIZE 1000000
#define COINBASE_MATURITY 100
#define IGUANA_HDRSCOUNT 2000

#define NODE_NETWORK (1 << 0)
#define NODE_GETUTXO (1 << 1)
#define NODE_BLOOM (1 << 2)

#define PROTOCOL_VERSION 70011
#define INIT_PROTO_VERSION 209 // initial proto version, to be increased after version/verack negotiation
#define GETHEADERS_VERSION 31800 // In this version, 'getheaders' was introduced.
#define MIN_PEER_PROTO_VERSION GETHEADERS_VERSION // disconnect from peers older than this proto version
// nTime field added to CAddress, starting with this version, if possible, avoid requesting addresses nodes older than this
#define CADDR_TIME_VERSION 31402
// only request blocks from nodes outside this range of versions
#define NOBLKS_VERSION_START 32000
#define NOBLKS_VERSION_END 32400

#define BIP0031_VERSION 60000 // BIP 0031, pong message, is enabled for all versions AFTER this one
#define MEMPOOL_GD_VERSION 60002 // "mempool" command, enhanced "getdata" behavior starts with this version
#define NO_BLOOM_VERSION 70011 // "filter*" disabled without NODE_BLOOM after and including this version

#define MSG_TX 1
#define MSG_BLOCK 2
#define MSG_FILTERED_BLOCK 3

#define IGUANA_MAXLOCATORS 64
#define IGUANA_MAXINV 50000

#define IGUANA_VOLATILE 1
#define IGUANA_ITEMIND_DATA 2
#define IGUANA_MAPPED_ITEM 4
#define IGUANA_SHA256 0x80
#define IGUANA_ALLOC_MULT 1.1
#define IGUANA_ALLOC_INCR 1000
#define portable_mutex_t pthread_mutex_t
#define portable_mutex_init(ptr) pthread_mutex_init(ptr,NULL)
#define portable_mutex_lock pthread_mutex_lock
#define portable_mutex_unlock pthread_mutex_unlock

#define SATOSHIDEN ((uint64_t)100000000L)
#define dstr(x) ((double)(x) / SATOSHIDEN)

#define SMALLVAL 0.000000000000001

#define SETBIT(bits,bitoffset) (((uint8_t *)bits)[(bitoffset) >> 3] |= (1 << ((bitoffset) & 7)))
#define GETBIT(bits,bitoffset) (((uint8_t *)bits)[(bitoffset) >> 3] & (1 << ((bitoffset) & 7)))
#define CLEARBIT(bits,bitoffset) (((uint8_t *)bits)[(bitoffset) >> 3] &= ~(1 << ((bitoffset) & 7)))
extern const bits256 bits256_zero;

#define IGUANA_MAPRECVDATA 1
#define IGUANA_MAPTXIDITEMS 2
#define IGUANA_MAPPKITEMS 4
#define IGUANA_MAPBLOCKITEMS 8
#define IGUANA_MAPPEERITEMS 16

#define IGUANA_PEER_ELIGIBLE 1
#define IGUANA_PEER_CONNECTING 2
#define IGUANA_PEER_READY 3
#define IGUANA_PEER_KILLED 4

#define CHAIN_BTCD 0
#define CHAIN_TESTNET3 1
#define CHAIN_BITCOIN 2

struct allocitem { uint32_t allocsize,type; } __attribute__((packed));
struct queueitem { struct queueitem *next,*prev; uint32_t allocsize,type;  } __attribute__((packed));
typedef struct queue
{
	struct queueitem *list;
	portable_mutex_t mutex;
    char name[31],initflag;
} queue_t;

typedef void (*iguana_func)(void *);
struct iguana_thread
{
    struct queueitem DL;
    pthread_t handle;
    char name[16];
    uint8_t type;
    iguana_func funcp;
    void *arg;
};

struct iguana_chain
{
	const int32_t chain_id;
	const char name[16];
	const uint8_t addr_pubkey,addr_script,wipval,netmagic[4];
	const char *genesis_hash,*genesis_hex; // hex string
    uint16_t default_port,hastimestamp;
    char *ramcoder_seed;
    uint64_t rewards[512][2];
    uint8_t genesis_hashdata[32]; bits256 rseed;
};

struct iguana_msghdr { uint8_t netmagic[4]; char command[12]; uint8_t serdatalen[4],hash[4]; } __attribute__((packed));

struct iguana_msgaddress {	uint32_t nTime; uint64_t nServices; uint8_t ip[16]; uint16_t port; } __attribute__((packed));

struct iguana_msgversion
{
	uint32_t nVersion;
	uint64_t nServices;
	int64_t nTime;
	struct iguana_msgaddress addrTo,addrFrom;
	uint64_t nonce;
	char strSubVer[80];
	uint32_t nStartingHeight;
    uint8_t relayflag;
};

struct iguana_msgblockhdr
{
    uint32_t version;
    bits256 prev_block,merkle_root;
    uint32_t timestamp,bits,nonce;
} __attribute__((packed));

struct iguana_msgblock
{
    struct iguana_msgblockhdr H; // double hashed for blockhash
    uint32_t txn_count;
    //double PoW; // yes I know this is not consensus safe, it is used only for approximations locally
} __attribute__((packed));

struct iguana_msgvin { bits256 prev_hash; uint8_t *script; uint32_t prev_vout,scriptlen,sequence; } __attribute__((packed));

struct iguana_msgvout { uint64_t value; uint32_t pk_scriptlen; uint8_t *pk_script; } __attribute__((packed));

struct iguana_msgtx
{
    uint32_t version,tx_in,tx_out,lock_time;
    struct iguana_msgvin *vins;
    struct iguana_msgvout *vouts;
    bits256 txid;
    int32_t allocsize;
} __attribute__((packed));

struct iguana_packet { struct queueitem DL; struct iguana_peer *addr; int32_t datalen,getdatablock; uint8_t serialized[]; };

struct msgcounts { uint32_t version,verack,getaddr,addr,inv,getdata,notfound,getblocks,getheaders,headers,tx,block,mempool,ping,pong,reject,filterload,filteradd,filterclear,merkleblock,alert; };

struct iguana_peer
{
    struct queueitem DL;
    queue_t sendQ;
    struct iguana_msgaddress A;
    char ipaddr[64],lastcommand[16],coinstr[16],symbol[16];
    uint64_t pingnonce,totalsent,totalrecv; double pingtime,sendmillis,pingsum,getdatamillis;
    uint32_t lastcontact,sendtime,ready,startsend,startrecv,pending,ipbits,lastgotaddr,lastblockrecv;
    int32_t dead,usock,sleeptime,protover,relayflag,numpackets,numpings,ipv6,height,rank,pendhdrs,pendblocks,recvhdrs;
    bits256 lastrequest,backstop;
    double recvblocks,recvtotal,hdrmillis;
    struct msgcounts msgcounts;
};

struct iguana_peers
{
    bits256 lastrequest;//,waitinghash[IGUANA_BUNDLESIZE]; float waiting[IGUANA_BUNDLESIZE];
    struct iguana_peer active[IGUANA_MAXPEERS],*ranked[IGUANA_MAXPEERS],*localaddr;
    struct iguana_thread *peersloop;
    portable_mutex_t rankedmutex;
    double topmetrics[IGUANA_MAXPEERS],avemetric;
    uint32_t numranked,mostreceived,shuttingdown,lastpeer,lastmetrics;
};

struct iguana_mappedptr
{
	char fname[512];
	void *fileptr,*pending;
	uint64_t allocsize,changedsize;
	int32_t rwflag,dirty,actually_allocated;
};

struct iguana_memspace
{
    portable_mutex_t mutex; void *ptr; long used,size;
    struct iguana_mappedptr M;
    int32_t alignflag,counter,maxheight,openfiles; uint8_t space[4];
};

struct iguana_prevdep { double PoW; uint64_t supply; uint32_t numtxids,numunspents,numspends,numpkinds; } __attribute__((packed));

struct iguana_counts
{
    bits256 lhashes[IGUANA_NUMAPPENDS],ledgerhash; struct sha256_vstate states[IGUANA_NUMAPPENDS];
    bits256 blockhash,merkle_root;
    uint64_t credits,debits;
    uint32_t timestamp,height;
    struct iguana_prevdep dep;
} __attribute__((packed));

struct iguana_checkpoint
{
    struct iguana_mappedptr M;
    bits256 hash2; int32_t height;
    struct iguana_counts snapshot;
};

struct iguana_recv
{
    uint8_t compressed[IGUANA_MAXPACKETSIZE],decompressed[IGUANA_MAXPACKETSIZE],checkbuf[IGUANA_MAXPACKETSIZE];
    long srcdatalen,compressedtotal; uint64_t histo[0x100];
    struct iguana_memspace RSPACE,*oldRSPACE; int32_t numold;
    int64_t packetsallocated,packetsfreed; int32_t numwaiting,maprecvdata;
    uint8_t *waitingbits; struct iguana_pending **recvblocks; uint32_t numwaitingbits,*waitstart;
    queue_t hdrsQ;
    uint32_t pendingtopstart,topheight,pendingtopheight,numcheckpoints,lasthdrtime; bits256 tophash2;
    struct iguana_checkpoint *checkpoints;
    //bits256 *checkpoints; int32_t *checkheights;
};

struct iguana_kvitem { UT_hash_handle hh; uint8_t keyvalue[]; } __attribute__((packed));

struct iguanakv
{
    char name[63],fname[512],threadsafe; FILE *fp;
    portable_mutex_t KVmutex,MMlock,MMmutex;
    //uint8_t sha256[256 >> 3]; struct sha256_vstate state;
    void *HDDitems,*HDDitems2,*HDDitems3,**HDDitemsp,**HDDitems2p,**HDDitems3p; // linear array of HDDitems;
    struct iguana_kvitem *hashtable; // of HDDitems
    struct iguana_mappedptr M,M2,M3;
    struct iguana_memspace HASHPTRS;//,MEM;
    double mult;
    uint64_t updated;
    int32_t keysize,keyoffset,RAMvaluesize,HDDvaluesize,valuesize2,valuesize3;
    int32_t numkeys,dispflag,flags,incr,numitems,numvalid,maxitemind;
    uint32_t iteruarg; int32_t iterarg;
    uint8_t *space;
};

struct iguana_iAddr { uint32_t ipbits,ind,lastkilled,numkilled,lastconnect,numconnects; int32_t status,height; };

// ramchain append only structs -> canonical 32bit inds and ledgerhashes
struct iguana_txid { bits256 txid; uint32_t firstvout,firstvin; } __attribute__((packed));
struct iguana_unspent { uint64_t value; uint32_t pkind,txidind; } __attribute__((packed));
struct iguana_spend { uint32_t unspentind; } __attribute__((packed)); // dont need nextspend
struct iguana_pkhash { uint8_t rmd160[20]; uint32_t firstunspentind; } __attribute__((packed));

// one zero to non-zero write (unless reorg)
struct iguana_pkextra { uint32_t firstspendind; } __attribute__((packed)); // pkind
struct iguana_Uextra { uint32_t spendind,prevunspentind; } __attribute__((packed)); // unspentind
struct iguana_Sextra { uint32_t prevspendind; } __attribute__((packed)); // spendind

// dynamic
struct iguana_account { uint64_t balance; uint32_t lastunspentind,lastspendind; } __attribute__((packed)); // pkind

// iguana blocks
struct iguana_block
{
    bits256 prev_block,merkle_root; // prev_block MUST be first
    struct iguana_prevdep L;
    int32_t height; uint32_t timestamp,nonce,bits;
    uint16_t txn_count,numvouts,numvins; uint8_t version,tbd;
    bits256 hash2;                  // hash2 MUST be last, it is the prev_block for next item
} __attribute__((packed));

struct iguana_pending
{
    int32_t next,numtx,datalen,origdatalen; struct iguana_block block; uint32_t allocsize,ipbits; uint8_t data[];
};

struct iguana_blocks
{
    char coin[8];
	bits256 hwmchain;
	struct iguanakv *db;
    int32_t hwmheight,maxblocks,rawblocks,initblocks,parsedblocks;
    portable_mutex_t mutex;
    double hwmPoW;
};

struct iguana_ledger
{
    struct iguana_counts snapshot;
    //struct iguana_account accounts[];
} __attribute__((packed));

struct iguana_info
{
    char name[64],symbol[8];
    uint64_t instance_nonce,myservices,totalsize,totalrecv,totalpackets,sleeptime;
    int64_t mining,totalfees,TMPallocated;
    int32_t width,widthready;
    uint32_t longestchain,starttime,coinmask,lastsync,parsetime,numiAddrs,newhdrs,lastwaiting,firstblock;
    struct iguana_chain *chain;
    struct iguanakv *iAddrs,*txids,*spends,*unspents,*pkhashes;
    struct iguana_txid *T;
    struct iguana_unspent *U; struct iguana_Uextra *Uextras;
    struct iguana_spend *S; struct iguana_Sextra *Sextras;
    struct iguana_pkhash *P; struct iguana_account *accounts; struct iguana_pkextra *pkextras;
    struct iguana_counts latest;
    struct iguana_blocks blocks;
    struct iguana_peers peers;
    struct iguana_recv R;
    queue_t blocksQ,priorityQ,possibleQ; double parsemillis;
    struct iguana_ledger LEDGER,loadedLEDGER;
};

// peers
int32_t iguana_verifypeer(struct iguana_info *coin,void *key,void *value,int32_t itemind,int32_t itemsize);
int32_t iguana_peermetrics(struct iguana_info *coin);
void iguana_peersloop(void *arg);
int32_t iguana_queue_send(struct iguana_info *coin,struct iguana_peer *addr,uint8_t *serialized,char *cmd,int32_t len,int32_t getdatablock,int32_t forceflag);
uint32_t iguana_ipbits2ind(struct iguana_info *coin,struct iguana_iAddr *iA,uint32_t ipbits,int32_t createflag);
uint32_t iguana_rwiAddrind(struct iguana_info *coin,int32_t rwflag,struct iguana_iAddr *iA,uint32_t ind);
uint32_t iguana_rwipbits_status(struct iguana_info *coin,int32_t rwflag,uint32_t ipbits,int32_t *statusp);
void iguana_connections(void *arg);
int32_t iguana_possible_peer(struct iguana_info *coin,char *ipaddr);
int32_t iguana_set_iAddrheight(struct iguana_info *coin,uint32_t ipbits,int32_t height);
struct iguana_peer *iguana_choosepeer(struct iguana_info *coin);
void iguana_initpeer(struct iguana_info *coin,struct iguana_peer *addr,uint32_t ipbits);
void iguana_startconnection(void *arg);
void iguana_shutdownpeers(struct iguana_info *coin,int32_t forceflag);

// serdes
int32_t iguana_rwnum(int32_t rwflag,uint8_t *serialized,int32_t len,void *endianedp);
int32_t iguana_rwvarint32(int32_t rwflag,uint8_t *serialized,uint32_t *int32p);
int32_t iguana_rwbignum(int32_t rwflag,uint8_t *serialized,int32_t len,uint8_t *endianedp);
int32_t iguana_rwblock(int32_t rwflag,bits256 *hash2p,uint8_t *serialized,struct iguana_msgblock *msg);
int32_t iguana_serialize_block(bits256 *hash2p,uint8_t serialized[sizeof(struct iguana_msgblock)],struct iguana_block *block);
void iguana_convblock(struct iguana_block *dest,struct iguana_msgblock *msg,bits256 hash2,int32_t height,uint32_t firsttxidind,uint32_t firstvout,uint32_t firstvin,double PoW);
void iguana_freetx(struct iguana_msgtx *tx,int32_t n);
int64_t iguana_MEMallocated(struct iguana_info *coin);
int32_t iguana_parser(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msghdr *H,uint8_t *data,int32_t datalen);

// send message
int32_t iguana_validatehdr(struct iguana_info *coin,struct iguana_msghdr *H);
int32_t iguana_sethdr(struct iguana_msghdr *H,const uint8_t netmagic[4],char *command,uint8_t *data,int32_t datalen);
int32_t iguana_request_data(struct iguana_info *coin,struct iguana_peer *addr,bits256 *hashes,int32_t n,uint32_t type,int32_t forceflag);
int32_t iguana_send_version(struct iguana_info *coin,struct iguana_peer *addr,uint64_t myservices);
int32_t iguana_send_hashes(struct iguana_info *coin,char *command,struct iguana_peer *addr,bits256 stophash,bits256 *hashes,int32_t n);
struct iguana_msgtx *iguana_gentxarray(struct iguana_info *coin,int32_t *lenp,struct iguana_block *block,uint8_t *data,int32_t datalen);
int32_t iguana_gethdrs(struct iguana_info *coin,uint8_t *serialized,char *cmd,char *hashstr);
int32_t iguana_getdata(struct iguana_info *coin,uint8_t *serialized,int32_t type,char *hashstr);

// DB
void iguana_closemap(struct iguana_mappedptr *M);
int32_t iguana_syncmap(struct iguana_mappedptr *mp,uint64_t len);
void *iguana_kvwrite(struct iguana_info *coin,struct iguanakv *kv,void *key,void *value,uint32_t *itemindp);
void *iguana_kvread(struct iguana_info *coin,struct iguanakv *kv,void *key,void *space,uint32_t *itemindp);
void *iguana_kviterate(struct iguana_info *coin,struct iguanakv *kv,uint64_t args,void *(*iterator)(struct iguana_info *coin,struct iguanakv *kv,struct iguana_kvitem *item,uint64_t args,void *key,void *value,int32_t valuesize));
void iguana_kvfree(struct iguana_info *coin,struct iguanakv *kv);
struct iguana_info *iguana_coin(const char *name);
void *iguana_kvensure(struct iguana_info *coin,struct iguanakv *kv,uint32_t ind);
//struct iguanakv *iguana_stateinit(struct iguana_info *coin,int32_t flags,char *coinstr,char *subdir,char *name,int32_t keyoffset,int32_t keysize,int32_t HDDvaluesize,int32_t RAMvaluesize,int32_t inititems,int32_t (*verifyitem)(struct iguana_info *coin,void *key,void *value,int32_t itemind,int32_t itemsize),int32_t (*inititem)(struct iguana_info *coin,struct iguanakv *kv,void *key,void *value,int32_t itemind,int32_t itemsize,int32_t numitems));
//int32_t iguana_kvtruncate(struct iguana_info *coin,struct iguanakv *kv,uint32_t maxitemind);
int32_t iguana_kvdisp(struct iguana_info *coin,struct iguanakv *kv);

// ramchain
int64_t iguana_verifyaccount(struct iguana_info *coin,struct iguana_account *acct,uint32_t pkind);
int32_t iguana_initramchain(struct iguana_info *coin,int32_t initialheight,int32_t mapflags,int32_t fullverify);
void iguana_syncramchain(struct iguana_info *coin);
int32_t iguana_validateramchain(struct iguana_info *coin,int64_t *netp,uint64_t *creditsp,uint64_t *debitsp,int32_t height,struct iguana_block *block,int32_t hwmheight);
int32_t iguana_calcrmd160(struct iguana_info *coin,uint8_t rmd160[20],uint8_t *pk_script,int32_t pk_scriptlen,bits256 debugtxid);
uint32_t iguana_updatescript(struct iguana_info *coin,uint32_t blocknum,uint32_t txidind,uint32_t spendind,uint32_t unspentind,uint64_t value,uint8_t *script,int32_t scriptlen,uint32_t sequence);
void iguana_gotblock(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *block,struct iguana_msgtx *tx,int32_t numtx,uint8_t *data,int32_t datalen);
int32_t iguana_parseblock(struct iguana_info *coin,struct iguana_block *block,struct iguana_msgtx *tx,int32_t numtx);
uint32_t iguana_txidind(struct iguana_info *coin,uint32_t *firstvoutp,uint32_t *firstvinp,bits256 txid);
bits256 iguana_txidstr(struct iguana_info *coin,uint32_t *firstvoutp,uint32_t *firstvinp,char *txidstr,uint32_t txidind);

// ...M() funcs pass in allocated mem
void iguana_gottxidsM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *txids,int32_t n);
void iguana_gotblockhashesM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *hashes,int32_t n);
void iguana_gotunconfirmedM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgtx *tx,int32_t datalen);

// blockchain
int32_t iguana_needhdrs(struct iguana_info *coin);
int32_t iguana_setchainvars(struct iguana_info *coin,uint32_t *firsttxidindp,uint32_t *firstvoutp,uint32_t *firstvinp,double *PoWp,bits256 hash2,uint32_t nBits,bits256 prevhash,int32_t txn_count);
int32_t iguana_blockcmp(struct iguana_info *coin,struct iguana_block *A,struct iguana_block *B,int32_t fastflag);
int32_t iguana_setdependencies(struct iguana_info *coin,struct iguana_block *block);
int32_t iguana_fixblocks(struct iguana_info *coin,int32_t startheight,int32_t endheight);
struct iguana_chain *iguana_chainfind(char *name);
int32_t iguana_height(struct iguana_info *coin,bits256 hash2);
int32_t iguana_numblocks(struct iguana_info *coin);
struct iguana_block *iguana_findblock(struct iguana_info *coin,struct iguana_block *space,bits256 hash2);
int32_t iguana_addblock(struct iguana_info *coin,bits256 hash2,struct iguana_block *newblock);
int32_t iguana_lookahead(struct iguana_info *coin,bits256 *hash2p,int32_t height);
struct iguana_block *iguana_block(struct iguana_info *coin,struct iguana_block *space,int32_t height);
bits256 iguana_blockhash(struct iguana_info *coin,int32_t height);
uint32_t iguana_syncs(struct iguana_info *coin);
void iguana_audit(struct iguana_info *coin);
void iguana_gotdata(struct iguana_info *coin,struct iguana_peer *addr,uint32_t height,bits256 hash2);
void iguana_mergeblock(struct iguana_block *dest,struct iguana_block *block);
uint64_t iguana_miningreward(struct iguana_info *coin,uint32_t blocknum);
//int32_t iguana_avail(struct iguana_info *coin,int32_t height,int32_t n);
int64_t iguana_balance(struct iguana_info *coin,uint64_t *creditsp,uint64_t *debitsp,int32_t *nump,uint32_t *unspents,long max,struct iguana_pkhash *P,uint32_t pkind);
int32_t iguana_queueblock(struct iguana_info *coin,int32_t height,bits256 hash2);
int32_t iguana_updatewaiting(struct iguana_info *coin,int32_t starti,int32_t max);

// recvbits
int32_t iguana_recvinit(struct iguana_info *coin,int32_t initialheight);
int32_t ramcoder_decompress(uint8_t *data,int32_t maxlen,uint8_t *bits,uint32_t numbits,bits256 seed);
int32_t ramcoder_compress(uint8_t *bits,int32_t maxlen,uint8_t *data,int32_t datalen,uint64_t *histo,bits256 seed);
int32_t hconv_bitlen(uint32_t bitlen);
int32_t iguana_recvblock(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *block,struct iguana_msgtx *tx,int32_t numtx,uint8_t *data,int32_t origdatalen);
void *iguana_mappedptr(void **ptrp,struct iguana_mappedptr *mp,uint64_t allocsize,int32_t rwflag,char *fname);
void *iguana_tmpalloc(struct iguana_info *coin,char *name,struct iguana_memspace *mem,long origsize);
int64_t iguana_packetsallocated(struct iguana_info *coin);
int32_t iguana_processrecv(struct iguana_info *coin);
int32_t iguana_waitstart(struct iguana_info *coin,int32_t height);
int32_t iguana_waitclear(struct iguana_info *coin,int32_t height);
int32_t iguana_setwaitstart(struct iguana_info *coin,int32_t height);
void iguana_recvalloc(struct iguana_info *coin,int32_t numitems);

// hdrs
int32_t iguana_updatehdrs(struct iguana_info *coin);
void iguana_parseline(struct iguana_info *coin,int32_t iter,FILE *fp);
void iguana_gotheaders(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *blocks,int32_t n);

// init
struct iguana_info *iguana_startcoin(char *symbol,int32_t initialheight,int32_t mapflags);

// utils
double PoW_from_compact(uint32_t nBits);
void calc_rmd160(char *hexstr,uint8_t buf[20],uint8_t *msg,int32_t len);
void calc_OP_HASH160(char *hexstr,uint8_t hash160[20],char *msg);
double dxblend(double *destp,double val,double decay);

char *mbstr(double);
int init_hexbytes_noT(char *hexbytes,unsigned char *message,long len);
int32_t decode_hex(unsigned char *bytes,int32_t n,char *hex);
char hexbyte(int32_t c);
char *clonestr(char *str);
long _stripwhite(char *buf,int accept);
int32_t myatoi(char *str,int32_t range);
int32_t safecopy(char *dest,char *src,long len);
void escape_code(char *escaped,char *str);
int32_t is_zeroes(char *str);
int64_t conv_floatstr(char *numstr);
int32_t has_backslash(char *str);

uint64_t calc_ipbits(char *ip_port);
void expand_ipbits(char *ipaddr,uint64_t ipbits);

bits256 bits256_doublesha256(char *hashstr,uint8_t *data,int32_t datalen);
char *bits256_str(bits256 x);
char *bits256_str2(bits256 x);
char *bits256_lstr(bits256 x);
bits256 bits256_add(bits256 a,bits256 b);
int32_t bits256_cmp(bits256 a,bits256 b);
bits256 bits256_from_compact(uint32_t c);
int32_t bits256_nonz(bits256 a);

void *mycalloc(uint8_t type,int32_t n,long itemsize);
void *myrealloc(uint8_t type,void *oldptr,int32_t oldsize,int32_t newsize);
void myfree(void *ptr,long size);
void *myaligned_alloc(uint64_t allocsize);
int32_t myaligned_free(void *ptr,long size);
long myallocated();

struct iguana_thread *iguana_launch(char *name,iguana_func funcp,void *arg,uint8_t type);
int32_t iguana_numthreads(int32_t mask);
void iguana_terminator(void *arg);
void free_queueitem(void *itemptr);
void *queueitem(char *str);
void queue_enqueue(char *name,queue_t *queue,struct queueitem *item,int32_t offsetflag);
void *queue_dequeue(queue_t *queue,int32_t offsetflag);

void ensure_directory(char *dirname);
char *iguana_compatible_path(char *str);
uint64_t iguana_filesize(char *fname);
int32_t iguana_compare_files(char *fname,char *fname2);
int64_t iguana_copyfile(char *fname,char *fname2,int32_t cmpflag);
int32_t iguana_renamefile(char *fname,char *newname);
void iguana_removefile(char *fname,int32_t scrubflag);

double milliseconds(void);
void randombytes(unsigned char *x,long xlen);

#endif
