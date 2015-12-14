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

#include "iguana777.h"
#define PUBKEY_ADDRESS_BTC 0
#define SCRIPT_ADDRESS_BTC 5
#define PRIVKEY_ADDRESS_BTC 128
#define PUBKEY_ADDRESS_BTCD 60
#define SCRIPT_ADDRESS_BTCD 85
#define PRIVKEY_ADDRESS_BTCD 0xbc
#define PUBKEY_ADDRESS_TEST 111
#define SCRIPT_ADDRESS_TEST 196
#define PRIVKEY_ADDRESS_TEST 239

static struct iguana_chain Chains[] =
{
	[CHAIN_TESTNET3] =
    {
		//CHAIN_TESTNET3,
        "testnet3", "tBTC",
		PUBKEY_ADDRESS_TEST, SCRIPT_ADDRESS_TEST, PRIVKEY_ADDRESS_TEST,
		"\x0b\x11\x09\x07",
        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae180101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000",
        18333,18334,0,
    },
    [CHAIN_BITCOIN] =
    {
		//CHAIN_BITCOIN,
        "bitcoin", "BTC",
		0, 5, 0x80,
		"\xf9\xbe\xb4\xd9",
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000",
        8333,8334,0,
        { { 210000, (50 * SATOSHIDEN) }, { 420000, (50 * SATOSHIDEN) / 2 }, { 630000, (50 * SATOSHIDEN) / 4 },{ 840000, (50 * SATOSHIDEN) / 8 },
        }
	},
	[CHAIN_BTCD] =
    {
		//CHAIN_BTCD,
        "btcd", "BTCD",
		PUBKEY_ADDRESS_BTCD, SCRIPT_ADDRESS_BTCD, PRIVKEY_ADDRESS_BTCD,
		"\xe4\xc2\xd8\xe6",
        "0000044966f40703b516c5af180582d53f783bfd319bb045e2dc3e05ea695d46",
        "0100000000000000000000000000000000000000000000000000000000000000000000002b5b9d8cdd624d25ce670a7aa34726858388da010d4ca9ec8fd86369cc5117fd0132a253ffff0f1ec58c7f0001010000000132a253010000000000000000000000000000000000000000000000000000000000000000ffffffff4100012a3d3138204a756e652032303134202d204269746f696e20796f75722077617920746f206120646f75626c6520657370726573736f202d20636e6e2e636f6dffffffff010000000000000000000000000000",
        14631,14632,1,
    },
};

void iguana_chaininit(struct iguana_chain *chain,int32_t hasheaders)
{
    chain->hasheaders = hasheaders;
    if ( strcmp(chain->symbol,"bitcoin") == 0 )
    {
        chain->unitval = 0x1d;
    }
    else
    {
        if ( chain->unitval == 0 )
            chain->unitval = 0x1e;
    }
    if ( hasheaders != 0 )
    {
        strcpy(chain->gethdrsmsg,"getheaders");
        chain->bundlesize = _IGUANA_HDRSCOUNT;
    }
    else
    {
        strcpy(chain->gethdrsmsg,"getblocks");
        chain->bundlesize = _IGUANA_BLOCKHASHES;
    }
    decode_hex((uint8_t *)chain->genesis_hashdata,32,(char *)chain->genesis_hash);
    if ( chain->ramchainport == 0 )
        chain->ramchainport = chain->portp2p - 1;
    if ( chain->portrpc == 0 )
        chain->portrpc = chain->portp2p + 1;
}

struct iguana_chain *iguana_chainfind(char *name)
{
    struct iguana_chain *chain; uint32_t i;
	for (i=0; i<sizeof(Chains)/sizeof(*Chains); i++)
    {
		chain = &Chains[i];
        printf("chain.(%s).%s vs %s.%d\n",chain->genesis_hash,chain->name,name,strcmp(name,chain->name));
		if ( chain->name[0] == 0 || chain->genesis_hash == 0 )
			continue;
		if ( strcmp(name,chain->symbol) == 0 )
        {
            iguana_chaininit(chain,strcmp(chain->symbol,"BTC") == 0);
            return(chain);
        }
	}
	return NULL;
}

struct iguana_chain *iguana_findmagic(uint8_t netmagic[4])
{
    struct iguana_chain *chain; uint8_t i;
	for (i=0; i<sizeof(Chains)/sizeof(*Chains); i++)
    {
		chain = &Chains[i];
		if ( chain->name[0] == 0 || chain->genesis_hash == 0 )
			continue;
		if ( memcmp(netmagic,chain->netmagic,4) == 0 )
			return(iguana_chainfind((char *)chain->symbol));
	}
	return NULL;
}

uint64_t iguana_miningreward(struct iguana_info *coin,uint32_t blocknum)
{
    int32_t i; uint64_t reward = 50LL * SATOSHIDEN;
    for (i=0; i<sizeof(coin->chain->rewards)/sizeof(*coin->chain->rewards); i++)
    {
        //printf("%d: %u %.8f\n",i,(int32_t)coin->chain->rewards[i][0],dstr(coin->chain->rewards[i][1]));
        if ( blocknum >= coin->chain->rewards[i][0] )
            reward = coin->chain->rewards[i][1];
        else break;
    }
    return(reward);
}

struct iguana_chain *iguana_createchain(cJSON *json)
{
    char *symbol,*name,*hexstr; cJSON *rewards,*rpair,*item; int32_t i,m,n; struct iguana_chain *chain = 0;
    if ( (symbol= jstr(json,"name")) != 0 && strlen(symbol) < 8 )
    {
        chain = mycalloc('C',1,sizeof(*chain));
        strcpy(chain->symbol,symbol);
        if ( (name= jstr(json,"description")) != 0 && strlen(name) < 32 )
            strcpy(chain->name,name);
        if ( (hexstr= jstr(json,"pubval")) != 0 && strlen(hexstr) == 2 )
            decode_hex((uint8_t *)&chain->pubval,1,hexstr);
        if ( (hexstr= jstr(json,"scriptval")) != 0 && strlen(hexstr) == 2 )
            decode_hex((uint8_t *)&chain->scriptval,1,hexstr);
        if ( (hexstr= jstr(json,"wipval")) != 0 && strlen(hexstr) == 2 )
            decode_hex((uint8_t *)&chain->wipval,1,hexstr);
        if ( (hexstr= jstr(json,"netmagic")) != 0 && strlen(hexstr) == 8 )
            decode_hex((uint8_t *)chain->netmagic,1,hexstr);
        if ( (hexstr= jstr(json,"unitval")) != 0 && strlen(hexstr) == 2 )
            decode_hex((uint8_t *)&chain->unitval,1,hexstr);
        if ( (hexstr= jstr(json,"genesishash")) != 0 )
        {
            chain->genesis_hash = mycalloc('G',1,strlen(hexstr)+1);
            strcpy(chain->genesis_hash,hexstr);
        }
        if ( (hexstr= jstr(json,"genesisblock")) != 0 )
        {
            chain->genesis_hex = mycalloc('G',1,strlen(hexstr)+1);
            strcpy(chain->genesis_hex,hexstr);
        }
        chain->portp2p = juint(json,"p2p");
        if ( (chain->ramchainport= juint(json,"ramchain")) == 0 )
            chain->ramchainport = chain->portp2p - 1;
        if ( (chain->portrpc= juint(json,"rpc")) == 0 )
            chain->portrpc = chain->portp2p + 1;
        chain->hastimestamp = juint(json,"hastimestamp");
        if ( (rewards= jarray(&n,json,"rewards")) != 0 )
        {
            for (i=0; i<n; i++)
            {
                item = jitem(rewards,i);
                if ( (rpair= jarray(&m,item,0)) != 0 && m == 0 )
                {
                    chain->rewards[i][0] = j64bits(jitem(rpair,0),0);
                    chain->rewards[i][1] = j64bits(jitem(rpair,1),0);
                }
            }
        }
        iguana_chaininit(chain,juint(json,"hasheaders"));
    }
    return(chain);
}

double PoW_from_compact(uint32_t nBits,uint8_t unitval) // NOT consensus safe, but most of the time will be correct
{
	uint32_t nbytes,nbits,i,n; double PoW;
    nbytes = (nBits >> 24) & 0xFF;
    nbits = (8 * (nbytes - 3));
    PoW = nBits & 0xFFFFFF;
    if ( nbytes > unitval )
    {
        printf("illegal nBits.%x\n",nBits);
        return(0.);
    }
    if ( (n= ((8* (unitval-3)) - nbits)) != 0 ) // 0x1d00ffff is genesis nBits so we map that to 1.
    {
        if ( n < 64 )
            PoW /= (1LL << n);
        else // very rare case efficiency not issue
        {
            for (i=0; i<n; i++)
                PoW /= 2.;
        }
    }
    PoW /=  0xffff;
    //printf("nBits.%x -> %.15f diff %.15f | n.%d\n",nBits,PoW,1./PoW,n);
    return(PoW);
}

int32_t iguana_setchainvars(struct iguana_info *coin,uint32_t *firsttxidindp,uint32_t *firstvoutp,uint32_t *firstvinp,double *PoWp,bits256 hash2,uint32_t nBits,bits256 prevhash,int32_t txn_count)
{
    int32_t height=-1,firstvout=0,firstvin=0,firsttxidind=0; double PoW; struct iguana_block *prev;
    *PoWp = *firsttxidindp = *firstvoutp = *firstvinp = 0;
    if ( memcmp(coin->chain->genesis_hashdata,hash2.bytes,sizeof(hash2)) == 0 )
    {
        PoW = PoW_from_compact(nBits,coin->chain->unitval);
        height = 0;
        firsttxidind = firstvout = firstvin = 1;
        printf("set genesis vars nBits.%x\n",nBits);
    }
    else
    {
        if ( (prev= iguana_blockfind(coin,prevhash)) == 0 )
        {
            if ( iguana_needhdrs(coin) == 0 )
            {
                char str[65],str2[65];
                bits256_str(str,hash2);
                bits256_str(str2,prevhash);
                printf("hash2.(%s) ",str);
                fprintf(stderr,"iguana_blockchain no prev block.(%s)\n",str2);
                //getchar();
            }
            return(-1);
        }
        else
        {
            height = prev->height + 1;
            PoW = (PoW_from_compact(nBits,coin->chain->unitval) + prev->L.PoW);
            if ( txn_count > 0 )
            {
                if ( prev->txn_count > 0 && prev->L.numtxids > 0 )
                    firsttxidind = prev->L.numtxids + prev->txn_count;
                if ( prev->numvouts > 0 && prev->L.numtxids > 0 )
                    firstvout = prev->L.numunspents + prev->numvouts;
                if ( prev->L.numspends > 0 )
                    firstvin = prev->L.numspends + prev->numvins;
                //printf("PREV.%d firsttxidind.%d firstvout.%d+%d firstvin.%d+%d (%d %d %d)\n",prev->height,prev->L.numtxids,prev->L.numunspents,prev->numvouts,prev->L.numspends,prev->numvins,firsttxidind,firstvout,firstvin);
            } //else printf("null txn_count in block.%d\n",height);
            //printf("txn.%d prev.(%d %f txn.%d) ",txn_count,prev->height,prev->PoW,prev->txn_count);
            //printf("prev.%d 1st %d + prev txn.%d %f -> %d\n",prev->height,prev->firsttxidind,prev->txn_count,prev->PoW,firsttxidind);
        }
    }
    *PoWp = PoW;
    *firsttxidindp = firsttxidind;
    *firstvoutp = firstvout;
    *firstvinp = firstvin;
    //printf("set height.%d: %d %f firstvin.%d firstvout.%d\n",height,firsttxidind,PoW,firstvin,firstvout);
    return(height);
}

int32_t iguana_setdependencies(struct iguana_info *coin,struct iguana_block *block)
{
    int32_t h,height;
    if ( block == 0 )
        return(-1);
    height = block->height;
    if ( (h= iguana_setchainvars(coin,&block->L.numtxids,&block->L.numunspents,&block->L.numspends,&block->L.PoW,block->hash2,block->bits,block->prev_block,block->txn_count)) == height )
    {
        // place to make sure connected to ramchain
        return(height);
    }
    if ( height < 0 )
        block->height = h;
    //printf("dependencies returned %d vs %d\n",h,height);
    return(-1);
}

int32_t iguana_chainextend(struct iguana_info *coin,bits256 hash2,struct iguana_block *newblock)
{
    int32_t h;
    if ( (newblock->height= iguana_setdependencies(coin,newblock)) >= 0 )
    {
        if ( newblock->L.PoW > coin->blocks.hwmPoW )
        {
            if ( newblock->height+1 > coin->blocks.maxblocks )
                coin->blocks.maxblocks = (newblock->height + 1);
            h = newblock->height;
            iguana_kvwrite(coin,coin->blocks.db,hash2.bytes,newblock,(uint32_t *)&h);
            coin->blocks.hwmheight = newblock->height;
            coin->blocks.hwmPoW = newblock->L.PoW;
            coin->blocks.hwmchain = hash2;
            coin->latest.blockhash = hash2;
            coin->latest.merkle_root = newblock->merkle_root;
            coin->latest.timestamp = newblock->timestamp;
            coin->latest.height = coin->blocks.hwmheight;
            //coin->latest.numtxids = newblock->firsttxidind + newblock->txn_count;
            //iguana_gotdata(coin,0,newblock->height,hash2);
            //if ( (newblock->height % coin->chain->bundlesize) == 0 )
            //   iguana_bundleinit(coin,newblock->height,hash2);
            //printf("%s height.%d PoW %f\n",bits256_str(hash2),block->height,block->PoW);
            // if ( coin->blocks.initblocks != 0 && ((newblock->height % 100) == 0 || coin->blocks.hwmheight > coin->longestchain-10) )
            char str[65],str2[65];
            bits256_str(str,newblock->hash2);
            bits256_str(str2,coin->blocks.hwmchain);
            printf("ADD %s %d:%d:%d <- (%s) n.%u max.%u PoW %f 1st.%d numtx.%d\n",str,h,iguana_chainheight(coin,newblock),newblock->height,str2,coin->blocks.hwmheight+1,coin->blocks.maxblocks,newblock->L.PoW,newblock->L.numtxids,newblock->txn_count);
            //iguana_queueblock(coin,newblock->height,hash2);
            //coin->newhdrs++;
        }
    } else printf("error from setchain.%d\n",newblock->height);
    if ( memcmp(hash2.bytes,coin->blocks.hwmchain.bytes,sizeof(hash2)) != 0 )
    {
        char str[65];
        bits256_str(str,hash2);
        if ( iguana_needhdrs(coin) == 0 )
            printf("ORPHAN.%s height.%d PoW %f vs best %f\n",str,newblock->height,newblock->L.PoW,coin->blocks.hwmPoW);
        newblock->height = -1;
    }
    //iguana_audit(coin);
    return(newblock->height);
}
