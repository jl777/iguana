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

#define iguana_hashfind(hashtable,key,keylen) iguana_hashsetHT(hashtable,0,key,keylen,-1)

struct iguana_kvitem *iguana_hashsetHT(struct iguana_kvitem *hashtable,struct iguana_memspace *mem,void *key,int32_t keylen,int32_t itemind)
{
    struct iguana_kvitem *ptr = 0; int32_t allocsize;
    HASH_FIND(hh,hashtable,key,keylen,ptr);
    if ( ptr == 0 && itemind >= 0 )
    {
        allocsize = (int32_t)(sizeof(*ptr));
        if ( mem != 0 )
            ptr = iguana_memalloc(mem,allocsize,1);
        else ptr = mycalloc('t',1,allocsize);
        if ( ptr == 0 )
            printf("fatal alloc error in hashset\n"), exit(-1);
        //printf("ptr.%p allocsize.%d key.%p keylen.%d itemind.%d\n",ptr,allocsize,key,keylen,itemind);
        ptr->hh.itemind = itemind;
        HASH_ADD_KEYPTR(hh,hashtable,key,keylen,ptr);
    }
    if ( ptr != 0 )
    {
        struct iguana_kvitem *tmp;
        HASH_FIND(hh,hashtable,key,keylen,tmp);
        char str[65];
        init_hexbytes_noT(str,key,keylen);
        if ( tmp != ptr )
            printf("%s itemind.%d search error %p != %p\n",str,itemind,ptr,tmp);
        // else printf("added.(%s) height.%d %p\n",str,itemind,ptr);
    }
    return(ptr);
}

int32_t iguana_parseblock(struct iguana_info *coin,struct iguana_block *block,struct iguana_msgtx *tx,int32_t numtx)
{
#ifdef oldway
    int32_t txind,pkind,i; uint16_t numvouts,numvins;
    pkind = block->L.numpkinds = coin->latest.dep.numpkinds;
    block->L.supply = coin->latest.dep.supply;
    if ( block->L.numtxids != coin->latest.dep.numtxids || block->L.numunspents != coin->latest.dep.numunspents || block->L.numspends != coin->latest.dep.numspends || block->L.numpkinds != coin->latest.dep.numpkinds )
    {
        printf("Block.(h%d t%d u%d s%d p%d) vs coin.(h%d t%d u%d s%d p%d)\n",block->height,block->L.numtxids,block->L.numunspents,block->L.numspends,block->L.numpkinds,coin->blocks.parsedblocks,coin->latest.dep.numtxids,coin->latest.dep.numunspents,coin->latest.dep.numspends,coin->latest.dep.numpkinds);
        block->L.numtxids = coin->latest.dep.numtxids;
        block->L.numunspents = coin->latest.dep.numunspents;
        block->L.numspends = coin->latest.dep.numspends;
        block->L.numpkinds = coin->latest.dep.numpkinds;
        iguana_kvwrite(coin,coin->blocks.db,0,block,(uint32_t *)&block->height);
        //getchar();
    }
    vcalc_sha256(0,coin->latest.ledgerhash.bytes,coin->latest.lhashes[0].bytes,sizeof(coin->latest.lhashes));
    coin->LEDGER.snapshot.dep = block->L;
    memcpy(&coin->LEDGER.snapshot.ledgerhash,&coin->latest.ledgerhash,sizeof(coin->latest.ledgerhash));
    memcpy(coin->LEDGER.snapshot.lhashes,coin->latest.lhashes,sizeof(coin->latest.lhashes));
    memcpy(coin->LEDGER.snapshot.states,coin->latest.states,sizeof(coin->latest.states));
    //printf("%08x Block.(h%d t%d u%d s%d p%d) vs (h%d t%d u%d s%d p%d)\n",(uint32_t)coin->latest.ledgerhash.txid,block->height,block->L.numtxids,block->L.numunspents,block->L.numspends,block->L.numpkinds,coin->blocks.parsedblocks,coin->latest.dep.numtxids,coin->latest.dep.numunspents,coin->latest.dep.numspends,coin->latest.dep.numpkinds);
    if ( (coin->blocks.parsedblocks % 1000) == 0 )
    {
        for (i=0; i<IGUANA_NUMAPPENDS; i++)
            printf("%llx ",(long long)coin->LEDGER.snapshot.lhashes[i].txid);
        char str[65];
        bits256_str(str,coin->LEDGER.snapshot.ledgerhash);
        printf("-> pre parse %s ledgerhashes.%d\n",str,coin->blocks.parsedblocks);
    }
    coin->LEDGER.snapshot.blockhash = block->hash2;
    coin->LEDGER.snapshot.merkle_root = block->merkle_root;
    coin->LEDGER.snapshot.timestamp = block->timestamp;
    coin->LEDGER.snapshot.credits = coin->latest.credits;
    coin->LEDGER.snapshot.debits = coin->latest.debits;
    coin->LEDGER.snapshot.height = block->height;
    //if ( coin->blocks.parsedblocks > 0 && (coin->blocks.parsedblocks % coin->chain->bundlesize) == 0 )
    //    coin->R.bundles[coin->blocks.parsedblocks / coin->chain->bundlesize].presnapshot = coin->LEDGER.snapshot;
    for (txind=block->numvouts=block->numvins=0; txind<block->txn_count; txind++)
    {
        //printf("block.%d txind.%d numvouts.%d numvins.%d block->(%d %d) U%d coin.%d\n",block->height,txind,numvouts,numvins,block->numvouts,block->numvins,block->L.numunspents,coin->latest.dep.numunspents);
        //fprintf(stderr,"t");
        if ( ramchain_parsetx(coin,&coin->mining,&coin->totalfees,&numvouts,&numvins,block->height,txind,&tx[txind],block->L.numtxids+txind,block->L.numunspents + block->numvouts,block->L.numspends + block->numvins) < 0 )
            return(-1);
        block->numvouts += numvouts;
        block->numvins += numvins;
        //printf("block.%d txind.%d numvouts.%d numvins.%d block->(%d %d) 1st.(%d %d)\n",block->height,txind,numvouts,numvins,block->numvouts,block->numvins,block->L.numunspents,block->L.numspends);
    }
    //printf(" Block.(h%d t%d u%d s%d p%d) vs coin.(h%d t%d u%d s%d p%d)\n",block->height,block->L.numtxids,block->L.numunspents,block->L.numspends,block->L.numpkinds,coin->blocks.parsedblocks,coin->latest.dep.numtxids,coin->latest.dep.numunspents,coin->latest.dep.numspends,coin->latest.dep.numpkinds);
    if ( coin->latest.dep.supply != (coin->latest.credits - coin->latest.debits) )
    {
        printf("height.%d supply %.8f != %.8f (%.8f - %.8f)\n",block->height,dstr(coin->latest.dep.supply),dstr(coin->latest.credits)-dstr(coin->latest.debits),dstr(coin->latest.credits),dstr(coin->latest.debits));
        getchar();
    }
#ifdef IGUANA_VERIFYFLAG
    while ( pkind < coin->latest.dep.numpkinds )
    {
        int64_t err;
        if ( (err= iguana_verifyaccount(coin,&coin->accounts[pkind],pkind)) < 0 )
            printf("pkind.%d err.%lld %.8f last.(U%d S%d)\n",pkind,(long long)err,dstr(coin->accounts[pkind].balance),coin->accounts[pkind].lastunspentind,coin->accounts[pkind].lastspendind), getchar();
        pkind++;
    }
#endif
    coin->parsetime = (uint32_t)time(NULL);
    coin->parsemillis = milliseconds();
    iguana_kvwrite(coin,coin->blocks.db,0,block,(uint32_t *)&block->height);
    if ( (coin->blocks.parsedblocks > coin->longestchain-100000 && (coin->blocks.parsedblocks % 100) == 0) || (coin->blocks.parsedblocks > coin->longestchain-1000 && (coin->blocks.parsedblocks % 10) == 0) || coin->blocks.parsedblocks > coin->longestchain-100 || (coin->blocks.parsedblocks % 100) == 0 )
    {
        printf("PARSED.%d T.%d U.%d+%d S.%d+%d P.%d hwm.%d longest.%d | %.8f - %.8f %.8f [%.8f] M %.8f F %.8f | %.02f minutes %.2f%% %.2f%% %.2f%% avail\n",coin->blocks.parsedblocks,coin->latest.dep.numtxids,block->L.numunspents,block->numvouts,block->L.numspends,block->numvins,block->L.numpkinds,coin->blocks.hwmheight,coin->longestchain,dstr(coin->latest.credits),dstr(coin->latest.debits),dstr(coin->latest.credits)-dstr(coin->latest.debits),(dstr(coin->latest.credits)-dstr(coin->latest.debits))/coin->blocks.parsedblocks,dstr(coin->mining),dstr(coin->totalfees),((double)time(NULL)-coin->starttime)/60.,(double)iguana_avail(coin,coin->blocks.parsedblocks+1,1000)/10.,(double)iguana_avail(coin,coin->blocks.parsedblocks+1,25000)/250.,100.*(double)iguana_avail(coin,coin->blocks.parsedblocks+1,coin->longestchain-coin->blocks.parsedblocks-1)/(coin->longestchain-coin->blocks.parsedblocks));
        myallocated(0,0);
    }
    if ( 0 && coin->loadedLEDGER.snapshot.height == coin->blocks.parsedblocks )
    {
        memcpy(&coin->latest.ledgerhash,&coin->loadedLEDGER.snapshot.ledgerhash,sizeof(coin->loadedLEDGER.snapshot.ledgerhash));
        memcpy(coin->latest.lhashes,coin->loadedLEDGER.snapshot.lhashes,sizeof(coin->loadedLEDGER.snapshot.lhashes));
        printf("restore lhashes, special alignement case\n");
    } //else printf("loaded.%d vs parsed.%d\n",coin->loadedLEDGER.snapshot.height,coin->blocks.parsedblocks);
    coin->blocks.parsedblocks++;
#endif
    return(0);
}

int32_t iguana_updateramchain(struct iguana_info *coin)
{
    return(0);
}

int32_t iguana_hashfree(struct iguana_kvitem *hashtable,int32_t delitem)
{
    struct iguana_kvitem *item,*tmp; int32_t n = 0;
    if ( hashtable != 0 )
    {
        HASH_ITER(hh,hashtable,item,tmp)
        {
            //printf("hashdelete.%p allocsize.%d itemind.%d delitem.%d\n",item,item->allocsize,item->hh.itemind,delitem);
            if ( delitem != 0 )
                HASH_DEL(hashtable,item);
            //if ( item->allocsize != 0 )
            //    myfree(item,item->allocsize);
            n++;
        }
    }
    return(n);
}

struct iguana_txblock *iguana_ramchainptrs(struct iguana_txid **Tptrp,struct iguana_unspent **Uptrp,struct iguana_spend **Sptrp,struct iguana_pkhash **Pptrp,bits256 **externalTptrp,struct iguana_memspace *mem,struct iguana_txblock *origtxdata)
{
    char str[65]; struct iguana_txblock *txdata; int32_t allocsize,extralen,rwflag = (origtxdata != 0);
    iguana_memreset(mem);
    allocsize = (int32_t)(sizeof(*txdata) - sizeof(txdata->space) + ((origtxdata != 0) ? origtxdata->extralen : 0));
    mem->alignflag = sizeof(uint32_t);
    if ( (txdata= iguana_memalloc(mem,allocsize,0)) == 0 )
        return(0);
    //printf("ptr.%p alloctxdata.%p T.%d U.%d S.%d P.%d\n",mem->ptr,txdata,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds);
    extralen = (origtxdata != 0) ? origtxdata->extralen : txdata->extralen;
    if ( origtxdata != 0 )
    {
        //printf("copy %d bytes from %p to %p extralen.%d size.%ld  T.%d U.%d S.%d P.%d \n",allocsize,origtxdata,txdata,extralen,sizeof(*txdata),txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds);
        memcpy(txdata,origtxdata,allocsize);
    } else iguana_memalloc(mem,txdata->extralen,0);
    *Tptrp = iguana_memalloc(mem,sizeof(**Tptrp) * txdata->numtxids,rwflag);
    *Uptrp = iguana_memalloc(mem,sizeof(**Uptrp) * txdata->numunspents,rwflag);
    *Sptrp = iguana_memalloc(mem,sizeof(**Sptrp) * txdata->numspends,rwflag);
    //printf("rwflag.%d ptr.%p alloctxdata.%p T.%d U.%d S.%d P.%d  pkoffset.%ld\n",rwflag,mem->ptr,txdata,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds,mem->used);
    if ( externalTptrp != 0 )
    {
        if ( txdata->pkoffset < (int32_t)mem->used )
            printf("allocsize.%d size.%ld %p %s (T.%d U.%d S.%d P.%d X.%d) iguana_ramchainptrs pkoffset.%d != %ld numspends.%d\n",allocsize,sizeof(*txdata),txdata,bits256_str(str,txdata->block.hash2),txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds,txdata->numexternaltxids,txdata->pkoffset,mem->used,txdata->numspends), getchar();
        mem->used = txdata->pkoffset;
        *Pptrp = iguana_memalloc(mem,sizeof(**Pptrp) * txdata->numpkinds,rwflag);
        *externalTptrp = iguana_memalloc(mem,txdata->numexternaltxids * sizeof(**externalTptrp),rwflag);
    }
    else
    {
        txdata->pkoffset = (int32_t)mem->used;
       // printf("set pkoffset.%d\n",txdata->pkoffset);
        *Pptrp = iguana_memalloc(mem,0,rwflag);
    }
    if ( 0 && rwflag == 0 )
        printf("datalen.%d rwflag.%d origtxdat.%p allocsize.%d extralen.%d T.%d U.%d S.%d P.%d X.%p[%d]\n",(int32_t)mem->totalsize,rwflag,origtxdata,allocsize,extralen,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds,externalTptrp!=0?*externalTptrp:0,txdata->numexternaltxids);
    return(txdata);
}

int32_t iguana_ramchainsave(struct iguana_info *coin,struct iguana_ramchain *ramchain)
{
    FILE *fp; char fname[1024],str[65];
    sprintf(fname,"DB/%s/%s.%d",coin->symbol,bits256_str(str,ramchain->hash2),ramchain->hdrsi);
    if ( (fp= fopen(fname,"wb")) != 0 )
    {
        fwrite(ramchain,1,ramchain->allocsize,fp);
        fclose(fp);
    }
    printf("ramchainsave.%s %d[%d] %s\n",coin->symbol,ramchain->hdrsi,ramchain->numblocks,mbstr(str,ramchain->allocsize));
    return(0);
}

int32_t iguana_ramchainfree(struct iguana_info *coin,struct iguana_memspace *mem,struct iguana_ramchain *ramchain)
{
    if ( ramchain->txids != 0 )
        iguana_hashfree(ramchain->txids,1);
    if ( ramchain->pkhashes != 0 )
        iguana_hashfree(ramchain->pkhashes,1);
    iguana_mempurge(mem);
    return(0);
}

struct iguana_ramchain *iguana_ramchainset(struct iguana_info *coin,struct iguana_ramchain *ramchain,struct iguana_txblock *txdata)
{
    struct iguana_memspace txmem;
    memset(&txmem,0,sizeof(txmem));
    iguana_meminit(&txmem,"bramchain",txdata,txdata->datalen,0);
    //printf("ramchainset <- txdata.%p memptr.%p T.%d U.%d S.%d P.%d X.%d\n",txdata,txmem.ptr,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds,txdata->numexternaltxids);
    if ( iguana_ramchainptrs(&ramchain->T,&ramchain->U,&ramchain->S,&ramchain->P,&ramchain->externalT,&txmem,0) != txdata || ramchain->T == 0 || ramchain->U == 0 || ramchain->S == 0 || ramchain->P == 0 )
    {
        printf("iguana_ramchainset: cant set pointers txdata.%p\n",txdata);
        return(0);
    }
   //int32_t i;
   // for (i=0; i<344; i++)
   //     printf("%02x ",((uint8_t *)txdata)[i]);
    //for (i=-1; i<2; i++)
    //    printf("%016lx ",*(long *)((struct iguana_pkhash *)((long)txdata + txdata->pkoffset))[i].rmd160);
    //printf("datalen.%d T.%d U.%d S.%d P.%d X.%d | %d vs %d ramchain.%p txdata.%p\n",txdata->datalen,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds,txdata->numexternaltxids,txdata->pkoffset,(int32_t)((long)ramchain->P - (long)txdata),ramchain,txdata);
    ramchain->numtxids = txdata->numtxids;
    ramchain->numunspents = txdata->numunspents;
    ramchain->numspends = txdata->numspends;
    ramchain->numpkinds = txdata->numpkinds;
    ramchain->numexternaltxids = txdata->numexternaltxids;
    //printf("ramchain T.%d U.%d S.%d P.%d X.%d %p\n",ramchain->numtxids,ramchain->numunspents,ramchain->numspends,ramchain->numpkinds,ramchain->numexternaltxids,ramchain->externalT);
    if ( ramchain->numexternaltxids != 0 && ramchain->externalT == 0 )
        getchar();
    ramchain->prevhash2 = txdata->block.prev_block;
    ramchain->hash2 = txdata->block.hash2;
    return(ramchain);
}

int32_t iguana_ramchaintxid(struct iguana_info *coin,bits256 *txidp,struct iguana_ramchain *ramchain,struct iguana_spend *s)
{
    memset(txidp,0,sizeof(*txidp));
    //printf("s.%p ramchaintxid vout.%x spendtxidind.%d numexternals.%d isext.%d numspendinds.%d\n",s,s->vout,s->spendtxidind,ramchain->numexternaltxids,s->external,ramchain->numspends);
    if ( s->vout == 0xffff )
        return(0);
    if ( s->external != 0 && s->spendtxidind < ramchain->numexternaltxids )
    {
        *txidp = ramchain->externalT[s->spendtxidind];
        return(0);
    }
    else if ( s->external == 0 && s->spendtxidind < ramchain->numtxids )
    {
        *txidp = ramchain->T[s->spendtxidind].txid;
        return(0);
    }
    return(-1);
}
/*
int32_t iguana_ramchainverifyPT(struct iguana_info *coin,struct iguana_ramchain *ramchain)
{
    int32_t j,k,txidind,pkind,unspentind,spendind; struct iguana_kvitem *ptr; bits256 txid;
    struct iguana_txid *tx; struct iguana_unspent *u; struct iguana_pkhash *p; struct iguana_spend *s;
    // iguana_txid { bits256 txid; uint32_t txidind,firstvout,firstvin; uint16_t numvouts,numvins;}
    txidind = pkind = unspentind = spendind = ramchain->firsti;
    for (j=item->firsti; j<ramchain->numtxids; j++,txidind++)
    {
        tx = &ramchain->T[txidind];
        if ( tx->txidind != txidind )
            return(-1);
        if ( (ptr= iguana_hashfind(ramchain->txids,tx->txid.bytes,sizeof(tx->txid))) == 0 )
            return(-2);
        if ( ptr->hh.itemind != txidind )
            return(-3);
        if ( tx->firstvout != unspentind )
            return(-4);
        if ( tx->firstvin != spendind )
            return(-5);
        for (k=item->firsti; k<tx->numvouts; k++,unspentind++)
        {
            u = &ramchain->U[unspentind];
            if ( u->txidind != txidind )
                return(-6);
            if ( (pkind= u->pkind) < 0 || pkind >= ramchain->numpkinds )
                return(-7);
            p = &ramchain->P[pkind];
            if ( (ptr= iguana_hashfind(ramchain->pkhashes,p->rmd160,sizeof(p->rmd160))) == 0 )
                return(-8);
            if ( ptr->hh.itemind == pkind && p->firstunspentind != unspentind )
                return(-9);
        }
        for (k=ramchain->firsti; k<tx->numvins; k++,spendind++)
        {
            s = &ramchain->S[spendind];
            //printf("item.%p [%d] X.%p i.%d j.%d k.%d txidind.%d/%d spendind.%d/%d s->txidind.%d/v%d\n",item,item->numexternaltxids,item->externalT,i,j,k,txidind,ramchain->numtxids,spendind,ramchain->numspends,item->S[k].spendtxidind,item->S[k].vout);
            if ( iguana_ramchaintxid(coin,&txid,ramchain,s) < 0 )
            {
                printf("j.%d k.%d error getting txid firsti.%d X.%d vout.%d spend.%d/%d numX.%d numT.%d\n",j,k,ramchain->firsti,s->external,s->vout,s->spendtxidind,ramchain->numspends,ramchain->numexternaltxids,ramchain->numtxids);
                return(-10);
            }
            if ( s->vout == 0xffff )
            {
                // mining output
            }
            else if ( (ptr= iguana_hashfind(ramchain->txids,txid.bytes,sizeof(txid))) != 0 )
            {
                if ( (s->spendtxidind= ptr->hh.itemind) >= ramchain->numtxids )
                {
                    s->external = 1;
                    s->spendtxidind -= ramchain->numtxids;
                }
                else if ( s->spendtxidind >= item->firsti && s->spendtxidind < item->numtxids )
                {
                    s->external = 0;
                    unspentind = (ramchain->T[s->spendtxidind].firstvout + s->vout);
                    u = &ramchain->U[unspentind];
                    p = &ramchain->P[u->pkind];
                    if ( ramchain->pkextras[u->pkind].firstspendind == 0 )
                        ramchain->pkextras[u->pkind].firstspendind = spendind;
                    acct = &ramchain->accounts[u->pkind];
                    s->prevspendind = acct->lastspendind;
                    acct->lastspendind = spendind;
                    if ( ramchain->Uextras[unspentind].spendind != 0 )
                    {
                        printf("double spend u.%d has spendind.%d when s.%d refers to it\n",unspentind,ramchain->Uextras[unspentind].spendind,spendind);
                        iguana_ramchainfree(coin,mem,ramchain);
                        return(0);
                    }
                    ramchain->Uextras[unspentind].spendind = spendind;
                }
                spendind++;
            }
            else if ( numexternaltxids < ramchain->numexternaltxids )
            {
                s->external = 1;
                ramchain->externalT[numexternaltxids] = txid;
                iguana_hashsetHT(ramchain->txids,0,ramchain->externalT[numexternaltxids].bytes,sizeof(ramchain->externalT[numexternaltxids]),ramchain->numtxids + numexternaltxids);
                s->spendtxidind = numexternaltxids++;
                spendind++;
            }
            else printf("numexternaltxids.%d >= ramchain numexternaltxids.%d\n",numexternaltxids,ramchain->numexternaltxids);
        }
    }
    return(0);
}*/

struct iguana_ramchain *iguana_ramchainmergeHT(struct iguana_info *coin,struct iguana_memspace *mem,struct iguana_ramchain *ramchains[],int32_t n,struct iguana_bundle *bp)
{
    uint32_t numtxids,numunspents,numspends,numpkinds,numexternaltxids,i,j,k; uint64_t allocsize = 0;
    struct iguana_txid *tx;  struct iguana_account *acct; struct iguana_ramchain *ramchain,*item;
    struct iguana_pkhash *p,oldP; struct iguana_unspent *u; struct iguana_kvitem *ptr;
    bits256 txid; uint32_t txidind,unspentind,spendind,pkind,numblocks; struct iguana_spend *s;
    numtxids = numunspents = numspends = numpkinds = 1;
    numexternaltxids = 1;
    numblocks = 0;
    for (i=0; i<n; i++)
    {
        if ( (item= ramchains[i]) == 0 )
        {
            printf("iguana_ramchaininit null hdrsi.%d txdatas[%d]\n",bp->ramchain.hdrsi,i);
            return(0);
        }
        numtxids += item->numtxids, numunspents += item->numunspents, numspends += item->numspends;
        numpkinds += item->numpkinds, numexternaltxids += item->numexternaltxids;
        numblocks += item->numblocks;
    }
    allocsize = sizeof(*ramchain) +
                (numtxids * sizeof(*ramchain->T)) +
                (numunspents * (sizeof(*ramchain->U) + sizeof(*ramchain->Uextras))) +
                (numspends * sizeof(*ramchain->S)) +
                (numpkinds * (sizeof(*ramchain->P) + sizeof(*ramchain->pkextras) + sizeof(*ramchain->accounts))) +
                (numexternaltxids * sizeof(*ramchain->externalT));
    
    iguana_meminit(mem,"ramchain",0,allocsize,0);
    mem->alignflag = sizeof(uint32_t);
    if ( (ramchain= iguana_memalloc(mem,sizeof(*ramchain),1)) == 0 )
    {
        iguana_mempurge(mem);
        return(0);
    }
    ramchain->numblocks = numblocks;
    ramchain->numtxids = numtxids, ramchain->numunspents = numunspents;
    ramchain->numspends = numspends, ramchain->numpkinds = numpkinds;
    ramchain->numexternaltxids = numexternaltxids;
    ramchain->hdrsi = bp->ramchain.hdrsi, ramchain->bundleheight = bp->ramchain.bundleheight, ramchain->numblocks = n;
    ramchain->prevbundlehash2 = bp->prevbundlehash2, ramchain->nextbundlehash2 = bp->nextbundlehash2;
    ramchain->hash2 = ramchains[0]->hash2;
    ramchain->prevhash2 = ramchains[0]->prevhash2, ramchain->lasthash2 = ramchains[n-1]->hash2;
    ramchain->T = iguana_memalloc(mem,sizeof(*ramchain->T) * ramchain->numtxids,0);
    ramchain->U = iguana_memalloc(mem,sizeof(*ramchain->U) * ramchain->numunspents,0);
    if ( ramchain->numspends > 0 )
        ramchain->S = iguana_memalloc(mem,sizeof(*ramchain->S) * ramchain->numspends,0);
    ramchain->Uextras = iguana_memalloc(mem,sizeof(*ramchain->Uextras) * ramchain->numunspents,1);
    ramchain->P = iguana_memalloc(mem,sizeof(*ramchain->P) * ramchain->numpkinds,1);
    ramchain->pkextras = iguana_memalloc(mem,sizeof(*ramchain->pkextras) * ramchain->numpkinds,1);
    ramchain->accounts = iguana_memalloc(mem,sizeof(*ramchain->accounts) * ramchain->numpkinds,1);
    if ( ramchain->numexternaltxids > 0 )
        ramchain->externalT = iguana_memalloc(mem,ramchain->numexternaltxids * sizeof(*ramchain->externalT),1);
    if ( mem->used != allocsize )
    {
        printf("error allocating ramchain %ld != %ld\n",(long)mem->used,(long)allocsize);
        iguana_ramchainfree(coin,mem,ramchain);
        return(0);
    }
    ramchain->allocsize = allocsize;
    ramchain->firsti = 1;
    //printf("Allocated %s for bp %d\n",mbstr(str,allocsize),bp->ramchain.bundleheight);
    txidind = unspentind = numtxids = spendind = numunspents = numspends = numpkinds = ramchain->firsti;
    numexternaltxids = 0;
    for (i=0; i<n; i++)
    {
        if ( (item= ramchains[i]) != 0 )
        {
            // iguana_txid { bits256 txid; uint32_t txidind,firstvout,firstvin; uint16_t numvouts,numvins;}
            for (j=item->firsti; j<item->numtxids; j++,txidind++)
            {
                tx = &ramchain->T[txidind];
                *tx = item->T[j];
                tx->txidind = txidind;
                if ( (ptr= iguana_hashfind(ramchain->txids,tx->txid.bytes,sizeof(tx->txid))) != 0 )
                {
                    printf("unexpected duplicate txid[%d]\n",txidind);
                    iguana_ramchainfree(coin,mem,ramchain);
                    return(0);
                }
                iguana_hashsetHT(ramchain->txids,0,tx->txid.bytes,sizeof(bits256),txidind);
                tx->firstvout = unspentind;
                for (k=item->firsti; k<tx->numvouts; k++,unspentind++)
                {
                    u = &ramchain->U[unspentind];
                    *u = item->U[k];
                    u->txidind = txidind;
                    oldP = item->P[item->U[k].pkind];
                    if ( (ptr= iguana_hashfind(ramchain->pkhashes,oldP.rmd160,sizeof(oldP.rmd160))) == 0 )
                    {
                        pkind = numpkinds++;
                        p = &ramchain->P[pkind];
                        *p = oldP;
                        p->firstunspentind = unspentind;
                        if ( (ptr= iguana_hashsetHT(ramchain->pkhashes,0,p->rmd160,sizeof(p->rmd160),numpkinds)) == 0 )
                        {
                            iguana_ramchainfree(coin,mem,ramchain);
                            printf("fatal error adding pkhash\n");
                            return(0);
                        }
                        //printf("pkind.%d: %p %016lx <- %016lx\n",pkind,p,*(long *)p->rmd160,*(long *)oldP.rmd160);
                    } else pkind = ptr->hh.itemind;
                    u->pkind = pkind;
                    acct = &ramchain->accounts[pkind];
                    u->prevunspentind = acct->lastunspentind;
                    acct->lastunspentind = unspentind;
                    acct->balance += u->value;
                }
                tx->firstvin = spendind;
                spendind += tx->numvins;
            }
            numtxids += item->numtxids, numunspents += item->numunspents;
        }
    }
    txidind = spendind = ramchain->firsti;
    for (i=0; i<n; i++)
    {
        if ( (item= ramchains[i]) != 0 )
        {
            for (j=item->firsti; j<item->numtxids; j++,txidind++)
            {
                tx = &ramchain->T[j];
                for (k=item->firsti; k<tx->numvins; k++)
                {
                    //printf("item.%p [%d] X.%p i.%d j.%d k.%d txidind.%d/%d spendind.%d/%d s->txidind.%d/v%d\n",item,item->numexternaltxids,item->externalT,i,j,k,txidind,ramchain->numtxids,spendind,ramchain->numspends,item->S[k].spendtxidind,item->S[k].vout);
                    if ( iguana_ramchaintxid(coin,&txid,item,&item->S[k]) < 0 )
                    {
                        printf("i.%d j.%d k.%d error getting txid firsti.%d X.%d vout.%d spend.%d/%d numX.%d numT.%d\n",i,j,k,item->firsti,item->S[k].external,item->S[k].vout,item->S[k].spendtxidind,item->numspends,item->numexternaltxids,item->numtxids);
                        //iguana_ramchainfree(coin,mem,ramchain);
                        //return(0);
                    }
                    s = &ramchain->S[spendind];
                    *s = item->S[k];
                    if ( s->vout == 0xffff )
                    {
                        // mining output
                    }
                    else if ( (ptr= iguana_hashfind(ramchain->txids,txid.bytes,sizeof(txid))) != 0 )
                    {
                        if ( (s->spendtxidind= ptr->hh.itemind) >= ramchain->numtxids )
                        {
                            s->external = 1;
                            s->spendtxidind -= ramchain->numtxids;
                        }
                        else if ( s->spendtxidind >= item->firsti && s->spendtxidind < item->numtxids )
                        {
                            s->external = 0;
                            unspentind = (ramchain->T[s->spendtxidind].firstvout + s->vout);
                            u = &ramchain->U[unspentind];
                            p = &ramchain->P[u->pkind];
                            if ( ramchain->pkextras[u->pkind].firstspendind == 0 )
                                ramchain->pkextras[u->pkind].firstspendind = spendind;
                            acct = &ramchain->accounts[u->pkind];
                            s->prevspendind = acct->lastspendind;
                            acct->lastspendind = spendind;
                            if ( ramchain->Uextras[unspentind].spendind != 0 )
                            {
                                printf("double spend u.%d has spendind.%d when s.%d refers to it\n",unspentind,ramchain->Uextras[unspentind].spendind,spendind);
                                iguana_ramchainfree(coin,mem,ramchain);
                                return(0);
                            }
                            ramchain->Uextras[unspentind].spendind = spendind;
                        }
                        spendind++;
                    }
                    else if ( numexternaltxids < ramchain->numexternaltxids )
                    {
                        s->external = 1;
                        ramchain->externalT[numexternaltxids] = txid;
                        iguana_hashsetHT(ramchain->txids,0,ramchain->externalT[numexternaltxids].bytes,sizeof(ramchain->externalT[numexternaltxids]),ramchain->numtxids + numexternaltxids);
                        s->spendtxidind = numexternaltxids++;
                        spendind++;
                    }
                    else printf("numexternaltxids.%d >= ramchain numexternaltxids.%d\n",numexternaltxids,ramchain->numexternaltxids);
                }
            }
            // iguana_unspent { uint64_t value; uint32_t txidind,pkind,prevunspentind; } iguana_Uextra { uint32_t spendind; }
            // iguana_pkhash { uint8_t rmd160[20]; uint32_t firstunspentind,flags; } iguana_pkextra { uint32_t firstspendind; }
            // iguana_account { uint64_t balance; uint32_t lastunspentind,lastspendind; }
            // iguana_spend { uint32_t unspentind,prevspendind:31,diffsequence:1; }
            numspends += item->numspends;
        }
    }
    //for (i=0; i<numpkinds; i++)
    //    printf("have pkind.%d: %p %016lx\n",i,&ramchain->P[i],*(long *)ramchain->P[i].rmd160);
    //printf("numpkinds.%d\n",numpkinds);
    if ( 0 )
    {
        memcpy(&ramchain->P[numpkinds],ramchain->pkextras,sizeof(*ramchain->pkextras) * numpkinds);
        ramchain->pkextras = (void *)&ramchain->P[numpkinds];
        memcpy(&ramchain->pkextras[numpkinds],ramchain->accounts,sizeof(*ramchain->accounts) * numpkinds);
        ramchain->accounts = (void *)&ramchain->pkextras[numpkinds];
        memcpy(&ramchain->accounts[numpkinds],ramchain->externalT,sizeof(*ramchain->externalT) * numexternaltxids);
        ramchain->externalT = (void *)&ramchain->accounts[numpkinds];
    }
    ramchain->allocsize -= ((ramchain->numpkinds - numpkinds) * (sizeof(*ramchain->P) + sizeof(*ramchain->pkextras) + sizeof(*ramchain->accounts)));
    ramchain->allocsize -= ((ramchain->numexternaltxids - numexternaltxids) * sizeof(*ramchain->externalT));
    ramchain->numpkinds = numpkinds;
    ramchain->numexternaltxids = numexternaltxids;
    /*vupdate_sha256(ramchain->lhashes[IGUANA_LHASH_UNSPENT].bytes,&ramchain->states[IGUANA_LHASH_UNSPENT],(void *)ramchain->U,sizeof(*ramchain->U)*ramchain->numunspents);
    vupdate_sha256(ramchain->lhashes[IGUANA_LHASH_ACCOUNTS].bytes,&ramchain->states[IGUANA_LHASH_ACCOUNTS],(void *)acct,sizeof(*acct));
    vupdate_sha256(ramchain->lhashes[IGUANA_LHASH_SPENDS].bytes,&ramchain->states[IGUANA_LHASH_SPENDS],(void *)ramchain->S,sizeof(*ramchain->S)*);
    vupdate_sha256(ramchain->lhashes[IGUANA_LHASH_TXIDS].bytes,&ramchain->states[IGUANA_LHASH_TXIDS],(void *)tx,sizeof(*tx));*/
    mem->used = (long)ramchain->allocsize;
    printf("B.%d T.%d U.%d S.%d P.%d combined ramchain size.%ld\n",ramchain->numblocks,ramchain->numtxids,ramchain->numunspents,ramchain->numspends,ramchain->numpkinds,(long)ramchain->allocsize);
    return(ramchain);
}
