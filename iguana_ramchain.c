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

uint32_t iguana_txidind(struct iguana_info *coin,uint32_t *firstvoutp,uint32_t *firstvinp,bits256 txid)
{
    struct iguana_txid tx; uint32_t itemind = 0;
    memset(&tx,0,sizeof(tx));
    if ( iguana_kvread(coin,coin->txids,txid.bytes,&tx,&itemind) != 0 )
    {
        //printf("%s -> itemind.%d\n",bits256_str(txid),itemind);
        if ( firstvoutp != 0 )
            *firstvoutp = tx.firstvout;
        if ( firstvinp != 0 )
            *firstvinp = tx.firstvin;
        if ( tx.firstvout > coin->latest.dep.numunspents )
        {
            printf("iguana_txidind: firsttxout.%d vs %d\n",tx.firstvout,coin->latest.dep.numunspents);
            getchar();
            return(0);
        }
        return(itemind);
    }
    char str[65];
    bits256_str(str,txid);
    printf("%s -> error\n",str);
    //iguana_kvdisp(coin,coin->txids);
    if ( firstvoutp != 0 )
        *firstvoutp = 0;
    if ( firstvinp != 0 )
        *firstvinp = 0;
    return(itemind);
}

bits256 iguana_txidstr(struct iguana_info *coin,uint32_t *firstvoutp,uint32_t *firstvinp,char *txidstr,uint32_t txidind)
{
    struct iguana_txid tx;
    memset(&tx,0,sizeof(tx));
    if ( iguana_kvread(coin,coin->txids,0,&tx,&txidind) != 0 )
    {
        if ( firstvoutp != 0 )
            *firstvoutp = tx.firstvout;
        if ( firstvinp != 0 )
            *firstvinp = tx.firstvin;
        if ( txidstr != 0 )
            init_hexbytes_noT(txidstr,tx.txid.bytes,sizeof(tx.txid));
    }
    else
    {
        if ( txidstr != 0 )
            txidstr[0] = 0;
        if ( firstvoutp != 0 )
            *firstvoutp = 0;
        if ( firstvinp != 0 )
            *firstvinp = 0;
    }
    return(tx.txid);
}

uint32_t iguana_pkind(struct iguana_info *coin,uint8_t rmd160[20],uint32_t unspentind)
{
    uint32_t pkind = -1; struct iguana_pkhash P;
    memset(&P,0,sizeof(P));
    if ( iguana_kvread(coin,coin->pkhashes,rmd160,&P,&pkind) == 0 )
    {
        //fprintf(stderr,"P");
        pkind = coin->latest.dep.numpkinds;
        memcpy(P.rmd160,rmd160,sizeof(P.rmd160));
        P.firstunspentind = unspentind;
        if ( iguana_kvwrite(coin,coin->pkhashes,rmd160,&P,&pkind) == 0 )
        {
            char hexstr[41];
            init_hexbytes_noT(hexstr,rmd160,20);
            printf("iguana_pkind: cant save.(%s)\n",hexstr);
            return(0);
        }
    }
    return(pkind);
}

int32_t iguana_rwtxidind(struct iguana_info *coin,int32_t rwflag,struct iguana_txid *T,uint32_t txidind)
{
    if ( rwflag == 0 )
    {
        memset(T,0,sizeof(*T));
        if ( iguana_kvread(coin,coin->txids,0,T,&txidind) != 0 )
            return(0);
        else printf("error getting txidind[%u] when %d\n",txidind,coin->latest.dep.numtxids);
    }
    else if ( iguana_kvwrite(coin,coin->txids,0,T,&txidind) != 0 )
        return(0);
    return(-1);
}

int32_t iguana_rwpkind(struct iguana_info *coin,int32_t rwflag,struct iguana_pkhash *P,uint32_t pkind)
{
    if ( rwflag == 0 )
    {
        memset(P,0,sizeof(*P));
        if ( iguana_kvread(coin,coin->pkhashes,0,P,&pkind) != 0 )
            return(0);
        else printf("error getting pkhash[%u] when %d\n",pkind,coin->latest.dep.numpkinds);
    }
    else if ( iguana_kvwrite(coin,coin->pkhashes,0,P,&pkind) != 0 )
        return(0);
    return(-1);
}

int32_t iguana_createunspentind(struct iguana_info *coin,struct iguana_unspent *U,uint32_t unspentind)
{
    int32_t retval;
    vupdate_sha256(coin->latest.lhashes[IGUANA_LHASH_UNSPENTS].bytes,&coin->latest.states[IGUANA_LHASH_UNSPENTS],(void *)U,sizeof(*U));
    retval = (iguana_kvwrite(coin,coin->unspents,0,U,&unspentind) != 0 ? 0 : -1);
    memset(&coin->Uextras[unspentind],0,sizeof(coin->Uextras[unspentind]));
    return(retval);
}

int32_t iguana_createspendind(struct iguana_info *coin,struct iguana_spend *S,uint32_t spendind)
{
    vupdate_sha256(coin->latest.lhashes[IGUANA_LHASH_SPENDS].bytes,&coin->latest.states[IGUANA_LHASH_SPENDS],(void *)S,sizeof(*S));
    return(iguana_kvwrite(coin,coin->spends,0,S,&spendind) != 0 ? 0 : -1);
}

uint64_t iguana_utxo(struct iguana_info *coin,struct iguana_unspent *U,uint32_t txidind,int16_t vout)
{
    struct iguana_txid *tx; uint32_t unspentind;
    tx = &coin->T[txidind];
    if ( txidind < coin->latest.dep.numtxids && tx->firstvout > 0 )
    {
        unspentind = tx->firstvout + vout;
        if ( unspentind < coin->latest.dep.numunspents && coin->Uextras[unspentind].spendind == 0 )
            return(coin->U[unspentind].value);
    } else printf("error getting txoffsets for txidind.%u\n",txidind), getchar();
    return(0);
}

uint32_t iguana_addunspent(struct iguana_info *coin,uint32_t blocknum,uint32_t txidind,uint32_t unspentind,uint64_t value,uint8_t *pk_script,int32_t pk_scriptlen,bits256 txid)
{
    struct iguana_unspent U; struct iguana_account *acct; uint8_t rmd160[20]; int32_t pkind = -1;
    if ( unspentind != coin->latest.dep.numunspents )
        printf("unspentind mismatch %d vs %d\n",unspentind,coin->latest.dep.numunspents), getchar();
    if ( iguana_calcrmd160(coin,rmd160,pk_script,pk_scriptlen,txid) == 0 && (pkind= iguana_pkind(coin,rmd160,unspentind)) > 0 )
    {
        if ( pkind == coin->latest.dep.numpkinds )
        {
            uint8_t buf[sizeof(rmd160)+sizeof(uint32_t)];
            memcpy(buf,rmd160,sizeof(rmd160));
            memcpy(&buf[sizeof(rmd160)],&unspentind,sizeof(unspentind));
            //char hexstr[41];//,coinaddr[64];
            //init_hexbytes_noT(hexstr,P.rmd160,20);
            //btc_convrmd160(coinaddr,coin->chain->addr_pubkey,P.rmd160);b
            //printf("new pkind.%d pkhash.(%s) %.8f\n",pkind,hexstr,dstr(value));
            vupdate_sha256(coin->latest.lhashes[IGUANA_LHASH_PKHASHES].bytes,&coin->latest.states[IGUANA_LHASH_PKHASHES],buf,sizeof(buf));
            memset(&coin->accounts[pkind],0,sizeof(coin->accounts[pkind]));
            memset(&coin->pkextras[pkind],0,sizeof(coin->pkextras[pkind]));
            coin->latest.dep.numpkinds = (pkind + 1);
        } //else printf("pkind.%d != numpkhashes.%d\n",pkind,coin->latest.dep.numpkinds);
        acct = &coin->accounts[pkind];
        coin->latest.dep.supply += value, coin->latest.credits += value, acct->balance += value;
        if ( acct->lastunspentind != 0 )
        {
            if ( acct->lastunspentind < coin->latest.dep.numunspents )
            {
                if ( coin->U[unspentind].prevunspentind != 0 && coin->U[unspentind].prevunspentind != acct->lastunspentind )
                    printf("warning: overwriting U%d next %d with %d\n",acct->lastunspentind,coin->U[unspentind].prevunspentind,unspentind);
            } else printf("block.%d U%d -> %.8f account[%d]:%d lastunspent.%d vs numunspents.%d\n",blocknum,unspentind,dstr(acct->balance),pkind,coin->latest.dep.numpkinds,acct->lastunspentind,coin->latest.dep.numunspents);
        }
        //printf("U%d vs %d: T%d P%d last.(U%d S%d) %.8f\n",unspentind,coin->latest.dep.numunspents,txidind,pkind,acct->lastunspentind,acct->lastspendind,dstr(value));
        memset(&U,0,sizeof(U)), U.value = value, U.pkind = pkind, U.txidind = txidind;
        if ( iguana_createunspentind(coin,&U,unspentind) < 0 )
        {
            printf("rwpkind error for pkind.%d U%d\n",pkind,unspentind);
            return(0);
        }
        //printf("Uextras[U%d].prevunspentind <- P[%d] lastunspentind U%d\n",unspentind,pkind,acct->lastunspentind);
        coin->U[unspentind].prevunspentind = acct->lastunspentind;
        vupdate_sha256(coin->latest.lhashes[IGUANA_LHASH_UPREV].bytes,&coin->latest.states[IGUANA_LHASH_UPREV],(void *)&acct->lastunspentind,sizeof(acct->lastunspentind));
        acct->lastunspentind = unspentind;
        coin->latest.dep.numunspents = (unspentind + 1);
        return(unspentind);
     } else printf("error iguana_addunspent U%d rmd160 err pkind.%d\n",unspentind,pkind), getchar();
    return(0);
}

uint32_t iguana_addspend(struct iguana_info *coin,uint64_t *spentvaluep,uint32_t blocknum,uint32_t txidind,uint32_t spendind,uint32_t spendtxidind,uint32_t vout,uint8_t *script,int32_t scriptlen,uint32_t sequence)
{
    struct iguana_spend S; struct iguana_account *acct; uint32_t pkind;
    struct iguana_unspent U; uint32_t unspentind; uint32_t buf[2];
    memset(&S,0,sizeof(S)), memset(&U,0,sizeof(U));
    *spentvaluep = 0;
    if ( spendind != coin->latest.dep.numspends )
        printf("spendind mismatch %d vs %d\n",spendind,coin->latest.dep.numspends), getchar();
    if ( spendtxidind == 0 || spendtxidind >= coin->latest.dep.numtxids )
    {
        printf(">>>>>>>>>>>> illegal spendtxidind.%d for spendind.%d\n",spendtxidind,spendind);
        return(0);
    }
    unspentind = coin->T[spendtxidind].firstvout + vout;
    if ( unspentind == 0 || (S.spendtxidind= unspentind) >= coin->latest.dep.numunspents )
        printf(">>>>>>>>>>>> height.%d T%d error unspent.%d overflow vs %d spend.%d\n",blocknum,txidind,unspentind,coin->latest.dep.numunspents,spendind), getchar();
    coin->Uextras[unspentind].spendind = spendind;
    buf[0] = unspentind;
    buf[1] = spendind;
    //printf("Uextras[U%d].spendind <- S%d\n",unspentind,spendind);
    vupdate_sha256(coin->latest.lhashes[IGUANA_LHASH_USPEND].bytes,&coin->latest.states[IGUANA_LHASH_USPEND],(void *)buf,sizeof(buf));
    //printf("S%d: T%d v%d U%d %.8f P%d\n",spendind,txidind,vout,unspentind,dstr(coin->U[unspentind].value),coin->U[unspentind].pkind);
    *spentvaluep = coin->U[unspentind].value;
    if ( (pkind= coin->U[unspentind].pkind) > 0 && pkind < coin->latest.dep.numpkinds )
    {
        acct = &coin->accounts[pkind];
        //printf("pkind.%d accounts.%p\n",pkind,coin->accounts);
        if ( coin->pkextras[pkind].firstspendind == 0 )
        {
            buf[0] = pkind, buf[1] = spendind;
            coin->pkextras[pkind].firstspendind = spendind;
            //printf("P[%d] firstspendind <- S%d\n",pkind,spendind);
            vupdate_sha256(coin->latest.lhashes[IGUANA_LHASH_PKFIRSTSPEND].bytes,&coin->latest.states[IGUANA_LHASH_PKFIRSTSPEND],(void *)buf,sizeof(buf));
        }
        if ( acct->balance >= coin->U[unspentind].value )
            coin->latest.dep.supply -= coin->U[unspentind].value, coin->latest.debits += coin->U[unspentind].value, acct->balance -= coin->U[unspentind].value;
        else printf(">>>>>>>>>>>> error height.%d T%d unspent.%d %.8f pkind.%d of %d overspend balance %.8f spend.%d\n",blocknum,spendtxidind,unspentind,dstr(coin->U[unspentind].value),pkind,coin->latest.dep.numpkinds,dstr(coin->accounts[pkind].balance),spendind), getchar();
        if ( acct->lastspendind != 0 )
        {
            if ( acct->lastspendind < coin->latest.dep.numspends )
            {
                if ( coin->S[spendind].prevspendind != 0 && coin->S[spendind].prevspendind != acct->lastspendind )
                    printf(">>>>>>>>>>>> warning: S%d T%d overwriting S%d prev %d with %d\n",spendind,spendtxidind,acct->lastspendind,coin->S[spendind].prevspendind,acct->lastspendind), getchar();
                //printf("Sprev[%d] <- S%d\n",spendind,acct->lastspendind);
            } else printf("T%d S%d -> U%d account[%d] lastspendind.%d vs numspends.%d\n",spendtxidind,spendind,unspentind,pkind,acct->lastspendind,coin->latest.dep.numspends);
        }
        if ( iguana_createspendind(coin,&S,spendind) < 0 )
        {
            printf("error saving spendind.%d\n",spendind);
            getchar();
            return(-1);
        }
        //printf("Sextras[S%d].prevspendind <- P%d.lastspendind %d\n",spendind,pkind,acct->lastspendind);
        coin->S[spendind].prevspendind = acct->lastspendind;
        vupdate_sha256(coin->latest.lhashes[IGUANA_LHASH_SPREV].bytes,&coin->latest.states[IGUANA_LHASH_SPREV],(void *)&acct->lastspendind,sizeof(acct->lastspendind));
        acct->lastspendind = spendind;
        coin->latest.dep.numspends = (spendind + 1);
        return(spendind);
    } else printf("error unspent.%d pkind.%d/%d spend.%d\n",unspentind,pkind,coin->latest.dep.numpkinds,spendind), getchar();
    return(0);
}

uint32_t iguana_addtxid(struct iguana_info *coin,uint32_t txidind,bits256 txid,uint32_t firstvout,int32_t numvouts,uint32_t firstvin,int32_t numvins,uint32_t version,uint32_t lock_time)
{
    struct iguana_txid tx;
    if ( txidind == coin->latest.dep.numtxids )
    {
        //printf("%llx crc.%x addtxid.%u: %s (%d %d)",(long long)coin->latest.lhashes[IGUANA_LHASH_TXIDS].txid,calc_crc32(0,&coin->latest.states[IGUANA_LHASH_TXIDS],sizeof(coin->latest.states[IGUANA_LHASH_TXIDS])),txidind,bits256_str(txid),firstvout,firstvin);
        //printf("T%d 1st(U%d S%d)\n",txidind,firstvout,firstvin);
        memset(&tx,0,sizeof(tx));
        tx.txid = txid, tx.firstvout = firstvout, tx.firstvin = firstvin;
        vupdate_sha256(coin->latest.lhashes[IGUANA_LHASH_TXIDS].bytes,&coin->latest.states[IGUANA_LHASH_TXIDS],(void *)&tx,sizeof(tx));
        //fprintf(stderr,"T");
        iguana_kvwrite(coin,coin->txids,tx.txid.bytes,&tx,&txidind);
        coin->totalsize += sizeof(tx);
        //printf("<<<<<<<<<<<< setnext txidind.%d %llx\n",coin->latest.dep.numtxids,(long long)coin->latest.lhashes[IGUANA_LHASH_TXIDS].txid);
        coin->latest.dep.numtxids = txidind+1;
        return(txidind);
    } else printf("iguana_addtxid: txidind mismatch %d != nexttxidind %d\n",txidind,coin->latest.dep.numtxids); getchar();
    return(0);
}

int64_t iguana_verifyaccount(struct iguana_info *coin,struct iguana_account *acct,uint32_t pkind)
{
    uint32_t prev,firstunspentind,firstspendind,unspentind; int64_t credits,debits,Udebits;
    credits = debits = Udebits = 0;
    while ( acct->lastunspentind >= coin->latest.dep.numunspents )
    {
        if ( (prev= coin->U[acct->lastunspentind].prevunspentind) < acct->lastunspentind )
            acct->lastunspentind = prev;
        else return(-1);
    }
    while ( acct->lastspendind >= coin->latest.dep.numspends )
    {
        if ( (prev= coin->S[acct->lastspendind].prevspendind) < acct->lastspendind )
            acct->lastspendind = prev;
        else return(-1);
    }
    prev = acct->lastunspentind, firstunspentind = 0;
    while ( prev != 0 )
    {
        firstunspentind = prev;
        if ( coin->U[prev].prevunspentind >= prev )
        {
            printf("pkind.%d illegal coin->U[%d].prevunspentind of %d\n",pkind,prev,coin->U[prev].prevunspentind);
            return(-2);
        }
        if ( coin->U[prev].pkind != pkind )
        {
            printf("pkind.%d fatal pkind mismatch coin->U[%d].pkind %d != %d pkind\n",pkind,prev,coin->U[prev].pkind,pkind);
            return(-3);
        }
        if ( coin->Uextras[prev].spendind >= coin->latest.dep.numspends )
        {
            printf("pkind.%d coin->Uextras[%d] %d >= %d coin->latest.dep.numspends\n",pkind,prev,coin->Uextras[prev].spendind,coin->latest.dep.numspends);
            return(-4);
        }
        credits += coin->U[prev].value;
        if ( coin->Uextras[prev].spendind != 0 )
            Udebits += coin->U[prev].value;
        prev = coin->U[prev].prevunspentind;
    }
    if ( firstunspentind != coin->P[pkind].firstunspentind )
    {
        printf("pkind.%d firstunspentind %u != %u coin->P[pkind].firstunspentind\n",pkind,firstunspentind,coin->P[pkind].firstunspentind );
        return(-5);
    }
    prev = acct->lastspendind, firstspendind = 0;
    while ( prev != 0 )
    {
        firstspendind = prev;
        if ( (unspentind= coin->S[prev].spendtxidind) == 0 || unspentind >= coin->latest.dep.numunspents )
        {
            printf("pkind.%d S[%d] -> U%d illegal numunspents.%d\n",pkind,prev,unspentind,coin->latest.dep.numunspents);
            return(-6);
        }
        if ( coin->Uextras[unspentind].spendind != prev )
        {
            printf("mismatch: pkind.%d coin->Uextras[%d].spendind %d != %d prev\n",pkind,prev,coin->Uextras[unspentind].spendind,prev);
            {
                prev = acct->lastspendind, firstspendind = 0;
                while ( prev != 0 )
                {
                    printf("(U%d S%d).S%d ",coin->S[prev].spendtxidind,coin->S[prev].prevspendind,prev);
                    prev = coin->S[prev].prevspendind;
                }
                printf("prevspendinds for S%d for acct[%d]\n",acct->lastspendind,pkind);
            }
            return(-7);
        }
        debits += coin->U[unspentind].value;
        prev = coin->S[prev].prevspendind;
    }
    if ( firstspendind != coin->pkextras[pkind].firstspendind )
    {
        printf("firstspendind %u != %u coin->P[%d].firstspendind\n",firstspendind,coin->pkextras[pkind].firstspendind,pkind);
        return(-8);
    }
    if ( debits != Udebits )
    {
        printf("pkind.%d: debits %.8f != Udebits %.8f\n",pkind,dstr(debits),dstr(Udebits));
        return(-9);
    }
    if ( acct->balance != (credits - debits) )
    {
        if ( credits < debits )
        {
            printf("pkind.%d balance mismatch %.8f != %.8f (%.8f - %.8f)\n",pkind,dstr(acct->balance),dstr(credits)-dstr(debits),dstr(credits),dstr(debits));
            {
                prev = acct->lastunspentind;
                while ( prev != 0 )
                {
                    printf("(U%d %.8f P%d S%d) ",prev,dstr(coin->U[prev].value),coin->U[prev].pkind,coin->Uextras[prev].spendind);
                    prev = coin->U[prev].prevunspentind;
                }
                printf("prevunspentinds for U%d for acct[%d]\n",acct->lastunspentind,pkind);
                prev = acct->lastspendind;
                while ( prev != 0 )
                {
                    printf("(U%d %.8f S%d).S%d ",coin->S[prev].spendtxidind,dstr(coin->U[coin->S[prev].spendtxidind].value),coin->S[prev].prevspendind,prev);
                    prev = coin->S[prev].prevspendind;
                }
                printf("prevspendinds for S%d for acct[%d]\n",acct->lastspendind,pkind);
            }
            return(-10);
        }
        acct->balance = (credits - debits);
    }
    return(acct->balance);
}

int32_t ramchain_parsetx(struct iguana_info *coin,int64_t *miningp,int64_t *totalfeesp,uint16_t *numvoutsp,uint16_t *numvinsp,int32_t blocknum,int32_t txind,struct iguana_msgtx *tx,uint32_t txidind,uint32_t firstvout,uint32_t firstvin)
{
    uint32_t t,spendtxidind,spentind,unspentind,spendind; int64_t inputs,outputs; uint64_t spentvalue,reward;
    int32_t i,numvins=0,numvouts=0; struct iguana_block *block=0; struct iguana_msgvin *vin;
    *numvinsp = *numvoutsp = 0;
    unspentind = firstvout;
    spendind = firstvin;
    //printf("ramchain blocknum.%d firstvin.%d firstvout.%d vouts.%d vins.%d tx.%p txid.(%s)\n",blocknum,firstvin,firstvout,tx->tx_out,tx->tx_in,tx,bits256_str(tx->txid));
    if ( blocknum != coin->blocks.parsedblocks )
    {
        printf("ramchain_parsetx: skip block.%d when parsed.%d\n",blocknum,coin->blocks.parsedblocks);
        return(-1);
    }
    inputs = outputs = 0;
    if ( blocknum >= 0 && (block= iguana_blockptr(coin,blocknum)) != 0 && txidind > 0 && unspentind > 0 && spendind > 0 )
    {
        if ( (blocknum == 91842 || blocknum == 91880) && txind == 0 && strcmp(coin->name,"bitcoin") == 0 )
            tx->txid.ulongs[0] ^= blocknum;
        if ( (t= iguana_addtxid(coin,txidind,tx->txid,firstvout,tx->tx_out,firstvin,tx->tx_in,tx->version,tx->lock_time)) == txidind )
        {
            for (i=0; i<tx->tx_out; i++)
            {
                //fprintf(stderr,"u");
                iguana_addunspent(coin,blocknum,txidind,unspentind,tx->vouts[i].value,tx->vouts[i].pk_script,tx->vouts[i].pk_scriptlen,tx->txid);
                numvouts++;
                unspentind++;
                outputs += tx->vouts[i].value;
            }
            coin->T[txidind+1].firstvout = unspentind;
            for (i=0; i<tx->tx_in; i++)
            {
                //fprintf(stderr,"s");
                vin = &tx->vins[i];
                if ( bits256_nonz(vin->prev_hash) == 0 )
                {
                    if ( i == 0 && (int32_t)vin->prev_vout < 0 )
                    {
                        reward = iguana_miningreward(coin,blocknum);
                        //printf("reward %.8f\n",dstr(reward));
                        inputs += reward;
                        (*miningp) += reward;
                    } else printf("unexpected prevout.%d\n",vin->prev_vout), getchar();
                    continue;
                }
                //printf("do spend.%s\n",bits256_str(vin->prev_hash));
                if ( (spendtxidind= iguana_txidind(coin,&spentind,0,vin->prev_hash)) > 0 )
                {
                    //fprintf(stderr,"S");
                    iguana_addspend(coin,&spentvalue,blocknum,txidind,spendind,spendtxidind,vin->prev_vout,vin->script,vin->scriptlen,vin->sequence);
                    numvins++;
                    spendind++;
                    inputs += spentvalue;
                }
                else
                {
                    char str[65];
                    bits256_str(str,vin->prev_hash);
                    printf("block.%u txindind.%u cant find prev_hash.(%s)\n",blocknum,txidind,str);
                    getchar();
                    break;
                }
            }
            coin->T[txidind+1].firstvin = spendind;
            *numvoutsp = numvouts;
            *numvinsp = numvins;
            if ( txind != 0 && outputs > inputs ) // need to calculate after entire block, also single thread all ramchains and add way to regen from reorg, ledgerhashes, sync to ledger, scripts and balances
            {
                char str[65];
                bits256_str(str,tx->txid);
                printf("FEECALC ERROR %s outputs %.8f > inputs %.8f\n",str,dstr(outputs),dstr(inputs));
            }
            (*totalfeesp) += (outputs - inputs);
            return(0);
        } else printf("ERROR block.%u got %d vs txidind.%d\n",blocknum,t,txidind), getchar();
    } else printf("ERROR ramchain_parsetx error blocknum.%u block.%p 1st.%d %d %d\n",blocknum,block,txidind,firstvin,firstvout), getchar();
    if ( numvins >= 65536 || numvouts >= 65535 )
        printf("numvins.%d or numvouts.%d overflow\n",numvins,numvouts), getchar();
    return(-1);
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

int32_t iguana_hashfree(struct iguana_kvitem *hashtable)
{
    struct iguana_kvitem *item,*tmp; int32_t n = 0;
    HASH_ITER(hh,hashtable,item,tmp)
    {
        HASH_DEL(hashtable,item);
        n++;
    }
    return(n);
}

struct iguana_txblock *iguana_ramchainptrs(struct iguana_txid **Tptrp,struct iguana_unspent **Uptrp,struct iguana_spend **Sptrp,struct iguana_pkhash **Pptrp,bits256 **externalTptrp,struct iguana_memspace *mem,struct iguana_txblock *origtxdata)
{
    struct iguana_txblock *txdata; int32_t allocsize,extralen,rwflag = (origtxdata != 0);
    iguana_memreset(mem);
    allocsize = (int32_t)(sizeof(*txdata) - sizeof(txdata->space) + ((origtxdata != 0) ? origtxdata->extralen : 0));
    mem->alignflag = sizeof(uint32_t);
    if ( (txdata= iguana_memalloc(mem,allocsize,0)) == 0 )
        return(0);
    extralen = (origtxdata != 0) ? origtxdata->extralen : txdata->extralen;
    if ( origtxdata != 0 )
        memcpy(txdata,origtxdata,allocsize);
    else iguana_memalloc(mem,txdata->extralen,0);
    *Tptrp = iguana_memalloc(mem,sizeof(**Tptrp) * txdata->numtxids,rwflag);
    *Uptrp = iguana_memalloc(mem,sizeof(**Uptrp) * txdata->numunspents,rwflag);
    *Sptrp = iguana_memalloc(mem,sizeof(**Sptrp) * txdata->numspends,rwflag);
    if ( externalTptrp != 0 )
    {
        if ( txdata->pkoffset != (int32_t)mem->used )
            printf("iguana_ramchainptrs pkoffset.%d != %ld numspends.%d\n",txdata->pkoffset,mem->used,txdata->numspends), getchar();
        *Pptrp = iguana_memalloc(mem,sizeof(**Pptrp) * txdata->numpkinds,rwflag);
        *externalTptrp = iguana_memalloc(mem,txdata->numexternaltxids * sizeof(**externalTptrp),rwflag);
    }
    else
    {
        txdata->pkoffset = (int32_t)mem->used;
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
        iguana_hashfree(ramchain->txids);
    if ( ramchain->pkhashes != 0 )
        iguana_hashfree(ramchain->pkhashes);
    iguana_mempurge(mem);
    return(0);
}

struct iguana_ramchain *iguana_ramchainset(struct iguana_info *coin,struct iguana_ramchain *ramchain,struct iguana_txblock *txdata)
{
    struct iguana_memspace txmem;
    memset(&txmem,0,sizeof(txmem));
    iguana_meminit(&txmem,"bramchain",txdata,txdata->datalen,0);
    printf("ramchainset <- txdata.%p memptr.%p\n",txdata,txmem.ptr);
    if ( iguana_ramchainptrs(&ramchain->T,&ramchain->U,&ramchain->S,&ramchain->P,&ramchain->externalT,&txmem,0) != txdata || ramchain->T == 0 || ramchain->U == 0 || ramchain->S == 0 || ramchain->P == 0 )
    {
        printf("iguana_ramchainset: cant set pointers txdata.%p\n",txdata);
        return(0);
    }
   int32_t i;
    for (i=0; i<344; i++)
        printf("%02x ",((uint8_t *)txdata)[i]);
    for (i=-1; i<2; i++)
        printf("%016lx ",*(long *)((struct iguana_pkhash *)((long)txdata + txdata->pkoffset))[i].rmd160);
    printf("datalen.%d T.%d U.%d S.%d P.%d X.%d | %d vs %d ramchain.%p txdata.%p\n",txdata->datalen,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds,txdata->numexternaltxids,txdata->pkoffset,(int32_t)((long)ramchain->P - (long)txdata),ramchain,txdata);
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

struct iguana_ramchain *iguana_ramchainmergeHT(struct iguana_info *coin,struct iguana_memspace *mem,struct iguana_ramchain *ramchains[],int32_t n,struct iguana_bundle *bp)
{
    uint32_t numtxids,numunspents,numspends,numpkinds,numexternaltxids,i,j,k; uint64_t allocsize = 0;
    struct iguana_txid *tx;  struct iguana_account *acct; struct iguana_ramchain *ramchain,*item;
    struct iguana_pkhash *p,oldP; struct iguana_unspent *u; struct iguana_kvitem *ptr;
    bits256 txid; char str[65]; uint32_t txidind,unspentind,spendind,pkind; struct iguana_spend *s;
    numtxids = numunspents = numspends = numpkinds = 1;
    numexternaltxids = 0;
    for (i=0; i<n; i++)
    {
        if ( (item= ramchains[i]) == 0 )
        {
            printf("iguana_ramchaininit null hdrsi.%d txdatas[%d]\n",bp->hdrsi,i);
            return(0);
        }
        numtxids += item->numtxids, numunspents += item->numunspents, numspends += item->numspends;
        numpkinds += item->numpkinds, numexternaltxids += item->numexternaltxids;
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
    ramchain->numtxids = numtxids, ramchain->numunspents = numunspents;
    ramchain->numspends = numspends, ramchain->numpkinds = numpkinds;
    ramchain->numexternaltxids = numexternaltxids;
    ramchain->hdrsi = bp->hdrsi, ramchain->bundleheight = bp->bundleheight, ramchain->numblocks = n;
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
    printf("Allocated %s for bp %d\n",mbstr(str,allocsize),bp->bundleheight);
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
                        printf("pkind.%d: %p %016lx <- %016lx\n",pkind,p,*(long *)p->rmd160,*(long *)oldP.rmd160);
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
                        printf("error getting txid\n");
                        iguana_ramchainfree(coin,mem,ramchain);
                        return(0);
                    }
                    s = &ramchain->S[spendind];
                    *s = item->S[k];
                    if ( s->vout == 0xffff )
                    {
                        // mining output
                    }
                    else if ( (ptr= iguana_hashfind(ramchain->txids,tx->txid.bytes,sizeof(tx->txid))) != 0 )
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
    for (i=0; i<numpkinds; i++)
        printf("have pkind.%d: %p %016lx\n",i,&ramchain->P[i],*(long *)ramchain->P[i].rmd160);
    printf("numpkinds.%d\n",numpkinds);
    memcpy(&ramchain->P[numpkinds],ramchain->pkextras,sizeof(*ramchain->pkextras) * numpkinds);
    ramchain->pkextras = (void *)&ramchain->P[numpkinds];
    memcpy(&ramchain->pkextras[numpkinds],ramchain->accounts,sizeof(*ramchain->accounts) * numpkinds);
    ramchain->accounts = (void *)&ramchain->pkextras[numpkinds];
    memcpy(&ramchain->accounts[numpkinds],ramchain->externalT,sizeof(*ramchain->externalT) * numexternaltxids);
    ramchain->externalT = (void *)&ramchain->accounts[numpkinds];
    ramchain->allocsize -= ((ramchain->numpkinds - numpkinds) * (sizeof(*ramchain->P) + sizeof(*ramchain->pkextras) + sizeof(*ramchain->accounts)));
    ramchain->allocsize -= ((ramchain->numexternaltxids - numexternaltxids) * sizeof(*ramchain->externalT));
    ramchain->numpkinds = numpkinds;
    ramchain->numexternaltxids = numexternaltxids;
    /*vupdate_sha256(ramchain->lhashes[IGUANA_LHASH_UNSPENT].bytes,&ramchain->states[IGUANA_LHASH_UNSPENT],(void *)ramchain->U,sizeof(*ramchain->U)*ramchain->numunspents);
    vupdate_sha256(ramchain->lhashes[IGUANA_LHASH_ACCOUNTS].bytes,&ramchain->states[IGUANA_LHASH_ACCOUNTS],(void *)acct,sizeof(*acct));
    vupdate_sha256(ramchain->lhashes[IGUANA_LHASH_SPENDS].bytes,&ramchain->states[IGUANA_LHASH_SPENDS],(void *)ramchain->S,sizeof(*ramchain->S)*);
    vupdate_sha256(ramchain->lhashes[IGUANA_LHASH_TXIDS].bytes,&ramchain->states[IGUANA_LHASH_TXIDS],(void *)tx,sizeof(*tx));*/
    mem->used = (long)ramchain->allocsize;
    printf("combined ramchain size.%ld\n",(long)ramchain->allocsize);
    return(ramchain);
}
