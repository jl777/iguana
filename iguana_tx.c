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

#define iguana_hashfind(hashtable,key,keylen) iguana_hashset(hashtable,0,key,keylen,-1)

struct iguana_kvitem *iguana_hashset(struct iguana_kvitem *hashtable,struct iguana_memspace *mem,void *key,int32_t keylen,int32_t itemind)
{
    struct iguana_kvitem *ptr; int32_t allocsize;
    HASH_FIND(hh,hashtable,key,keylen,ptr);
    if ( ptr == 0 && itemind >= 0 )
    {
        allocsize = (int32_t)(sizeof(*ptr));
        ptr = (mem == 0) ? mycalloc('y',1,allocsize) : iguana_memalloc(mem,allocsize,1);
        if ( ptr == 0 )
            printf("fatal alloc error in hashset\n"), getchar();
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

struct iguana_txblock *iguana_txdataptrs(struct iguana_txid **Tptrp,struct iguana_unspent **Uptrp,struct iguana_spend **Sptrp,struct iguana_pkhash **Pptrp,bits256 **externalTptrp,struct iguana_memspace *mem,struct iguana_txblock *origtxdata)
{
    struct iguana_txblock *txdata; int32_t allocsize,rwflag = (origtxdata != 0);
    iguana_memreset(mem);
    allocsize = (int32_t)(sizeof(*txdata) - sizeof(txdata->space) + ((origtxdata != 0) ? origtxdata->extralen : 0));
    mem->alignflag = 4;
    if ( (txdata = iguana_memalloc(mem,allocsize,0)) == 0 )
        return(0);
    //printf("rwflag.%d origtxdat.%p allocsize.%d extralen.%d T.%d U.%d S.%d P.%d\n",rwflag,origtxdata,allocsize,origtxdata->extralen,txdata->numtxids,txdata->numunspents,txdata->numspends,txdata->numpkinds);
    if ( origtxdata != 0 )
        memcpy(txdata,origtxdata,allocsize);
    *Tptrp = iguana_memalloc(mem,sizeof(**Tptrp) * txdata->numtxids,rwflag);
    *Uptrp = iguana_memalloc(mem,sizeof(**Uptrp) * txdata->numunspents,rwflag);
    *Sptrp = iguana_memalloc(mem,sizeof(**Sptrp) * txdata->numspends,rwflag);
    if ( externalTptrp != 0 )
    {
        *Pptrp = iguana_memalloc(mem,0,rwflag);
        externalTptrp = iguana_memalloc(mem,txdata->numexternaltxids * sizeof(**externalTptrp),rwflag);
    } else *Pptrp = iguana_memalloc(mem,sizeof(**Pptrp) * txdata->numpkinds,rwflag);
    return(txdata);
}

uint64_t iguana_txdataset(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_txblock *origtxdata,struct iguana_msgtx *txarray,int32_t txn_count,uint8_t *data,int32_t recvlen)
{
    struct iguana_txid *T,*t; struct iguana_unspent *U,*u; struct iguana_spend *S,*s; struct iguana_pkhash *P;
    FILE *fp; long fpos;  bits256 *externalT; struct iguana_kvitem *txids,*pkhashes,*ptr;
    struct iguana_memspace *txmem,*hashmem; struct iguana_msgtx *tx; struct iguana_txblock *txdata = 0;
    int32_t i,j,numvins,numvouts,numexternal,numpkinds,scriptlen,sequence,spend_unspentind,datalen = 0;
    uint32_t txidind,unspentind,spendind,pkind; uint8_t *script,rmd160[20]; uint64_t txdatabits = 0;
    txmem = &addr->TXDATA, hashmem = &addr->HASHMEM;
    txids = pkhashes = 0;
    //printf("recvlen.%d txn_count.%d\n",recvlen,txn_count);
    if ( (txdata= iguana_txdataptrs(&T,&U,&S,&P,0,txmem,origtxdata)) == 0 || T == 0 || U == 0 || S == 0 || P == 0 )
    {
        printf("fatal error getting txdataptrs\n");
        getchar();
        return(0);
    }
    txidind = unspentind = spendind = pkind = 0;
    for (i=numvouts=numpkinds=0; i<txn_count; i++,txidind++)
    {
        tx = &txarray[i];
        t = &T[txidind];
        t->txid = tx->txid, t->txidind = txidind, t->firstvout = unspentind, t->numvouts = tx->tx_out;
        iguana_hashset(txids,hashmem,t->txid.bytes,sizeof(bits256),txidind);
        for (j=0; j<tx->tx_out; j++,numvouts++,unspentind++)
        {
            u = &U[unspentind];
            script = tx->vouts[j].pk_script, scriptlen = tx->vouts[j].pk_scriptlen;
            if ( (ptr= iguana_hashfind(pkhashes,rmd160,sizeof(rmd160))) == 0 )
            {
                memcpy(P[numpkinds].rmd160,rmd160,sizeof(rmd160));
                if ( (ptr= iguana_hashset(pkhashes,hashmem,rmd160,sizeof(rmd160),numpkinds++)) == 0 )
                    printf("fatal error adding pkhash\n"), getchar();
            }
            u->value = tx->vouts[j].value, u->txidind = txidind;
            u->pkind = ptr->hh.itemind;
            P[u->pkind].firstunspentind = unspentind;
            // prevunspentind requires having accts, so that waits for third pass
        }
    }
    if ( (txdata->numpkinds= numpkinds) > 0 )
        P = iguana_memalloc(txmem,sizeof(*P)*numpkinds,0);
    externalT = iguana_memalloc(txmem,0,1);
    txidind = 0;
    for (i=numvins=numexternal=0; i<txn_count; i++,txidind++)
    {
        tx = &txarray[i];
        t = &T[txidind];
        t->firstvin = spendind, t->numvins = tx->tx_in;
        for (j=0; j<tx->tx_in; j++,numvins++,spendind++)
        {
            script = tx->vins[j].script, scriptlen = tx->vins[j].scriptlen;
            s = &S[spendind];
            if ( (sequence= tx->vins[j].sequence) != (uint32_t)-1 )
                s->diffsequence = 1;
            spend_unspentind = -1;
            if ( (ptr= iguana_hashfind(txids,tx->vins[j].prev_hash.bytes,sizeof(bits256))) != 0 )
                spend_unspentind = ptr->hh.itemind;
            else
            {
                spend_unspentind = (txdata->numunspents + numexternal);
                externalT[numexternal++] = tx->vins[j].prev_hash;
            }
            if ( spend_unspentind >= 0 && spend_unspentind < (txdata->numunspents + numexternal) )
                s->unspentind = ((spend_unspentind << 16) | tx->vins[j].prev_vout);
            // prevspendind requires having accts, so that waits for third pass
        }
    }
    if ( (txdata->numexternaltxids= numexternal) > 0 )
        externalT = iguana_memalloc(txmem,sizeof(*externalT) * numexternal,0);
    datalen = (int32_t)txmem->used;
    if ( numvins != txdata->numspends || numvouts != txdata->numunspents || i != txdata->numtxids )
    {
        printf("counts mismatch: numvins %d != %d txdata->numvins || numvouts %d != %d txdata->numvouts || i %d != %d txdata->numtxids\n",numvins,txdata->numspends,numvouts,txdata->numunspents,i,txdata->numtxids);
        return(0);
    }
    if ( (fp= addr->fp) != 0 )
    {
        fpos = ftell(addr->fp);
        txdatabits = fpos | ((uint64_t)addr->addrind << IGUANA_LOG2MAXFILESIZE) | ((uint64_t)addr->filecount << (IGUANA_LOG2MAXFILESIZE+IGUANA_LOG2MAXPEERS));
        if ( fp != 0 )
        {
            fwrite(&txdata->datalen,1,sizeof(txdata->datalen),fp);
            fwrite(txdata,1,txdata->datalen,fp);
        }
    }
    return(txdatabits);
}

// two passes to check data size
int32_t iguana_rwvin(int32_t rwflag,struct iguana_memspace *mem,uint8_t *serialized,struct iguana_msgvin *msg)
{
    int32_t len = 0;
    len += iguana_rwbignum(rwflag,&serialized[len],sizeof(msg->prev_hash),msg->prev_hash.bytes);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->prev_vout),&msg->prev_vout);
    //printf("vin.(%s) %d\n",bits256_str(msg->prev_hash),msg->prev_vout);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->scriptlen);
    if ( rwflag == 0 )
        msg->script = iguana_memalloc(mem,msg->scriptlen,1);
    len += iguana_rwmem(rwflag,&serialized[len],msg->scriptlen,msg->script);
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->sequence),&msg->sequence);
    //int i; for (i=0; i<msg->scriptlen; i++)
    // printf("%02x ",msg->script[i]);
    //printf(" inscriptlen.%d, prevhash.%llx prev_vout.%d | ",msg->scriptlen,(long long)msg->prev_hash.txid,msg->prev_vout);
    return(len);
}

int32_t iguana_rwvout(int32_t rwflag,struct iguana_memspace *mem,uint8_t *serialized,struct iguana_msgvout *msg)
{
    int32_t len = 0;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->value),&msg->value);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->pk_scriptlen);
    if ( rwflag == 0 )
        msg->pk_script = iguana_memalloc(mem,msg->pk_scriptlen,1);
    len += iguana_rwmem(rwflag,&serialized[len],msg->pk_scriptlen,msg->pk_script);
    //printf("(%.8f scriptlen.%d) ",dstr(msg->value),msg->pk_scriptlen);
    //int i; for (i=0; i<msg->pk_scriptlen; i++)
    //    printf("%02x",msg->pk_script[i]);
    //printf("\n");
    return(len);
}

int32_t iguana_rwtx(int32_t rwflag,struct iguana_memspace *mem,uint8_t *serialized,struct iguana_msgtx *msg,int32_t maxsize,bits256 *txidp,int32_t height,int32_t hastimestamp)
{
    int32_t i,len = 0; uint8_t *txstart = serialized; char txidstr[65]; uint32_t timestamp;
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->version),&msg->version);
    if ( hastimestamp != 0 )
        len += iguana_rwnum(rwflag,&serialized[len],sizeof(timestamp),&timestamp);
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_in);
    //printf("version.%d ",msg->version);
    if ( msg->tx_in > 0 && msg->tx_out*100 < maxsize )
    {
        if ( rwflag == 0 )
            msg->vins = iguana_memalloc(mem,msg->tx_in * sizeof(*msg->vins),1);
        for (i=0; i<msg->tx_in; i++)
            len += iguana_rwvin(rwflag,mem,&serialized[len],&msg->vins[i]);
        //printf("numvins.%d\n",msg->tx_in);
    }
    else
    {
        printf("invalid tx_in.%d\n",msg->tx_in);
        return(-1);
    }
    len += iguana_rwvarint32(rwflag,&serialized[len],&msg->tx_out);
    if ( msg->tx_out > 0 && msg->tx_out*32 < maxsize )
    {
        //printf("numvouts.%d ",msg->tx_out);
        if ( rwflag == 0 )
            msg->vouts = iguana_memalloc(mem,msg->tx_out * sizeof(*msg->vouts),1);
        for (i=0; i<msg->tx_out; i++)
            len += iguana_rwvout(rwflag,mem,&serialized[len],&msg->vouts[i]);
    }
    else
    {
        printf("invalid tx_out.%d\n",msg->tx_out);
        return(-1);
    }
    len += iguana_rwnum(rwflag,&serialized[len],sizeof(msg->lock_time),&msg->lock_time);
    *txidp = bits256_doublesha256(txidstr,txstart,len);
    msg->allocsize = len;
    return(len);
}

int32_t iguana_gentxarray(struct iguana_info *coin,struct iguana_memspace *mem,struct iguana_txblock *txdata,int32_t *lenp,uint8_t *data,int32_t datalen)
{
    struct iguana_msgtx *tx; bits256 hash2; struct iguana_msgblock msg; int32_t i,n,len,numvouts,numvins;
    memset(&msg,0,sizeof(msg));
    len = iguana_rwblock(0,&hash2,data,&msg);
    iguana_convblock(&txdata->block,&msg,hash2,-1);
    tx = iguana_memalloc(mem,msg.txn_count*sizeof(*tx),1);
    for (i=numvins=numvouts=0; i<msg.txn_count; i++)
    {
        if ( (n= iguana_rwtx(0,mem,&data[len],&tx[i],datalen - len,&tx[i].txid,txdata->block.height,coin->chain->hastimestamp)) < 0 )
            break;
        numvouts += tx[i].tx_out;
        numvins += tx[i].tx_in;
        len += n;
    }
    if ( coin->chain->hastimestamp != 0 && len != datalen && data[len] == (datalen - len - 1) )
    {
        printf("\n>>>>>>>>>>> len.%d vs datalen.%d [%d]\n",len,datalen,data[len]);
        memcpy(txdata->space,&data[len],datalen-len);
        len += (datalen-len);
        txdata->extralen = (datalen - len);
    } else txdata->extralen = 0;
    txdata->recvlen = len;
    txdata->numtxids = msg.txn_count;
    txdata->numunspents = numvouts;
    txdata->numspends = numvins;
    return(len);
}

struct iguana_bundlereq *iguana_bundlereq(struct iguana_info *coin,struct iguana_peer *addr,int32_t type,int32_t datalen)
{
    struct iguana_bundlereq *req; int32_t allocsize;
    allocsize = (uint32_t)sizeof(*req) + datalen;
    req = mycalloc(type,1,allocsize);
    req->allocsize = allocsize;
    req->datalen = datalen;
    req->addr = addr;
    req->coin = coin;
    req->type = type;
    return(req);
}

void iguana_gottxidsM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *txids,int32_t n)
{
    struct iguana_bundlereq *req;
    printf("got %d txids from %s\n",n,addr->ipaddr);
    req = iguana_bundlereq(coin,addr,'T',0);
    req->hashes = txids, req->n = n;
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotunconfirmedM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_msgtx *tx,uint8_t *data,int32_t datalen)
{
    struct iguana_bundlereq *req;
    char str[65]; bits256_str(str,tx->txid);
    printf("%s unconfirmed.%s\n",addr->ipaddr,str);
    req = iguana_bundlereq(coin,addr,'U',datalen);
    req->datalen = datalen;
    memcpy(req->serialized,data,datalen);
    //iguana_freetx(tx,1);
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotblockM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_txblock *txdata,struct iguana_msgtx *txarray,uint8_t *data,int32_t datalen)
{
    struct iguana_bundlereq *req; int32_t i; uint64_t txdatabits = 0;
    if ( 0 )
    {
        for (i=0; i<txdata->space[0]; i++)
            if ( txdata->space[i] != 0 )
                break;
        if ( i != txdata->space[0] )
        {
            for (i=0; i<txdata->space[0]; i++)
                printf("%02x ",txdata->space[i]);
            printf("extra\n");
        }
    }
    req = iguana_bundlereq(coin,addr,'B',0);
    if ( addr != 0 )
    {
        if ( addr->pendblocks > 0 )
            addr->pendblocks--;
        addr->lastblockrecv = (uint32_t)time(NULL);
        addr->recvblocks += 1.;
        addr->recvtotal += datalen;
        if ( (txdatabits= iguana_txdataset(coin,addr,txdata,txarray,txdata->block.txn_count,data,datalen)) != 0 )
            req->datalen = datalen;
    }
    coin->recvcount++;
    coin->recvtime = (uint32_t)time(NULL);
    req->block = txdata->block;
    req->txdatabits = txdatabits;
    req->block.txn_count = req->numtx = txdata->block.txn_count;
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotheadersM(struct iguana_info *coin,struct iguana_peer *addr,struct iguana_block *blocks,int32_t n)
{
    struct iguana_bundlereq *req;
    if ( addr != 0 )
    {
        addr->recvhdrs++;
        if ( addr->pendhdrs > 0 )
            addr->pendhdrs--;
        //printf("%s blocks[%d] ht.%d gotheaders pend.%d %.0f\n",addr->ipaddr,n,blocks[0].height,addr->pendhdrs,milliseconds());
    }
    req = iguana_bundlereq(coin,addr,'H',0);
    req->blocks = blocks, req->n = n;
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

void iguana_gotblockhashesM(struct iguana_info *coin,struct iguana_peer *addr,bits256 *blockhashes,int32_t n)
{
    struct iguana_bundlereq *req;
    if ( addr != 0 )
    {
        addr->recvhdrs++;
        if ( addr->pendhdrs > 0 )
            addr->pendhdrs--;
    }
    req = iguana_bundlereq(coin,addr,'S',0);
    req->hashes = blockhashes, req->n = n;
    //printf("bundlesQ blockhashes.%p[%d]\n",blockhashes,n);
    queue_enqueue("bundlesQ",&coin->bundlesQ,&req->DL,0);
}

int32_t iguana_helpertask(FILE *fp,struct iguana_helper *ptr)
{
   /* if ( bp->type == 'Q' )
    {
        req = (struct iguana_bundlereq *)ptr;
        //printf("START.%p save tmp txdata %p [%d].%d datalen.%d %p\n",req,req->argbp,req->argbp!=0?req->argbp->hdrsi:-1,req->argbundlei,req->datalen,req->data);
        if ( fp != 0 )
        {
            if ( fwrite(req->data,1,req->datalen,fp) != req->datalen )
                printf("error writing [%d].%d datalen.%d\n",req->argbp!=0?req->argbp->hdrsi:-1,req->argbundlei,req->datalen);
        }
        //Tx_freed++;
        //Tx_freesize += req->allocsize;
        if ( req->data != 0 )
            myfree(req->data,req->datalen);
        if ( req->blocks != 0 )
            myfree(req->blocks,sizeof(*req->blocks));
        myfree(req,req->allocsize);
    }
    else if ( bp->type == 'E' )
    {
        fflush(fp);
        //myallocated(0,0);
        //iguana_emittxdata(bp->coin,bp);
        //myallocated(0,0);
        if ( bp->coin != 0 )
        {
            if ( bp->coin->estsize > bp->coin->MAXRECVCACHE*.9 && bp->coin->MAXBUNDLES > _IGUANA_MAXBUNDLES )
                bp->coin->MAXBUNDLES--;
            else if ( bp->coin->activebundles >= bp->coin->MAXBUNDLES && bp->coin->estsize < bp->coin->MAXRECVCACHE*.5 )
                bp->coin->MAXBUNDLES++;
            bp->coin->numemitted++;
        }
    }
    else
    {
        printf("iguana_helper: unsupported type.%c %d %p\n",bp->type,bp->type,bp);
    }*/
    return(0);
}
